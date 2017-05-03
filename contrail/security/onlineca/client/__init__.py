"""Online CA service client package

Contrail Project
"""
__author__ = "P J Kershaw"
__date__ = "28/05/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
log = logging.getLogger(__name__)
import base64
import os
import errno

import six
from pip._vendor.requests.sessions import session
from requests.sessions import Session
import requests_oauthlib

if six.PY2:
    _unicode_conv = lambda string_: string_
else:
    _unicode_conv = lambda string_: (isinstance(string_, bytes) and
                                     string_.decode() or string_)

import requests
from requests.auth import HTTPBasicAuth
import requests_oauthlib

from OpenSSL import SSL, crypto


class OnlineCaClientErrorResponse(Exception):
    '''Error response for Online CA client'''
    def __init__(self, message, http_resp):
        ''':param message: exception message
        :type message: string
        :param http_resp: HTTP response object
        :type http_resp: requests.Response
        '''
        super(OnlineCaClientErrorResponse, self).__init__(message)
        self.http_resp = http_resp


class OnlineCaClient(object):
    '''Client to Online Certificate Authority Service'''

    PRIKEY_NBITS = 2048
    MESSAGE_DIGEST_TYPE = "sha256"
    CERT_REQ_POST_PARAM_KEYNAME = b'certificate_request'
    TRUSTED_CERTS_FIELDNAME = b'TRUSTED_CERTS'
    TRUSTED_CERTS_FILEDATA_FIELDNAME_PREFIX = b'FILEDATA_'

    def __init__(self):
        self.__ca_cert_dir = None

    @property
    def ca_cert_dir(self):
        return self.__ca_cert_dir

    @ca_cert_dir.setter
    def ca_cert_dir(self, val):
        if not isinstance(val, six.string_types):
            raise TypeError('Expecting string type for "ca_cert_dir"; got %r' %
                            type(val))

        self.__ca_cert_dir = val

    @staticmethod
    def create_key_pair(n_bits_for_key=PRIKEY_NBITS):
        """Generate key pair and return as PEM encoded string
        :type n_bits_for_key: int
        :param n_bits_for_key: number of bits for private key generation -
        default is 2048
        :rtype: OpenSSL.crypto.PKey
        :return: public/private key pair
        """
        key_pair = crypto.PKey()
        key_pair.generate_key(crypto.TYPE_RSA, n_bits_for_key)

        return key_pair

    @staticmethod
    def create_cert_req(key_pair, message_digest=MESSAGE_DIGEST_TYPE):
        """Create a certificate request.

        :type key_pair: string/None
        :param key_pair: public/private key pair
        :type message_digest: basestring
        :param message_digest: message digest type - default is MD5
        :rtype: base string
        :return: certificate request PEM text and private key PEM text
        """

        # Check all required certificate request DN parameters are set
        # Create certificate request
        cert_req = crypto.X509Req()

        # Create public key object
        cert_req.set_pubkey(key_pair)

        # Add the public key to the request
        cert_req.sign(key_pair, message_digest)

        cert_req = crypto.dump_certificate_request(crypto.FILETYPE_PEM,
                                                   cert_req)

        return cert_req

    def get_certificate_using_session(self, session, server_url,
                                      pem_out_filepath=None):
        '''Obtain a create a new key pair and invoke the SLCS service to obtain
        a certificate using authentication method determined by input session
        object: the latter can be username/password using HTTPBasicAuth object
        or OAuth 2.0 access token with OAuth2Session

        :param session: Requests session containing the authentication context:
        either a session with a HTTBasicAuth object as its auth attribute or a
        requests_oauthlib.OAuth2Session
        :param server_url: URL for get certificate endpoint
        :param pem_out_filepath: optionally set output path for file containing
        concatenated private key and certificate issued
        :return: tuple of key pair object and certificate
        '''
        if not isinstance(session, requests.Session):
            raise TypeError('Expecting requests.Session or '
                            'oauthlib_requests.OAuth2Session type for session '
                            'object')

        key_pair = self.__class__.create_key_pair()
        cert_req = self.__class__.create_cert_req(key_pair)

        # Convert plus chars to make it safe for HTTP POST
        encoded_cert_req = cert_req.replace(b'+', b'%2B')
        req = b"%s=%s\n" % (self.__class__.CERT_REQ_POST_PARAM_KEYNAME,
                            encoded_cert_req)

        res = session.post(server_url, data=req, verify=self.ca_cert_dir)
        if not res.ok:
            raise OnlineCaClientErrorResponse('Error getting certificate'
                                              ': status: {} {}'.format(
                                                                res.status_code,
                                                                res.reason),
                                              res)

        # Response contains PEM-encoded certificate just issued + any additional
        # CA certificates in the chain of trust configured on the server-side.
        # Parse into OpenSSL.crypto.X509 objects
        cert_s = res.content.decode(encoding='utf-8')
        cert_list = []
        for pem_cert_frag in cert_s.split('-----BEGIN CERTIFICATE-----')[1:]:
            pem_cert = '-----BEGIN CERTIFICATE-----' + pem_cert_frag
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_cert)
            cert_list.append(cert)

        cert = crypto.load_certificate(crypto.FILETYPE_PEM, res.content)

        # Optionally output the private key and certificate together PEM
        # encoded in a single file
        if pem_out_filepath:
            pem_pkey = crypto.dump_privatekey(crypto.FILETYPE_PEM, key_pair)
            pem_cert = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)

            with open(pem_out_filepath, 'wb', 0o400) as pem_out_file:
                pem_out_file.write(res.content)
                pem_out_file.write(pem_pkey)

        return key_pair, (cert, ) + tuple(cert_list)

    def get_certificate(self, username, password, server_url,
                        pem_out_filepath=None):
        """Obtain a create a new key pair and invoke the SLCS service to obtain
        a certificate using username/password with HTTP Basic Auth

        :param username: username for user authentication
        :param password: password for user authentication
        :param server_url: URL for get certificate endpoint
        :param pem_out_filepath: optionally set output path for file containing
        concatenated private key and certificate issued
        :return: tuple of key pair object and certificate
        """
        session = requests.Session()
        session.auth = HTTPBasicAuth(username, password)

        return self.get_certificate_using_session(session, server_url,
                                            pem_out_filepath=pem_out_filepath)

    def get_delegated_certificate(self, access_token, server_url,
                                  pem_out_filepath=None):
        '''Obtain a create a new key pair and invoke the SLCS service to obtain
        a delegated certificate using an OAuth 2.0 access token.  Nb.
        get_certificate_using_session can be used as an alternative to allow
        passing in a populated OAuth2Session object

        :param access_token: OAuth 2.0 access token
        :param server_url: URL for get certificate endpoint
        :param pem_out_filepath: optionally set output path for file containing
        concatenated private key and certificate issued
        :return: tuple of key pair object and certificate
        '''
        session = requests_oauthlib.OAuth2Session()
        session.access_token = access_token

        return self.get_certificate_using_session(session, server_url,
                                            pem_out_filepath=pem_out_filepath)

    def get_trustroots(self, server_url, write_to_ca_cert_dir=False,
                       bootstrap=False):
        """Get Certificate authority files to enable client to correctly apply
        SSL verification of server peer.

        :param server_url: URL for get certificate endpoint
        :param write_to_ca_cert_dir: optionally set output path for directory
        to write CA trust root files
        :param bootstrap: set to True to bootstrap trust in the server.  This
        disables SSL authentication of the server to initialise trust in it.
        Use with caution as this exposes the client to spoofing attacks
        :return: dictionary containing CA trust root files as strings
        """
        if bootstrap:
            kwargs = {'verify': False}
        else:
            kwargs = {'verify': self.ca_cert_dir}

        res = requests.get(server_url, **kwargs)
        if not res.ok:
            raise OnlineCaClientErrorResponse('Error retrieving CA trust roots'
                                              ': status: {} {}'.format(
                                                                res.status_code,
                                                                res.reason),
                                              res)

        files_dict = {}
        for line in res.content.splitlines():
            file_name, enc_file_content = line.strip().split(b'=', 1)
            files_dict[file_name] = base64.b64decode(enc_file_content)

        if write_to_ca_cert_dir:
            # Create the CA directory path if doesn't already exist
            try:
                os.makedirs(self.ca_cert_dir)
            except OSError as e:
                # Ignore if the path already exists
                if e.errno != errno.EEXIST:
                    raise

            for file_name, file_contents in files_dict.items():
                file_path = os.path.join(self.ca_cert_dir,
                                         _unicode_conv(file_name))
                with open(file_path, 'wb') as trustroot_file:
                    trustroot_file.write(file_contents)

        return files_dict
