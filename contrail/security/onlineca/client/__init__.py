"""Online CA service client package

Contrail Project
"""
__author__ = "P J Kershaw"
__date__ = "28/05/12"
__copyright__ = "Copyright 2019 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
import logging
import stat
log = logging.getLogger(__name__)
import base64
import os
import errno
import json

import six
from requests.sessions import session
import requests
import requests_oauthlib
from OpenSSL import SSL, crypto
from asn1crypto.x509 import BasicConstraints

if six.PY2:
    _unicode_conv = lambda string_: string_
else:
    _unicode_conv = lambda string_: (isinstance(string_, bytes) and
                                     string_.decode() or string_)


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
    PEM_CERT_BEGIN_DELIM = '-----BEGIN CERTIFICATE-----'
    X509_BASIC_CONSTR_FIELDNAME = b'basicConstraints'
    X509_BASIC_CONSTR_CAFLAG_FIELDNAME = 'ca'

    # Optionally, OAuth Access Token can be stored and retrieved from this 
    # default location
    DEF_OAUTH_TOK_FILENAME = ".onlinecaclient_token.json"
    DEF_OAUTH_TOK_FILEPATH = os.path.join(os.environ['HOME'], 
                                        DEF_OAUTH_TOK_FILENAME)

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

        cert_req_s = crypto.dump_certificate_request(crypto.FILETYPE_PEM,
                                                     cert_req)

        return cert_req_s

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

        req = {self.__class__.CERT_REQ_POST_PARAM_KEYNAME: cert_req}

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
        certchain = []
        endentity_cert = None
        for pem_cert_frag in cert_s.split(self.PEM_CERT_BEGIN_DELIM)[1:]:
            pem_cert = self.PEM_CERT_BEGIN_DELIM + pem_cert_frag

            cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_cert)

            # Separate certificates into the end entity certificate and any
            # certificates in an intermediate chain of trust to the root.
            # The end entity certificate ought to be the first but this code
            # does a sanity check
            if self._is_ca_certificate(cert):
                # If it's a CA certificate, then it must be part of the 
                # intermediate chain. Nb. RFC3820 Proxy certificates are not 
                # supported here
                certchain.append(cert)
            else:
                # check for more than one end entity certificate
                if endentity_cert is not None:
                    raise Exception('Multiple end-entity certificates found '
                        'in response: certificates with subject, '
                        f'{endentity_cert.get_subject()} and {cert.get_subject()}')

                endentity_cert = cert

        # Optionally output the private key and certificate together PEM
        # encoded in a single file. Any additional certificate chain is appended
        # to the end of the output
        if pem_out_filepath:
            pem_pkey = crypto.dump_privatekey(crypto.FILETYPE_PEM, key_pair)
            pem_endentity_cert = crypto.dump_certificate(crypto.FILETYPE_PEM, 
                                                         endentity_cert)
            pem_certchain = b""
            for cacert in certchain:
                pem_certchain += crypto.dump_certificate(crypto.FILETYPE_PEM, cacert)

            with open(pem_out_filepath, 'wb', 0o400) as pem_out_file:
                pem_out_file.write(pem_endentity_cert)
                pem_out_file.write(pem_pkey)
                pem_out_file.write(pem_certchain)

        return key_pair, (endentity_cert, ) + tuple(certchain)

    @classmethod
    def _is_ca_certificate(cls, cert):
        '''Helper method for checking whether a certificate is a CA certificate.
        It checks the BasicConstraints extension for ca flag set. This method
        is used for parsing and organising response from get certificate
        call.
        '''
        n_ext = cert.get_extension_count()
        for i in range(n_ext):
            ext = cert.get_extension(i)
            short_name = ext.get_short_name()
            if short_name == cls.X509_BASIC_CONSTR_FIELDNAME:
                ext_dat = ext.get_data()
                parsed_ext_dat = BasicConstraints.load(ext_dat)
                if parsed_ext_dat.native.get(
                        cls.X509_BASIC_CONSTR_CAFLAG_FIELDNAME, False) is True:
                    return True

        return False

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
        session.auth = requests.auth.HTTPBasicAuth(username, password)

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
        session = requests_oauthlib.OAuth2Session(token=access_token)

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

    @classmethod
    def save_oauth_tok(cls, token, tok_filepath=None):
        """Convenience routine - serialise OAuth token for later re-use.

        Care should be taken to ensure that the content is held securely
        on the target file system
        """
        if tok_filepath is None:
            tok_filepath = cls.DEF_OAUTH_TOK_FILEPATH

        tok_file_content = json.dumps(token)

        # Write file with user-only rw permissions
        fname = '/tmp/myfile'
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL  # Refer to "man 2 open".
        mode = stat.S_IRUSR | stat.S_IWUSR  # 0o600 mode
        umask = 0o777 ^ mode  # Prevents always downgrading umask to 0.

        # For security, remove file with potentially elevated mode
        try:
            os.remove(tok_filepath)
        except OSError:
            pass

        # Open file descriptor
        umask_original = os.umask(umask)

        try:
            tok_file_desc = os.open(tok_filepath, flags, mode)
        finally:
            os.umask(umask_original)

        with os.fdopen(tok_file_desc, "w") as tok_file:
            tok_file.write(tok_file_content)

    @classmethod
    def read_oauth_tok(cls, tok_filepath=None):
        """Convenience routine - read previously saved OAuth token for re-use.
        
        Care should be taken to ensure that the content is held securely
        on the target file system
        """
        if tok_filepath is None:
            tok_filepath = cls.DEF_OAUTH_TOK_FILEPATH
        
        with open(tok_filepath) as tok_file:
            tok_file_content = tok_file.read()

        return json.loads(tok_file_content)
