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

if six.PY2:
    _unicode_conv = lambda string_: string_
else:
    _unicode_conv = lambda string_: (isinstance(string_, bytes) and
                                     string_.decode() or string_)

import requests
from requests.auth import HTTPBasicAuth

from six.moves import urllib
from six.moves.urllib.parse import urlparse, urlunparse

from OpenSSL import SSL, crypto

from ndg.httpsclient.ssl_context_util import make_ssl_context
from ndg.httpsclient.urllib2_build_opener import build_opener
from ndg.httpsclient.utils import (_should_use_proxy, fetch_stream_from_url,
                                   Configuration)


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

    def get_certificate(self, username, password, server_url, pem_out_filepath=None):
        """Obtain a create a new key pair and invoke the SLCS service to obtain
        a certificate
        """
        http_basic_auth = HTTPBasicAuth(username, password)

        key_pair = self.__class__.create_key_pair()
        cert_req = self.__class__.create_cert_req(key_pair)

        # Convert plus chars to make it safe for HTTP POST
        encoded_cert_req = cert_req.replace(b'+', b'%2B')
        req = b"%s=%s\n" % (self.__class__.CERT_REQ_POST_PARAM_KEYNAME,
                            encoded_cert_req)

        res = requests.post(server_url, data=req, auth=http_basic_auth,
                            verify=self.ca_cert_dir)

        pem_out = res.read()
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_out)

        # Optionally output the private key and certificate together PEM
        # encoded in a single file
        if pem_out_filepath:
            pem_pkey = crypto.dump_privatekey(crypto.FILETYPE_PEM, key_pair)
            pem_cert = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)

            with open(pem_out_filepath, 'wb', 0o400) as pem_out_file:
                pem_out_file.write(pem_pkey)
                pem_out_file.write(pem_cert)

        return key_pair, cert

    def get_trustroots(self, server_url, write_to_ca_cert_dir=False,
                       bootstrap=False):
        """Get trustroots"""
        if bootstrap:
            kwargs = {}
        else:
            kwargs = {'verify': self.ca_cert_dir}

        res = requests.get(server_url, **kwargs)

        files_dict = {}
        for line in res.readlines():
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
                open(file_path, 'wb').write(file_contents)

        return files_dict
