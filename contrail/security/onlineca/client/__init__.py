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
    MESSAGE_DIGEST_TYPE = "md5"
    CERT_REQ_POST_PARAM_KEYNAME = b'certificate_request'
    TRUSTED_CERTS_FIELDNAME = b'TRUSTED_CERTS'
    TRUSTED_CERTS_FILEDATA_FIELDNAME_PREFIX = b'FILEDATA_'
    SSL_METHOD = SSL.TLSv1_METHOD

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
        @type n_bits_for_key: int
        @param n_bits_for_key: number of bits for private key generation - 
        default is 2048
        @rtype: OpenSSL.crypto.PKey
        @return: public/private key pair
        """
        key_pair = crypto.PKey()
        key_pair.generate_key(crypto.TYPE_RSA, n_bits_for_key)
        
        return key_pair
            
    @staticmethod
    def create_cert_req(key_pair, message_digest=MESSAGE_DIGEST_TYPE):
        """Create a certificate request.
        
        @type keyPair: string/None
        @param keyPair: public/private key pair
        @type messageDigest: basestring
        @param messageDigest: message digest type - default is MD5
        @rtype: base string
        @return certificate request PEM text and private key PEM text
        """
        
        # Check all required certifcate request DN parameters are set                
        # Create certificate request
        cert_req = crypto.X509Req()
        
        # Create public key object
        cert_req.set_pubkey(key_pair)
        
        # Add the public key to the request
        cert_req.sign(key_pair, message_digest)
        
        cert_req = crypto.dump_certificate_request(crypto.FILETYPE_PEM, 
                                                   cert_req)
        
        return cert_req
        
    def logon(self, username, password, server_url, proxies=None, no_proxy=None,
              cert_life_time=86400, ssl_ctx=None, pem_out_filepath=None):
        """Obtain a create a new key pair and invoke the SLCS service to obtain
        a certificate
        """
        if ssl_ctx is None:
            ssl_ctx = make_ssl_context(ca_dir=self.ca_cert_dir, 
									   verify_peer=True, 
                                       url=server_url, 
                                       method=self.__class__.SSL_METHOD)

        # Create a password manager
        password_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        
        # Get base URL for setting basic auth scope
        parsed_url = urlparse(server_url)
        base_url = urlunparse(parsed_url[0:2] + ('/', '', '', ''))
        
        # Add the username and password.
        # If we knew the realm, we could use it instead of ``None``.
        password_mgr.add_password(None, base_url, username, password)
        
        handlers = [urllib.request.HTTPBasicAuthHandler(password_mgr)]
            
        key_pair = self.__class__.create_key_pair()
        cert_req = self.__class__.create_cert_req(key_pair)
        
        # Convert plus chars to make it safe for HTTP POST
        encoded_cert_req = cert_req.replace(b'+', b'%2B')
        req = b"%s=%s\n" % (self.__class__.CERT_REQ_POST_PARAM_KEYNAME, 
                            encoded_cert_req)
        config = Configuration(ssl_ctx, True)
        res = fetch_stream_from_url(server_url, config, data=req, 
                                    handlers=handlers)
                                    
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
            ca_cert_dir = None
        else:
            ca_cert_dir = self.ca_cert_dir

        ssl_ctx = make_ssl_context(ca_cert_dir, 
								   verify_peer=not bootstrap, 
								   url=server_url, 
								   method=self.__class__.SSL_METHOD)

        config = Configuration(ssl_ctx, True)
        res = fetch_stream_from_url(server_url, config)
        
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
