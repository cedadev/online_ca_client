"""MyProxy Web Service - web services client package

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
import urllib2
from urlparse import urlparse, urlunparse

from OpenSSL import SSL, crypto
from ndg.httpsclient.utils import (_should_use_proxy, fetch_stream_from_url, 
                                   Configuration)
from ndg.httpsclient.ssl_context_util import make_ssl_context
from ndg.httpsclient.urllib2_build_opener import build_opener

testvar = True

class MyProxyWSClient(object):
    PRIKEY_NBITS = 2048
    MESSAGE_DIGEST_TYPE = "md5"
    CERT_REQ_POST_PARAM_KEYNAME = 'certificate_request'
    TRUSTED_CERTS_FIELDNAME = 'TRUSTED_CERTS'
    TRUSTED_CERTS_FILEDATA_FIELDNAME_PREFIX = 'FILEDATA_'

    def __init__(self):
        self.__ca_cert_dir = None
        self.timeout = 500

    @property
    def ca_cert_dir(self):
        return self.__ca_cert_dir
    
    @ca_cert_dir.setter
    def ca_cert_dir(self, val):
        if not isinstance(val, basestring):
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
        
        @type CN: basestring
        @param CN: Common Name for certificate - effectively the same as the
        username for the MyProxy credential
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
              cert_life_time=86400, ssl_ctx=None):
        """Obtain a new certificate"""
        if ssl_ctx is None:
            ssl_ctx = make_ssl_context(ca_dir=self.ca_cert_dir, verify_peer=True, 
                                       url=server_url, 
                                       method=SSL.SSLv3_METHOD)

        # Create a password manager
        password_mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
        
        # Get base URL for setting basic auth scope
        parsed_url = urlparse(server_url)
        base_url = urlunparse(parsed_url[0:2] + ('/', '', '', ''))
        
        # Add the username and password.
        # If we knew the realm, we could use it instead of ``None``.
        password_mgr.add_password(None, base_url, username, password)
        
        handlers = [urllib2.HTTPBasicAuthHandler(password_mgr)]
            
        key_pair = self.__class__.create_key_pair()
        cert_req = self.__class__.create_cert_req(key_pair)
        
        # Convert plus chars to make it safe for HTTP POST
        encoded_cert_req = cert_req.replace('+', '%2B')
        req = "%s=%s\n" % (self.__class__.CERT_REQ_POST_PARAM_KEYNAME, 
                           encoded_cert_req)
        config = Configuration(ssl_ctx, True)
        res = fetch_stream_from_url(server_url, config, data=req, 
                                    handlers=handlers)
        
        return res
        
    def get_trustroots(self, server_url, write_to_ca_cert_dir=False, 
                       bootstrap=False):
        """Get trustroots"""
        raise NotImplementedError('To be completed in a subsequent release')
        prefix = self.__class__.TRUSTED_CERTS_FILEDATA_FIELDNAME_PREFIX
        field_name = self.__class__.TRUSTED_CERTS_FIELDNAME
        file_data = {}
        
        files_dict = dict([(k.split(prefix, 1)[1], base64.b64decode(v)) 
                          for k, v in file_data.items() if k != field_name])
        
        if write_to_ca_cert_dir:
            # Create the CA directory path if doesn't already exist
            try:
                os.makedirs(self.ca_cert_dir)
            except OSError, e:
                # Ignore if the path already exists
                if e.errno != errno.EEXIST:
                    raise
                
            for file_name, file_contents in files_dict.items():
                file_path = os.path.join(self.ca_cert_dir, file_name)
                open(file_path, 'wb').write(file_contents)
                
        return files_dict