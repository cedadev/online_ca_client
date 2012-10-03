#!/usr/bin/env python
"""Unit tests for MyProxy WSGI Middleware classes and Application.  These are
run using paste.fixture i.e. tests stubs to a web application server
"""
__author__ = "P J Kershaw"
__date__ = "21/05/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
logging.basicConfig(level=logging.DEBUG)

import unittest
import os
import base64
from getpass import getpass
from ConfigParser import SafeConfigParser, NoOptionError

from OpenSSL import crypto
import paste.fixture
from paste.deploy import loadapp

from myproxy.ws.server.wsgi.middleware import MyProxyLogonWSMiddleware


class TestMyProxyClientMiddlewareApp(object):
    '''Test Application for MyClientProxyMiddleware'''
    RESPONSE = "Test MyProxyClientMiddleware"
    
    def __call__(self, environ, start_response):
        
        assert(environ[MyProxyLogonWSMiddleware.DEFAULT_CLIENT_ENV_KEYNAME])
        status = "200 OK"
                
        start_response(status,
                       [('Content-length', 
                         str(len(self.__class__.RESPONSE))),
                        ('Content-type', 'text/plain')])
        return [self.__class__.RESPONSE]


class MyProxyClientMiddlewareTestCase(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        app = TestMyProxyClientMiddlewareApp()
        app = MyProxyLogonWSMiddleware.filter_app_factory(app, {}, prefix='')
        self.app = paste.fixture.TestApp(app)
         
        unittest.TestCase.__init__(self, *args, **kwargs)

    def test01AssertMyProxyClientInEnviron(self):
        # Check the middleware has set the MyProxy client object in environ
        response = self.app.get('/', status=200)
        self.assert_(response)
        

class MyProxyPasteDeployTestCaseBase(unittest.TestCase):  
    """Base class for common Paste Deploy related set-up"""
    INI_FILENAME = 'myproxywsgi.ini'
    THIS_DIR = os.path.abspath(os.path.dirname(__file__))
    CONFIG_FILENAME = 'test_myproxywsgi.cfg'
    CONFIG_FILEPATH = os.path.join(THIS_DIR, CONFIG_FILENAME)
    
    def __init__(self, *args, **kwargs):
        here_dir = os.path.dirname(os.path.abspath(__file__))
        wsgiapp = loadapp('config:' + self.__class__.INI_FILENAME, 
                          relative_to=here_dir)
        self.app = paste.fixture.TestApp(wsgiapp)
        
        self.cfg = SafeConfigParser({'here': self.__class__.THIS_DIR})
        self.cfg.optionxform = str
        self.cfg.read(self.__class__.CONFIG_FILEPATH)
        
        unittest.TestCase.__init__(self, *args, **kwargs)  
                
                
class MyProxyLogonAppTestCase(MyProxyPasteDeployTestCaseBase):
    """Test HTTP MyProxy logon interface"""
        
    def _createRequestCreds(self):
        keyPair = crypto.PKey()
        keyPair.generate_key(crypto.TYPE_RSA, 1024)
        
        certReq = crypto.X509Req()
        
        # Create public key object
        certReq.set_pubkey(keyPair)
        
        # Add the public key to the request
        certReq.sign(keyPair, "md5")
        
        pemCertReq = crypto.dump_certificate_request(crypto.FILETYPE_PEM, 
                                                     certReq)
        return keyPair, pemCertReq
        
    def test01Logon(self):
        # Test successful logon
        username = self.cfg.get('MyProxyLogonAppTestCase.test01Logon', 
                                'username')
        try: 
            password = self.cfg.get('MyProxyLogonAppTestCase.test01Logon', 
                                    'password')
        except NoOptionError:
            password = getpass('MyProxyLogonAppTestCase.test01Logon password: ')
            
        base64String = base64.encodestring('%s:%s' % (username, password))[:-1]
        authHeader =  "Basic %s" % base64String
        headers = {'Authorization': authHeader}
        
        # Create key pair and certificate request
        keyPair, certReq = self._createRequestCreds()
        
        postData = {
            MyProxyLogonWSMiddleware.CERT_REQ_POST_PARAM_KEYNAME: certReq
        }
        response = self.app.post('/logon', postData, headers=headers, 
                                 status=200)
        print response 
        self.assert_(response)
        
    def test02NoAuthorisationHeaderSet(self):   
        # Test failure with omission of HTTP Basic Auth header - a 401 result is
        # expected.
             
        # Create key pair and certificate request
        keyPair, certReq = self._createRequestCreds()
        response = self.app.post('/logon', certReq, status=401)
        print response 
        self.assert_(response)  
        
    def test03NoCertificateRequestSent(self):
        # Test with missing certificate request
        
        # Username and password don't matter - exception is raised in server
        # middleware prior to authentication
        username = ''
        password = ''
                    
        base64String = base64.encodestring('%s:%s' % (username, password))[:-1]
        authHeader =  "Basic %s" % base64String
        headers = {'Authorization': authHeader}
        
        # Bad POST'ed content
        response = self.app.post('/logon', 'x', headers=headers, status=400)
        print response 
        self.assert_(response)
        
    def test04GET(self):
        # Test HTTP GET request - should be rejected - POST is expected
        
        # Username and password don't matter - exception is raised in server
        # middleware prior to authentication
        username = ''
        password = ''
        base64String = base64.encodestring('%s:%s' % (username, password))[:-1]
        authHeader =  "Basic %s" % base64String
        headers = {'Authorization': authHeader}
        
        response = self.app.get('/logon', headers=headers, status=405)
        print response 
        self.assert_(response)               


class MyProxyGetTrustRootsMiddlewareTestCase(MyProxyPasteDeployTestCaseBase):
    """Test HTTP MyProxy get trust roots interface"""
    
    def test01(self):
        response = self.app.get('/get-trustroots', status=200)
        self.assert_(response)         
        print response 
        
        # Test deserialisation
        for line in response.body.split('\n'):
            fieldName, val = line.split('=', 1)
            print("%s: %s\n" % (fieldName, base64.b64decode(val)))

if __name__ == "__main__":
    unittest.main()        
