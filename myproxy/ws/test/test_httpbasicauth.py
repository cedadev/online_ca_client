#!/usr/bin/env python
"""Unit tests for MyProxy WSGI Middleware classes and Application
"""
__author__ = "P J Kershaw"
__date__ = "21/05/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id: $'
import unittest
import os
import base64

import paste.fixture
from paste.deploy import loadapp

from myproxy.ws.server.wsgi.httpbasicauth import (HttpBasicAuthMiddleware,
                                               HttpBasicAuthResponseException)


class TestApp(object):
    """Test WSGI Application for use with the unit tests for the HTTP Basic
    Auth middleware developed for the myproxy.ws.server.app.MyProxyApp 
    application
    """
    def __init__(self, global_conf, **app_conf):
        """Follow standard Paste Deploy app factory function signature"""
    
    def __call__(self, environ, start_response):
        """Make a simple response for unit test code to trap and validate 
        against.  If this method is executed then the HTTP Basic Auth step in
        the upstream middleware has succeeded.
        """
        contentType = 'text/plain'
        response = 'Authenticated!'
        status = 200
        start_response(status,
                       [('Content-type', contentType),
                        ('Content-Length', str(len(response)))])
        return [response]
    
            
class TestHttpBasicAuthCallBackAppMiddleware(object):
    """Add an authentication function to the environ for HttpBasicAuthMiddleware
    to pick up and use.  It behaves as an application returning a response
    """    
    USERNAME = 'myusername'
    PASSWORD = 'mypassword'
    SUCCESS_RESPONSE = 'AUTHENTICATED'
    FAILURE_RESPONSE = 'FAILED'
    
    def __init__(self, app, global_conf, **app_conf):
        """Follow standard Paste Deploy app factory function signature"""
        self.app = app
        
    def __call__(self, environ, start_response):
        def authenticationApp(environ, start_response, username, password):
            """Authentication callback application - its responsible for the
            response message and response code
            """
            if (username == self.__class__.USERNAME and
                password == self.__class__.PASSWORD):
                response = self.__class__.SUCCESS_RESPONSE
                status = '200 OK'
            else:
                response = self.__class__.FAILURE_RESPONSE
                status = '401 Unauthorized'
                
            start_response(status,
                           [('Content-type', 'text/plain'),
                            ('Content-Length', str(len(response)))])
            return [response]
            
        environ['HTTPBASICAUTH_FUNC'] = authenticationApp
        
        return self.app(environ, start_response)


class TestHttpBasicAuthCallBackMiddleware(object):
    """Add an authentication function to the environ for HttpBasicAuthMiddleware
    to pick up and use.  The callback does not return a response leaving control
    with the HttpBasicAuthMiddleware
    """    
    USERNAME = 'myusername'
    PASSWORD = 'mypassword'
    
    def __init__(self, app, global_conf, **app_conf):
        """Follow standard Paste Deploy app factory function signature"""
        self.app = app
        
    def __call__(self, environ, start_response):
        """Create HTTP Basic Auth callback"""
        def authenticate(environ, start_response, username, password):
            """HTTP Basic Auth callback function"""
            if (username != self.__class__.USERNAME or
                password != self.__class__.PASSWORD):
                raise HttpBasicAuthResponseException("Invalid credentials")
            
        environ['HTTPBASICAUTH_FUNC'] = authenticate
        
        return self.app(environ, start_response)
    

class HttpBasicAuthMiddlewareTestCase(unittest.TestCase):
    """Unit tests for HTTP Basic Auth middleware used with the MyProxyWebService
    package
    """
    CONFIG_FILE = 'httpbasicauth.ini'
    
    def __init__(self, *args, **kwargs):
        """Set-up Paste fixture from ini file settings"""
        here_dir = os.path.dirname(os.path.abspath(__file__))
        configFilePath = ('config:%s' % 
                          HttpBasicAuthMiddlewareTestCase.CONFIG_FILE)
        wsgiapp = loadapp(configFilePath, relative_to=here_dir)
        self.app = paste.fixture.TestApp(wsgiapp)
         
        unittest.TestCase.__init__(self, *args, **kwargs)
        
    def test01NoHttpBasicAuthHeader(self):
        # Try with no HTTP Basic Auth HTTP header
        response = self.app.get('/auth', status=401)
            
    def test02ValidCredentials(self):
        # Try with no HTTP Basic Auth HTTP header
        username = TestHttpBasicAuthCallBackAppMiddleware.USERNAME
        password = TestHttpBasicAuthCallBackAppMiddleware.PASSWORD
        
        base64String = base64.encodestring('%s:%s' % (username, password))[:-1]
        authHeader =  "Basic %s" % base64String
        headers = {'Authorization': authHeader}
        
        response = self.app.get('/auth', headers=headers, status=200)
        self.assert_((TestHttpBasicAuthCallBackAppMiddleware.SUCCESS_RESPONSE in
                      response))
                      
    def test03InvalidCredentials(self):
        # Try with no HTTP Basic Auth HTTP header
        username = 'x'
        password = 'y'
        
        base64String = base64.encodestring('%s:%s' % (username, password))[:-1]
        authHeader =  "Basic %s" % base64String
        headers = {'Authorization': authHeader}
        
        response = self.app.get('/auth', headers=headers, status=401)
        self.assert_((TestHttpBasicAuthCallBackAppMiddleware.FAILURE_RESPONSE in
                      response))
        
    def _createCallbackMiddleware(self):
        # Test creating app independently of PasteScript and using an 
        # alternate middleware which doesn't return a response but simply 
        # raises a 401 exception type if input credentials don't match
        app = TestApp({})
        app = HttpBasicAuthMiddleware.filter_app_factory(app, {},
                                prefix='',
                                authnFuncEnvironKeyName='HTTPBASICAUTH_FUNC')
        app = TestHttpBasicAuthCallBackMiddleware(app, {})

        self.app2 = paste.fixture.TestApp(app)
        
    def test04SimpleCBMiddlewareWithValidCredentials(self):
        self._createCallbackMiddleware()
        username = TestHttpBasicAuthCallBackAppMiddleware.USERNAME
        password = TestHttpBasicAuthCallBackAppMiddleware.PASSWORD
        
        base64String = base64.encodestring('%s:%s' % (username, password))[:-1]
        authHeader =  "Basic %s" % base64String
        headers = {'Authorization': authHeader}
        
        response = self.app.get('/auth', headers=headers, status=200)
        
    def test05SimpleCBMiddlewareWithInvalidCredentials(self):
        self._createCallbackMiddleware()
        username = 'a'
        password = 'b'
        
        base64String = base64.encodestring('%s:%s' % (username, password))[:-1]
        authHeader =  "Basic %s" % base64String
        headers = {'Authorization': authHeader}
        
        response = self.app.get('/auth', headers=headers, status=401)       

    