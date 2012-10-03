#!/usr/bin/env python
"""Unit tests for MyProxy WSGI Middleware classes and Application.  These are
run using paste.fixture i.e. tests stubs to a web application server
"""
__author__ = "P J Kershaw"
__date__ = "23/09/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)

import base64
import os
import unittest

import paste.fixture
from paste.deploy import loadapp
from paste.httpexceptions import HTTPUnauthorized

from myproxy.ws.server.wsgi.client_register import ClientRegisterMiddleware
from myproxy.ws.test import test_dir, test_ca_dir


class TestApp(object):
    """Test WSGI Application for use with the unit tests for the Client Register
    middleware developed for the myproxy.ws.server.app.MyProxyApp application
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
        status = '200 OK'
        start_response(status,
                       [('Content-type', contentType),
                        ('Content-Length', str(len(response)))])
        return [response]
    
    
class TestClientRegisterMiddleware(unittest.TestCase):
    CONFIG_FILE = 'client_register.ini'
    CLIENT_CERT = open(os.path.join(test_dir, 'localhost.crt')).read()
    INVALID_CLIENT_CERT = open(os.path.join(test_ca_dir, 'd573507a.0')).read()
    
    def setUp(self):
        """Set-up Paste fixture from ini file settings"""
        
        config_filepath = ('config:%s' % self.__class__.CONFIG_FILE)
        wsgiapp = loadapp(config_filepath, relative_to=test_dir)
        self.app = paste.fixture.TestApp(wsgiapp)
            
    def test01_valid_client(self):
        username = 'j.bloggs'
        password = ''
        base64string = base64.encodestring('%s:%s' % (username, password))[:-1]
        auth_header =  "Basic %s" % base64string
        headers = {'Authorization': auth_header}

        environ = {ClientRegisterMiddleware.DEFAULT_SSL_CLIENT_CERT_KEYNAME: 
                   self.__class__.CLIENT_CERT}
        response = self.app.get('/', status=200, headers=headers,
                                extra_environ=environ)
        log.debug(response)
        
    def test02_invalid_client_and_username(self):
        username = 'j.bogus'
        password = ''
        base64string = base64.encodestring('%s:%s' % (username, password))[:-1]
        auth_header =  "Basic %s" % base64string
        headers = {'Authorization': auth_header}

        environ = {ClientRegisterMiddleware.DEFAULT_SSL_CLIENT_CERT_KEYNAME: 
                   self.__class__.INVALID_CLIENT_CERT}
        self.assertRaises(HTTPUnauthorized, self.app.get, '/', status=401, 
                          headers=headers, extra_environ=environ)
        
    def test03_invalid_client(self):
        username = 'an_other'
        password = ''
        base64string = base64.encodestring('%s:%s' % (username, password))[:-1]
        auth_header =  "Basic %s" % base64string
        headers = {'Authorization': auth_header}

        environ = {ClientRegisterMiddleware.DEFAULT_SSL_CLIENT_CERT_KEYNAME: 
                   self.__class__.INVALID_CLIENT_CERT}
        self.assertRaises(HTTPUnauthorized, self.app.get, '/', status=401, 
                          headers=headers, extra_environ=environ)
            
    def test04_valid_username(self):
        username = 'asmith'
        password = ''
        base64string = base64.encodestring('%s:%s' % (username, password))[:-1]
        auth_header =  "Basic %s" % base64string
        headers = {'Authorization': auth_header}

        environ = {ClientRegisterMiddleware.DEFAULT_SSL_CLIENT_CERT_KEYNAME: 
                   self.__class__.CLIENT_CERT}
        self.assertRaises(HTTPUnauthorized, self.app.get, '/', status=401, 
                          headers=headers, extra_environ=environ)

