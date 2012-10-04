#!/usr/bin/env python
"""Unit tests for MyProxy Web Service client 
"""
__author__ = "P J Kershaw"
__date__ = "28/05/12"
__copyright__ = "(C) 2012 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
logging.basicConfig(level=logging.DEBUG)
import unittest
import os
from getpass import getpass
from ConfigParser import SafeConfigParser, NoOptionError

from OpenSSL import crypto, SSL

from ndg.httpsclient.ssl_context_util import make_ssl_context

from myproxy.ws.client import MyProxyWSClient
from myproxy.ws.test import test_ca_dir


class WSClientTestCase(unittest.TestCase):
    """Test MyProxy Web Service Client"""
    here_dir = os.path.dirname(os.path.abspath(__file__))
    config_filepath = os.path.join(here_dir, 
                                   'test_myproxywebservice_client.cfg')
    
    def __init__(self, *args, **kwargs):
        self.cfg = SafeConfigParser({'here': self.__class__.here_dir})
        self.cfg.optionxform = str
        self.cfg.read(self.__class__.config_filepath)
        
        unittest.TestCase.__init__(self, *args, **kwargs)  
          
    def test01_logon(self):
        opt_name = 'WSClientTestCase.test01_logon'
        username = self.cfg.get(opt_name, 'username')
        try: 
            password = self.cfg.get(opt_name, 'password')
        except NoOptionError:
            password = getpass('WSClientTestCase.test01_logon password: ')

        server_url = self.cfg.get(opt_name, 'uri')
        
        myproxy_client = MyProxyWSClient()
        myproxy_client.ca_cert_dir = test_ca_dir
        
        res = myproxy_client.logon(username, password, server_url)
        self.assert_(res)
        
        pem_out = res.read()
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_out)
        subj = cert.get_subject()
        self.assert_(subj)
        self.assert_(subj.CN)
        print("Returned certificate subject CN=%r" % subj)
          
    def test02_logon_with_ssl_client_authn(self):
        # Some cases may require client to pass cert in SSL handshake
        opt_name = 'WSClientTestCase.test02_logon_with_ssl_client_authn'
        username = self.cfg.get(opt_name, 'username')
        try: 
            password = self.cfg.get(opt_name, 'password')
        except NoOptionError:
            password = ''

        server_url = self.cfg.get(opt_name, 'uri')
        client_cert_filepath = self.cfg.get(opt_name, 'client_cert_filepath')
        client_key_filepath = self.cfg.get(opt_name, 'client_key_filepath')
        
        myproxy_client = MyProxyWSClient()

        ssl_ctx = make_ssl_context(cert_file=client_cert_filepath,
                                   key_file=client_key_filepath,
                                   ca_dir=test_ca_dir, 
                                   verify_peer=True, 
                                   url=server_url, 
                                   method=SSL.SSLv3_METHOD)
        
        res = myproxy_client.logon(username, password, server_url, 
                                   ssl_ctx=ssl_ctx)
        self.assert_(res)
        
        pem_out = res.read()
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_out)
        subj = cert.get_subject()
        self.assert_(subj)
        self.assert_(subj.CN)
        print("Returned certificate subject CN=%r" % subj)

if __name__ == "__main__":
    unittest.main() 
