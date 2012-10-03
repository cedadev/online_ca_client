#!/usr/bin/env python
"""Unit tests for MyProxy WSGI Middleware classes and Application testing them
with Paster web application server.  The server is started from __init__ method
of the Test Case class and then called by the unit test methods.  The unit
test methods themselves using a bash script myproxy-ws-logon.sh to query the 
MyProxy web application.
"""
__author__ = "P J Kershaw"
__date__ = "25/05/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
from os import path, listdir, remove
from getpass import getpass
from ConfigParser import SafeConfigParser, NoOptionError
import subprocess
import unittest
import socket
import logging
logging.basicConfig(level=logging.DEBUG)

from OpenSSL import SSL, crypto

from myproxy.ws.test import (test_ca_dir, logon_shell_script_path,
                             get_trustroots_shell_script_path)
from myproxy.ws.test.server_utils import PasteDeployAppServer
        

class MyProxyLogonAppWithPasterTestCase(unittest.TestCase):
    """Test MyProxy Logon App WSGI in Paster web application server container
    with bash shell script clients.  For POSIX-like systems ONLY
    """
    THIS_DIR = path.abspath(path.dirname(__file__))
    CA_DIRNAME = 'ca'
    CA_DIR = test_ca_dir
    CA_ENV_VARNAME = 'X509_CERT_DIR'
    
    tmp_ca_dir = path.join(THIS_DIR, 'tmp_ca')
    
    # CA files retrieved by the getTrustRoots unittest are cleared out 
    # afterwards by this classes' __del__' method but some CA file(s) need to be
    # reserved to allow verification of the paster web service's SSL certificate
    RESERVED_CA_DIR_FILENAMES = ('3d41aba9.0', )
    
    INI_FILENAME = 'myproxywsgi.ini'
    INI_FILEPATH = path.join(THIS_DIR, INI_FILENAME)  
    CONFIG_FILENAME = 'test_myproxywsgi.cfg'
    CONFIG_FILEPATH = path.join(THIS_DIR, CONFIG_FILENAME)  
    SSLCERT_FILEPATH = 'localhost.crt'
    SSLKEY_FILEPATH = 'localhost.key'

    SERVICE_PORTNUM = 10443
    LOGON_SCRIPT_CMD = logon_shell_script_path
    LOGON_SCRIPT_USER_OPTNAME = '-l'
    LOGON_SCRIPT_STDIN_PASS_OPTNAME = '-S'
    
    SCRIPT_URI_OPTNAME = '-U'
    
    GET_TRUSTROOTS_SCRIPT_CMD = get_trustroots_shell_script_path
    GET_TRUSTROOTS_SCRIPT_BOOTSTRAP_OPTNAME = '-b'
    
    def __init__(self, *arg, **kw):
        """Read settings from a config file and create thread for paster 
        based MyProxy Web Service app running over HTTPS
        """
        super(MyProxyLogonAppWithPasterTestCase, self).__init__(*arg, **kw)
        self.services = []
        self.disableServiceStartup = False
        
        self.cfg = SafeConfigParser(defaults={'here': self.__class__.THIS_DIR})
        self.cfg.optionxform = str
        self.cfg.read(self.__class__.CONFIG_FILEPATH)
        
        # Start the MyProxy web service
        self.addService(cfgFilePath=self.__class__.INI_FILEPATH, 
                        port=self.__class__.SERVICE_PORTNUM,
                        withSSL=True,
                        withLoggingConfig=False)
    
    def test01GetTrustRootsScriptWithBootstrap(self):
        # Test curl/base64 based client script
        optName = 'MyProxyLogonAppWithPasterTestCase.test02GetTrustRootsScript'
        uri = self.cfg.get(optName, 'uri')
        
        cmd = (
            self.__class__.GET_TRUSTROOTS_SCRIPT_CMD, 
            "%s %s" % (self.__class__.SCRIPT_URI_OPTNAME, uri),
            "%s" % self.__class__.GET_TRUSTROOTS_SCRIPT_BOOTSTRAP_OPTNAME
        )
                
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    env={self.__class__.CA_ENV_VARNAME:
                                         self.__class__.tmp_ca_dir})
        except OSError, e:
            self.failIf(e.errno == 13, 'Check that the %r script is set with '
                        'execute permissions' % 
                        self.__class__.GET_TRUSTROOTS_SCRIPT_CMD)
            raise

        stdoutdata, stderrdata = proc.communicate()
        self.failIf(len(stderrdata) > 0, "An error message was returned: %s" % 
                    stderrdata)
        print("stdout = %s" % stdoutdata)
    
    def test02LogonScript(self):
        # Test curl/openssl based client script access
        optName = 'MyProxyLogonAppWithPasterTestCase.test02LogonScript'
        username = self.cfg.get(optName, 'username')
        try: 
            password = self.cfg.get(optName, 'password')
        except NoOptionError:
            password = getpass(optName + ' password: ')

        uri = self.cfg.get(optName, 'uri')
        
        cmd = (
            self.__class__.LOGON_SCRIPT_CMD, 
            "%s %s"%(self.__class__.SCRIPT_URI_OPTNAME, uri),
            "%s %s"%(self.__class__.LOGON_SCRIPT_USER_OPTNAME, username),
            self.__class__.LOGON_SCRIPT_STDIN_PASS_OPTNAME
        )
                
        p1 = subprocess.Popen(["echo", password], stdout=subprocess.PIPE)
        try:
            p2 = subprocess.Popen(cmd, stdin=p1.stdout, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE,
                                  env={self.__class__.CA_ENV_VARNAME:
                                       self.__class__.tmp_ca_dir})
        except OSError, e:
            self.failIf(e.errno == 13, 'Check that the %r script is set with '
                        'execute permissions' % self.__class__.LOGON_SCRIPT_CMD)
            raise
        
        stdoutdata, stderrdata = p2.communicate()
        self.failIf(len(stderrdata) > 0, "An error message was returned: %s" % 
                    stderrdata)
        print("stdout = %s" % stdoutdata)
        
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, stdoutdata)
        subj = cert.get_subject()
        self.assert_(subj)
        self.assert_(subj.CN)
        print("Returned certificate subject CN=%r" % subj)
        
    def addService(self, *arg, **kw):
        """Utility for setting up threads to run Paste HTTP based services with
        unit tests
        
        @param arg: tuple contains ini file path setting for the service
        @type arg: tuple
        @param kw: keywords including "port" - port number to run the service 
        from
        @type kw: dict
        """
        if self.disableServiceStartup:
            return
        
        withSSL = kw.pop('withSSL', False)
        if withSSL:
            certFilePath = path.join(self.__class__.THIS_DIR, 
                                     self.__class__.SSLCERT_FILEPATH)
            priKeyFilePath = path.join(self.__class__.THIS_DIR, 
                                       self.__class__.SSLKEY_FILEPATH)
            
            kw['ssl_context'] = SSL.Context(SSL.SSLv23_METHOD)
            kw['ssl_context'].set_options(SSL.OP_NO_SSLv2)
        
            kw['ssl_context'].use_privatekey_file(priKeyFilePath)
            kw['ssl_context'].use_certificate_file(certFilePath)
            
        try:
            self.services.append(PasteDeployAppServer(*arg, **kw))
            self.services[-1].startThread()
            
        except socket.error:
            pass

    def __del__(self):
        """Stop any services started with the addService method and clean up
        the CA directory following the trust roots call
        """
        if hasattr(self, 'services'):
            for service in self.services:
                service.terminateThread()
                
        parentObj = super(MyProxyLogonAppWithPasterTestCase, self)
        if hasattr(parentObj, '__del__'):
            parentObj.__del__()
            
        for fileName in listdir(self.__class__.CA_DIR):
            if (fileName not in self.__class__.RESERVED_CA_DIR_FILENAMES and
                fileName[0] != '.'):
                filePath = path.join(self.__class__.CA_DIR, fileName)
                remove(filePath)
                                

if __name__ == "__main__":
    unittest.main()        
