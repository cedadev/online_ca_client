"""MyProxy Web Service WSGI middleware - exposes MyProxy logon and get trust
roots as web service methods
 
NERC MashMyData Project
"""
__author__ = "P J Kershaw"
__date__ = "24/05/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id: $"
import logging
log = logging.getLogger(__name__)

import httplib
import socket
import base64
import traceback

from webob import Request
from OpenSSL import crypto

from myproxy.client import MyProxyClient, MyProxyClientError
from myproxy.server.wsgi.middleware import (MyProxyClientMiddlewareBase, 
                                            MyProxyClientMiddleware)
from myproxy.ws.server.wsgi.httpbasicauth import HttpBasicAuthResponseException


class MyProxyLogonWSMiddlewareError(Exception):
    """Errors related to the MyProxy Web Service middleware"""


class MyProxyLogonWSMiddleware(MyProxyClientMiddleware):
    """Build on MyClientMiddleware to expose a special logon Web Service method
    
    TODO: possible refactor to NOT inherit from MyProxyClientMiddleware but 
    instead receive a MyProxyClient instance via environ set from an upstream 
    MyProxyClientMiddleware object
    
    @cvar LOGON_FUNC_ENV_KEYNAME_OPTNAME: ini file option name to set the key 
    name in WSGI environ dict to assign to the Logon function created by this
    middleware
    @type LOGON_FUNC_ENV_KEYNAME_OPTNAME: string
    
    @cvar DEFAULT_LOGON_FUNC_ENV_KEYNAME: default value for the key name in 
    WSGI environ dict to assign to the Logon function created by this
    middleware
    @type DEFAULT_LOGON_FUNC_ENV_KEYNAME: string
    
    @cvar CERT_REQ_POST_PARAM_KEYNAME: HTTP POST field name for the 
    certificate request posted in logon calls
    @type CERT_REQ_POST_PARAM_KEYNAME: string
    
    @ivar __logonFuncEnvironKeyName: 
    @type __logonFuncEnvironKeyName: string
    
    @cvar PARAM_PREFIX: prefix for ini file option names 
    @type PARAM_PREFIX: string
    """
    
    # Options for ini file
    LOGON_FUNC_ENV_KEYNAME_OPTNAME = 'logonFuncEnvKeyName'
    DEFAULT_GLOBAL_PASSWD_OPTNAME = 'global_passwd'

    # Default environ key names
    DEFAULT_LOGON_FUNC_ENV_KEYNAME = ('myproxy.server.wsgi.middleware.'
                                      'MyProxyClientMiddleware.logon')
    
    CERT_REQ_POST_PARAM_KEYNAME = 'certificate_request'
    
    __slots__ = (
        '__logonFuncEnvironKeyName', 
        '__global_passwd'
    )
    PARAM_PREFIX = 'myproxy.ws.server.logon.'
    
    def __init__(self, app):
        '''Create attributes
        
        @type app: function
        @param app: WSGI callable for next application in stack
        '''
        super(MyProxyLogonWSMiddleware, self).__init__(app)
        self.__logonFuncEnvironKeyName = None
        self.__global_passwd = None  
          
    def parseConfig(self, prefix=PARAM_PREFIX, myProxyClientPrefix=None,
                    **app_conf):
        """Parse dictionary of configuration items updating the relevant 
        attributes of this instance
        
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type myProxyClientPrefix: basestring
        @param myProxyClientPrefix: explicit prefix for MyProxyClient class 
        specific configuration items - ignored in this derived method
        @type app_conf: dict        
        @param app_conf: PasteDeploy application specific configuration 
        dictionary
        """
        
        # Call parent version
        super(MyProxyLogonWSMiddleware, self).parseConfig(prefix=prefix, 
                            myProxyClientPrefix=myProxyClientPrefix, **app_conf)  
            
        # Extract additional parameters
        logonFuncEnvKeyOptName = prefix + \
                        self.__class__.LOGON_FUNC_ENV_KEYNAME_OPTNAME

        self.logonFuncEnvironKeyName = app_conf.get(logonFuncEnvKeyOptName,
                        self.__class__.DEFAULT_LOGON_FUNC_ENV_KEYNAME)
        
        global_passwd_optname = prefix + \
                        self.__class__.DEFAULT_GLOBAL_PASSWD_OPTNAME
                        
        self.__global_passwd = app_conf.get(global_passwd_optname)

    @property
    def logonFuncEnvironKeyName(self):
        """Get MyProxyClient logon function environ key name
        
        @rtype: basestring
        @return: MyProxyClient logon function environ key name
        """
        return self.__logonFuncEnvironKeyName

    @logonFuncEnvironKeyName.setter
    def logonFuncEnvironKeyName(self, value):
        """Set MyProxyClient environ key name
        
        @type value: basestring
        @param value: MyProxyClient logon function environ key name
        """
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for '
                            '"logonFuncEnvironKeyName"; got %r type' % 
                            type(value))
        self.__logonFuncEnvironKeyName = value
    
    def __call__(self, environ, start_response):
        '''Set MyProxy logon method in environ
        
        @type environ: dict
        @param environ: WSGI environment variables dictionary
        @type start_response: function
        @param start_response: standard WSGI start response function
        '''
        log.debug("MyProxyClientMiddleware.__call__ ...")
        environ[self.logonFuncEnvironKeyName] = self.myProxyLogon
        
        return super(MyProxyLogonWSMiddleware, self).__call__(environ, 
                                                              start_response)
        
    @property
    def myProxyLogon(self):
        """Return the MyProxy logon method wrapped as a HTTP Basic Auth 
        authenticate interface function
        
        @rtype: function
        @return: MyProxy logon HTTP Basic Auth Callback
        """
        def _myProxylogon(environ, start_response, username, password):
            """Wrap MyProxy logon method as a WSGI app
            @type environ: dict
            @param environ: WSGI environment variables dictionary
            @type start_response: function
            @param start_response: standard WSGI start response function
            @type username: basestring
            @param username: username credential to MyProxy logon
            @type password: basestring
            @param password: pass-phrase for MyProxy logon call
            @raise HttpBasicAuthResponseException: invalid client request
            @raise MyProxyClientMiddlewareError: socket error for backend
            MyProxy server
            """  
            request = Request(environ)
            
            requestMethod = environ.get('REQUEST_METHOD')                         
            if requestMethod != 'POST':
                response = "HTTP Request method not recognised"
                log.error("HTTP Request method %r not recognised", 
                          requestMethod)
                raise HttpBasicAuthResponseException(response, 
                                                     httplib.METHOD_NOT_ALLOWED)
                
            # Extract cert request and convert to standard string - SSL library
            # will not accept unicode
            cert_req_key = self.__class__.CERT_REQ_POST_PARAM_KEYNAME
            pem_cert_req = str(request.POST.get(cert_req_key))
            if pem_cert_req is None:
                response = ("No %r form variable set in POST message" % 
                            cert_req_key)
                log.error(response)
                raise HttpBasicAuthResponseException(response, 
                                                     httplib.BAD_REQUEST)
        
            log.debug("cert req = %r", pem_cert_req)
            
            # Expecting PEM encoded request
            try:
                cert_req = crypto.load_certificate_request(crypto.FILETYPE_PEM,
                                                           pem_cert_req)
            except crypto.Error, e:
                log.error("Error loading input certificate request: %r", 
                          pem_cert_req)
                raise HttpBasicAuthResponseException("Error loading input "
                                                     "certificate request",
                                                     httplib.BAD_REQUEST)
            
            # Convert to ASN1 format expect by logon client call
            asn1CertReq = crypto.dump_certificate_request(crypto.FILETYPE_ASN1, 
                                                          cert_req)

            # A global password can be set for the MyProxy call.  This is used
            # for the special case where this service is providing delegation
            # The MyProxyCA uses a special PAM with a single password set for
            # all usernames.  Clients to this service must be protected by
            # SSL client authentication
            if self.__global_passwd is not None:
                password_ = self.__global_passwd
            else:
                password_ = password
                
            try:
                credentials = self.myProxyClient.logon(username, 
                                                       password_,
                                                       certReq=asn1CertReq)
                status = self.getStatusMessage(httplib.OK)
                response = '\n'.join(credentials)
                
                start_response(status,
                               [('Content-length', str(len(response))),
                                ('Content-type', 'text/plain')])
                return [response]
                       
            except MyProxyClientError, e:
                raise HttpBasicAuthResponseException(str(e),
                                                     httplib.UNAUTHORIZED)
            except socket.error, e:
                raise MyProxyLogonWSMiddlewareError("Socket error "
                                        "with MyProxy server %r: %s" % 
                                        (self.myProxyClient.hostname, e))
            except Exception, e:
                log.error("MyProxyClient.logon raised an unknown exception "
                          "calling %r: %s", 
                          self.myProxyClient.hostname,
                          traceback.format_exc())
                raise # Trigger 500 Internal Server Error
            
        return _myProxylogon
    
    
class MyProxyGetTrustRootsMiddlewareError(Exception):
    """MyProxyGetTrustRootsMiddleware exception class"""
    
    
class MyProxyGetTrustRootsMiddleware(MyProxyClientMiddlewareBase):
    """HTTP client interface for MyProxy server Get Trust Roots method
    
    It relies on a myproxy.server.wsgi.MyProxyClientMiddleware instance called 
    upstream in the WSGI stack to set up a MyProxyClient instance and make it 
    available in the environ to call its getTrustRoots method.
    
    @cvar PATH_OPTNAME: ini file option to set the URI path for this service
    @type PATH_OPTNAME: string
    
    @cvar DEFAULT_PATH: default URI path setting
    @type DEFAULT_PATH: string

    @cvar PARAM_PREFIX: prefix for ini file option names 
    @type PARAM_PREFIX: string
    
    @ivar __path: URI path setting for this service
    @type __path: basestring
    """
        
    PATH_OPTNAME = 'path'     
    DEFAULT_PATH = '/myproxy/get-trustroots'
    
    # Option prefixes
    PARAM_PREFIX = 'myproxy.getTrustRoots.'
    
    __slots__ = (
        '__path',
    )
    
    def __init__(self, app):
        '''Create attributes
        
        @type app: function
        @param app: WSGI callable for next application in stack
        '''
        super(MyProxyGetTrustRootsMiddleware, self).__init__(app)
        self.__path = None
        
    @classmethod
    def filter_app_factory(cls, app, global_conf, prefix=PARAM_PREFIX, 
                           **app_conf):
        """Function following Paste filter app factory signature
        
        @type app: callable following WSGI interface
        @param app: next middleware/application in the chain      
        @type global_conf: dict        
        @param global_conf: PasteDeploy global configuration dictionary
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type app_conf: dict        
        @param app_conf: PasteDeploy application specific configuration 
        dictionary
        
        @rtype: myproxy.server.wsgi.middleware.MyProxyGetTrustRootsMiddleware
        @return: an instance of this middleware
        """
        app = cls(app)
        app.parseConfig(prefix=prefix, **app_conf)
        return app
    
    def parseConfig(self, prefix=PARAM_PREFIX, **app_conf):
        """Parse dictionary of configuration items updating the relevant 
        attributes of this instance
        
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type app_conf: dict        
        @param app_conf: PasteDeploy application specific configuration 
        dictionary
        """
        clientEnvKeyOptName = prefix + self.__class__.CLIENT_ENV_KEYNAME_OPTNAME
                    
        self.clientEnvironKeyName = app_conf.get(clientEnvKeyOptName,
                                    self.__class__.DEFAULT_CLIENT_ENV_KEYNAME)
        
        pathOptName = prefix + self.__class__.PATH_OPTNAME
        self.path = app_conf.get(pathOptName, self.__class__.DEFAULT_PATH)

    def _getPath(self):
        """Get URI path for get trust roots method
        @rtype: basestring
        @return: path for get trust roots method
        """
        return self.__path

    def _setPath(self, value):
        """Set URI path for get trust roots method
        @type value: basestring
        @param value: path for get trust roots method
        """
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "path"; got %r' % 
                            type(value))
        
        self.__path = value

    path = property(fget=_getPath, fset=_setPath, 
                    doc="environ SCRIPT_NAME path which invokes the "
                        "getTrustRoots method on this middleware")
    
    def __call__(self, environ, start_response):
        '''Get MyProxyClient instance from environ and call MyProxy 
        getTrustRoots method returning the response.
        
        MyProxyClientMiddleware must be in place upstream in the WSGI stack
        
        @type environ: dict
        @param environ: WSGI environment variables dictionary
        @type start_response: function
        @param start_response: standard WSGI start response function
        
        @rtype: list
        @return: get trust roots response
        '''
        # Skip if path doesn't match
        if environ['PATH_INFO'] != self.path:
            return self.app(environ, start_response)
        
        log.debug("MyProxyGetTrustRootsMiddleware.__call__ ...")
        
        # Check method
        requestMethod = environ.get('REQUEST_METHOD')             
        if requestMethod != 'GET':
            response = "HTTP Request method not recognised"
            log.error("HTTP Request method %r not recognised", requestMethod)
            status = self.__class__.getStatusMessage(httplib.BAD_REQUEST)
            start_response(status,
                           [('Content-type', 'text/plain'),
                            ('Content-length', str(len(response)))])
            return [response]
        
        myProxyClient = environ[self.clientEnvironKeyName]
        if not isinstance(myProxyClient, MyProxyClient):
            raise TypeError('Expecting %r type for "myProxyClient" environ[%r] '
                            'attribute got %r' % (MyProxyClient, 
                                                  self.clientEnvironKeyName,
                                                  type(myProxyClient)))
        
        response = self._getTrustRoots(myProxyClient)
        start_response(self.getStatusMessage(httplib.OK),
                       [('Content-length', str(len(response))),
                        ('Content-type', 'text/plain')])

        return [response]
    
    @classmethod
    def _getTrustRoots(cls, myProxyClient):
        """Call getTrustRoots method on MyProxyClient instance retrieved from
        environ and format and return a HTTP response
        
        @type myProxyClient: myproxy.client.MyProxyClient
        @param myProxyClient: MyProxyClient instance on which to call 
        getTrustRoots method
        
        @rtype: basestring
        @return: trust roots base64 encoded and concatenated together
        @raise MyProxyGetTrustRootsMiddlewareError: socket error with backend
        MyProxy server
        @raise MyProxyClientError: error response received by MyProxyClient
        instance
        """
        try:
            trustRoots = myProxyClient.getTrustRoots()
            
            # Serialise dict response
            response = "\n".join(["%s=%s" % (k, base64.b64encode(v))
                                  for k,v in trustRoots.items()])
            
            return response
                   
        except MyProxyClientError, e:
            log.error("MyProxyClient.getTrustRoots raised an "
                      "MyProxyClientError exception calling %r: %s", 
                      myProxyClient.hostname,
                      traceback.format_exc())
            raise
            
        except socket.error, e:
            raise MyProxyGetTrustRootsMiddlewareError("Socket error with "
                                                      "MyProxy server %r: %s" % 
                                                      (myProxyClient.hostname, 
                                                       e))
        except Exception, e:
            log.error("MyProxyClient.getTrustRoots raised an unknown exception "
                      "calling %r: %s", 
                      myProxyClient.hostname,
                      traceback.format_exc())
            raise # Trigger 500 Internal Server Error
       