"""MyProxy WSGI middleware - places a MyProxy client instance in environ for
other downstream middleware or apps to access and use
 
NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "23/03/11"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id: $"
import logging
log = logging.getLogger(__name__)
import httplib

from myproxy.client import MyProxyClient
  

class MyProxyClientMiddlewareError(Exception):
    """Runtime error with MyProxyClientMiddleware"""

       
class MyProxyClientMiddlewareConfigError(MyProxyClientMiddlewareError):
    """Configuration error with MyProxyClientMiddleware"""


class MyProxyClientMiddlewareBase(object):
    """Base class for common functionality
    
    @cvar CLIENT_ENV_KEYNAME_OPTNAME: ini file option which sets the key name
    in the WSGI environ for referring to the MyProxy client instance shared
    between MyProxy* middleware/apps
    @type CLIENT_ENV_KEYNAME_OPTNAME: string
    
    @cvar DEFAULT_CLIENT_ENV_KEYNAME: default value for key name set in the
    WSGI environ dict which refers to the MyProxy client instance shared
    between MyProxy* middleware/apps
    @type DEFAULT_CLIENT_ENV_KEYNAME: string
    
    @ivar __app: WSGI callable for next middleware or app in the WSGI stack
    @type __app: function
    
    @ivar __clientEnvironKeyName: key name set in the WSGI environ dict which 
    refers to the MyProxy client instance shared between MyProxy* middleware/
    apps
    @type __clientEnvironKeyName: string
    """
    __slots__ = (
        '__app', 
        '__clientEnvironKeyName',
    )
    
    CLIENT_ENV_KEYNAME_OPTNAME = 'clientEnvKeyName'
    DEFAULT_CLIENT_ENV_KEYNAME = ('myproxy.server.wsgi.middleware.'
                                  'MyProxyClientMiddleware.myProxyClient')
        
    def __init__(self, app):
        """Create WSGI app and MyProxy client attributes
        @type app: function
        @param app: WSGI callable for next middleware or app in the WSGI stack
        """
        self.__app = app
        self.__clientEnvironKeyName = None
    
    def _getClientEnvironKeyName(self):
        """Get MyProxyClient environ key name
        
        @rtype: basestring
        @return: MyProxyClient environ key name
        """
        return self.__clientEnvironKeyName

    def _setClientEnvironKeyName(self, value):
        """Set MyProxyClient environ key name
        
        @type value: basestring
        @param value: MyProxyClient environ key name
        """
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for "clientEnvironKeyName"; '
                            'got %r type' % type(value))
        self.__clientEnvironKeyName = value

    clientEnvironKeyName = property(fget=_getClientEnvironKeyName, 
                                    fset=_setClientEnvironKeyName, 
                                    doc="key name in environ for the "
                                        "MyProxyClient instance")  
    
    @property
    def app(self):
        """Get Property method for reference to next WSGI application in call
        stack
        @rtype: function
        @return: WSGI application
        """
        return self.__app
    
    @staticmethod
    def getStatusMessage(statusCode):
        '''Make a standard status message for use with start_response
        @type statusCode: int
        @param statusCode: HTTP status code
        @rtype: string
        @return: status code with standard message
        @raise KeyError: for invalid status code
        '''
        return '%d %s' % (statusCode, httplib.responses[statusCode])
        
    
class MyProxyClientMiddleware(MyProxyClientMiddlewareBase):
    '''Create a MyProxy client and make it available to other middleware in the 
    WSGI stack
    
    @cvar PARAM_PREFIX: prefix for ini file option names 
    @type PARAM_PREFIX: string
    
    @cvar MYPROXY_CLIENT_PARAM_PREFIX: default value for ini file sub-prefix 
    used for MyProxyClient initialisation settings such as MyProxy server 
    hostname, CA cert directory etc.  The prefix is such that option names 
    will look like this e.g.
    <PARAM_PREFIX><MYPROXY_CLIENT_PARAM_PREFIX>hostname
    ...
    @type MYPROXY_CLIENT_PARAM_PREFIX: string
    
    @ivar __myProxyClient: MyProxy client interface object to enable this
    middleware to communicate with a backend MyProxy server using the MyProxy
    protocol
    @type __myProxyClient: myproxy.client.MyProxyClient
    '''
    # Option prefixes
    PARAM_PREFIX = 'myproxy.'
    MYPROXY_CLIENT_PARAM_PREFIX = 'client.'
    
    __slots__ = (
        '__myProxyClient', 
    )
    
    def __init__(self, app):
        '''Create attributes
        
        @type app: function
        @param app: WSGI callable for next application in stack
        '''
        super(MyProxyClientMiddleware, self).__init__(app)
        self.__myProxyClient = None

    @classmethod
    def filter_app_factory(cls, app, global_conf, 
                           prefix=PARAM_PREFIX, 
                           myProxyClientPrefix=MYPROXY_CLIENT_PARAM_PREFIX, 
                           **app_conf):
        """Function following Paste filter app factory signature
        
        @type app: callable following WSGI interface
        @param app: next middleware/application in the chain      
        @type global_conf: dict        
        @param global_conf: PasteDeploy global configuration dictionary
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type myProxyClientPrefix: ini file sub-prefix used for MyProxyClient 
        initialisation settings such as MyProxy server  hostname, CA cert. 
        directory etc.  
        @param myProxyClientPrefix: basestring
        @type app_conf: dict        
        @param app_conf: PasteDeploy application specific configuration 
        dictionary
        
        @rtype: myproxy.server.wsgi.middleware.MyProxyClientMiddleware
        @return: an instance of this application
        """
        app = cls(app)
        app.parseConfig(prefix=prefix, myProxyClientPrefix=myProxyClientPrefix,
                        **app_conf)
        return app
    
    def parseConfig(self, 
                    prefix=PARAM_PREFIX, 
                    myProxyClientPrefix=MYPROXY_CLIENT_PARAM_PREFIX,
                    **app_conf):
        """Parse dictionary of configuration items updating the relevant 
        attributes of this instance
        
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type myProxyClientPrefix: basestring
        @param myProxyClientPrefix: explicit prefix for MyProxyClient class 
        specific configuration items
        @type app_conf: dict        
        @param app_conf: PasteDeploy application specific configuration 
        dictionary
        """
        
        # Get MyProxyClient initialisation parameters
        myProxyClientFullPrefix = prefix + myProxyClientPrefix
                            
        myProxyClientKw = dict([(k.replace(myProxyClientFullPrefix, ''), v) 
                                 for k,v in app_conf.items() 
                                 if k.startswith(myProxyClientFullPrefix)])
        
        self.myProxyClient = MyProxyClient(**myProxyClientKw)
        clientEnvKeyOptName = prefix + \
                            MyProxyClientMiddleware.CLIENT_ENV_KEYNAME_OPTNAME
                    
        self.clientEnvironKeyName = app_conf.get(clientEnvKeyOptName,
                            MyProxyClientMiddleware.DEFAULT_CLIENT_ENV_KEYNAME)
    
    def _getMyProxyClient(self):
        """Get MyProxyClient instance
        
        @rtype: myproxy.client.MyProxyClient
        @return: MyProxyClient instance
        """
        return self.__myProxyClient

    def _setMyProxyClient(self, value):
        """Set MyProxyClient instance
        
        @type value: myproxy.client.MyProxyClient
        @param value: MyProxyClient instance
        """
        if not isinstance(value, MyProxyClient):
            raise TypeError('Expecting %r type for "myProxyClient" attribute '
                            'got %r' % (MyProxyClient, type(value)))
        self.__myProxyClient = value
        
    myProxyClient = property(fget=_getMyProxyClient,
                             fset=_setMyProxyClient, 
                             doc="MyProxyClient instance used to convert HTTPS"
                                 " call into a call to a MyProxy server")

    def __call__(self, environ, start_response):
        '''Set MyProxyClient instance and MyProxy logon method in environ
        
        @type environ: dict
        @param environ: WSGI environment variables dictionary
        @type start_response: function
        @param start_response: standard WSGI start response function
        '''
        log.debug("MyProxyClientMiddleware.__call__ ...")
        environ[self.clientEnvironKeyName] = self.myProxyClient
        
        return self.app(environ, start_response)