"""WSGI middleware implementing HTTP Basic Auth to support HTTPS proxy app to 
MyProxy server.
"""
__author__ = "P J Kershaw"
__date__ = "21/05/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import logging
log = logging.getLogger(__name__)
import traceback
import re
import httplib
import base64
    
class HttpBasicAuthMiddlewareError(Exception):
    """Base exception type for HttpBasicAuthMiddleware"""
    
    
class HttpBasicAuthMiddlewareConfigError(HttpBasicAuthMiddlewareError):
    """Configuration error with HTTP Basic Auth middleware"""


class HttpBasicAuthResponseException(HttpBasicAuthMiddlewareError):
    """Exception class for use by the authentication function callback to
    signal HTTP codes and messages back to HttpBasicAuthMiddleware.  The code 
    can conceivably a non-error HTTP code such as 200
    """
    def __init__(self, *arg, **kw):
        """Extend Exception type to accommodate an extra HTTP response code
        argument
        """
        self.response = arg[0]
        if len(arg) == 2:
            argList = list(arg)
            self.code = argList.pop()
            arg = tuple(argList)
        else:
            self.code = httplib.UNAUTHORIZED
                
        HttpBasicAuthMiddlewareError.__init__(self, *arg, **kw)
    
    
class HttpBasicAuthMiddleware(object):
    '''HTTP Basic Authentication Middleware 

    @cvar AUTHN_FUNC_ENV_KEYNAME: key name for referencing Authentication
    callback function in environ.  Upstream middleware must set this.
    @type AUTHN_FUNC_ENV_KEYNAME: string
    @cvar AUTHN_FUNC_ENV_KEYNAME_OPTNAME: in file option name for setting the
    Authentication callback environ key
    @type AUTHN_FUNC_ENV_KEYNAME_OPTNAME: string
    @cvar REALM_OPTNAME: ini file option name for setting the HTTP Basic Auth
    authentication realm
    @type REALM_OPTNAME: string
    @cvar PARAM_PREFIX: prefix for ini file options
    @type PARAM_PREFIX: string
    @cvar AUTHENTICATE_HDR_FIELDNAME: HTTP header field name 'WWW-Authenticate'
    @type AUTHENTICATE_HDR_FIELDNAME: string
    @cvar AUTHENTICATE_HDR_FIELDNAME_LOWER: lowercase version of 
    AUTHENTICATE_HDR_FIELDNAME class variable included for convenience with
    string matching 
    @type AUTHENTICATE_HDR_FIELDNAME_LOWER: string
    @cvar AUTHN_SCHEME_HDR_FIELDNAME: HTTP Authentication scheme identifier
    @type AUTHN_SCHEME_HDR_FIELDNAME: string
    @cvar FIELD_SEP: field separator for username/password header string
    @type FIELD_SEP: string
    @cvar AUTHZ_ENV_KEYNAME: WSGI environ key name for HTTP Basic Auth header
    content
    @type AUTHZ_ENV_KEYNAME: string
    @cvar AUTHN_HDR_FORMAT: HTTP Basic Auth format string following RFC2617
    @type AUTHN_HDR_FORMAT: string
    
    @ivar __rePathMatchList: list of regular expression patterns used to match
    incoming requests and enforce HTTP Basic Auth against
    @type __rePathMatchList: list
    @ivar __authnFuncEnvironKeyName: __authnFuncEnvironKeyName
    @type __authnFuncEnvironKeyName: string
    @ivar __realm: HTTP Basic Auth authentication realm
    @type __realm: string
    @ivar __app: next WSGI app/middleware in call chain
    @type __app: function
    '''
    AUTHN_FUNC_ENV_KEYNAME = (
    'myproxy.server.wsgi.httpbasicauth.HttpBasicAuthMiddleware.authenticate')
    
    # Config file option names
    AUTHN_FUNC_ENV_KEYNAME_OPTNAME = 'authnFuncEnvKeyName'       
    RE_PATH_MATCH_LIST_OPTNAME = 'rePathMatchList'
    REALM_OPTNAME = 'realm'
    
    PARAM_PREFIX = 'http.auth.basic.'
    
    # HTTP header request and response field parameters
    AUTHENTICATE_HDR_FIELDNAME = 'WWW-Authenticate'
    
    # For testing header content in start_response_wrapper
    AUTHENTICATE_HDR_FIELDNAME_LOWER = AUTHENTICATE_HDR_FIELDNAME.lower()
    
    AUTHN_SCHEME_HDR_FIELDNAME = 'Basic'
    AUTHN_SCHEME_HDR_FIELDNAME_LOWER = AUTHN_SCHEME_HDR_FIELDNAME.lower()
    
    FIELD_SEP = ':'
    AUTHZ_ENV_KEYNAME = 'HTTP_AUTHORIZATION'
    
    AUTHN_HDR_FORMAT = '%s ' + REALM_OPTNAME + '="%s"' 
    
    __slots__ = (
        '__rePathMatchList', 
        '__authnFuncEnvironKeyName', 
        '__realm',
        '__app'
    )
    
    def __init__(self, app):
        """Create instance variables
        @param app: next middleware/app in WSGI stack
        @type app: function
        """
        self.__rePathMatchList = None
        self.__authnFuncEnvironKeyName = None
        self.__realm = None
        self.__app = app

    @classmethod
    def filter_app_factory(cls, app, global_conf, prefix=PARAM_PREFIX, 
                           **local_conf):
        """Function following Paste filter app factory signature
        
        @type app: callable following WSGI interface
        @param app: next middleware/application in the chain      
        @type global_conf: dict        
        @param global_conf: PasteDeploy global configuration dictionary
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type local_conf: dict        
        @param local_conf: PasteDeploy application specific configuration 
        dictionary
        @rtype: myproxy.server.wsgi.httpbasicauth.HttpBasicAuthMiddleware
        @return: an instance of this middleware
        """
        httpBasicAuthFilter = cls(app)
        httpBasicAuthFilter.parseConfig(prefix=prefix, **local_conf)
        
        return httpBasicAuthFilter
        
    def parseConfig(self, prefix='', **app_conf):
        """Parse dictionary of configuration items updating the relevant 
        attributes of this instance
        
        @type prefix: basestring
        @param prefix: prefix for configuration items
        @type app_conf: dict        
        @param app_conf: PasteDeploy application specific configuration 
        dictionary
        """
        rePathMatchListOptName = prefix + \
                            HttpBasicAuthMiddleware.RE_PATH_MATCH_LIST_OPTNAME
        rePathMatchListVal = app_conf.pop(rePathMatchListOptName, '')
        
        self.rePathMatchList = [re.compile(i) 
                                for i in rePathMatchListVal.split()]

        paramName = prefix + \
                    HttpBasicAuthMiddleware.AUTHN_FUNC_ENV_KEYNAME_OPTNAME
                    
        self.authnFuncEnvironKeyName = app_conf.get(paramName,
                                HttpBasicAuthMiddleware.AUTHN_FUNC_ENV_KEYNAME)

    def _getAuthnFuncEnvironKeyName(self):
        """Get authentication callback function environ key name
        
        @rtype: basestring
        @return: callback function environ key name
        """
        return self.__authnFuncEnvironKeyName

    def _setAuthnFuncEnvironKeyName(self, value):
        """Set authentication callback environ key name
        
        @type value: basestring
        @param value: callback function environ key name
        """
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for '
                            '"authnFuncEnvironKeyName"; got %r type' % 
                            type(value))
            
        self.__authnFuncEnvironKeyName = value

    authnFuncEnvironKeyName = property(fget=_getAuthnFuncEnvironKeyName, 
                                       fset=_setAuthnFuncEnvironKeyName, 
                                       doc="key name in environ for the "
                                           "custom authentication function "
                                           "used by this class")

    def _getRePathMatchList(self):
        """Get regular expression path match list
        
        @rtype: tuple or list
        @return: list of regular expressions used to match incoming request 
        paths and apply HTTP Basic Auth to
        """
        return self.__rePathMatchList

    def _setRePathMatchList(self, value):
        """Set regular expression path match list
        
        @type value: tuple or list
        @param value: list of regular expressions used to match incoming request 
        paths and apply HTTP Basic Auth to
        """
        if not isinstance(value, (list, tuple)):
            raise TypeError('Expecting list or tuple type for '
                            '"rePathMatchList"; got %r' % type(value))
        
        self.__rePathMatchList = value

    rePathMatchList = property(fget=_getRePathMatchList, 
                               fset=_setRePathMatchList, 
                               doc="List of regular expressions determine the "
                                   "URI paths intercepted by this middleware")

    def _getRealm(self):
        """Get realm
        
        @rtype: basestring
        @return: HTTP Authentication realm to set in responses
        """
        return self.__realm

    def _setRealm(self, value):
        """Set realm
        
        @type value: basestring
        @param value: HTTP Authentication realm to set in responses
        """
        if not isinstance(value, basestring):
            raise TypeError('Expecting string type for '
                            '"realm"; got %r' % type(value))
        
        self.__realm = value

    realm = property(fget=_getRealm, fset=_setRealm, 
                     doc="HTTP Authentication realm to set in responses")

    def _pathMatch(self, environ):
        """Apply a list of regular expression matching patterns to the contents
        of environ['PATH_INFO'], if any match, return True.  This method is
        used to determine whether to apply SSL client authentication
        
        @param environ: WSGI environment variables dictionary
        @type environ: dict
        @return: True if request path matches the regular expression list set,
        False otherwise
        @rtype: bool 
        """
        path = environ['PATH_INFO']
        for regEx in self.rePathMatchList:
            if regEx.match(path):
                return True
            
        return False   

    @classmethod
    def parse_credentials(cls, environ):
        """Extract username and password from HTTP_AUTHORIZATION environ key
        
        @param environ: WSGI environ dict
        @type environ: dict
        
        @rtype: tuple
        @return: username and password.  If the key is not set or the auth
        method is not basic return a two element tuple with elements both set
        to None
        """
        basicAuthHdr = environ.get(cls.AUTHZ_ENV_KEYNAME)
        if basicAuthHdr is None:
            log.debug("No %r setting in environ: skipping HTTP Basic Auth",
                      HttpBasicAuthMiddleware.AUTHZ_ENV_KEYNAME)
            return None, None
                       
        method, encodedCreds = basicAuthHdr.split(None, 1)
        if (method.lower() != cls.AUTHN_SCHEME_HDR_FIELDNAME_LOWER):
            log.debug("Auth method is %r not %r: skipping request",
                      method, 
                      cls.AUTHN_SCHEME_HDR_FIELDNAME)
            return None, None
            
        creds = base64.decodestring(encodedCreds)
        username, password = creds.rsplit(cls.FIELD_SEP, 1)
        return username, password

    def __call__(self, environ, start_response):
        """Authenticate based HTTP header elements as specified by the HTTP
        Basic Authentication spec.
        
        @param environ: WSGI environ 
        @type environ: dict-like type
        @param start_response: WSGI start response function
        @type start_response: function
        @return: response
        @rtype: iterable
        @raise HttpBasicAuthMiddlewareConfigError: no authentication callback
        found in environ
        """
        log.debug("HttpBasicAuthNMiddleware.__call__ ...")
        
        if not self._pathMatch(environ):
            return self.__app(environ, start_response)
        
        def start_response_wrapper(status, headers): 
            """Ensure Authentication realm is included with 401 responses"""
            statusCode = int(status.split()[0])
            if statusCode == httplib.UNAUTHORIZED:
                authnRealmHdrFound = False
                for name, val in headers:
                    if (name.lower() == 
                            self.__class__.AUTHENTICATE_HDR_FIELDNAME_LOWER):
                        authnRealmHdrFound = True
                        break
                     
                if not authnRealmHdrFound:
                    # Nb. realm requires double quotes according to RFC
                    authnRealmHdr = (self.__class__.AUTHENTICATE_HDR_FIELDNAME,
                                     self.__class__.AUTHN_HDR_FORMAT % (                                   
                                     self.__class__.AUTHN_SCHEME_HDR_FIELDNAME,
                                     self.realm))
                    headers.append(authnRealmHdr)
                
            return start_response(status, headers)
        
        username, password = self.parse_credentials(environ)
        if username is None:
            log.error('No username set in HTTP Authorization header')
            return self.setErrorResponse(start_response_wrapper, 
                                         msg="No username set\n")
        
        authenticateFunc = environ.get(self.authnFuncEnvironKeyName)
        if authenticateFunc is None:
            # HTTP 500 default is right for this error
            raise HttpBasicAuthMiddlewareConfigError("No authentication "
                                                     "function set in environ")
        
        # Call authentication middleware/application.  If no response is set,
        # the next middleware is called in the chain
        try:
            response = authenticateFunc(environ, 
                                        start_response_wrapper, 
                                        username, 
                                        password)
            if response is None:
                return self.__app(environ, start_response_wrapper)
            else:
                return response
            
        except HttpBasicAuthResponseException, e:
            log.error('Client authentication raised an exception: %s', 
                      traceback.format_exc())
            return self.setErrorResponse(start_response_wrapper,
                                         msg=e.response,
                                         code=e.code)    

    @classmethod
    def setErrorResponse(cls,
                         start_response, 
                         msg=None, 
                         code=httplib.UNAUTHORIZED,
                         contentType=None):
        '''Convenience method to set a simple error response
        
        @type start_response: function
        @param start_response: standard WSGI callable to set the HTTP header
        @type msg: basestring
        @param msg: optional error message
        @type code: int
        @param code: standard HTTP error response code
        @type contentType: basestring
        @param contentType: set 'Content-type' HTTP header field - defaults to
        'text/plain'
        @rtype: list
        @return: HTTP error response
        '''                        
        status = '%d %s' % (code, httplib.responses[code])
        if msg is None:
            response = "%s\n" % status
        else:
            response = msg
        
        if contentType is None:
            contentType = 'text/plain'
                        
        headers = [
            ('Content-type', contentType), 
            ('Content-length', str(len(msg)))
        ]
        start_response(status, headers)
        return [response]