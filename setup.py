#!/usr/bin/env python
"""Distribution Utilities setup program for MyProxy Server Utilities Package

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "21/05/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = """BSD - See LICENSE file in top-level directory"""
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id: $'

# Bootstrap setuptools if necessary.
try:
    from setuptools import setup, find_packages
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages


setup(
    name =            	'MyProxyWebService',
    version =         	'0.2.3',
    description =     	'MyProxy Web Service',
    long_description = 	'''\
Provides a simple web service interface to MyProxyCA.  MyProxy is a Service for 
managing and issuing PKI based credentials which is part of the Globus Toolkit.  
MyProxyWebService provides a HTTP based wrapper interface to MyProxy enabling
HTTP based clients to connect to a MyProxy server and retrieve credentials.

The interface is implemented as a WSGI application which fronts a normal 
MyProxyCA server.  ``myproxy-logon`` and ``myproxy-get-trustroots`` are 
expressed as web service calls.  The WSGI application forwards the requests on 
to the MyProxy server over the usual MyProxy protocol.  The web service 
interface is RESTful using GET and POST operations and the logon interface makes
uses of HTTP Basic Auth to pass username and pass-phrase credentials.  The 
service is hosted over HTTPS.

The unit tests include a test application served using paster.  Client scripts
are also available which need no specialised installation or applications, only
openssl and wget or curl which are typically available on Linux/UNIX based 
systems.

Changes for version 0.2.3
=========================
Added example to tests to show SSL client authentication.

Changes for version 0.2.2
=========================
The package hierarchy has been re-organised:
 * ``myproxy.server.wsgi``: contains middleware to make calls to a MyProxy 
   service using the ``MyProxyClient`` package.  It exposes this interface 
   through the ``environ`` dict so that other middleware or an app can access 
   and use it.
 * ``myproxy.ws``: contains functionality specific to the web service interface:
    - ``myproxy.ws.client``: contains all the functionality for web service clients to the MyProxy web service. This includes:
       + shell scripts (``.sh`` suffix) for logon and get trustroots calls.  
         These are implemented with openssl and curl.  Alternative 
         implementations are also provided which use wget (``-wget.sh`` suffix)
         instead of curl.  These scripts have also been tested against an 
         independent Short-Lived Credential Service developed for the Contrail 
         EU FP7 project.
       + ``myproxy.ws.client.MyProxyWSClient``: is a Python client interface to
         the web service.  The third party package ``ndg_httpclient`` is needed
         for this class but note that overall, it is set as an optional install.  
    - ``myproxy.ws.server``: contains the server side functionality - a set of 
      WSGI middleware and an application to implement logon and get-trustroot 
      web service calls.

Prerequisites
=============
This has been developed and tested for Python 2.6 and 2.7.

Installation
============
Installation can be performed using easy_install or pip.  Since this package is
a wrapper to MyProxy, a MyProxy instance must be deployed that this service can
call and use.

Configuration
=============
Examples are contained in ``myproxy.ws.client.test`` and ``myproxy.server.test``.
''',
    author =          	'Philip Kershaw',
    author_email =    	'Philip.Kershaw@stfc.ac.uk',
    maintainer =        'Philip Kershaw',
    maintainer_email =  'Philip.Kershaw@stfc.ac.uk',
    url =             	'http://proj.badc.rl.ac.uk/ndg/wiki/Security/MyProxyWebService',
    platforms =         ['POSIX', 'Linux', 'Windows'],
    install_requires =  ['PasteDeploy', 
                         'PasteScript',
                         'WebOb', 
                         'MyProxyClient'],
    extras_require =    {'Python_client': 'ndg_httpclient'},
    license =           __license__,
    test_suite =        'myproxy.ws.test',
    packages =          find_packages(),
    package_data =      {
        'myproxy.ws.test': [
            'README', '*.cfg', '*.ini', '*.crt', '*.key', '*.pem', 'ca/*.0'
        ],
        'myproxy.ws.client': [
            'README', '*.sh'
        ],
        'myproxy.ws.client.test': [
            'README', '*.cfg'
        ]
    },
    classifiers = [
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Environment :: Web Environment',
        'Intended Audience :: End Users/Desktop',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Topic :: Security',
        'Topic :: Internet',
        'Topic :: Scientific/Engineering',
        'Topic :: System :: Distributed Computing',
        'Topic :: System :: Systems Administration :: Authentication/Directory',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
    zip_safe = False
)
