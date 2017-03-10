#!/usr/bin/env python
"""Distribution Utilities setup program for Online CA Client Package

Contrail Project
"""
__author__ = "P J Kershaw"
__date__ = "21/05/10"
__copyright__ = "(C) 2014 Science and Technology Facilities Council"
__license__ = """BSD - See LICENSE file in contrail.security.onlineca.client"""
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
    name =            	'ContrailOnlineCAClient',
    version =         	'0.4.0',
    description =     	'Certificate Authority web service client',
    long_description = 	'''\
Provides the client interface for an online Certificate Authority web-service.
This package works with the ``ContrailOnlineCAService`` the server-side
implementation also available from PyPI.

Web service calls can be made to request a certificate.  The web service
interface is RESTful using GET and POST operations.  To request a certificate,
a Certificate Signing Request is sent as a field with a HTTP POST call.  The
service should be hosted over HTTPS.  The client authenticates using HTTP Basic
Auth or SSL client authentication.  In the first case, username and password
are sent.  For the latter, at least a username should be set as this needed to
configure the subject name of the certificate requested.  If authentication
succeeds, an X.509 certificate is returned.

As well as a Python client, an implementation is included as shell scripts.
These require only openssl and wget or curl which are typically available on
Linux/UNIX based systems.

The code has been developed for the Contrail Project, http://contrail-project.eu/

Prerequisites
=============
This has been developed and tested for Python 2.7 and Python 3.5.

Installation
============
Installation can be performed using pip.

Configuration
=============
Examples are contained in ``onlineca.client.test``.
''',
    author =          	'Philip Kershaw',
    author_email =    	'Philip.Kershaw@stfc.ac.uk',
    maintainer =        'Philip Kershaw',
    maintainer_email =  'Philip.Kershaw@stfc.ac.uk',
    url =             	'https://github.com/cedadev/online_ca_client',
    platforms =         ['POSIX', 'Linux', 'Windows'],
    install_requires =  ['requests', 'requests_oauthlib'],
    license =           __license__,
    test_suite =        'contrail.security.onlineca.client.test',
    packages =          find_packages(),
    package_data =      {
        'contrail.security.onlineca.client.test': [
            '*.cfg', '*.crt', '*.key', '*.pem', 'ca/*.0'
        ],
        'contrail.security.onlineca.client.sh': [
            '*.sh'
        ],
        'contrail.security.onlineca.client': [
            'README'
        ],
        'contrail.security.onlineca.client': [
            'LICENSE'
        ]
    },
    classifiers = [
        'Development Status :: 5 - Production/Stable',
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
        'Programming Language :: Python :: 3',
        'Topic :: Security',
        'Topic :: Internet',
        'Topic :: Scientific/Engineering',
        'Topic :: System :: Distributed Computing',
        'Topic :: System :: Systems Administration :: Authentication/Directory',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
    entry_points={
        'console_scripts': [
            'online-ca-client = contrail.security.onlineca.client.cli:main',
             ],
        },
    zip_safe = False
)
