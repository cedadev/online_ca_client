Online CA Client
================
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
-------------
This has been developed and tested for Python 2.6 and 2.7.

Installation
------------
Installation can be performed using easy_install or pip.

Configuration
-------------
Examples are contained in ``onlineca.client.test``.

Shell script client - bootstrapping trust saving CA trust root certificates in ``./ca`` directory: 
```
$ ./onlineca-get-trustroots.sh -U https://<hostname>/onlineca/trustroots/ -c ./ca -b
Bootstrapping Short-Lived Credential Service root of trust.
Trust roots have been installed in ./ca.
```
Obtaining a certificate:
```
$ ./onlineca-get-cert.sh -U https://<hostname>/onlineca/certificate/ -l <username> -c ./ca
Enter Short-Lived Credential phrase: 
-----BEGIN CERTIFICATE-----
...
```

