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
This has been developed and tested for Python 2.7 and 3.6.

Installation
------------
Installation can be performed using pip:
```
$ pip install ContrailOnlineCAClient
```

Configuration
-------------
Examples are contained in ``onlineca.client.test``.

Example Clients
---------------
The is a shell script client as well as Python command line client and API.

### Shell script client ###
Bootstrap trust saving CA trust root certificates in ``./ca-trustroots`` directory:
```
$ ./onlineca-get-trustroots.sh -U https://<hostname>/onlineca/trustroots/ -c ./ca-trustroots -b
Bootstrapping Short-Lived Credential Service root of trust.
Trust roots have been installed in ./ca-trustroots.
```
Obtain a certificate:
```
$ ./onlineca-get-cert.sh -U https://<hostname>/onlineca/certificate/ -l <username> -c ./ca-trustroots
Enter Short-Lived Credential phrase:
-----BEGIN CERTIFICATE-----
...
```

### Python command line client ###
Bootstrap trust saving CA trust root certificates in ``./ca-trustroots`` directory:
```
$ online-ca-client get_trustroots -s https://<hostname>/onlineca/trustroots -b -c ./ca-trustroots
```
Obtain a certificate:
```
$ online-ca-client get_cert -s https://slcs.somewhere.ac.uk/onlineca/certificate/ -l pjkersha -c ./ca-trustroots/ -o ./credentials.pem
```

### Python API ###
Initialise setting directory to store CA certificate trust roots:
```
>>> from contrail.security.onlineca.client import OnlineCaClient
>>> onlineca_client = OnlineCaClient()
>>> onlineca_client.ca_cert_dir = "./ca-trustroots"
```
Bootstrap trust saving CA trust root certificates in ``./ca-trustroots`` directory:
```
>>> trustroots = onlineca_client.get_trustroots("https://slcs.somewhere.ac.uk/onlineca/trustroots/", bootstrap=True, write_to_ca_cert_dir=True)
```
Get certificate - key and certificate(s) may be optionally written to a file
```
>>> key_pair, certs = onlineca_client.get_certificate(username, password, 'https://slcs.somewhere.ac.uk/onlineca/certificate/', pem_out_filepath="./credentials.pem")
```
