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

The code was originally developed for the EU Framework 7 programme Contrail
Project.

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
The is a shell script client as well as Python command line client and API. It is *strongly* recommended to use the Python command line or API rather than the shell script client because the latter may be deprecated in the future.

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
#### Obtain a certificate using username and password ####
```
$ online-ca-client get_cert -s https://slcs.somewhere.ac.uk/onlineca/certificate/ -l <username> -c ./ca-trustroots/ -o ./credentials.pem
```

#### Delegated certificate retrieval using OAuth 2.0 ####
This method can be used for scenarios where credentials are needed for an unattended applications requiring user authentication with certificates such as scripts or long running jobs for example large file transfers using GridFTP.

To obtain a delegated certificate, the identity provider must support an OAuth 2.0 interface. This enables delegated clients to obtain certificates on behalf of a user. In summary the process is: i) client registers with OAuth service obtaining an id and secret. ii) client calls Oauth service to obtain an access token. iii) client calls OnlineCA SLCS service to obtain a new certificate authenticating using the access token instead of username and password as in the more conventional case.

In more detail:
 1. Configure OAuth client credentials. The client application seeking to obtain delegated credentials on behalf of the user needs to register a client ID and secret with the identity provider. This will need to be done out of band of the client as it is dependent on the identity provider concerned and their policies. 
 2. Set identity provider configuration file. Once obtained the details need to be entered into this configuration file:
```
# Client credentials
client_id: "<client id>"
client_secret: "<client secret>"

# Configuration details for interacting with the Authorisation Server
authorization_base_url: 'https://<identity provider OAuth service host name>/oauth/authorize'
token_url: 'https://<identity provider OAuth service host name>/oauth/token/'
scope: "https://<SLCS Service host name>/certificate/"

# Start location for user to invoke
start_url: "http://localhost:5000/"

# Location on the client that the Authorisation Server is configured to redirect to
redirect_url: "http://localhost:5000/callback"
```
All other host name details between `<>` need to be filled out. Save this file in the location, `~/.onlinecaclient_idp.yaml` or explicitly set a path in the command line options (see later step).

 3. Obtain OAuth access token. This preliminary step is required in order to obtain a delegated authentication certificate. *Note that this command will launch a web browser link and display a page for the identity provider. Follow the steps to sign in with the identity provider and to authorise the client application to obtain delegated credentials. The specific steps may vary depending on the implementation of the identity provider.*
```
# online-ca-client get_token -f <identity provider configuration file location>
```
Note that the `-f` option can be omitted in which case, the default identity provider file location will be used (`~/.onlinecaclient_idp.yaml`). If successful, the access token obtained is written out to the file `~/.onlinecaclient_token.json`

 4. Obtain certificate using OAuth access token. This call is a similar form to the method with username and password listed above except username and password settings are replaced with the `-t` token switch:
```
# online-ca-client get_cert -s https://slcs.jasmin.ac.uk/certificate/ -t - -c ./ca-trustroots/ -o credentials.pem 
```
The setting, `-` for the token option (`-t`) indicates to use the default location for the access token as obtained in the previous step i.e. `~/.onlinecaclient_token.json`

 5. Obtain an updated access token using a Refresh token. In some cases, it may be necessary to renew an access token as it is due to expire. A fresh access token can be obtained using the steps above or alternatively, a new token can be issued if the OAuth Service supports _Refresh tokens_. In this case, when the initial `get_token` call is made a refresh token should have been included in the response from the OAuth Service and written out to the token file (default location - `~/.onlinecaclient_token.json`). This can be checked by listing this file and looking for the key name `"refresh_token"`. If this is present then the refresh token call can be made:
```
# online-ca-client refresh_token -f <identity provider configuration file location>
```
As with the `get_token` command, the `-f` option can be omitted in order to use the default location. If successful, a new token file will be written out containing a new access token.

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
