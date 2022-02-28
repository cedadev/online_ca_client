"""Online CA service client - OAuth 2.0 client for obtaining a delegated 
certificate

Contrail Project
"""
__author__ = "P J Kershaw"
__date__ = "18/02/22"
__copyright__ = "Copyright 2022 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
import os
import socket

from requests_oauthlib import OAuth2Session
from flask import Flask, request, redirect, session, url_for
import yaml
from waitress import serve

from contrail.security.onlineca.client import OnlineCaClient


app = Flask(__name__)
socket_ = None
THIS_DIR = os.path.dirname(__file__)
SETTINGS_FILEPATH = os.path.join(THIS_DIR, "test", "idp.yaml")

def read_settings_file(settings_filepath: str) -> dict:
    with open(settings_filepath) as settings_file:
        settings = yaml.safe_load(settings_file)
    
    return settings

settings = read_settings_file(SETTINGS_FILEPATH)

@app.route("/")
def get_user_authorisation():
    """Step 1: User Authorization.

    Redirect the user/resource owner to the OAuth provider (i.e. Github)
    using an URL with a few key OAuth parameters.
    """
    oauth_session = OAuth2Session(settings['client_id'], 
                                scope=settings['scope'])
    authorization_url, state = oauth_session.authorization_url(
                                settings['authorization_base_url'])

    # State is used to prevent CSRF, keep this for later.
    session['oauth_state'] = state
    return redirect(authorization_url)

@app.route("/callback")
def get_access_token():
    """ Step 3: Retrieving an access token.

    The user has been redirected back from the provider to your registered
    callback URL. With this redirection comes an authorization code included
    in the redirect URL. We will use that to obtain an access token.
    """
    oauth2_session = OAuth2Session(settings['client_id'], state=session['oauth_state'])
    token = oauth2_session.fetch_token(settings['token_url'], 
                                client_secret=settings['client_secret'],
                                authorization_response=request.url)

    # At this point you can fetch protected resources but lets save
    # the token and show how this is done from a persisted token
    # in /profile.
    session['oauth_token'] = token

    return redirect(url_for('.close'))
    

@app.route("/close")
def close():
    socket_.close()

def get_access_token():
    pass


def get_certificate():
    """Fetching a protected resource using an OAuth 2 token.
    """
    oauth2_session = OAuth2Session(settings['client_id'], token=session['oauth_token'])

    online_ca_clnt = OnlineCaClient()

    # Scope setting is also the URI to the resource - the certificate issuing 
    # endpoint
    response = online_ca_clnt.get_certificate_using_session(oauth2_session, settings['scope'])

    return str(response)


if __name__ == "__main__":
    # This allows us to use a plain HTTP callback
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = "1"
    
    app.secret_key = os.urandom(24)
    
    socket_ = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_.bind(('127.0.0.1', 5000))
    # app.run(debug=True, host='0.0.0.0')
    # app.run(host='0.0.0.0')
    # serve(app, port=5000, threads=1)
    try:
        serve(app, sockets=[socket_])
    except Exception as e:
        pass

