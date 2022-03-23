"""Online CA service client - Quart web application for OAuth 2.0 client to 
support authorisation code flow for obtaining a delegated certificate

Contrail Project
"""
__author__ = "P J Kershaw"
__date__ = "23/03/22"
__copyright__ = "Copyright 2022 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
import os
from urllib.parse import urlparse

import yaml
from quart import Quart, request, redirect, session
from requests_oauthlib import OAuth2Session

from contrail.security.onlineca.client import OnlineCaClient

# Quart application to manage OAuth flow
QUART_SECRET_KEY_LEN = 24
app = Quart(__name__)
app.secret_key = os.urandom(QUART_SECRET_KEY_LEN)

THIS_DIR = os.path.dirname(__file__)
SETTINGS_FILEPATH = os.path.join(THIS_DIR, "test", "idp.yaml")
OAUTH_WEB_APP_CALLBACK_COMPL_MSG = (
    'Successfully obtained access token for Online CA Client. You can close '
    'this browser tab now'
)

def read_settings_file(settings_filepath: str = None) -> dict:
    if settings_filepath is None:
        settings_filepath = SETTINGS_FILEPATH

    with open(settings_filepath) as settings_file:
        settings = yaml.safe_load(settings_file)
    
    return settings


SETTINGS = read_settings_file()
REDIRECT_URL = urlparse(SETTINGS['redirect_url'])
START_URL = urlparse(SETTINGS['start_url'])


@app.route(START_URL.path)
async def get_user_authorisation():
    """User Authorization. Redirect the user/resource owner to the OAuth 
    provider using an URL with a few key OAuth parameters.
    """
    oauth_session = OAuth2Session(SETTINGS['client_id'], 
                                scope=SETTINGS['scope'])
    authorization_url, state = oauth_session.authorization_url(
                                SETTINGS['authorization_base_url'])

    # State is used to prevent CSRF, keep this for later.
    session['oauth_state'] = state
    return redirect(authorization_url)


# Configure path based on expected redirect url for OAuth Authorisation Server
@app.route(REDIRECT_URL.path)
async def get_access_token():
    """Retrieve an access token
    """
    oauth2_session = OAuth2Session(SETTINGS['client_id'], state=session['oauth_state'])
    token = oauth2_session.fetch_token(SETTINGS['token_url'], 
                                client_secret=SETTINGS['client_secret'],
                                authorization_response=request.url)

    # Save token in a file
    OnlineCaClient.save_oauth_tok(token)

    return OAUTH_WEB_APP_CALLBACK_COMPL_MSG