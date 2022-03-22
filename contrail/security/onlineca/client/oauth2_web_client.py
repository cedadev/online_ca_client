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
import time
from queue import Queue
import webbrowser
import json

import yaml
import uvicorn 
from uvicorn.protocols.http.h11_impl import H11Protocol
from uvicorn.lifespan.on import LifespanOn
from quart import Quart, request, redirect, session
from requests_oauthlib import OAuth2Session

from contrail.security.onlineca.client import OnlineCaClient
from contrail.security.onlineca.client.web_server import StoppableWebServer

# Make a queue object to communicate that the OAuth flow has been completed
SHUTDOWN_QUEUE = Queue()
            
# Quart application to manage OAuth flow
oauth_onlineca_client_web_app = Quart(__name__)
oauth_onlineca_client_web_app.secret_key = os.urandom(24)
THIS_DIR = os.path.dirname(__file__)
SETTINGS_FILEPATH = os.path.join(THIS_DIR, "test", "idp.yaml")


class OAuthFlowH11Protocol(H11Protocol):
    CALLBACK_PATH = "/callback"

    def on_response_complete(self):
        super().on_response_complete()

        # Kill HTTP server once callback response has been completed
        if self.scope.get("path") == self.CALLBACK_PATH:
            # Signal to server via queue object
            SHUTDOWN_QUEUE.put(True)


class OAuthFlowStoppableWebServer(StoppableWebServer):
    """Extend web server to allow launch of browser window on start-up"""
    HOSTNAME = "localhost"

    def thread_callback(self):
        if self.started and not getattr(self, "launched_browser", False):
            time.sleep(1)
            webbrowser.open(f"http://{self.HOSTNAME}:{self.config.port}")
            self.launched_browser = True


def read_settings_file(settings_filepath: str) -> dict:
    with open(settings_filepath) as settings_file:
        settings = yaml.safe_load(settings_file)
    
    return settings

settings = read_settings_file(SETTINGS_FILEPATH)


@oauth_onlineca_client_web_app.route("/")
async def get_user_authorisation():
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


@oauth_onlineca_client_web_app.route("/callback")
async def get_access_token():
    """ Step 3: Retrieving an access token.

    The user has been redirected back from the provider to your registered
    callback URL. With this redirection comes an authorization code included
    in the redirect URL. We will use that to obtain an access token.
    """
    oauth2_session = OAuth2Session(settings['client_id'], state=session['oauth_state'])
    token = oauth2_session.fetch_token(settings['token_url'], 
                                client_secret=settings['client_secret'],
                                authorization_response=request.url)

    # Save token in a file
    save_tok(token)

    return ('Successfully obtained access token for Online CA Client. You can '
            'close this browser tab now')

def save_tok(token, tok_filepath=None):
    if tok_filepath is None:
        tok_filepath = os.path.join(THIS_DIR, "token.json")

    tok_file_content = json.dumps(token)

    with open(tok_filepath, "w") as tok_file:
        tok_file.write(tok_file_content)


def read_tok(tok_filepath=None):
    if tok_filepath is None:
        tok_filepath = os.path.join(THIS_DIR, "token.json")
    
    with open(tok_filepath) as tok_file:
        tok_file_content = tok_file.read()

    return json.loads(tok_file_content)


def get_certificate() -> tuple:
    """Fetching a protected resource using an OAuth 2 token.
    """
    token = read_tok()

    oauth2_session = OAuth2Session(settings['client_id'], token=token)

    online_ca_clnt = OnlineCaClient()

    # Scope setting is also the URI to the resource - the certificate issuing 
    # endpoint
    return online_ca_clnt.get_certificate_using_session(oauth2_session, settings['scope'])


def main():
    # This allows us to use a plain HTTP callback
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = "1"
    
    module_name = os.path.basename(__file__).split('.')[0]
    port_num = 5000
    config = uvicorn.Config(f"{module_name}:oauth_onlineca_client_web_app", 
                            host="127.0.0.1", port=port_num, http=OAuthFlowH11Protocol,
                            log_level="info")
    server = OAuthFlowStoppableWebServer(config, SHUTDOWN_QUEUE)

    with server.run_in_thread():
        # Server started.
        response = get_certificate()

    # Server stopped.
    print ("completed")


if __name__ == "__main__":
    main()



