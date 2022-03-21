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
from queue import Queue
import contextlib
import time
import threading

import yaml
import uvicorn 
from uvicorn.protocols.http.h11_impl import H11Protocol
from quart import Quart, request, redirect, session
from requests_oauthlib import OAuth2Session

from contrail.security.onlineca.client import OnlineCaClient


# Make a queue object to communicate that the OAuth flow has been completed
OAUTH_FLOW_COMPLETE = Queue()
            
# Application to manage OAuth flow
app = Quart(__name__)
app.secret_key = os.urandom(24)
THIS_DIR = os.path.dirname(__file__)
SETTINGS_FILEPATH = os.path.join(THIS_DIR, "test", "idp.yaml")


class OAuthFlowH11Protocol(H11Protocol):
    CALLBACK_PATH = "/callback"

    def on_response_complete(self):
        super().on_response_complete()

        # Kill HTTP server once callback response has been completed
        if self.scope.get("path") == self.CALLBACK_PATH:
            # raise KeyboardInterrupt
            OAUTH_FLOW_COMPLETE.put(self)


class OAuthAuthorisationCodeClientServer(uvicorn.Server):
    """Threaded Uvicorn server which receives content from an external queue
    to signal to shutdown the service
    """
    @contextlib.contextmanager
    def run_in_thread(self) -> None:
        thread = threading.Thread(target=self.run)
        thread.start()
        try:
            # Flow complete Queue object is used to flag that the OAuth
            # process has been completed
            while OAUTH_FLOW_COMPLETE.qsize() < 1:
                time.sleep(1e-3)
            yield
        finally:
            self.should_exit = True
            thread.join()


def read_settings_file(settings_filepath: str) -> dict:
    with open(settings_filepath) as settings_file:
        settings = yaml.safe_load(settings_file)
    
    return settings

settings = read_settings_file(SETTINGS_FILEPATH)


@app.route("/")
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


@app.route("/callback")
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

    # At this point you can fetch protected resources but lets save
    # the token and show how this is done from a persisted token
    # in /profile.
    session['oauth_token'] = token

    return 'Success'


def get_certificate():
    """Fetching a protected resource using an OAuth 2 token.
    """
    oauth2_session = OAuth2Session(settings['client_id'], token=session['oauth_token'])

    online_ca_clnt = OnlineCaClient()

    # Scope setting is also the URI to the resource - the certificate issuing 
    # endpoint
    response = online_ca_clnt.get_certificate_using_session(oauth2_session, settings['scope'])

    return str(response)


def main():
    # This allows us to use a plain HTTP callback
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = "1"
    
    module_name = os.path.basename(__file__).split('.')[0]

    config = uvicorn.Config(f"{module_name}:app", host="127.0.0.1", port=5000,
                            http=OAuthFlowH11Protocol, log_level="info")
    server = OAuthAuthorisationCodeClientServer(config=config)

    with server.run_in_thread():
        # Server started.
        pass

    # Server stopped.
    print ("completed")


if __name__ == "__main__":
    main()



