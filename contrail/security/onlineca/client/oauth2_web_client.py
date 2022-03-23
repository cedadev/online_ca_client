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
from urllib.parse import urlparse

import uvicorn 
from uvicorn.protocols.http.h11_impl import H11Protocol
from requests_oauthlib import OAuth2Session

from contrail.security.onlineca.client import OnlineCaClient
from contrail.security.onlineca.client.web_server import StoppableWebServer
from contrail.security.onlineca.client.oauth_web_app import __name__ as OAUTH_WEB_APP_MODULE_NAME

# TODO: Refactor where these are obtained from
from contrail.security.onlineca.client.oauth_web_app import read_settings_file

THIS_DIR = os.path.dirname(__file__)
        

class OAuthFlowH11Protocol(H11Protocol):
    """Derive from H11Protocol class and inject into uvicorn as way of managing
    when to send a signal to the web server that the final callback in the
    OAuth flow has been completed"""
        
    def on_response_complete(self):
        super().on_response_complete()

        # Kill HTTP server once callback response has been completed
        if self.scope.get("path") == self.config.h11_callback_path:
            # Signal to server via queue object
            self.config.h11_shutdown_queue.put(True)


class OAuthFlowStoppableWebServer(StoppableWebServer):
    """Extend web server to allow launch of browser window on start-up"""
    
    def thread_callback(self):
        """Invoke browser once web server is started and ready to receive
        client requests
        """
        if self.started and not getattr(self, "launched_browser", False):
            webbrowser.open(f"http://{self.config.host}:{self.config.port}")
            self.launched_browser = True


class OAuthAuthorisationCodeFlowClient:
    """Manage OAuth Authorisation Code flow to obtain an access token for use
    retrieving a user certificate
    """
    # Path for Quart web app to pass to uvicorn
    WEB_APP_PATH = f"{OAUTH_WEB_APP_MODULE_NAME}:app"

    def __init__(self, settings=None):
        if settings is None:
            self.settings = read_settings_file()
        else:
            self.settings = settings

    def get_certificate(self) -> tuple:
        """Fetching a protected resource using an OAuth 2 token.
        """
        token = OnlineCaClient.read_oauth_tok()

        oauth2_session = OAuth2Session(client_id=self.settings['client_id'], 
                                    token=token)

        online_ca_clnt = OnlineCaClient()

        # Scope setting is also the URI to the resource - the certificate issuing 
        # endpoint
        return online_ca_clnt.get_certificate_using_session(oauth2_session, 
                                                        self.settings['scope'])

    def get_access_tok(self) -> None:
        """Obtain access token by starting a client web server ready for the 
        user to authenticate with the OAuth Authorisation Server and grant 
        permission for the client
        """

        # These two settings must match what has been used configured at the OAuth
        # Authorisation Server as the callback url for this client      
        redirect_url = urlparse(self.settings['redirect_url'])

        # This allows us to use a plain HTTP callback
        os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = "1"
        try:
            config = uvicorn.Config(self.WEB_APP_PATH, 
                                    host=redirect_url.hostname, 
                                    port=redirect_url.port, 
                                    http=OAuthFlowH11Protocol,
                                    log_level="critical")
            config.h11_shutdown_queue = Queue()
            config.h11_callback_path = redirect_url.path

            server = OAuthFlowStoppableWebServer(config)

            with server.run_in_thread():
                # Server started.
                print(f"Loading page {self.settings['start_url']} in your "
                    "default browser ...")
        finally:
            del os.environ['OAUTHLIB_INSECURE_TRANSPORT']

        # Server stopped.
        print("completed")


if __name__ == "__main__":
    clnt = OAuthAuthorisationCodeFlowClient()
    clnt.get_access_tok()
    creds = clnt.get_certificate()



