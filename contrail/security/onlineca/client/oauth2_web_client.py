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
import webbrowser
from urllib.parse import urlparse

import yaml
import uvicorn
from uvicorn.protocols.http.h11_impl import H11Protocol

from .web_server import StoppableWebServer
from .oauth2_web_app import OAuth2WebApp


class OAuthFlowH11Protocol(H11Protocol):
    """Derive from H11Protocol class and inject into uvicorn as way of managing
    when to send a signal to the web server that the final callback in the
    OAuth flow has been completed"""

    def on_response_complete(self):
        super().on_response_complete()

        # Kill HTTP server once callback response has been completed
        if self.scope.get("path") == self.config.oauth_callback_path:
            # Signal to server via queue object
            self.config.shutdown_queue.put(True)


class OAuthFlowStoppableWebServer(StoppableWebServer):
    """Extend web server to allow launch of browser window on start-up"""

    def __init__(self, config: uvicorn.Config, callback_path: str) -> None:
        super().__init__(config)
        self.config.oauth_callback_path = callback_path

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

    DEF_SETTINGS_FILENAME = ".onlinecaclient_idp.yaml"
    DEF_SETTINGS_FILEPATH = os.path.join(os.environ["HOME"], DEF_SETTINGS_FILENAME)
    SETTINGS_FILEPATH_ENVVARNAME = "ONLINECA_CLNT_SETTINGS_FILEPATH"

    def __init__(
        self,
        settings: dict = None,
        settings_filepath: str = None,
        tok_filepath: str = None,
    ):
        if settings is None:
            self.settings = self.read_settings_file(filepath=settings_filepath)
        else:
            self.settings = settings

        self.tok_filepath = tok_filepath

    @classmethod
    def read_settings_file(cls, filepath: str = None) -> dict:
        """Read settings for OAuth connections from YAML file. YAML file
        path is set via an environment variable. If this is not set, it's
        taken from a default"""

        # Follow an order of precedence for where to get file from
        if filepath is None:
            filepath = os.environ.get(cls.SETTINGS_FILEPATH_ENVVARNAME)
            if filepath is None:
                filepath = cls.DEF_SETTINGS_FILEPATH

        with open(filepath) as settings_file:
            settings = yaml.safe_load(settings_file)

        return settings

    def get_access_tok(self) -> None:
        """Obtain access token by starting a client web server ready for the
        user to authenticate with the OAuth Authorisation Server and grant
        permission for the client
        """

        # These two settings must match what has been used configured at the OAuth
        # Authorisation Server as the callback url for this client
        redirect_url = urlparse(self.settings["redirect_url"])
        start_url = urlparse(self.settings["start_url"])

        # This allows us to use a plain HTTP callback
        oauthlib_insecure_transport = os.environ.get("OAUTHLIB_INSECURE_TRANSPORT")
        os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

        web_app = OAuth2WebApp(self.settings, __name__, tok_filepath=self.tok_filepath)

        try:
            config = uvicorn.Config(
                web_app,
                host=start_url.hostname,
                port=start_url.port,
                http=OAuthFlowH11Protocol,
                log_level="error",
            )

            server = OAuthFlowStoppableWebServer(config, redirect_url.path)

            with server.run_in_thread():
                # Server started.
                print(
                    f"Loading page {self.settings['start_url']} in your "
                    "default browser. If this doesn't work, please paste this "
                    "address in a new browser window and follow the "
                    "instructions ..."
                )
        finally:
            if oauthlib_insecure_transport is None:
                del os.environ["OAUTHLIB_INSECURE_TRANSPORT"]
            else:
                os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = oauthlib_insecure_transport
