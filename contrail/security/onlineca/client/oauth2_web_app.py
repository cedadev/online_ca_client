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

from quart import Quart, request, redirect, session
from requests_oauthlib import OAuth2Session

from contrail.security.onlineca.client import OnlineCaClient


class OAuth2WebApp(Quart):
    """Quart-based Web application for performing the basic function of a client
    in the Auth 2.0 Authorisation Code flow (3-legged OAuth)
    """

    # Quart application to manage OAuth flow
    QUART_SECRET_KEY_LEN = 24

    OAUTH_WEB_APP_CALLBACK_COMPL_MSG = (
        "Successfully obtained access token for Online CA Client. You can close "
        "this browser tab now"
    )
    REDIRECT_URL = "/callback"
    START_URL = "/"

    def __init__(self, settings, *arg, **kwarg) -> None:
        tok_filepath = kwarg.pop("tok_filepath", None)
        super().__init__(*arg, **kwarg)

        self.secret_key = os.urandom(self.QUART_SECRET_KEY_LEN)

        # Define event handler functions here
        async def get_user_authorisation():
            """User Authorization. Redirect the user/resource owner to the OAuth
            provider using an URL with a few key OAuth parameters.
            """
            oauth_session = OAuth2Session(
                settings["client_id"], scope=settings["scope"]
            )
            authorization_url, state = oauth_session.authorization_url(
                settings["authorization_base_url"]
            )

            # State is used to prevent CSRF, keep this for later.
            session["oauth_state"] = state
            return redirect(authorization_url)

        # Configure path based on expected redirect url for OAuth Authorisation
        # Server
        async def get_access_token():
            """Retrieve an access token"""
            oauth2_session = OAuth2Session(
                settings["client_id"], state=session["oauth_state"]
            )
            token = oauth2_session.fetch_token(
                settings["token_url"],
                client_secret=settings["client_secret"],
                authorization_response=request.url,
            )

            # Save token in a file
            OnlineCaClient.save_oauth_tok(token, tok_filepath=tok_filepath)

            return self.OAUTH_WEB_APP_CALLBACK_COMPL_MSG

        redirect_url = urlparse(settings.get("redirect_url", self.REDIRECT_URL))
        start_url = urlparse(settings.get("start_url", self.START_URL))

        # Configure the event handler functions into the URL map for the app
        self.add_url_rule(start_url.path, view_func=get_user_authorisation)
        self.add_url_rule(redirect_url.path, view_func=get_access_token)
