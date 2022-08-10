"""Online CA service client - OAuth 2.0 client utilities for obtaining a 
delegated certificate

Contrail Project
"""
__author__ = "P J Kershaw"
__date__ = "10/08/22"
__copyright__ = "Copyright 2022 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
import os
import yaml
import json


class OAuth2Utils:
    """Utility methods and variables for manage OAuth 2.0 settings"""

    DEF_SETTINGS_FILENAME = ".onlinecaclient_idp.yaml"
    DEF_SETTINGS_FILEPATH = os.path.join(os.environ["HOME"], DEF_SETTINGS_FILENAME)
    SETTINGS_FILEPATH_ENVVARNAME = "ONLINECA_CLNT_SETTINGS_FILEPATH"

    # Optionally, OAuth Access Token can be stored and retrieved from this
    # default location
    DEF_OAUTH_TOK_FILENAME = ".onlinecaclient_token.json"
    DEF_OAUTH_TOK_FILEPATH = os.path.join(os.environ["HOME"], DEF_OAUTH_TOK_FILENAME)

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

    @classmethod
    def save_oauth_tok(cls, token, tok_filepath=None):
        """Convenience routine - serialise OAuth token for later re-use.

        Care should be taken to ensure that the content is held securely
        on the target file system
        """
        if tok_filepath is None:
            tok_filepath = cls.DEF_OAUTH_TOK_FILEPATH

        tok_file_content = json.dumps(token)

        # Write file with user-only rw permissions
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL  # Refer to "man 2 open".
        mode = stat.S_IRUSR | stat.S_IWUSR  # 0o600 mode
        umask = 0o777 ^ mode  # Prevents always downgrading umask to 0.

        # For security, remove file with potentially elevated mode
        try:
            os.remove(tok_filepath)
        except OSError:
            pass

        # Open file descriptor
        umask_original = os.umask(umask)

        try:
            tok_file_desc = os.open(tok_filepath, flags, mode)
        finally:
            os.umask(umask_original)

        with os.fdopen(tok_file_desc, "w") as tok_file:
            tok_file.write(tok_file_content)

    @classmethod
    def read_oauth_tok(cls, tok_filepath=None):
        """Convenience routine - read previously saved OAuth token for re-use.

        Care should be taken to ensure that the content is held securely
        on the target file system
        """
        if tok_filepath is None:
            tok_filepath = cls.DEF_OAUTH_TOK_FILEPATH

        with open(tok_filepath) as tok_file:
            tok_file_content = tok_file.read()

        return json.loads(tok_file_content)