# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

# Python imports
import base64
import json
import os
from datetime import datetime
from urllib.parse import urlencode

import pytz
import requests
from django.conf import settings

# Module imports
from plane.authentication.adapter.oauth import OauthAdapter
from plane.license.utils.instance_value import get_configuration_value
from plane.authentication.adapter.error import (
    AuthenticationException,
    AUTHENTICATION_ERROR_CODES,
)


class OIDCOAuthProvider(OauthAdapter):
    provider = "oidc"
    scope = "openid profile email"

    def __init__(self, request, code=None, state=None, callback=None):
        (
            OIDC_CLIENT_ID,
            OIDC_CLIENT_SECRET,
            OIDC_TOKEN_URL,
            OIDC_USERINFO_URL,
            OIDC_AUTHORIZE_URL,
            OIDC_IDP_NAME,
        ) = get_configuration_value(
            [
                {
                    "key": "OIDC_CLIENT_ID",
                    "default": os.environ.get("OIDC_CLIENT_ID"),
                },
                {
                    "key": "OIDC_CLIENT_SECRET",
                    "default": os.environ.get("OIDC_CLIENT_SECRET"),
                },
                {
                    "key": "OIDC_TOKEN_URL",
                    "default": os.environ.get("OIDC_TOKEN_URL"),
                },
                {
                    "key": "OIDC_USERINFO_URL",
                    "default": os.environ.get("OIDC_USERINFO_URL"),
                },
                {
                    "key": "OIDC_AUTHORIZE_URL",
                    "default": os.environ.get("OIDC_AUTHORIZE_URL"),
                },
                {
                    "key": "OIDC_IDP_NAME",
                    "default": os.environ.get("OIDC_IDP_NAME", "OIDC"),
                },
            ]
        )

        if not (OIDC_CLIENT_ID and OIDC_CLIENT_SECRET and OIDC_TOKEN_URL and OIDC_USERINFO_URL and OIDC_AUTHORIZE_URL):
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["OIDC_NOT_CONFIGURED"],
                error_message="OIDC_NOT_CONFIGURED",
            )

        client_id = OIDC_CLIENT_ID
        client_secret = OIDC_CLIENT_SECRET
        self.idp_name = OIDC_IDP_NAME

        if settings.APP_BASE_URL:
            redirect_uri = f"{settings.APP_BASE_URL}/auth/oidc/callback/"
        else:
            redirect_uri = f"""{"https" if request.is_secure() else "http"}://{request.get_host()}/auth/oidc/callback/"""
        url_params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": self.scope,
            "state": state,
            "response_type": "code",
        }
        auth_url = f"{OIDC_AUTHORIZE_URL}?{urlencode(url_params)}"
        super().__init__(
            request,
            self.provider,
            client_id,
            self.scope,
            redirect_uri,
            auth_url,
            OIDC_TOKEN_URL,
            OIDC_USERINFO_URL,
            client_secret,
            code,
            callback=callback,
        )

    def set_token_data(self):
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": self.code,
            "redirect_uri": self.redirect_uri,
            "grant_type": "authorization_code",
        }
        token_response = self.get_user_token(
            data=data,
            headers={"Accept": "application/json"},
        )
        super().set_token_data(
            {
                "access_token": token_response.get("access_token"),
                "refresh_token": token_response.get("refresh_token", None),
                "access_token_expired_at": (
                    datetime.fromtimestamp(token_response.get("expires_in"), tz=pytz.utc)
                    if token_response.get("expires_in")
                    else None
                ),
                "refresh_token_expired_at": (
                    datetime.fromtimestamp(token_response.get("refresh_token_expired_at"), tz=pytz.utc)
                    if token_response.get("refresh_token_expired_at")
                    else None
                ),
                "id_token": token_response.get("id_token", ""),
            }
        )

    @staticmethod
    def _decode_jwt_payload(token):
        """Decode JWT payload without signature verification
        (token already trusted from direct Keycloak exchange)."""
        payload = token.split(".")[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += "=" * padding
        return json.loads(base64.urlsafe_b64decode(payload))

    def set_user_data(self):
        # Use id_token claims instead of userinfo endpoint to avoid
        # issuer mismatch when Keycloak is behind a reverse proxy
        id_token = self.token_data.get("id_token", "")
        if id_token:
            try:
                user_info_response = self._decode_jwt_payload(id_token)
            except Exception:
                user_info_response = self.get_user_response()
        else:
            user_info_response = self.get_user_response()

        email = user_info_response.get("email")
        if not email:
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["OIDC_OAUTH_PROVIDER_ERROR"],
                error_message="OIDC_OAUTH_PROVIDER_ERROR",
                payload={"error": "No email returned by the OIDC provider."},
            )

        super().set_user_data(
            {
                "email": email,
                "user": {
                    "provider_id": user_info_response.get("sub"),
                    "email": email,
                    "avatar": user_info_response.get("picture", ""),
                    "first_name": user_info_response.get("given_name", user_info_response.get("name", "")),
                    "last_name": user_info_response.get("family_name", ""),
                    "is_password_autoset": True,
                },
            }
        )
