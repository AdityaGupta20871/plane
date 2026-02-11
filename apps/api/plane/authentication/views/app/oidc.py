# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

# Python imports
import uuid

# Django import
from django.http import HttpResponseRedirect
from django.views import View

# Module imports
from plane.authentication.provider.oauth.oidc import OIDCOAuthProvider
from plane.authentication.utils.login import user_login
from plane.authentication.utils.redirection_path import get_redirection_path
from plane.authentication.utils.user_auth_workflow import post_user_auth_workflow
from plane.license.models import Instance
from plane.authentication.utils.host import base_host
from plane.authentication.adapter.error import (
    AuthenticationException,
    AUTHENTICATION_ERROR_CODES,
)
from plane.utils.path_validator import get_safe_redirect_url

OIDC_STATE_COOKIE = "oidc-state"
OIDC_NEXT_PATH_COOKIE = "oidc-next-path"


class OIDCOauthInitiateEndpoint(View):
    def get(self, request):
        request.session["host"] = base_host(request=request, is_app=True)
        next_path = request.GET.get("next_path")
        if next_path:
            request.session["next_path"] = str(next_path)

        instance = Instance.objects.first()
        if instance is None or not instance.is_setup_done:
            exc = AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["INSTANCE_NOT_CONFIGURED"],
                error_message="INSTANCE_NOT_CONFIGURED",
            )
            params = exc.get_error_dict()
            url = get_safe_redirect_url(
                base_url=base_host(request=request, is_app=True), next_path=next_path, params=params
            )
            return HttpResponseRedirect(url)
        try:
            state = uuid.uuid4().hex
            provider = OIDCOAuthProvider(request=request, state=state)
            request.session["state"] = state
            auth_url = provider.get_auth_url()
            response = HttpResponseRedirect(auth_url)
            response.set_cookie(
                OIDC_STATE_COOKIE, state,
                max_age=300, httponly=True, samesite="Lax",
            )
            if next_path:
                response.set_cookie(
                    OIDC_NEXT_PATH_COOKIE, str(next_path),
                    max_age=300, httponly=True, samesite="Lax",
                )
            return response
        except AuthenticationException as e:
            params = e.get_error_dict()
            url = get_safe_redirect_url(
                base_url=base_host(request=request, is_app=True), next_path=next_path, params=params
            )
            return HttpResponseRedirect(url)


class OIDCCallbackEndpoint(View):
    def get(self, request):
        code = request.GET.get("code")
        state = request.GET.get("state")
        next_path = request.session.get("next_path") or request.COOKIES.get(OIDC_NEXT_PATH_COOKIE)

        expected_state = request.session.get("state", "") or request.COOKIES.get(OIDC_STATE_COOKIE, "")

        if state != expected_state:
            exc = AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["OIDC_OAUTH_PROVIDER_ERROR"],
                error_message="OIDC_OAUTH_PROVIDER_ERROR",
            )
            params = exc.get_error_dict()
            url = get_safe_redirect_url(
                base_url=base_host(request=request, is_app=True), next_path=next_path, params=params
            )
            response = HttpResponseRedirect(url)
            response.delete_cookie(OIDC_STATE_COOKIE)
            response.delete_cookie(OIDC_NEXT_PATH_COOKIE)
            return response

        if not code:
            exc = AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES["OIDC_OAUTH_PROVIDER_ERROR"],
                error_message="OIDC_OAUTH_PROVIDER_ERROR",
            )
            params = exc.get_error_dict()
            url = get_safe_redirect_url(
                base_url=base_host(request=request, is_app=True), next_path=next_path, params=params
            )
            response = HttpResponseRedirect(url)
            response.delete_cookie(OIDC_STATE_COOKIE)
            response.delete_cookie(OIDC_NEXT_PATH_COOKIE)
            return response

        try:
            provider = OIDCOAuthProvider(request=request, code=code, callback=post_user_auth_workflow)
            user = provider.authenticate()
            user_login(request=request, user=user, is_app=True)
            if next_path:
                path = next_path
            else:
                path = get_redirection_path(user=user)

            url = get_safe_redirect_url(base_url=base_host(request=request, is_app=True), next_path=path, params={})
            response = HttpResponseRedirect(url)
            response.delete_cookie(OIDC_STATE_COOKIE)
            response.delete_cookie(OIDC_NEXT_PATH_COOKIE)
            return response
        except AuthenticationException as e:
            params = e.get_error_dict()
            url = get_safe_redirect_url(
                base_url=base_host(request=request, is_app=True), next_path=next_path, params=params
            )
            response = HttpResponseRedirect(url)
            response.delete_cookie(OIDC_STATE_COOKIE)
            response.delete_cookie(OIDC_NEXT_PATH_COOKIE)
            return response
