# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import requests as http_requests
from django.http import HttpResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt

KEYCLOAK_INTERNAL_URL = "http://keycloak:8080"


@method_decorator(csrf_exempt, name="dispatch")
class KeycloakProxyView(View):
    """Reverse-proxy Keycloak requests so browsers never need direct
    access to the Keycloak port (useful in Codespaces where the tunnel
    for port 8080 is unreliable)."""

    def dispatch(self, request, path="", *args, **kwargs):
        target_url = f"{KEYCLOAK_INTERNAL_URL}{request.path}"
        if request.META.get("QUERY_STRING"):
            target_url += f"?{request.META['QUERY_STRING']}"

        # Forward relevant headers (keep X-Forwarded-* so Keycloak
        # generates correct browser-facing URLs)
        headers = {}
        for key, value in request.META.items():
            if key.startswith("HTTP_"):
                header = key[5:].replace("_", "-").title()
                if header.lower() not in ("host", "connection"):
                    headers[header] = value
        if request.content_type:
            headers["Content-Type"] = request.content_type
        headers["Host"] = "keycloak:8080"

        try:
            resp = http_requests.request(
                method=request.method,
                url=target_url,
                headers=headers,
                data=request.body if request.body else None,
                allow_redirects=False,
                stream=True,
                timeout=30,
            )
        except http_requests.ConnectionError:
            return HttpResponse("Keycloak unreachable", status=502)

        # Build Django response
        excluded = {"content-encoding", "transfer-encoding", "connection", "keep-alive"}
        response = HttpResponse(
            resp.content,
            status=resp.status_code,
            content_type=resp.headers.get("Content-Type", "text/html"),
        )
        for header, value in resp.headers.items():
            if header.lower() not in excluded:
                response[header] = value

        return response
