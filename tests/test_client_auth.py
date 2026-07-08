# Copyright (c) 2026 Analyst1
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Analyst1Client auth behavior: basic vs OAuth, token cache/refresh, error surfacing."""

import base64

import pytest
from soar_sdk.asset_state import AssetState

import app as analyst1_app
from tests.conftest import (
    ASSET_ID,
    BASE_URL,
    BASIC_PASSWORD,
    BASIC_USERNAME,
    BY_ID_ERROR_ID,
    HTML_ERROR_READABLE_TEXT,
    HTML_ERROR_VALUE,
    OAUTH_CLIENT_ID,
    basic_asset,
    oauth_asset,
    preload_oauth_token,
)


def _basic_auth_header() -> str:
    credentials = f"{BASIC_USERNAME}:{BASIC_PASSWORD}".encode()
    return f"Basic {base64.b64encode(credentials).decode()}"


def _make_basic_client() -> analyst1_app.Analyst1Client:
    """Build an Analyst1Client directly (basic auth) for client-level tests."""
    asset = analyst1_app.Asset(
        base_url=BASE_URL,
        verify_ssl=False,
        client_id="",
        client_secret="",
        username=BASIC_USERNAME,
        password=BASIC_PASSWORD,
    )
    auth_state = AssetState(analyst1_app.app.actions_manager, "auth", ASSET_ID, encrypted=True)
    return analyst1_app.Analyst1Client(asset, auth_state)


class TestConnectivity:
    def test_basic_auth_success(self, api, run_action):
        result = run_action("test_connectivity", {}, asset=basic_asset())

        assert result["status"] is True
        assert api.token_requests == []
        (match_request,) = api.api_requests("/indicator/match")
        assert "/api/1_0/indicator/match/" in match_request["path"]
        assert match_request["headers"]["authorization"] == _basic_auth_header()

    def test_oauth_success(self, api, run_action):
        result = run_action("test_connectivity", {}, asset=oauth_asset())

        assert result["status"] is True
        (token_request,) = api.token_requests
        assert token_request["method"] == "POST"
        token_body = token_request["content"].decode()
        assert "grant_type=client_credentials" in token_body
        assert f"client_id={OAUTH_CLIENT_ID}" in token_body
        (match_request,) = api.api_requests("/indicator/match")
        assert "/api/1_1/indicator/match/" in match_request["path"]
        assert match_request["headers"]["authorization"] == "Bearer unit-token-1"

    def test_oauth_token_endpoint_failure(self, api, run_action):
        api.token_response_status = 401

        result = run_action("test_connectivity", {}, asset=oauth_asset())

        assert result["status"] is False
        assert "Failed to get OAuth token" in result["message"]
        assert "Status: 401" in result["message"]
        assert "invalid_client" in result["message"]
        assert api.api_requests("/indicator/match") == []


class TestOAuthTokenLifecycle:
    def test_oauth_token_cache_reuse(self, api, run_action):
        preload_oauth_token("cached-unit-token")

        result = run_action("lookup_domain", {"domain": "test.com"}, asset=oauth_asset())

        assert result["status"] is True
        assert api.token_requests == []  # no token request issued: the cached token is reused
        (match_request,) = api.api_requests("/indicator/match")
        assert match_request["headers"]["authorization"] == "Bearer cached-unit-token"

    def test_oauth_token_refresh_on_401(self, api, run_action):
        api.api_401_remaining = 1  # first API call is rejected; refresh must recover

        result = run_action("lookup_domain", {"domain": "test.com"}, asset=oauth_asset())

        assert result["status"] is True
        assert result["data"][0]["id"] == 12345
        assert len(api.token_requests) == 2  # initial token + forced refresh
        match_requests = api.api_requests("/indicator/match")
        assert len(match_requests) == 2  # original call + exactly one retry
        assert match_requests[0]["headers"]["authorization"] == "Bearer unit-token-1"
        assert match_requests[1]["headers"]["authorization"] == "Bearer unit-token-2"

    def test_oauth_persistent_401_fails_after_single_retry(self, api, run_action):
        api.api_401_always = True

        result = run_action("lookup_domain", {"domain": "test.com"}, asset=oauth_asset())

        assert result["status"] is False
        assert "API error. Status: 401" in result["message"]
        # Exactly one retry after the forced refresh -- no infinite loop.
        assert len(api.api_requests("/indicator/match")) == 2
        assert len(api.token_requests) == 2


class TestErrorHandling:
    # HTML error bodies are reduced to their readable text (classic 1.2.1's
    # _process_html_response parity, restored per a1soar-tri) before landing
    # in the Analyst1APIError message; non-HTML bodies pass through verbatim.
    def test_html_error_body_raises_api_error_with_readable_text(self, api):
        client = _make_basic_client()
        try:
            with pytest.raises(analyst1_app.Analyst1APIError) as exc_info:
                client.indicator_match(HTML_ERROR_VALUE, "domain")
        finally:
            client.close()

        message = str(exc_info.value)
        assert "API error. Status: 500" in message
        assert HTML_ERROR_READABLE_TEXT in message  # readable text extracted from the HTML body
        assert "<html" not in message  # no raw markup in the message
        assert "<style" not in message
        assert "font-family" not in message

    def test_html_error_body_fails_action_cleanly(self, api, run_action):
        result = run_action("lookup_domain", {"domain": HTML_ERROR_VALUE}, asset=basic_asset())

        assert result["status"] is False
        assert "API error. Status: 500" in result["message"]
        assert HTML_ERROR_READABLE_TEXT in result["message"]
        assert "<html" not in result["message"]
        assert result["data"] == []

    def test_non_html_error_body_passes_through_verbatim(self, api):
        client = _make_basic_client()
        try:
            with pytest.raises(analyst1_app.Analyst1APIError) as exc_info:
                client.get(f"/actor/{BY_ID_ERROR_ID}")  # mock answers 500 with a JSON body
        finally:
            client.close()

        message = str(exc_info.value)
        assert "API error. Status: 500" in message
        # The raw JSON body is embedded verbatim (markup intact, no extraction).
        assert '"message"' in message
        assert "Internal server error" in message

    def test_html_error_body_parse_failure_falls_back(self, api, monkeypatch):
        def _boom(*args, **kwargs):
            raise ValueError("parse failure")

        monkeypatch.setattr(analyst1_app, "BeautifulSoup", _boom)
        client = _make_basic_client()
        try:
            with pytest.raises(analyst1_app.Analyst1APIError) as exc_info:
                client.indicator_match(HTML_ERROR_VALUE, "domain")
        finally:
            client.close()

        message = str(exc_info.value)
        assert "API error. Status: 500" in message
        assert "Cannot parse error details" in message

    def test_match_404_returns_none_from_client(self, api):
        client = _make_basic_client()
        try:
            assert client.indicator_match("missing.com", "domain") is None
        finally:
            client.close()
