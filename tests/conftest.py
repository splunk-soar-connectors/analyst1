# Copyright (c) 2026 Splunk Inc.
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
"""Shared fixtures for the Analyst1 SDK app unit tests.

Actions run in-process through the real SDK plumbing (params validated by each
action's Params class, sensitive asset fields platform-encrypted, then
``App.handle()``), while every ``httpx.Client`` the app constructs is wired to
an ``httpx.MockTransport`` that serves sanitized fixture payloads and records
each request. No network access, no live credentials.
"""

import json
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from soar_sdk.asset_state import AssetState
from soar_sdk.input_spec import ActionParameter, AppConfig, InputSpecification
from soar_sdk.shims.phantom_common.encryption.encryption_manager_factory import platform_encryption_backend


TESTS_DIR = Path(__file__).resolve().parent
FIXTURES_DIR = TESTS_DIR / "fixtures"
REPO_ROOT = TESTS_DIR.parent

sys.path.insert(0, str(REPO_ROOT / "src"))

import app as analyst1_app  # the SDK app under test (src/app.py)


# ---------------------------------------------------------------------------
# Synthetic asset configuration (never real credentials or hostnames)
# ---------------------------------------------------------------------------

BASE_URL = "https://analyst1.unit.test"
BASIC_USERNAME = "unit-user"
BASIC_PASSWORD = "unit-pass"  # pragma: allowlist secret
OAUTH_CLIENT_ID = "unit-client-id"
OAUTH_CLIENT_SECRET = "unit-client-secret"  # pragma: allowlist secret

ASSET_ID = "1"
CONTAINER_ID = 1

# Same synthetic values the sanitized real-shaped (1_1) fixtures carry.
SYNTH_SHA256 = "AAAABBBBCCCCDDDDEEEEFFFF0000111122223333444455556666777788889999"  # pragma: allowlist secret
SYNTH_EMAIL = "attacker@example.com"

# Values /indicator/match answers with 404 (indicator not found).
NOTFOUND_VALUES = {
    "missing.com",
    "missing@example.com",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "198.51.100.99",
    "2001:db8::99",
    "http://missing.example.com/x",
    "Global\\missingmutex",
    "missing-string",
    "GET /missing.html",
}

NOTFOUND_BODY = {"message": "The requested resource was not found."}

# Value that /indicator/match answers with a 500 and a non-JSON (HTML) body.
HTML_ERROR_VALUE = "html-error.example.com"
HTML_ERROR_BODY = "<html><body><h1>Internal Server Error</h1></body></html>"

# Evidence uploadStatus uuid that answers 404 (upload key not found).
MISSING_STATUS_UUID = "missing-uuid"

# batchCheck: this value alone answers an empty {"results": []} envelope; the
# error value (anywhere in the csv) answers a 500.
BATCH_NOMATCH_VALUE = "nomatch.example.com"
BATCH_ERROR_VALUE = "batch-error.example.com"

# By-id resources: the known ids of the fixture payloads (indicator reuses
# match_xsoar.json); this id answers a 500 on any resource; other ids 404.
MATCH_INDICATOR_ID = 12345
ACTOR_ID = 7
MALWARE_ID = 55
BY_ID_ERROR_ID = 666


def basic_asset() -> dict[str, Any]:
    """Asset configuration for Basic auth (1_0 API)."""
    return {
        "base_url": BASE_URL,
        "verify_ssl": False,
        "username": BASIC_USERNAME,
        "password": BASIC_PASSWORD,
    }


def oauth_asset() -> dict[str, Any]:
    """Asset configuration for OAuth2 client-credentials auth (1_1 API)."""
    return {
        "base_url": BASE_URL,
        "verify_ssl": False,
        "client_id": OAUTH_CLIENT_ID,
        "client_secret": OAUTH_CLIENT_SECRET,
    }


def load_fixture(name: str) -> Any:
    """Load a sanitized JSON fixture from tests/fixtures/."""
    return json.loads((FIXTURES_DIR / name).read_text())


# ---------------------------------------------------------------------------
# Mock Analyst1 API (httpx.MockTransport handler + request recorder)
# ---------------------------------------------------------------------------


class MockAnalyst1API:
    """Fixture-driven Analyst1 API double, routing like the parity harness mock server.

    Records every request (method, url, path, params, headers, body) so tests
    can assert auth headers, the api-version path segment, and query params.
    Behavior knobs let individual tests inject token failures, 401s, and
    synthetic evidence paging.
    """

    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self.match_default = load_fixture("match_xsoar.json")
        self.match_map: dict[str, dict] = {}
        for name in ("match_real_file.json", "match_real_email.json"):
            payload = load_fixture(name)
            self.match_map[payload["value"]["name"]] = payload
        self.evidence_status = load_fixture("evidence_status.json")
        self.evidence_upload_response = load_fixture("evidence_upload_response.json")
        self.evidence_pages = load_fixture("evidence_pages.json")
        self.batch_check = load_fixture("batch_check.json")
        self.actor_resource = load_fixture("actor_resource.json")
        self.malware_resource = load_fixture("malware_resource.json")
        # Behavior knobs
        self.token_response_status = 200
        self.token_calls = 0
        self.api_401_remaining = 0  # the next N /api/ requests get a 401
        self.api_401_always = False  # every /api/ request gets a 401
        self.evidence_synthetic_total_pages: int | None = None  # advertise N pages of 2 synthetic rows each

    def api_requests(self, path_fragment: str) -> list[dict[str, Any]]:
        """Recorded requests whose path contains the given fragment."""
        return [r for r in self.requests if path_fragment in r["path"]]

    @property
    def token_requests(self) -> list[dict[str, Any]]:
        return self.api_requests("/oauth2/token")

    @property
    def evidence_list_requests(self) -> list[dict[str, Any]]:
        return [r for r in self.requests if r["method"] == "GET" and r["path"].endswith("/evidence")]

    def handler(self, request: httpx.Request) -> httpx.Response:
        content = request.read()
        record = {
            "method": request.method,
            "url": str(request.url),
            "path": request.url.path,
            "params": dict(request.url.params),
            "headers": dict(request.headers),
            "content": content,
        }
        self.requests.append(record)

        if request.url.path == "/oauth2/token":
            return self._handle_token()
        if self.api_401_always or self.api_401_remaining > 0:
            self.api_401_remaining = max(0, self.api_401_remaining - 1)
            return httpx.Response(401, json={"message": "Unauthorized"})
        if "/indicator/match" in request.url.path:
            return self._handle_match(record["params"])
        if "/batchCheck" in request.url.path:
            return self._handle_batch_check(record["params"])
        segments = [segment for segment in request.url.path.split("/") if segment]  # e.g. /api/1_0/actor/7
        if len(segments) == 4 and segments[2] in ("indicator", "actor", "malware"):
            return self._handle_by_id(segments[2], segments[3])
        if "/evidence/uploadStatus/" in request.url.path:
            if request.url.path.endswith(f"/{MISSING_STATUS_UUID}"):
                return httpx.Response(404, json=NOTFOUND_BODY)
            return httpx.Response(200, json=self.evidence_status)
        if request.url.path.endswith("/evidence"):
            if request.method == "POST":
                return httpx.Response(200, json=self.evidence_upload_response)
            return self._handle_evidence_list(record["params"])
        raise AssertionError(f"unmocked request: {request.method} {request.url.path}")

    def _handle_token(self) -> httpx.Response:
        if self.token_response_status != 200:
            return httpx.Response(
                self.token_response_status,
                json={"error": "invalid_client", "error_description": "Client authentication failed"},
            )
        self.token_calls += 1
        return httpx.Response(
            200,
            json={"access_token": f"unit-token-{self.token_calls}", "token_type": "Bearer", "expires_in": 3600},
        )

    def _handle_match(self, params: dict[str, Any]) -> httpx.Response:
        value = params.get("value", "")
        if value in NOTFOUND_VALUES:
            return httpx.Response(404, json=NOTFOUND_BODY)
        if value == HTML_ERROR_VALUE:
            return httpx.Response(500, text=HTML_ERROR_BODY, headers={"Content-Type": "text/html"})
        return httpx.Response(200, json=self.match_map.get(value, self.match_default))

    def _handle_by_id(self, resource: str, resource_id: str) -> httpx.Response:
        if resource_id == str(BY_ID_ERROR_ID):
            return httpx.Response(500, json={"message": "Internal server error"})
        known = {
            "indicator": (str(MATCH_INDICATOR_ID), self.match_default),
            "actor": (str(ACTOR_ID), self.actor_resource),
            "malware": (str(MALWARE_ID), self.malware_resource),
        }
        known_id, payload = known[resource]
        if resource_id == known_id:
            return httpx.Response(200, json=payload)
        return httpx.Response(404, json=NOTFOUND_BODY)

    def _handle_batch_check(self, params: dict[str, Any]) -> httpx.Response:
        values = [value for value in params.get("values", "").split(",") if value]
        if BATCH_ERROR_VALUE in values:
            return httpx.Response(500, json={"message": "Internal server error"})
        if set(values) == {BATCH_NOMATCH_VALUE}:
            return httpx.Response(200, json={"results": []})
        return httpx.Response(200, json=self.batch_check)

    def _handle_evidence_list(self, params: dict[str, Any]) -> httpx.Response:
        page = int(params.get("page", "1"))
        if self.evidence_synthetic_total_pages is not None:
            total_pages = self.evidence_synthetic_total_pages
            results = [{"id": page * 10 + 1}, {"id": page * 10 + 2}] if 1 <= page <= total_pages else []
            return httpx.Response(200, json={"results": results, "totalPages": total_pages, "totalResults": total_pages * 2})
        pages = self.evidence_pages["pages"]
        results = pages[page - 1] if 1 <= page <= len(pages) else []
        return httpx.Response(
            200,
            json={
                "results": results,
                "totalPages": self.evidence_pages["totalPages"],
                "totalResults": self.evidence_pages["totalResults"],
            },
        )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def api(monkeypatch: pytest.MonkeyPatch) -> MockAnalyst1API:
    """Route every httpx.Client the app builds through a MockTransport, and reset shared app state.

    ``Analyst1Client.__init__`` calls ``httpx.Client(verify=..., timeout=...)``;
    patching the ``httpx.Client`` name (as seen from src/app.py) makes that call
    return a client wired to the recording MockTransport.
    """
    mock = MockAnalyst1API()
    transport = httpx.MockTransport(mock.handler)
    real_client_cls = httpx.Client

    def client_factory(*args: Any, **kwargs: Any) -> httpx.Client:
        kwargs["transport"] = transport
        return real_client_cls(*args, **kwargs)

    monkeypatch.setattr(httpx, "Client", client_factory)

    # The in-process app is a module singleton shared across tests: drop any
    # persisted asset state (cached OAuth tokens) and the cached Asset object.
    sdk_app = analyst1_app.app
    sdk_app.actions_manager.save_state({})
    sdk_app.__dict__.pop("_asset", None)
    return mock


@pytest.fixture
def run_action(api: MockAnalyst1API):
    """Run an SDK action in-process and return its ActionResult as a plain dict.

    Mirrors the platform (and AppCliRunner) input plumbing: params validated by
    the action's Params class, sensitive asset fields encrypted with the
    platform encryption backend keyed by asset_id, then ``App.handle()``.
    """

    def _run(identifier: str, params: dict[str, Any] | None = None, asset: dict[str, Any] | None = None) -> dict[str, Any]:
        sdk_app = analyst1_app.app
        action = sdk_app.actions_manager.get_action(identifier)
        assert action is not None, f"unknown SDK action: {identifier}"

        parameter_list = []
        if getattr(action, "params_class", None) is not None:
            validated = action.params_class.model_validate(params or {})
            parameter_list.append(ActionParameter(**validated.model_dump()))

        input_data = InputSpecification(
            action=identifier,
            identifier=identifier,
            asset_id=ASSET_ID,
            config=AppConfig(app_version="1.0.0", directory=".", main_module="src.app"),
            parameters=parameter_list,
        )
        asset_json = dict(asset if asset is not None else basic_asset())
        for field in sdk_app.asset_cls.fields_requiring_decryption():
            if asset_json.get(field):
                asset_json[field] = platform_encryption_backend.encrypt(asset_json[field], ASSET_ID)
        input_data.config = AppConfig(**input_data.config.model_dump(), **asset_json)

        # Per-run resets: in production every action run is a fresh spawn; the
        # shared in-process SOARClient would otherwise leak the previous run's
        # results, summary/message, and cached Asset into this one.
        sdk_app.actions_manager.action_results.clear()
        sdk_app.soar_client.set_summary(None)
        sdk_app.soar_client.set_message("")
        sdk_app.__dict__.pop("_asset", None)

        sdk_app.handle(input_data.model_dump_json())

        results = sdk_app.actions_manager.get_action_results()
        if not results:
            return {"status": False, "message": "", "summary": {}, "data": []}
        action_result = results[0]
        return {
            "status": bool(action_result.get_status()),
            "message": action_result.get_message(),
            "summary": action_result.get_summary(),
            "data": action_result.get_data(),
        }

    return _run


@pytest.fixture
def vault_id():
    """Seed the SDK's local vault fallback with the sample evidence file, removing it on teardown.

    The fallback vault is process-global; delete_attachment only pops the
    in-memory record (unauthenticated mode never touches the file on disk).
    """
    attachment_id = analyst1_app.app.soar_client.vault.add_attachment(
        container_id=CONTAINER_ID,
        file_location=str(FIXTURES_DIR / "evidence_sample.txt"),
        file_name="unit_evidence.txt",
    )
    yield attachment_id
    analyst1_app.app.soar_client.vault.delete_attachment(vault_id=attachment_id)


def preload_oauth_token(access_token: str, expires_in_seconds: int = 3600) -> None:
    """Pre-populate the persisted auth state with an OAuth token, as a prior action run would."""
    state = AssetState(analyst1_app.app.actions_manager, "auth", ASSET_ID, encrypted=True)
    expires_at = datetime.now() + timedelta(seconds=expires_in_seconds)
    state["oauth_token"] = {
        "access_token": access_token,
        "expires_at": expires_at.isoformat(),
        "token_type": "Bearer",
    }
