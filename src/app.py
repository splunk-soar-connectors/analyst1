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
"""Analyst1 SOAR App - SDK Version

This app implements investigative actions on the Analyst1 platform.
"""

import ipaddress
import json
from datetime import datetime, timedelta
from typing import Any

import httpx
from bs4 import BeautifulSoup
from pydantic import field_validator
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput
from soar_sdk.app import App
from soar_sdk.asset import AssetField, BaseAsset
from soar_sdk.asset_state import AssetState
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.meta.app import AppContributor
from soar_sdk.params import Param, Params


logger = getLogger()

# =============================================================================
# Constants
# =============================================================================

# Friendly display names for enrichmentResults.*.type. Keys are the
# EnrichmentResultResource type enum from the Analyst1 OpenAPI 2.15.0 spec
# (SCREAMING_SNAKE; confirmed live, e.g. indicator 2144 sends
# "WHOIS_IP_REGISTRATION"). The classic app keyed this map on camelCase, so
# it never matched an API value and the friendly name was dead code -- fixed
# here rather than preserved. Unknown types fall back to the raw enum.
ENRICHMENT_RESULTS_NAME_MAP = {
    "WHOIS_DOMAIN_REGISTRATION": "WHOIS Domain Registration",
    "WHOIS_IP_REGISTRATION": "WHOIS IP Registration",
    "DOMAIN_TOOLS": "Domain Tools",
    "VIRUS_TOTAL": "VirusTotal",
    "DEEP_SIGHT": "DeepSight",
    "RECORDED_FUTURE_V1": "Recorded Future",
    "RECORDED_FUTURE_V2": "Recorded Future",
    "SANS_DSHIELD": "SANS DShield",
    "SHADOWSERVER": "Shadowserver",
    "SIPC": "Symantec SIPC",
    "INTEL_471_V1": "Intel 471",
    "GREY_NOISE_V3_COMMUNITY": "GreyNoise Community",
    "GREY_NOISE_V2_ENTERPRISE": "GreyNoise Enterprise",
    "FLASHPOINT_V1": "Flashpoint",
    "MANDIANT_V4": "Mandiant",
    "DOMAINTOOLS_IRIS_ENRICH_V1": "DomainTools Iris",
    "DRAGOS_WORLDVIEW": "Dragos WorldView",
}

EVIDENCE_POST_FIELD_MAP = {
    "evidence_file_classification": "evidenceFileClassification",
    "tlp": "tlp",
    "source_id": "sourceId",
    "source_title": "sourceTitle",
    "source_url": "sourceUrl",
    "iso_contributor_country_code": "isoContributorCountryCode",
    "iso_contributor_region_code": "isoContributorRegionCode",
    "contributor_org": "contributorOrg",
    "contributor_consent": "contibutorConsent",
    "disable_indicator_auto_enrichment": "disableIndicatorAutoEnrichment",
}


# =============================================================================
# Exceptions
# =============================================================================


class Analyst1Error(Exception):
    """Base exception for Analyst1 errors."""


class Analyst1AuthError(Analyst1Error):
    """Authentication error with Analyst1."""


class Analyst1APIError(Analyst1Error):
    """API error from Analyst1; `status` carries the HTTP status when one was received."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


# =============================================================================
# Asset Configuration
# =============================================================================


class Asset(BaseAsset):
    """Analyst1 asset configuration."""

    base_url: str = AssetField(
        required=True,
        description="Base URL with no trailing slash (e.g. https://analyst1.customer.com)",
        default="",
    )
    verify_ssl: bool = AssetField(
        required=False,
        description="Require SSL verification",
        default=False,
    )
    client_id: str = AssetField(
        required=False,
        description="Analyst1 Client ID (Oauth2 authentication)",
        default="",
    )
    client_secret: str = AssetField(
        required=False,
        sensitive=True,
        description="Analyst1 Client Secret (Oauth2 authentication)",
    )
    username: str = AssetField(
        required=False,
        description="Analyst1 Username (Basic authentication for REST-enabled account)",
        default="",
    )
    password: str = AssetField(
        required=False,
        sensitive=True,
        description="Analyst1 Password (Basic authentication for REST-enabled account)",
    )


def _readable_error_body(response: httpx.Response) -> str:
    """Return an error-response body suitable for embedding in an error message.

    HTML bodies (e.g. the Tomcat error page the API's auth tier answers a 401
    with, or a proxy error page) are reduced to their readable text via
    BeautifulSoup, replicating classic 1.2.1's _process_html_response. Classic
    also brace-escaped the text ({ -> {{) to guard classic Phantom's format
    pipeline; that is intentionally dropped -- SDK/SOAR 8.5 renders
    brace-laden messages fine (verified live). Non-HTML bodies (including the
    API's RFC-7807 XML 400s, same as classic) pass through verbatim.
    """
    if "html" not in response.headers.get("Content-Type", "").lower():
        return response.text
    try:
        soup = BeautifulSoup(response.text, "html.parser")
        lines = [line.strip() for line in soup.text.split("\n") if line.strip()]
        return "\n".join(lines)
    except Exception:
        return "Cannot parse error details"


# =============================================================================
# API Client
# =============================================================================


class Analyst1Client:
    """Client for interacting with the Analyst1 API."""

    def __init__(self, asset: Asset, auth_state: AssetState):
        self.asset = asset
        self.base_url = asset.base_url.rstrip("/")
        self._auth_state = auth_state  # Persistent state from SDK
        self._access_token: str | None = None
        self._token_expires_at: datetime | None = None

        # Determine auth method and API version
        if asset.client_id and asset.client_secret:
            self._use_oauth = True
            self._api_version = "1_1"
        else:
            self._use_oauth = False
            self._api_version = "1_0"

        # Create HTTP client
        self._client = httpx.Client(
            verify=asset.verify_ssl,
            timeout=30.0,
        )

        # Load token from persistent state if using OAuth
        if self._use_oauth:
            self._load_token_from_state()

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()

    def _load_token_from_state(self) -> None:
        """Load OAuth token from persistent auth_state."""
        token_data = self._auth_state.get("oauth_token", {})
        self._access_token = token_data.get("access_token")

        expires_at_str = token_data.get("expires_at")
        if expires_at_str:
            try:
                self._token_expires_at = datetime.fromisoformat(expires_at_str)
            except (ValueError, TypeError):
                self._token_expires_at = None
                self._access_token = None

    def _save_token_to_state(self, token: str, expires_in: int) -> None:
        """Save OAuth token to persistent auth_state."""
        expires_at = datetime.now() + timedelta(seconds=expires_in)
        self._auth_state["oauth_token"] = {
            "access_token": token,
            "expires_at": expires_at.isoformat(),
            "token_type": "Bearer",
        }

    def _clear_token_from_state(self) -> None:
        """Remove OAuth token from persistent auth_state."""
        self._auth_state.pop("oauth_token", None)
        self._access_token = None
        self._token_expires_at = None

    def _get_oauth_token(self, force_new: bool = False) -> str:
        """Get OAuth access token, using persistent state across action calls."""
        # Check if we have a valid token (either from state or memory)
        if not force_new and self._access_token and self._token_expires_at:
            if datetime.now() < self._token_expires_at:
                logger.info("Using cached OAuth token from persistent state")
                return self._access_token

        # Request new token
        logger.info("Requesting new OAuth token from Analyst1")
        token_url = f"{self.base_url}/oauth2/token"

        data = {
            "grant_type": "client_credentials",
            "client_id": self.asset.client_id,
            "client_secret": self.asset.client_secret,
        }

        response = self._client.post(token_url, data=data)

        if response.status_code != 200:
            error_msg = f"Failed to get OAuth token. Status: {response.status_code}"
            try:
                error_data = response.json()
                error_msg += f", Error: {error_data.get('error', 'Unknown')}"
                error_msg += f", Description: {error_data.get('error_description', 'Not provided')}"
            except Exception:
                error_msg += f", Response: {response.text}"
            raise Analyst1AuthError(error_msg)

        token_data = response.json()
        self._access_token = token_data.get("access_token")

        if not self._access_token:
            raise Analyst1AuthError("No access token in response")

        # Calculate expiration time and save to persistent state
        expires_in = token_data.get("expires_in", 3600)
        self._token_expires_at = datetime.now() + timedelta(seconds=expires_in)
        self._save_token_to_state(self._access_token, expires_in)

        logger.info("Successfully obtained and saved new OAuth token to persistent state")
        return self._access_token

    def _get_auth(self) -> dict[str, Any]:
        """Get authentication for requests."""
        if self._use_oauth:
            token = self._get_oauth_token()
            return {"headers": {"Authorization": f"Bearer {token}"}}
        else:
            if not self.asset.username or not self.asset.password:
                raise Analyst1AuthError("Username and password required for basic auth")
            return {"auth": (self.asset.username, self.asset.password)}

    def _make_request(
        self,
        method: str,
        endpoint: str,
        retry_on_auth_error: bool = True,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Make an API request with automatic token refresh."""
        url = f"{self.base_url}/api/{self._api_version}{endpoint}"

        # Add auth
        auth_kwargs = self._get_auth()
        if "headers" in auth_kwargs:
            headers = kwargs.get("headers", {})
            headers.update(auth_kwargs["headers"])
            kwargs["headers"] = headers
        if "auth" in auth_kwargs:
            kwargs["auth"] = auth_kwargs["auth"]

        try:
            response = self._client.request(method, url, **kwargs)
        except Exception as e:
            raise Analyst1APIError(f"Error connecting to server: {e!s}") from e

        # Handle 401 with token refresh
        if response.status_code == 401 and self._use_oauth and retry_on_auth_error:
            logger.info("OAuth token invalid, clearing from state and refreshing...")
            self._clear_token_from_state()
            self._get_oauth_token(force_new=True)
            return self._make_request(method, endpoint, retry_on_auth_error=False, **kwargs)

        # Process response
        if response.status_code == 404:
            # 404 is valid for indicator not found
            try:
                return response.json()
            except Exception:
                return {}

        if response.status_code >= 400:
            error_msg = f"API error. Status: {response.status_code}"
            try:
                error_msg += f", Response: {_readable_error_body(response)}"
            except Exception:
                pass
            raise Analyst1APIError(error_msg, status=response.status_code)

        if not response.text:
            return {}

        try:
            return response.json()
        except Exception as e:
            raise Analyst1APIError(f"Unable to parse JSON response: {e!s}") from e

    def get(self, endpoint: str, **kwargs: Any) -> dict[str, Any]:
        """Make a GET request."""
        return self._make_request("GET", endpoint, **kwargs)

    def post(self, endpoint: str, **kwargs: Any) -> dict[str, Any]:
        """Make a POST request."""
        return self._make_request("POST", endpoint, **kwargs)

    def _decorate_indicator(self, response: dict[str, Any]) -> None:
        """Apply classic-app runtime decorations to an indicator payload.

        Classic-app runtime decorations (analyst1_connector.py, release/1.2.1):
        base_url for view rendering, actor links, and human-friendly
        enrichment result names. Unlike classic, enrichmentResults[].result
        is intentionally NOT json.loads()-ed into an object: the SDK output
        contract types it as a string, so the raw JSON string is preserved
        (documented delta, see release notes).
        """
        response["base_url"] = self.base_url

        for actor in response.get("actors") or []:
            if (actor.get("id") or 0) > 1:
                actor["link"] = f"{self.base_url}/actors/{actor['id']}"

        for enrichment_result in response.get("enrichmentResults") or []:
            enrichment_type = enrichment_result.get("type", "")
            enrichment_result["name"] = ENRICHMENT_RESULTS_NAME_MAP.get(enrichment_type, enrichment_type)

    def indicator_match(self, value: str, indicator_type: str) -> dict[str, Any] | None:
        """Look up an indicator in Analyst1."""
        response = self.get("/indicator/match/", params={"value": value, "type": indicator_type})

        if not response or not response.get("id"):
            return None

        self._decorate_indicator(response)
        return response

    def get_indicator_by_id(self, indicator_id: str) -> dict[str, Any] | None:
        """Fetch an indicator by its Analyst1 numeric id; None when not found (404).

        Hash indicator ids may arrive suffixed (e.g. "14131-md5"); strip the
        suffix like XSOAR's Client.get_indicator does.
        """
        clean_id = str(indicator_id).split("-")[0].split("_")[0]
        resp = self.get(f"/indicator/{clean_id}")
        if not resp or not resp.get("id"):
            return None
        self._decorate_indicator(resp)
        return resp

    def get_actor_by_id(self, actor_id: int) -> dict[str, Any] | None:
        """Fetch an actor by its Analyst1 id; None when not found (404)."""
        resp = self.get(f"/actor/{actor_id}")
        return resp if resp and resp.get("id") else None

    def get_malware_by_id(self, malware_id: int) -> dict[str, Any] | None:
        """Fetch a malware family by its Analyst1 id; None when not found (404)."""
        resp = self.get(f"/malware/{malware_id}")
        return resp if resp and resp.get("id") else None

    def get_sensors(self, params: dict[str, Any]) -> dict[str, Any]:
        """Fetch one page of sensors (paged SensorListResultsPage envelope)."""
        resp = self.get("/sensors", params=params)
        if not isinstance(resp, dict):
            return {}
        # Live /sensors rows carry `_links` (underscore, rel-keyed object),
        # which Pydantic cannot declare as a field name. Rename `_links` ->
        # `links` on each row before validation so _links_to_list can
        # normalize it.
        for row in resp.get("results") or []:
            if isinstance(row, dict) and "_links" in row and "links" not in row:
                row["links"] = row.pop("_links")
        return resp

    def get_sensor_taskings(self, sensor_id: int) -> dict[str, Any]:
        """Fetch a sensor's current taskings; {} when not found (404).

        Extended per-request timeout for XSOAR parity: tasking fetches can be
        slow.
        """
        resp = self.get(f"/sensors/{sensor_id}/taskings", timeout=200.0)
        return resp if isinstance(resp, dict) else {}

    def get_sensor_config_text(self, sensor_id: int) -> str:
        """Fetch a sensor's config file as raw text; "" when not found (404).

        The endpoint returns a text config file, not JSON, so this bypasses
        _make_request's JSON parsing (one-shot; no 401-retry: config is a
        rare manual action and the OAuth token is normally warm).
        """
        url = f"{self.base_url}/api/{self._api_version}/sensors/{sensor_id}/taskings/config"
        auth_kwargs = self._get_auth()
        kwargs: dict[str, Any] = {}
        if "headers" in auth_kwargs:
            kwargs["headers"] = auth_kwargs["headers"]
        if "auth" in auth_kwargs:
            kwargs["auth"] = auth_kwargs["auth"]

        try:
            response = self._client.request("GET", url, **kwargs)
        except Exception as e:
            raise Analyst1APIError(f"Error connecting to server: {e!s}") from e

        if response.status_code == 404:
            return ""
        if response.status_code >= 400:
            raise Analyst1APIError(
                f"API error. Status: {response.status_code}, Response: {_readable_error_body(response)}", status=response.status_code
            )
        return response.text

    def get_sensor_diff(self, sensor_id: int, version: int) -> dict[str, Any]:
        """Fetch the tasking diff between a sensor config version and the latest; {} when not found.

        A sensor with no finalized config version answers HTTP 500 with "No
        finalized versions found..." (verified live), NOT a 404 -- treated as
        empty, not an error. Extended per-request timeout for XSOAR parity.
        """
        try:
            resp = self.get(f"/sensors/{sensor_id}/taskings/diff/{version}", timeout=200.0)
        except Analyst1APIError as exc:
            if exc.status == 500 and "no finalized versions" in str(exc).lower():
                return {}
            raise
        return resp if isinstance(resp, dict) else {}

    def batch_check(self, values_csv: str) -> list[dict[str, Any]]:
        """Batch check indicator values. Returns [] when nothing matches (or 404).

        The live API returns a {"results": [...]} envelope. Parse it, but
        tolerate a bare array defensively in case a future/older deployment
        differs.
        """
        resp = self.get("/batchCheck", params={"values": values_csv})
        if isinstance(resp, dict):
            results = resp.get("results")
            return results if isinstance(results, list) else []
        return resp if isinstance(resp, list) else []


# =============================================================================
# App Definition
# =============================================================================

app = App(
    name="Analyst1",
    app_type="information",
    logo="analyst1.png",
    logo_dark="analyst1_dark.png",
    product_vendor="Analyst1",
    product_name="Analyst1",
    publisher="Analyst1",
    appid="8ee822f1-a285-44f4-b8e7-303245811a32",
    min_phantom_version="7.0.0",
    fips_compliant=False,
    asset_cls=Asset,
)

# Splunk's connector contribution rules require a contributors entry in the app
# manifest. SDK 3.25.3 offers no first-class way to declare contributors (App()
# does not accept them and the pyproject adapter does not map project authors),
# but the SDK's ManifestProcessor copies every app_meta_info entry onto the
# generated manifest, so inject the SDK's canonical contributor model here.
app.app_meta_info["contributors"] = [AppContributor(name="Mike Forgione (Analyst1)")]


# =============================================================================
# Shared Output Models
#
# The nested sub-models below reproduce the classic app's (v1.2.1)
# action_result.data.* datapath contract for the nine lookup actions. The
# authoritative source is the classic analyst1.json lookup_domain output list
# (all nine lookups declare the identical data datapaths).
# =============================================================================


def _lenient_str(value: Any) -> str | None:
    """Coerce a value of uncertain runtime shape to the classic string datapath type.

    The classic manifest declares some datapaths as strings that the API may
    return as numbers or structured objects. Classic passed them through
    untyped; the SDK's typed outputs would fail validation instead, so coerce
    scalars via str() and structures via JSON to keep the declared string type
    without crashing the action.
    """
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, int | float | bool):
        return str(value)
    return json.dumps(value)


def _links_to_list(value: Any) -> Any:
    """Coerce the API's object-form `links` serialization to the classic list form.

    The live API serializes links as a rel-keyed object
    ({"self": {"href": ...}, "evidence": {...}, ...}) under BOTH auth modes —
    verified 2026-07-07 against 1_1 (OAuth) and 1_0 (basic) on
    /indicator/match, /indicator/{id}, and /actor/{id}; the OpenAPI spec's
    Links definition is likewise an object. The list of {rel, href} exists
    only in the classic manifest contract (and XSOAR's code/test fixtures),
    so coerce the object form to the list form, preserving insertion order,
    to make the declared links.* datapaths actually resolve. hrefs are
    emitted verbatim (no XSOAR-style URL rewriting). Anything else passes
    through to normal validation (lenient posture; never raise here).
    """
    if isinstance(value, dict):
        return [{"rel": rel, "href": item.get("href") if isinstance(item, dict) else None} for rel, item in value.items()]
    return value


class ClassifiedDate(ActionOutput):
    """A date with a classification (activityDates, reportedDates)."""

    classification: str | None = None
    date: str | None = None


class ClassifiedName(ActionOutput):
    """A name with a classification (description, fileNames, ipRegistration, ...)."""

    classification: str | None = None
    name: str | None = None


class ClassifiedIdName(ActionOutput):
    """An id/name pair with a classification (attackPatterns, targets, malwares, exploitStage)."""

    classification: str | None = None
    id: int | None = None
    name: str | None = None


class ActorOutput(ClassifiedIdName):
    """A threat actor; `link` is a classic runtime decoration built from base_url."""

    link: str | None = None


class BenignOutput(ActionOutput):
    classification: str | None = None
    value: bool | None = None


class ConfidenceLevelOutput(ActionOutput):
    classification: str | None = None
    value: str | None = None


class EnrichmentFieldOutput(ActionOutput):
    """Enrichment field (OpenAPI 2.15.0 EnrichmentFieldResource).

    The classic manifest declared this field as `nunmeric` -- a typo the API
    never sends (spec key: `numeric`), so classic's datapath could never be
    populated; the spec-correct name is used here.
    """

    type: str | None = None
    value: str | None = None
    name: str | None = None
    numeric: str | None = None
    classification: str | None = None

    @field_validator("value", "numeric", mode="before")
    @classmethod
    def _coerce_str(cls, value: Any) -> str | None:
        return _lenient_str(value)


class EnrichmentResultOutput(ActionOutput):
    """Enrichment result; `name` is a classic runtime decoration (friendly type name).

    `result` stays a JSON string (classic parsed json-format results into an
    object at runtime; the SDK output contract cannot type an arbitrary object).
    """

    date: str | None = None
    format: str | None = None
    type: str | None = None
    result: str | None = None
    name: str | None = None


class FileSizeOutput(ActionOutput):
    """The file size object ({value, classification}; live 1_1 evidence, indicator 2690).

    The classic manifest declared fileSize as a list (fileSize.*.value), but the
    API returns a single object and classic's own template dereferences
    record.fileSize.value -- a ratified shape correction.
    """

    value: int | None = None
    classification: str | None = None


class HashOutput(ActionOutput):
    type: str | None = None
    value: str | None = None
    classification: str | None = None


class LinkOutput(ActionOutput):
    href: str | None = OutputField(cef_types=["url"])
    rel: str | None = None


class PortOutput(ActionOutput):
    value: int | None = None
    classification: str | None = None


class DateRangeOutput(ActionOutput):
    """A classified date range (activityRange, reportedRange, verifiedDateRange; 1_1 API)."""

    classification: str | None = None
    startDate: str | None = None
    endDate: str | None = None


class SourceOutput(ActionOutput):
    """An intelligence source reference (sources.*; 1_1 API).

    `url` is feed metadata (frequently empty), intentionally NOT a cef url.
    """

    id: int | None = None
    type: str | None = None
    title: str | None = None
    url: str | None = None
    category: str | None = None
    enabled: bool | None = None


class TagOutput(ActionOutput):
    """A tag reference (tags.*; 1_1 API payloads carry no classification here)."""

    id: int | None = None
    name: str | None = None


class StixObjectOutput(ActionOutput):
    """A STIX object association (stixObjects.*; OpenAPI 2.15.0 StixObjectAssociation)."""

    id: str | None = None  # STIX identifier (string, not int)
    reportingSourceId: int | None = None
    type: str | None = None  # STIX object type enum (kept as free str)


class VerificationOutput(ActionOutput):
    """A verification record (verifications.*; OpenAPI 2.15.0 VerificationRecord)."""

    verifier: str | None = None
    verifierOrg: str | None = None
    verificationDate: str | None = None
    evidenceId: int | None = None
    evidenceTitle: str | None = None


class HitStatDimensionValueOutput(ActionOutput):
    """A hit-stat dimension value (hitStatDetails.*.dimensions.*.dimensionValues.*)."""

    id: int | None = None
    label: str | None = None
    firstHit: str | None = None
    lastHit: str | None = None
    totalHits: int | None = None


class HitStatDimensionOutput(ActionOutput):
    """A hit-stat dimension (hitStatDetails.*.dimensions.*)."""

    label: str | None = None
    dimension: int | None = None
    firstHit: str | None = None
    lastHit: str | None = None
    totalHits: int | None = None
    dimensionValues: list[HitStatDimensionValueOutput] | None = None


class HitStatDetailOutput(ActionOutput):
    """A per-source hit-stat detail (hitStatDetails.*; live 1_1 evidence, indicator 14131)."""

    label: str | None = None
    external: bool | None = None
    firstHit: str | None = None
    lastHit: str | None = None
    totalHits: int | None = None
    dimensions: list[HitStatDimensionOutput] | None = None


class IndicatorValueOutput(ActionOutput):
    """The indicator value itself; per-action subclasses add the CEF type on `name`."""

    classification: str | None = None
    name: str | None = None


class IndicatorOutput(ActionOutput):
    """Output model for the nine indicator lookup actions (classic 76-datapath contract).

    Shape corrections vs the classic manifest (which declared these
    incorrectly, contradicting the API payloads and the OpenAPI 2.15.0 spec):
    `exploitStage` (with an `id`; live 1_1 evidence, indicator 2690), `path`,
    `fileSize` and `domainRegistration` (spec: NameClassificationPair) are
    objects (classic's own template dereferences record.fileSize.value) and
    `originatingIps` is a list of objects; `hitCount` is numeric. `base_url`,
    `actors.*.link` and `enrichmentResults.*.name` are classic runtime
    decorations that classic emitted without declaring; the SDK declares
    everything it emits. `campaigns` and `indicatorRiskScore` are real API
    fields the classic view rendered/received but never declared.

    1_1 (OAuth) API serialization support (a1soar-30c decision memo + OpenAPI
    2.15.0 amendment): `links` is normalized from the 1_1 object form to the
    classic 1_0 list-of-{rel, href} shape (see _normalize_links), the
    fixture-proven 1_1-only fields are modeled (activityRange, reportedRange,
    verifiedDateRange, sources, tags, externalhitCount, firstExternalHit,
    lastExternalHit, expand), the spec-defined fields are modeled
    (indicatorDerivation, integrationSources, stixObjects, verifications),
    and the live-evidenced nested hitStatDetails is modeled (indicator
    14131) -- all optional, absent under 1_0. `externalhitCount`
    deliberately matches the API's lowercase-h spelling. Every 1_1 payload
    key is now emitted; the only remaining runtime delta versus classic is
    `enrichmentResults.*.result` staying a JSON string.
    """

    active: bool | None = None
    activityDates: list[ClassifiedDate] | None = None
    actors: list[ActorOutput] | None = None
    attackPatterns: list[ClassifiedIdName] | None = None
    benign: BenignOutput | None = None
    confidenceLevel: ConfidenceLevelOutput | None = None
    description: ClassifiedName | None = None
    domainRegistration: ClassifiedName | None = None
    enrichmentFields: list[EnrichmentFieldOutput] | None = None
    enrichmentResults: list[EnrichmentResultOutput] | None = None
    exploitStage: ClassifiedIdName | None = None
    fileNames: list[ClassifiedName] | None = None
    fileSize: FileSizeOutput | None = None
    firstHit: str | None = None
    hashes: list[HashOutput] | None = None
    hitCount: int | None = None
    id: int | None = None
    ipRegistration: ClassifiedName | None = None
    ipResolution: ClassifiedName | None = None
    lastHit: str | None = None
    links: list[LinkOutput] | None = None
    malwares: list[ClassifiedIdName] | None = None
    originatingIps: list[ClassifiedName] | None = None
    path: ClassifiedName | None = None
    ports: list[PortOutput] | None = None
    reportCount: int | None = None
    reportedDates: list[ClassifiedDate] | None = None
    requestMethods: list[ClassifiedName] | None = None
    status: str | None = None
    subjects: list[ClassifiedName] | None = None
    targets: list[ClassifiedIdName] | None = None
    tasked: bool | None = None
    tlp: str | None = None
    tlpCaveats: str | None = None
    tlpHighestAssociated: str | None = None
    tlpJustification: str | None = None
    tlpLowestAssociated: str | None = None
    tlpResolution: str | None = None
    type: str | None = None
    value: IndicatorValueOutput | None = None
    verified: bool | None = None
    base_url: str | None = None
    campaigns: list[ClassifiedIdName] | None = None
    indicatorRiskScore: ClassifiedName | None = None
    # 1_1 (OAuth) API serialization fields (a1soar-30c); absent under 1_0.
    activityRange: DateRangeOutput | None = None
    reportedRange: DateRangeOutput | None = None
    verifiedDateRange: DateRangeOutput | None = None
    sources: list[SourceOutput] | None = None
    tags: list[TagOutput] | None = None
    externalhitCount: int | None = None  # literal API key spelling (lowercase h)
    firstExternalHit: str | None = None
    lastExternalHit: str | None = None
    expand: str | None = None
    # OpenAPI 2.15.0 spec-defined fields (a1soar-30c amendment).
    indicatorDerivation: str | None = None
    integrationSources: list[str] | None = None
    stixObjects: list[StixObjectOutput] | None = None
    verifications: list[VerificationOutput] | None = None
    # Live-evidenced nested hit stats (a1soar-30c; indicator 14131).
    hitStatDetails: list[HitStatDetailOutput] | None = None

    @field_validator("links", mode="before")
    @classmethod
    def _normalize_links(cls, value: Any) -> Any:
        # 1_1 object-form links -> classic {rel, href} list (see _links_to_list).
        return _links_to_list(value)


class EnumDtoOutput(ActionOutput):
    """A key/title enum pair (OpenAPI 2.15.0 EnumDto; batchCheck entity/type/indicatorRiskScore)."""

    key: str | None = None
    title: str | None = None


class AkaDtoOutput(ActionOutput):
    """An associated entity with aliases (OpenAPI 2.15.0 AkaDto; batchCheck actor/malware/system)."""

    id: int | None = None
    title: str | None = None
    akas: list[str] | None = None


class SensorOrgOutput(ActionOutput):
    """A sensor's owning organization (spec IdNamePair; null on some live rows)."""

    id: int | None = None
    name: str | None = None


class TaskingIndicatorOutput(ActionOutput):
    """A tasked indicator (spec "Model that carries indicator and classification information.").

    `fileHashes` arrives as an object keyed by hash algorithm; it is kept as
    a JSON string (see _lenient_str).
    """

    id: int | None = None
    type: str | None = None
    value: str | None = None
    classification: str | None = None
    fileHashes: str | None = None
    links: list[LinkOutput] | None = None

    @field_validator("fileHashes", mode="before")
    @classmethod
    def _coerce_str(cls, value: Any) -> str | None:
        return _lenient_str(value)

    @field_validator("links", mode="before")
    @classmethod
    def _normalize_links(cls, value: Any) -> Any:
        # 1_1 object-form links -> classic {rel, href} list (see _links_to_list).
        return _links_to_list(value)


class TaskingRuleOutput(ActionOutput):
    """A tasked rule (spec "Model that carries rule tasking and classfication information.")."""

    id: int | None = None
    versionNumber: int | None = None
    signature: str | None = None
    classification: str | None = None
    links: list[LinkOutput] | None = None

    @field_validator("links", mode="before")
    @classmethod
    def _normalize_links(cls, value: Any) -> Any:
        # 1_1 object-form links -> classic {rel, href} list (see _links_to_list).
        return _links_to_list(value)


# Per-action `value.name` CEF types (from the classic manifest; lookup_ipv6,
# lookup_mutex and lookup_http_request declare none and use IndicatorOutput
# directly).


class DomainIndicatorValue(IndicatorValueOutput):
    name: str | None = OutputField(cef_types=["domain"])


class DomainIndicatorOutput(IndicatorOutput):
    value: DomainIndicatorValue | None = None


class EmailIndicatorValue(IndicatorValueOutput):
    name: str | None = OutputField(cef_types=["email"])


class EmailIndicatorOutput(IndicatorOutput):
    value: EmailIndicatorValue | None = None


class HashIndicatorValue(IndicatorValueOutput):
    name: str | None = OutputField(cef_types=["hash", "sha256", "sha1", "md5"])


class HashIndicatorOutput(IndicatorOutput):
    value: HashIndicatorValue | None = None


class IpIndicatorValue(IndicatorValueOutput):
    name: str | None = OutputField(cef_types=["ip"])


class IpIndicatorOutput(IndicatorOutput):
    value: IpIndicatorValue | None = None


class StringIndicatorValue(IndicatorValueOutput):
    # Classic declares contains ["ip"] on lookup_string's value.name;
    # reproduced verbatim for contract parity.
    name: str | None = OutputField(cef_types=["ip"])


class StringIndicatorOutput(IndicatorOutput):
    value: StringIndicatorValue | None = None


class UrlIndicatorValue(IndicatorValueOutput):
    name: str | None = OutputField(cef_types=["url"])


class UrlIndicatorOutput(IndicatorOutput):
    value: UrlIndicatorValue | None = None


class LookupSummary(ActionOutput):
    """Runtime summary for lookups: classic sets only `id` (and nothing when not found)."""

    id: int | None = None


class LookupSummaryDatapaths(LookupSummary):
    """Manifest summary datapaths for lookups.

    Classic additionally declares action_result.summary.total_objects, which
    the platform populates; it is declared here but never set by the app.
    """

    total_objects: int | None = None


# =============================================================================
# Test Connectivity
# =============================================================================


@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset):
    """Test connectivity to the Analyst1 platform."""
    logger.info("Testing connectivity to Analyst1")

    client = Analyst1Client(asset, asset.auth_state)
    try:
        # Test with a simple request
        client.get("/indicator/match/", params={"value": "test.com", "type": "domain"})
        auth_method = "OAuth2" if client._use_oauth else "Basic Auth"
        logger.info(f"Successfully connected using {auth_method}")
    finally:
        client.close()


# =============================================================================
# Lookup Actions - Parameters
# =============================================================================


class LookupDomainParams(Params):
    domain: str = Param(
        description="Domain to lookup",
        primary=True,
        default="",
        cef_types=["domain"],
    )


class LookupEmailParams(Params):
    email: str = Param(
        description="Email to lookup",
        primary=True,
        default="",
        cef_types=["email"],
    )


class LookupHashParams(Params):
    hash: str = Param(
        description="Hash to lookup",
        primary=True,
        default="",
        cef_types=["hash", "sha256", "sha1", "md5", "string"],
    )


class LookupStringParams(Params):
    string: str = Param(
        description="String to lookup",
        primary=True,
        default="",
    )


class LookupIpParams(Params):
    ip: str = Param(
        description="IP to lookup",
        primary=True,
        cef_types=["ip", "ipv6"],
    )


class LookupIpv6Params(Params):
    ipv6: str = Param(
        description="IPv6 to lookup",
        primary=True,
        default="",
    )


class LookupUrlParams(Params):
    url: str = Param(
        description="URL to lookup",
        primary=True,
        default="",
        cef_types=["url"],
    )


class LookupMutexParams(Params):
    mutex: str = Param(
        description="Mutex to lookup",
        primary=True,
        default="",
    )


class LookupHttpRequestParams(Params):
    http_request: str = Param(
        description="HTTP request to lookup",
        primary=True,
        default="",
    )


# =============================================================================
# Lookup Actions - Implementations
# =============================================================================


def _safe_int(value: Any) -> int | None:
    """Safely convert value to int, returning None if not possible."""
    if value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def _safe_str(value: Any) -> str | None:
    """Safely convert value to string, returning None if not possible."""
    if value is None:
        return None
    try:
        return str(value)
    except (ValueError, TypeError):
        return None


def _do_indicator_lookup(
    soar: SOARClient,
    asset: Asset,
    value: str,
    indicator_type: str,
    output_cls: type[IndicatorOutput],
) -> list[IndicatorOutput]:
    """Common logic for indicator lookups.

    Classic parity (_handle_indicator_match): on a match, one data record plus
    summary.id; when the indicator is not found (API 404), no data records and
    an empty summary, with the action still succeeding.
    """
    client = Analyst1Client(asset, asset.auth_state)
    try:
        result = client.indicator_match(value, indicator_type)
        if result is None:
            return []
        soar.set_summary(LookupSummary(id=result["id"]))
        return [output_cls(**result)]
    finally:
        client.close()


# Fields the display template iterates or dereferences; the view handler
# guarantees these keys exist so Jinja rendering never hits an undefined.
_TEMPLATE_LIST_FIELDS = (
    "activityDates",
    "actors",
    "attackPatterns",
    "campaigns",
    "enrichmentFields",
    "enrichmentResults",
    "fileNames",
    "hashes",
    "malwares",
    "originatingIps",
    "ports",
    "reportedDates",
    "requestMethods",
    "subjects",
    "targets",
)
_TEMPLATE_OBJECT_FIELDS = (
    "benign",
    "confidenceLevel",
    "description",
    "exploitStage",
    "fileSize",  # object ({value, classification}); template renders record.fileSize.value
    "ipResolution",
    "path",
    "value",
)


@app.view_handler(template="display_indicators.html")
def display_indicators_view(outputs: list[IndicatorOutput]) -> dict:
    """Custom view handler for displaying indicator results.

    Renders directly from the typed IndicatorOutput models (the classic view
    filtered out records without an id and showed "No matches found" when
    nothing remained).

    Args:
        outputs: List of IndicatorOutput objects from action results

    Returns:
        Dictionary with results formatted for the template
    """
    results = []

    for output in outputs:
        if not output.id:
            continue
        record = output.model_dump(exclude_none=True)
        for field in _TEMPLATE_LIST_FIELDS:
            record.setdefault(field, [])
        for field in _TEMPLATE_OBJECT_FIELDS:
            record.setdefault(field, {})
        # The template compares element.id > 0 for actors and malwares
        for element in (*record["actors"], *record["malwares"]):
            element.setdefault("id", 0)
        # The template sorts these lists by attribute; Jinja's sort filter
        # raises if an element lacks the key (exclude_none drops None keys)
        for element in (*record["originatingIps"], *record["subjects"], *record["fileNames"]):
            element.setdefault("name", "")
        for element in record["ports"]:
            element.setdefault("value", 0)
        results.append({"data": [record]})

    if not results:
        # Not-found runs emit no data records; render the "No matches found" row
        results.append({"data": []})

    return {
        "results": results,
        "title1": "Analyst1 Indicator Lookup",
        "title2": "Threat Intelligence",
        "title_logo": "analyst1.png",
    }


@app.action(
    description="Check for the presence of a domain in the Analyst1 platform",
    action_type="investigate",
    view_handler=display_indicators_view,
    summary_type=LookupSummaryDatapaths,
)
def lookup_domain(params: LookupDomainParams, soar: SOARClient, asset: Asset) -> list[DomainIndicatorOutput]:
    """Look up a domain in Analyst1."""
    logger.info(f"Looking up domain: {params.domain}")
    return _do_indicator_lookup(soar, asset, params.domain, "domain", DomainIndicatorOutput)


@app.action(
    description="Check for the presence of an email in the Analyst1 platform",
    action_type="investigate",
    view_handler=display_indicators_view,
    summary_type=LookupSummaryDatapaths,
)
def lookup_email(params: LookupEmailParams, soar: SOARClient, asset: Asset) -> list[EmailIndicatorOutput]:
    """Look up an email in Analyst1."""
    logger.info(f"Looking up email: {params.email}")
    return _do_indicator_lookup(soar, asset, params.email, "email", EmailIndicatorOutput)


@app.action(
    description="Check for the presence of a hash in the Analyst1 platform",
    action_type="investigate",
    view_handler=display_indicators_view,
    summary_type=LookupSummaryDatapaths,
)
def lookup_hash(params: LookupHashParams, soar: SOARClient, asset: Asset) -> list[HashIndicatorOutput]:
    """Look up a file hash in Analyst1."""
    logger.info(f"Looking up hash: {params.hash}")
    return _do_indicator_lookup(soar, asset, params.hash, "file", HashIndicatorOutput)


@app.action(
    description="Check for the presence of a string in the Analyst1 platform",
    action_type="investigate",
    view_handler=display_indicators_view,
    summary_type=LookupSummaryDatapaths,
)
def lookup_string(params: LookupStringParams, soar: SOARClient, asset: Asset) -> list[StringIndicatorOutput]:
    """Look up a string in Analyst1."""
    logger.info(f"Looking up string: {params.string}")
    return _do_indicator_lookup(soar, asset, params.string, "string", StringIndicatorOutput)


@app.action(
    description="Check for the presence of an IP in the Analyst1 platform",
    action_type="investigate",
    view_handler=display_indicators_view,
    summary_type=LookupSummaryDatapaths,
)
def lookup_ip(params: LookupIpParams, soar: SOARClient, asset: Asset) -> list[IpIndicatorOutput]:
    """Look up an IP address in Analyst1."""
    logger.info(f"Looking up IP: {params.ip}")
    # Determine if IPv4 or IPv6 (classic parity: an invalid IP fails the action)
    try:
        ip_obj = ipaddress.ip_address(params.ip)
    except ValueError as e:
        raise ActionFailure(str(e)) from e
    indicator_type = "ip" if ip_obj.version == 4 else "ipv6"
    return _do_indicator_lookup(soar, asset, params.ip, indicator_type, IpIndicatorOutput)


@app.action(
    description="Check for the presence of an IPv6 in the Analyst1 platform",
    action_type="investigate",
    view_handler=display_indicators_view,
    summary_type=LookupSummaryDatapaths,
)
def lookup_ipv6(params: LookupIpv6Params, soar: SOARClient, asset: Asset) -> list[IndicatorOutput]:
    """Look up an IPv6 address in Analyst1."""
    logger.info(f"Looking up IPv6: {params.ipv6}")
    return _do_indicator_lookup(soar, asset, params.ipv6, "ipv6", IndicatorOutput)


@app.action(
    description="Check for the presence of a URL in the Analyst1 platform",
    action_type="investigate",
    view_handler=display_indicators_view,
    summary_type=LookupSummaryDatapaths,
)
def lookup_url(params: LookupUrlParams, soar: SOARClient, asset: Asset) -> list[UrlIndicatorOutput]:
    """Look up a URL in Analyst1."""
    logger.info(f"Looking up URL: {params.url}")
    return _do_indicator_lookup(soar, asset, params.url, "url", UrlIndicatorOutput)


@app.action(
    description="Check for the presence of a mutex in the Analyst1 platform",
    action_type="investigate",
    view_handler=display_indicators_view,
    summary_type=LookupSummaryDatapaths,
)
def lookup_mutex(params: LookupMutexParams, soar: SOARClient, asset: Asset) -> list[IndicatorOutput]:
    """Look up a mutex in Analyst1."""
    logger.info(f"Looking up mutex: {params.mutex}")
    return _do_indicator_lookup(soar, asset, params.mutex, "mutex", IndicatorOutput)


@app.action(
    description="Check for the presence of an HTTP request in the Analyst1 platform",
    action_type="investigate",
    view_handler=display_indicators_view,
    summary_type=LookupSummaryDatapaths,
)
def lookup_http_request(params: LookupHttpRequestParams, soar: SOARClient, asset: Asset) -> list[IndicatorOutput]:
    """Look up an HTTP request in Analyst1."""
    logger.info(f"Looking up HTTP request: {params.http_request}")
    return _do_indicator_lookup(soar, asset, params.http_request, "httpRequest", IndicatorOutput)


# =============================================================================
# Batch Check Action
# =============================================================================


# Hard guard against the GET variant's URL-length ceiling; a POST/file variant
# that would lift it is a deferred parity item.
BATCH_CHECK_MAX_VALUES_LENGTH = 6000


class BatchCheckParams(Params):
    values: str = Param(
        description=(
            "Comma- or newline-separated indicator values to check; the indicator type of each value is auto-detected. "
            "The combined length is limited to 6000 characters (URL length limit); split larger inputs."
        ),
        primary=True,
    )


class BatchCheckResultOutput(ActionOutput):
    """A batchCheck row (OpenAPI 2.15.0 BatchCheckResult).

    Shapes intentionally differ from IndicatorOutput: `benign` is a plain
    boolean and `entity`/`type`/`indicatorRiskScore` are EnumDto {key, title}
    pairs. Live rows commonly carry `benign: null` and
    `indicatorRiskScore: null`.
    """

    searchedValue: str | None = None
    matchedValue: str | None = None
    id: int | None = None
    entity: EnumDtoOutput | None = None
    type: EnumDtoOutput | None = None
    benign: bool | None = None
    indicatorRiskScore: EnumDtoOutput | None = None
    actor: list[AkaDtoOutput] | None = None
    malware: list[AkaDtoOutput] | None = None
    system: list[AkaDtoOutput] | None = None


class BatchCheckSummary(ActionOutput):
    total_values: int | None = None
    total_results: int | None = None


@app.action(
    description="Check a batch of indicator values (type auto-detected) against the Analyst1 platform",
    action_type="investigate",
    render_as="table",
    summary_type=BatchCheckSummary,
)
def batch_check(params: BatchCheckParams, soar: SOARClient, asset: Asset) -> list[BatchCheckResultOutput]:
    """Batch check indicator values in Analyst1."""
    logger.info("Running batch check")

    values = [value.strip() for chunk in params.values.split("\n") for value in chunk.split(",")]
    values = [value for value in values if value]
    if not values:
        raise ActionFailure("No values provided")

    values_csv = ",".join(values)
    if len(values_csv) > BATCH_CHECK_MAX_VALUES_LENGTH:
        raise ActionFailure("Too many/long values for batch check (URL length limit); split the input")

    client = Analyst1Client(asset, asset.auth_state)
    try:
        results = client.batch_check(values_csv)
        soar.set_summary(BatchCheckSummary(total_values=len(values), total_results=len(results)))
        return [BatchCheckResultOutput(**row) for row in results]
    finally:
        client.close()


# =============================================================================
# By-Id Actions
# =============================================================================


class ByIdSummary(ActionOutput):
    """Runtime summary for by-id retrievals: the resource id, or unset when not found."""

    id: int | None = None


class GetIndicatorByIdParams(Params):
    indicator_id: str = Param(
        description="Analyst1 indicator ID (hash indicator IDs may carry a type suffix, e.g. 14131-md5; the suffix is stripped)",
        primary=True,
    )


@app.action(
    description="Fetch an indicator from the Analyst1 platform by its Analyst1 ID",
    action_type="investigate",
    view_handler=display_indicators_view,
    summary_type=LookupSummaryDatapaths,
)
def get_indicator_by_id(params: GetIndicatorByIdParams, soar: SOARClient, asset: Asset) -> list[IndicatorOutput]:
    """Get an indicator by its Analyst1 ID."""
    logger.info(f"Getting indicator by id: {params.indicator_id}")
    client = Analyst1Client(asset, asset.auth_state)
    try:
        result = client.get_indicator_by_id(params.indicator_id)
        if result is None:
            return []
        soar.set_summary(LookupSummary(id=result["id"]))
        return [IndicatorOutput(**result)]
    finally:
        client.close()


class GetActorByIdParams(Params):
    actor_id: int = Param(
        description="Analyst1 actor ID",
        primary=True,
    )


class ActorResourceOutput(ActionOutput):
    """A standalone actor resource (OpenAPI 2.15.0 ActorResource; GET /actor/{id}).

    (`ActorOutput` is the indicator lookup's nested actor sub-model; this is
    the full resource.) `country`/`sponsor`/`primaryMotivation` are
    {id, name, classification} triples (verified live).
    """

    id: int | None = None
    links: list[LinkOutput] | None = None
    title: ClassifiedName | None = None
    country: ClassifiedIdName | None = None
    sponsor: ClassifiedIdName | None = None
    description: ClassifiedName | None = None
    primaryMotivation: ClassifiedIdName | None = None
    activityRange: DateRangeOutput | None = None
    campaigns: list[ClassifiedIdName] | None = None
    attackPatterns: list[ClassifiedIdName] | None = None
    targets: list[ClassifiedIdName] | None = None
    akas: list[ClassifiedIdName] | None = None
    malware: list[ClassifiedIdName] | None = None
    cves: list[ClassifiedIdName] | None = None
    secondaryMotivations: list[ClassifiedIdName] | None = None
    personalMotivations: list[ClassifiedIdName] | None = None

    @field_validator("links", mode="before")
    @classmethod
    def _normalize_links(cls, value: Any) -> Any:
        # 1_1 object-form links -> classic {rel, href} list (see _links_to_list).
        return _links_to_list(value)


@app.action(
    description="Fetch an actor from the Analyst1 platform by its Analyst1 ID",
    action_type="investigate",
    render_as="table",
    summary_type=ByIdSummary,
)
def get_actor_by_id(params: GetActorByIdParams, soar: SOARClient, asset: Asset) -> list[ActorResourceOutput]:
    """Get an actor by its Analyst1 ID."""
    logger.info(f"Getting actor by id: {params.actor_id}")
    client = Analyst1Client(asset, asset.auth_state)
    try:
        result = client.get_actor_by_id(params.actor_id)
        if result is None:
            return []
        soar.set_summary(ByIdSummary(id=result["id"]))
        return [ActorResourceOutput(**result)]
    finally:
        client.close()


class GetMalwareByIdParams(Params):
    malware_id: int = Param(
        description="Analyst1 malware ID",
        primary=True,
    )


class MalwareResourceOutput(ActionOutput):
    """A standalone malware resource (OpenAPI 2.15.0 MalwareResource; GET /malware/{id}).

    `category`/`stage` are {id, name, classification} triples (verified live).
    """

    id: int | None = None
    links: list[LinkOutput] | None = None
    title: ClassifiedName | None = None
    category: ClassifiedIdName | None = None
    stage: ClassifiedIdName | None = None
    description: ClassifiedName | None = None
    akas: list[ClassifiedIdName] | None = None
    stixObjects: list[StixObjectOutput] | None = None

    @field_validator("links", mode="before")
    @classmethod
    def _normalize_links(cls, value: Any) -> Any:
        # 1_1 object-form links -> classic {rel, href} list (see _links_to_list).
        return _links_to_list(value)


@app.action(
    description="Fetch a malware family from the Analyst1 platform by its Analyst1 ID",
    action_type="investigate",
    render_as="table",
    summary_type=ByIdSummary,
)
def get_malware_by_id(params: GetMalwareByIdParams, soar: SOARClient, asset: Asset) -> list[MalwareResourceOutput]:
    """Get a malware family by its Analyst1 ID."""
    logger.info(f"Getting malware by id: {params.malware_id}")
    client = Analyst1Client(asset, asset.auth_state)
    try:
        result = client.get_malware_by_id(params.malware_id)
        if result is None:
            return []
        soar.set_summary(ByIdSummary(id=result["id"]))
        return [MalwareResourceOutput(**result)]
    finally:
        client.close()


# =============================================================================
# Evidence Actions
# =============================================================================


class UploadEvidenceFileParams(Params):
    vault_id: str = Param(
        description="Phantom vault ID of file",
        primary=True,
        default="",
        cef_types=["vault id"],
        column_name="vault_id",
    )
    evidence_file_classification: str = Param(
        description="The evidence file's classification. Only used if a classification can not be determined during extraction.",
        default="unclass",
        value_list=[
            "unclass",
            "fouo",
            "secretFvey",
            "secretNoforn",
            "confFvey",
            "confNoforn",
            "confFveyFisa",
            "confNofornFisa",
            "secretFveyFisa",
            "secretNofornFisa",
            "tsFvey",
            "tsNoforn",
            "tsFveyFisa",
            "tsNofornFisa",
            "tsSiFvey",
            "tsSiNoforn",
            "tsSiFveyFisa",
            "tsSiNofornFisa",
            "tsSiGFvey",
            "tsSiGNoforn",
            "tsSiGFveyFisa",
            "tsSiGNofornFisa",
            "tsOcFvey",
            "tsOcNoforn",
            "tsOcFveyFisa",
            "tsOcNofornFisa",
            "tsSiOcFvey",
            "tsSiOcNoforn",
            "tsSiOcFveyFisa",
            "tsSiOcNofornFisa",
            "tsSiGOcFvey",
            "tsSiGOcNoforn",
            "tsSiGOcFveyFisa",
            "tsSiGOcNofornFisa",
        ],
    )
    tlp: str = Param(
        description="The evidence file's traffic light protocol (TLP) designation. Only used if a TLP can not be determined during extraction.",
        default="undetermined",
        value_list=["undetermined", "white", "green", "amber", "red"],
    )
    source_id: int = Param(
        description="The evidence file's source ID number.",
        required=True,
    )
    source_title: str = Param(
        description=(
            "The evidence file's source name. If included, an exact match search will run against Analyst1's Evidence Sources. "
            "If a match is found that Source will be assigned this created Evidence. The Name is used second (2nd) in Source "
            "discovery order. If no Source discovery method is provided (ID, Name, or URL) then the Source will be 'Unknown' "
            "on the Evidence created."
        ),
        required=False,
        default="",
    )
    source_url: str = Param(
        description=(
            "The evidence file's source URL. If included, all REGEX values defined for Evidence Sources will be compared. "
            "If a match is found the Source will be assgined this created Evidence. The URL is used third (3rd) in Source "
            "discovery order. If no Source discovery method is provided (ID, Name, or URL) then the Source will be 'Unknown' "
            "on the Evidence created."
        ),
        required=False,
        default="",
    )
    disable_indicator_auto_enrichment: bool = Param(
        description=(
            "Influences Indicator automated enrichment during ingest. Default (false) is to allow enrichment. "
            "Caller may override and disable automated enrichment. Value ignored if Indicator Auto Enrichment "
            "is not enabled in this Analyst1's Admin Controls."
        ),
        required=False,
        default=False,
    )


class UploadEvidenceFileOutput(ActionOutput):
    uuid: str = OutputField(cef_types=["analyst1 evidence upload key"], column_name="UUID")


class UploadEvidenceFileSummary(ActionOutput):
    uuid: str | None = OutputField(cef_types=["analyst1 evidence upload key"])


@app.action(
    description="Upload file from vault to Analyst1 as evidence file",
    action_type="generic",
    read_only=False,
    render_as="table",
    summary_type=UploadEvidenceFileSummary,
)
def upload_evidence_file(params: UploadEvidenceFileParams, soar: SOARClient, asset: Asset) -> UploadEvidenceFileOutput:
    """Upload a file from the vault to Analyst1 as evidence."""
    logger.info(f"Uploading evidence file from vault: {params.vault_id}")

    # Get file info from vault
    attachments = soar.vault.get_attachment(vault_id=params.vault_id)
    if not attachments:
        raise Analyst1Error(f"File not found in vault: {params.vault_id}")
    vault_info = attachments[0]

    # Build form data (classic parity: falsy values are not sent)
    data = {}
    param_dict = params.model_dump()
    for param_key, api_key in EVIDENCE_POST_FIELD_MAP.items():
        value = param_dict.get(param_key)
        if value:
            data[api_key] = value

    # Read file and upload
    client = Analyst1Client(asset, asset.auth_state)
    try:
        file_path = vault_info.path
        file_name = vault_info.name or "evidence_file"

        with open(file_path, "rb") as f:
            files = {"evidenceFile": (file_name, f)}
            response = client.post("/evidence", data=data, files=files)

        uuid = _safe_str(response.get("uuid"))
        if not uuid:
            raise Analyst1Error("No UUID returned from evidence upload")

        logger.info(f"Evidence uploaded successfully, UUID: {uuid}")
        soar.set_summary(UploadEvidenceFileSummary(uuid=uuid))
        return UploadEvidenceFileOutput(uuid=uuid)
    finally:
        client.close()


class CheckEvidenceStatusParams(Params):
    uuid: str = Param(
        description="Evidence upload key",
        primary=True,
        cef_types=["analyst1 evidence upload key"],
    )


class CheckEvidenceStatusOutput(ActionOutput):
    message: str | None = OutputField(column_name="Message")
    id: int | None = OutputField(column_name="Evidence ID")


class CheckEvidenceStatusSummary(ActionOutput):
    """Runtime summary: classic sets `message` and `evidence_id`."""

    message: str | None = None
    evidence_id: int | None = None


class CheckEvidenceStatusSummaryDatapaths(CheckEvidenceStatusSummary):
    """Manifest summary datapaths.

    The classic manifest declares summary.message and summary.id, while the
    classic connector actually set summary.message and summary.evidence_id;
    both key sets are declared for compatibility.
    """

    id: int | None = OutputField(cef_types=["analyst1 evidence id"])


@app.action(
    description="Check the status of an evidence file upload",
    action_type="generic",
    render_as="table",
    summary_type=CheckEvidenceStatusSummaryDatapaths,
)
def check_evidence_status(params: CheckEvidenceStatusParams, soar: SOARClient, asset: Asset) -> CheckEvidenceStatusOutput:
    """Check the status of an evidence file upload."""
    logger.info(f"Checking evidence status for UUID: {params.uuid}")

    client = Analyst1Client(asset, asset.auth_state)
    try:
        response = client.get(f"/evidence/uploadStatus/{params.uuid}")
        message = _safe_str(response.get("message"))
        evidence_id = _safe_int(response.get("id"))
        soar.set_summary(CheckEvidenceStatusSummary(message=message, evidence_id=evidence_id))
        return CheckEvidenceStatusOutput(message=message, id=evidence_id)
    finally:
        client.close()


class GetEvidenceParams(Params):
    page: int | None = Param(
        description=(
            "The specific page number to retrieve (1-indexed). If provided, only that single page will be returned. "
            "If not provided, all pages will be retrieved up to the specified limit."
        ),
        required=False,
        column_name="page",
    )
    desc_sort: bool = Param(
        description="The sort direction. True for a descending sort, false for a ascending sort.",
        required=False,
        default=True,
        column_name="desc_sort",
    )
    sort_by: str = Param(
        description=(
            "The value to sort results on. Allowed values are 'id', 'analyzed', 'indicatorsStatus', 'title', 'tlp', "
            "'type', 'exploitStage', 'attackPattern', 'activityDate', 'reportedDate', & 'assignedTo'."
        ),
        required=False,
        default="id",
        column_name="sort_by",
        value_list=[
            "analyzed",
            "activityDate",
            "assignedTo",
            "attackPattern",
            "exploitStage",
            "id",
            "indicatorStatus",
            "reportedDate",
            "title",
            "tlp",
            "type",
        ],
    )
    type: str = Param(
        description=(
            "Filter results based on evidence type. Allowed values are 'pcap', 'image', 'pdf', 'txt', 'web', "
            "'incident_04', 'stix', 'caseType', 'spreadsheet', 'doc', 'ppt', 'xml', & 'other'."
        ),
        required=False,
        default="",
        column_name="type",
        value_list=[
            "pcap",
            "image",
            "pdf",
            "txt",
            "web",
            "incident_04",
            "stix",
            "caseType",
            "spreadsheet",
            "doc",
            "ppt",
            "xml",
            "other",
        ],
    )
    indicators_verified_date_from: str = Param(
        description="Filter results based on indicators verified date after (including) this provided date in ISO-8601 format.",
        required=False,
        default="",
        column_name="indicators_verified_date_from",
    )
    indicators_verified_date_to: str = Param(
        description="Filter results based on indicators verified date before (including) this provided date in ISO-8601 format.",
        required=False,
        default="",
        column_name="indicators_verified_date_to",
    )
    analyzed_date_from: str = Param(
        description="Filter results based on analyzed date after (including) this provided date in ISO-8601 format.",
        required=False,
        default="",
        column_name="analyzed_date_from",
    )
    analyzed_date_to: str = Param(
        description="Filter results based on analyzed date before (including) this provided date in ISO-8601 format.",
        required=False,
        default="",
        column_name="analyzed_date_to",
    )
    nominated_for_incident: bool | None = Param(
        description="Filter results based on Nominated for Incident Response State.",
        required=False,
        column_name="nominated_for_incident",
    )
    nominated_for_report: bool | None = Param(
        description="Filter results based on Nominated for Report State.",
        required=False,
        column_name="nominated_for_report",
    )


class EvidenceItemOutput(PermissiveActionOutput):
    """Single evidence record, passed through untyped.

    Classic added each raw evidence dict as a data record and declared no
    data.* datapaths for this action; PermissiveActionOutput reproduces that
    lossless passthrough.
    """


class GetEvidenceSinglePageSummary(ActionOutput):
    """Classic single-page summary keys (base set)."""

    page_requested: int | None = None
    evidence_on_page: int | None = None


class GetEvidenceSinglePageFullSummary(GetEvidenceSinglePageSummary):
    """Classic single-page summary keys when a response was received."""

    total_pages: int | None = None
    total_results: int | None = None


class GetEvidenceMultiPageSummary(ActionOutput):
    """Classic multi-page summary keys."""

    total_evidence_retrieved: int | None = None
    pages_processed: int | None = None
    max_pages_limit: int | None = None
    limited_by: str | None = None


class GetEvidenceMultiPageLimitedSummary(GetEvidenceMultiPageSummary):
    """Classic multi-page summary keys when results were capped at max pages."""

    note: str | None = None


@app.action(
    description="Browse and fetch evidence resources.",
    action_type="investigate",
    render_as="table",
)
def get_evidence(params: GetEvidenceParams, soar: SOARClient, asset: Asset) -> list[EvidenceItemOutput]:
    """Get evidence resources with pagination support."""
    logger.info("Fetching evidence resources")

    page = params.page
    if page is not None and page < 1:
        raise ActionFailure("Page must be greater than 0")

    client = Analyst1Client(asset, asset.auth_state)
    try:
        # Build parameters
        api_params: dict[str, Any] = {
            "descSort": params.desc_sort,
            "sortBy": params.sort_by,
            "pageSize": 100,
        }

        if params.type:
            api_params["type"] = params.type
        if params.analyzed_date_from:
            api_params["analyzedDateFrom"] = params.analyzed_date_from
        if params.analyzed_date_to:
            api_params["analyzedDateTo"] = params.analyzed_date_to
        if params.indicators_verified_date_from:
            api_params["indicatorsVerifiedDateFrom"] = params.indicators_verified_date_from
        if params.indicators_verified_date_to:
            api_params["indicatorsVerifiedDateTo"] = params.indicators_verified_date_to
        if params.nominated_for_incident is not None:  # Boolean - False is valid
            api_params["nominatedForIncident"] = params.nominated_for_incident
        if params.nominated_for_report is not None:  # Boolean - False is valid
            api_params["nominatedForReport"] = params.nominated_for_report

        # Determine pagination mode (classic parity: no page -> up to 10 pages)
        if page is not None:
            max_pages = 1
            start_page = page
        else:
            max_pages = 10  # Limit to 10 pages (1000 items)
            start_page = 1

        all_evidence: list[dict] = []
        current_page = start_page
        pages_processed = 0
        response: dict[str, Any] | None = None

        while pages_processed < max_pages:
            api_params["page"] = current_page
            response = client.get("/evidence", params=api_params)

            if not response or "results" not in response:
                break

            page_results = response.get("results", [])
            pages_processed += 1

            if not page_results:
                break

            all_evidence.extend(page_results)
            logger.info(f"Retrieved {len(page_results)} items from page {current_page}")

            # Check if single page mode
            if page is not None:
                break

            # Check if last page
            total_pages = response.get("totalPages", 1)
            if current_page >= total_pages:
                break

            current_page += 1

        # Classic summary keys per pagination mode
        if page is not None:
            if response:
                soar.set_summary(
                    GetEvidenceSinglePageFullSummary(
                        page_requested=page,
                        evidence_on_page=len(all_evidence),
                        total_pages=response.get("totalPages", 1),
                        total_results=response.get("totalResults", len(all_evidence)),
                    )
                )
            else:
                soar.set_summary(GetEvidenceSinglePageSummary(page_requested=page, evidence_on_page=len(all_evidence)))
        elif pages_processed >= max_pages and response and current_page < response.get("totalPages", 1):
            soar.set_summary(
                GetEvidenceMultiPageLimitedSummary(
                    total_evidence_retrieved=len(all_evidence),
                    pages_processed=pages_processed,
                    max_pages_limit=max_pages,
                    limited_by="max_pages",
                    note=f"Results limited to {max_pages} pages. Use page parameter to access specific pages beyond page {max_pages}.",
                )
            )
        else:
            soar.set_summary(
                GetEvidenceMultiPageSummary(
                    total_evidence_retrieved=len(all_evidence),
                    pages_processed=pages_processed,
                    max_pages_limit=max_pages,
                    limited_by="available_data",
                )
            )

        logger.info(f"Total evidence retrieved: {len(all_evidence)}")
        return [EvidenceItemOutput(**evidence) for evidence in all_evidence]
    finally:
        client.close()


# =============================================================================
# Sensor Actions
# =============================================================================


class GetSensorsParams(Params):
    page: int | None = Param(
        description=(
            "The specific page number to retrieve (1-indexed). If provided, only that single page will be returned. "
            "If not provided, all pages will be retrieved up to a 10 page limit."
        ),
        required=False,
        column_name="page",
    )
    page_size: int = Param(
        description="The number of sensors to return per page.",
        required=False,
        default=50,
        column_name="page_size",
    )
    type: str = Param(
        description="Filter results based on sensor type.",
        required=False,
        default="",
        column_name="type",
    )
    org: int | None = Param(
        description="Filter results based on the sensor's organization ID.",
        required=False,
        column_name="org",
    )
    logical_location: str = Param(
        description="Filter results based on the sensor's logical location.",
        required=False,
        default="",
        column_name="logical_location",
    )
    desc_sort: bool = Param(
        description="The sort direction. True for a descending sort, false for a ascending sort.",
        required=False,
        default=False,
        column_name="desc_sort",
    )
    sort_by: str = Param(
        description="The value to sort results on.",
        required=False,
        default="id",
        column_name="sort_by",
    )


class SensorOutput(ActionOutput):
    """A sensor (OpenAPI 2.15.0 SensorResource).

    Live rows serialize the links under `_links` (underscore, rel-keyed
    object); the client renames them to `links` before validation.
    `org` and `logicalLocation` are null on some live rows.
    """

    id: int | None = None
    name: str | None = None
    logicalLocation: str | None = None
    org: SensorOrgOutput | None = None
    type: str | None = None
    currentVersionNumber: int | None = None
    latestConfigVersionNumber: int | None = None
    links: list[LinkOutput] | None = None

    @field_validator("links", mode="before")
    @classmethod
    def _normalize_links(cls, value: Any) -> Any:
        # 1_1 object-form links -> classic {rel, href} list (see _links_to_list).
        return _links_to_list(value)


class GetSensorsSummary(ActionOutput):
    total_sensors: int | None = None
    pages_processed: int | None = None
    total_pages: int | None = None


@app.action(
    description="Browse and fetch sensors from the Analyst1 platform",
    action_type="investigate",
    render_as="table",
    summary_type=GetSensorsSummary,
)
def get_sensors(params: GetSensorsParams, soar: SOARClient, asset: Asset) -> list[SensorOutput]:
    """Get sensors with pagination support."""
    logger.info("Fetching sensors")

    page = params.page
    if page is not None and page < 1:
        raise ActionFailure("Page must be greater than 0")

    client = Analyst1Client(asset, asset.auth_state)
    try:
        api_params: dict[str, Any] = {
            "descSort": params.desc_sort,
            "sortBy": params.sort_by,
            "pageSize": params.page_size,
        }
        if params.type:
            api_params["type"] = params.type
        if params.org is not None:
            api_params["org"] = params.org
        if params.logical_location:
            api_params["logicalLocation"] = params.logical_location

        # Pagination mode mirrors get_evidence: no page -> auto-page up to a cap.
        if page is not None:
            max_pages = 1
            start_page = page
        else:
            max_pages = 10
            start_page = 1

        all_sensors: list[dict] = []
        current_page = start_page
        pages_processed = 0
        response: dict[str, Any] | None = None

        while pages_processed < max_pages:
            api_params["page"] = current_page
            response = client.get_sensors(api_params)

            if not response or "results" not in response:
                break

            page_results = response.get("results", [])
            pages_processed += 1

            if not page_results:
                break

            all_sensors.extend(page_results)
            logger.info(f"Retrieved {len(page_results)} sensors from page {current_page}")

            if page is not None:
                break

            total_pages = response.get("totalPages", 1)
            if current_page >= total_pages:
                break

            current_page += 1

        soar.set_summary(
            GetSensorsSummary(
                total_sensors=len(all_sensors),
                pages_processed=pages_processed,
                total_pages=response.get("totalPages") if response else None,
            )
        )
        logger.info(f"Total sensors retrieved: {len(all_sensors)}")
        return [SensorOutput(**sensor) for sensor in all_sensors]
    finally:
        client.close()


class GetSensorTaskingsParams(Params):
    sensor_id: int = Param(
        description="Analyst1 sensor ID",
        primary=True,
    )


class SensorTaskingsOutput(ActionOutput):
    """A sensor's current taskings (spec "Model for sensor taskings.")."""

    id: int | None = None
    version: int | None = None
    indicators: list[TaskingIndicatorOutput] | None = None
    rules: list[TaskingRuleOutput] | None = None
    links: list[LinkOutput] | None = None

    @field_validator("links", mode="before")
    @classmethod
    def _normalize_links(cls, value: Any) -> Any:
        # 1_1 object-form links -> classic {rel, href} list (see _links_to_list).
        return _links_to_list(value)


class SensorTaskingsSummary(ActionOutput):
    version: int | None = None
    indicator_count: int | None = None
    rule_count: int | None = None


@app.action(
    description="Fetch the indicators and rules currently tasked to an Analyst1 sensor",
    action_type="investigate",
    render_as="table",
    summary_type=SensorTaskingsSummary,
)
def get_sensor_taskings(params: GetSensorTaskingsParams, soar: SOARClient, asset: Asset) -> list[SensorTaskingsOutput]:
    """Get the taskings for a sensor."""
    logger.info(f"Fetching taskings for sensor: {params.sensor_id}")
    client = Analyst1Client(asset, asset.auth_state)
    try:
        result = client.get_sensor_taskings(params.sensor_id)
        if not result or not result.get("id"):
            return []
        soar.set_summary(
            SensorTaskingsSummary(
                version=result.get("version"),
                indicator_count=len(result.get("indicators") or []),
                rule_count=len(result.get("rules") or []),
            )
        )
        return [SensorTaskingsOutput(**result)]
    finally:
        client.close()


class GetSensorConfigParams(Params):
    sensor_id: int = Param(
        description="Analyst1 sensor ID",
        primary=True,
    )


class SensorConfigOutput(ActionOutput):
    sensor_id: int | None = None
    vault_id: str | None = OutputField(cef_types=["vault id"])
    file_name: str | None = None
    config_text: str | None = None


class SensorConfigSummary(ActionOutput):
    vault_id: str | None = None
    file_name: str | None = None


@app.action(
    description="Fetch an Analyst1 sensor's current configuration file and store it in the vault",
    action_type="investigate",
    render_as="table",
    summary_type=SensorConfigSummary,
)
def get_sensor_config(params: GetSensorConfigParams, soar: SOARClient, asset: Asset) -> list[SensorConfigOutput]:
    """Get a sensor's configuration file and store it in the vault."""
    logger.info(f"Fetching config for sensor: {params.sensor_id}")
    client = Analyst1Client(asset, asset.auth_state)
    try:
        config_text = client.get_sensor_config_text(params.sensor_id)
    finally:
        client.close()

    if not config_text:
        # Not found (404) or blank config: succeed with no data, no vault write.
        return []

    file_name = f"sensor{params.sensor_id}Config.txt"
    vault_id = soar.vault.create_attachment(soar.get_executing_container_id(), config_text, file_name)
    soar.set_summary(SensorConfigSummary(vault_id=vault_id, file_name=file_name))
    return [
        SensorConfigOutput(
            sensor_id=params.sensor_id,
            vault_id=vault_id,
            file_name=file_name,
            config_text=config_text,
        )
    ]


class GetSensorDiffParams(Params):
    sensor_id: int = Param(
        description="Analyst1 sensor ID",
    )
    version: int = Param(
        description="The sensor config version to diff against the latest version",
        primary=True,
    )


class SensorDiffOutput(ActionOutput):
    """A tasking diff between a sensor config version and the latest (spec SensorDiff)."""

    id: int | None = None
    version: int | None = None
    latestVersion: int | None = None
    indicatorsAdded: list[TaskingIndicatorOutput] | None = None
    indicatorsRemoved: list[TaskingIndicatorOutput] | None = None
    rulesAdded: list[TaskingRuleOutput] | None = None
    rulesRemoved: list[TaskingRuleOutput] | None = None
    links: list[LinkOutput] | None = None

    @field_validator("links", mode="before")
    @classmethod
    def _normalize_links(cls, value: Any) -> Any:
        # 1_1 object-form links -> classic {rel, href} list (see _links_to_list).
        return _links_to_list(value)


class SensorDiffSummary(ActionOutput):
    version: int | None = None
    latest_version: int | None = None
    indicators_added: int | None = None
    indicators_removed: int | None = None
    rules_added: int | None = None
    rules_removed: int | None = None


@app.action(
    description="Fetch the tasking differences between an Analyst1 sensor config version and the latest version",
    action_type="investigate",
    render_as="table",
    summary_type=SensorDiffSummary,
)
def get_sensor_diff(params: GetSensorDiffParams, soar: SOARClient, asset: Asset) -> list[SensorDiffOutput]:
    """Get the tasking diff for a sensor config version."""
    logger.info(f"Fetching tasking diff for sensor {params.sensor_id}, version {params.version}")
    client = Analyst1Client(asset, asset.auth_state)
    try:
        result = client.get_sensor_diff(params.sensor_id, params.version)
        if not result or not result.get("id"):
            logger.info("No tasking diff available (not found, or no finalized config versions for this sensor)")
            return []
        soar.set_summary(
            SensorDiffSummary(
                version=result.get("version"),
                latest_version=result.get("latestVersion"),
                indicators_added=len(result.get("indicatorsAdded") or []),
                indicators_removed=len(result.get("indicatorsRemoved") or []),
                rules_added=len(result.get("rulesAdded") or []),
                rules_removed=len(result.get("rulesRemoved") or []),
            )
        )
        return [SensorDiffOutput(**result)]
    finally:
        client.close()


# =============================================================================
# View Handlers (defined in Lookup Actions section for action references)
# =============================================================================


# =============================================================================
# Entry Point
# =============================================================================

if __name__ == "__main__":
    app.cli()
