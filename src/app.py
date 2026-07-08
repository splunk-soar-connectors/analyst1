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
"""Analyst1 SOAR App - SDK Version

This app implements investigative actions on the Analyst1 platform.
"""

import ipaddress
import json
from datetime import datetime, timedelta
from typing import Any

import httpx
from pydantic import field_validator
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput
from soar_sdk.app import App
from soar_sdk.asset import AssetField, BaseAsset
from soar_sdk.asset_state import AssetState
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params


logger = getLogger()

# =============================================================================
# Constants
# =============================================================================

ENRICHMENT_RESULTS_NAME_MAP = {
    "whoisDomainRegistration": "WHOIS Domain Registration",
    "whoisIPRegistration": "WHOIS IP Registration",
    "domainTools": "Domain Tools",
    "virusTotal": "VirusTotal",
    "deepSight": "DeepSight",
    "recordedfuture": "Recorded Future",
    "sansDshield": "SANS DShield",
    "shadowserver": "Shadowserver",
    "sipc": "Symantec SIPC",
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
    """API error from Analyst1."""


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
                error_msg += f", Response: {response.text}"
            except Exception:
                pass
            raise Analyst1APIError(error_msg)

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

    def indicator_match(self, value: str, indicator_type: str) -> dict[str, Any] | None:
        """Look up an indicator in Analyst1."""
        response = self.get("/indicator/match/", params={"value": value, "type": indicator_type})

        if not response or not response.get("id"):
            return None

        # Classic-app runtime decorations (analyst1_connector.py, release/1.2.1):
        # base_url for view rendering, actor links, and human-friendly
        # enrichment result names. Unlike classic, enrichmentResults[].result
        # is intentionally NOT json.loads()-ed into an object: the SDK output
        # contract types it as a string, so the raw JSON string is preserved
        # (documented delta, see release notes).
        response["base_url"] = self.base_url

        for actor in response.get("actors") or []:
            if (actor.get("id") or 0) > 1:
                actor["link"] = f"{self.base_url}/actors/{actor['id']}"

        for enrichment_result in response.get("enrichmentResults") or []:
            enrichment_type = enrichment_result.get("type", "")
            enrichment_result["name"] = ENRICHMENT_RESULTS_NAME_MAP.get(enrichment_type, enrichment_type)

        return response


# =============================================================================
# App Definition
# =============================================================================

app = App(
    name="Analyst1",
    app_type="information",
    logo="logo_analyst1.svg",
    logo_dark="logo_analyst1_dark.svg",
    product_vendor="Analyst1",
    product_name="Analyst1",
    publisher="Analyst1",
    appid="8ee822f1-a285-44f4-b8e7-303245811a32",
    min_phantom_version="7.0.0",
    fips_compliant=False,
    asset_cls=Asset,
)


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


class ClassifiedDate(ActionOutput):
    """A date with a classification (activityDates, reportedDates)."""

    classification: str | None = None
    date: str | None = None


class ClassifiedName(ActionOutput):
    """A name with a classification (description, fileNames, ipRegistration, ...)."""

    classification: str | None = None
    name: str | None = None


class ClassifiedIdName(ActionOutput):
    """An id/name pair with a classification (attackPatterns, targets, malwares)."""

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
    """Enrichment field; `nunmeric` reproduces the classic manifest's field name verbatim."""

    type: str | None = None
    value: str | None = None
    name: str | None = None
    nunmeric: str | None = None
    classification: str | None = None

    @field_validator("value", "nunmeric", mode="before")
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


class IndicatorValueOutput(ActionOutput):
    """The indicator value itself; per-action subclasses add the CEF type on `name`."""

    classification: str | None = None
    name: str | None = None


class IndicatorOutput(ActionOutput):
    """Output model for the nine indicator lookup actions (classic 76-datapath contract).

    Shape corrections vs the classic manifest (which declared these as flat
    strings, contradicting the API payloads the classic view rendered):
    `exploitStage`, `path` are objects and `originatingIps` is a list of
    objects; `hitCount` is numeric. `base_url`, `actors.*.link` and
    `enrichmentResults.*.name` are classic runtime decorations that classic
    emitted without declaring; the SDK declares everything it emits.
    `campaigns` and `indicatorRiskScore` are real API fields the classic view
    rendered/received but never declared.
    """

    active: bool | None = None
    activityDates: list[ClassifiedDate] | None = None
    actors: list[ActorOutput] | None = None
    attackPatterns: list[ClassifiedIdName] | None = None
    benign: BenignOutput | None = None
    confidenceLevel: ConfidenceLevelOutput | None = None
    description: ClassifiedName | None = None
    domainRegistration: str | None = None
    enrichmentFields: list[EnrichmentFieldOutput] | None = None
    enrichmentResults: list[EnrichmentResultOutput] | None = None
    exploitStage: ClassifiedName | None = None
    fileNames: list[ClassifiedName] | None = None
    fileSize: list[FileSizeOutput] | None = None
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

    @field_validator("domainRegistration", mode="before")
    @classmethod
    def _coerce_str(cls, value: Any) -> str | None:
        return _lenient_str(value)

    @field_validator("fileSize", mode="before")
    @classmethod
    def _wrap_file_size(cls, value: Any) -> Any:
        # Classic manifest declares fileSize as a list (fileSize.*.value);
        # tolerate a single object by wrapping it.
        if isinstance(value, dict):
            return [value]
        return value


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
    "fileSize",
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
        "title_logo": "logo_analyst1.svg",
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
# View Handlers (defined in Lookup Actions section for action references)
# =============================================================================


# =============================================================================
# Entry Point
# =============================================================================

if __name__ == "__main__":
    app.cli()
