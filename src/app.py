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
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.app import App
from soar_sdk.asset import AssetField, BaseAsset
from soar_sdk.asset_state import AssetState
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

        # Add base_url for view rendering
        response["base_url"] = self.base_url

        # Add actor links
        for actor in response.get("actors", []):
            if actor.get("id", 0) > 1:
                actor["link"] = f"{self.base_url}/actors/{actor['id']}"

        # Add human-friendly enrichment result names
        for enrichment_result in response.get("enrichmentResults", []):
            enrichment_result["name"] = ENRICHMENT_RESULTS_NAME_MAP.get(enrichment_result["type"], enrichment_result["type"])
            if enrichment_result.get("format") == "json":
                try:
                    enrichment_result["result"] = json.loads(enrichment_result["result"])
                except Exception:
                    pass

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
# =============================================================================


class IndicatorOutput(ActionOutput):
    """Output model for indicator lookup actions."""

    # Indicator found flag
    found: bool = True
    message: str = ""

    # Primary indicator fields
    id: int | None = None
    type: str | None = None
    active: bool | None = None
    verified: bool | None = None
    tasked: bool | None = None
    reportCount: int | None = None
    hitCount: int | None = None
    firstHit: str | None = None
    lastHit: str | None = None
    status: str | None = None
    tlp: str | None = None
    base_url: str | None = None

    # Value as string (the actual indicator value)
    indicator_value: str | None = None

    # Complex data stored as JSON strings for downstream processing
    raw_data: str | None = None  # Full API response as JSON


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
        cef_types=["hash", "sha256", "sha1", "md5"],
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
        cef_types=["ipv6"],
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


def _safe_bool(value: Any) -> bool | None:
    """Safely convert value to bool, returning None if not possible."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in ("true", "1", "yes")
    try:
        return bool(value)
    except (ValueError, TypeError):
        return None


def _do_indicator_lookup(asset: Asset, value: str, indicator_type: str) -> IndicatorOutput:
    """Common logic for indicator lookups."""
    client = Analyst1Client(asset, asset.auth_state)
    try:
        result = client.indicator_match(value, indicator_type)
        if result:
            # Extract value string from nested object
            value_obj = result.get("value", {})
            if isinstance(value_obj, dict):
                indicator_value = value_obj.get("name") or value_obj.get("value", "")
            else:
                indicator_value = str(value_obj) if value_obj else ""

            return IndicatorOutput(
                found=True,
                id=_safe_int(result.get("id")),
                type=_safe_str(result.get("type")),
                active=_safe_bool(result.get("active")),
                verified=_safe_bool(result.get("verified")),
                tasked=_safe_bool(result.get("tasked")),
                reportCount=_safe_int(result.get("reportCount")),
                hitCount=_safe_int(result.get("hitCount")),
                firstHit=_safe_str(result.get("firstHit")),
                lastHit=_safe_str(result.get("lastHit")),
                status=_safe_str(result.get("status")),
                tlp=_safe_str(result.get("tlp")),
                base_url=_safe_str(result.get("base_url")),
                indicator_value=_safe_str(indicator_value),
                raw_data=json.dumps(result),
            )
        return IndicatorOutput(found=False, message="Indicator not found in Analyst1")
    finally:
        client.close()


@app.view_handler(template="display_indicators.html")
def display_indicators_view(outputs: list[IndicatorOutput]) -> dict:
    """Custom view handler for displaying indicator results.

    This function prepares data for the display_indicators.html template.
    The SDK automatically parses action results into IndicatorOutput objects.

    Args:
        outputs: List of IndicatorOutput objects from action results

    Returns:
        Dictionary with results formatted for the template
    """
    results = []

    for output in outputs:
        # Parse the raw_data JSON to get the full API response for the template
        data_list = []
        if output.raw_data:
            try:
                indicator_data = json.loads(output.raw_data)
                data_list.append(indicator_data)
            except (json.JSONDecodeError, TypeError):
                pass

        results.append(
            {
                "param": {"indicator": output.indicator_value},
                "data": data_list,
                "found": output.found,
                "message": output.message,
            }
        )

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
)
def lookup_domain(params: LookupDomainParams, soar: SOARClient, asset: Asset) -> IndicatorOutput:
    """Look up a domain in Analyst1."""
    logger.info(f"Looking up domain: {params.domain}")
    return _do_indicator_lookup(asset, params.domain, "domain")


@app.action(
    description="Check for the presence of an email in the Analyst1 platform",
    action_type="investigate",
    view_handler=display_indicators_view,
)
def lookup_email(params: LookupEmailParams, soar: SOARClient, asset: Asset) -> IndicatorOutput:
    """Look up an email in Analyst1."""
    logger.info(f"Looking up email: {params.email}")
    return _do_indicator_lookup(asset, params.email, "email")


@app.action(
    description="Check for the presence of a hash in the Analyst1 platform",
    action_type="investigate",
    view_handler=display_indicators_view,
)
def lookup_hash(params: LookupHashParams, soar: SOARClient, asset: Asset) -> IndicatorOutput:
    """Look up a file hash in Analyst1."""
    logger.info(f"Looking up hash: {params.hash}")
    return _do_indicator_lookup(asset, params.hash, "file")


@app.action(
    description="Check for the presence of a string in the Analyst1 platform",
    action_type="investigate",
    view_handler=display_indicators_view,
)
def lookup_string(params: LookupStringParams, soar: SOARClient, asset: Asset) -> IndicatorOutput:
    """Look up a string in Analyst1."""
    logger.info(f"Looking up string: {params.string}")
    return _do_indicator_lookup(asset, params.string, "string")


@app.action(
    description="Check for the presence of an IP in the Analyst1 platform",
    action_type="investigate",
    view_handler=display_indicators_view,
)
def lookup_ip(params: LookupIpParams, soar: SOARClient, asset: Asset) -> IndicatorOutput:
    """Look up an IP address in Analyst1."""
    logger.info(f"Looking up IP: {params.ip}")
    # Determine if IPv4 or IPv6
    try:
        ip_obj = ipaddress.ip_address(params.ip)
        indicator_type = "ip" if ip_obj.version == 4 else "ipv6"
    except ValueError:
        indicator_type = "ip"
    return _do_indicator_lookup(asset, params.ip, indicator_type)


@app.action(
    description="Check for the presence of an IPv6 in the Analyst1 platform",
    action_type="investigate",
    view_handler=display_indicators_view,
)
def lookup_ipv6(params: LookupIpv6Params, soar: SOARClient, asset: Asset) -> IndicatorOutput:
    """Look up an IPv6 address in Analyst1."""
    logger.info(f"Looking up IPv6: {params.ipv6}")
    return _do_indicator_lookup(asset, params.ipv6, "ipv6")


@app.action(
    description="Check for the presence of a URL in the Analyst1 platform",
    action_type="investigate",
    view_handler=display_indicators_view,
)
def lookup_url(params: LookupUrlParams, soar: SOARClient, asset: Asset) -> IndicatorOutput:
    """Look up a URL in Analyst1."""
    logger.info(f"Looking up URL: {params.url}")
    return _do_indicator_lookup(asset, params.url, "url")


@app.action(
    description="Check for the presence of a mutex in the Analyst1 platform",
    action_type="investigate",
    view_handler=display_indicators_view,
)
def lookup_mutex(params: LookupMutexParams, soar: SOARClient, asset: Asset) -> IndicatorOutput:
    """Look up a mutex in Analyst1."""
    logger.info(f"Looking up mutex: {params.mutex}")
    return _do_indicator_lookup(asset, params.mutex, "mutex")


@app.action(
    description="Check for the presence of an HTTP request in the Analyst1 platform",
    action_type="investigate",
    view_handler=display_indicators_view,
)
def lookup_http_request(params: LookupHttpRequestParams, soar: SOARClient, asset: Asset) -> IndicatorOutput:
    """Look up an HTTP request in Analyst1."""
    logger.info(f"Looking up HTTP request: {params.http_request}")
    return _do_indicator_lookup(asset, params.http_request, "httpRequest")


# =============================================================================
# Evidence Actions
# =============================================================================


class UploadEvidenceFileParams(Params):
    vault_id: str = Param(
        description="Phantom vault ID of file",
        primary=True,
        default="",
        cef_types=["vault id"],
    )
    evidence_file_classification: str = Param(
        description="The evidence file's classification.",
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
        description="The evidence file's TLP designation.",
        default="undetermined",
        value_list=["undetermined", "white", "green", "amber", "red"],
    )
    source_id: int = Param(
        description="The evidence file's source ID number.",
        required=False,
        default=0,
    )
    source_title: str = Param(
        description="The evidence file's source name.",
        required=False,
        default="",
    )
    source_url: str = Param(
        description="The evidence file's source URL.",
        required=False,
        default="",
    )
    disable_indicator_auto_enrichment: bool = Param(
        description="Disable automated enrichment during ingest.",
        required=False,
        default=False,
    )


class UploadEvidenceFileOutput(ActionOutput):
    uuid: str = OutputField(cef_types=["analyst1 evidence upload key"])


@app.action(
    description="Upload file from vault to Analyst1 as evidence file",
    action_type="generic",
    read_only=False,
)
def upload_evidence_file(params: UploadEvidenceFileParams, soar: SOARClient, asset: Asset) -> UploadEvidenceFileOutput:
    """Upload a file from the vault to Analyst1 as evidence."""
    logger.info(f"Uploading evidence file from vault: {params.vault_id}")

    # Get file info from vault
    attachments = soar.vault.get_attachment(vault_id=params.vault_id)
    if not attachments:
        raise Analyst1Error(f"File not found in vault: {params.vault_id}")
    vault_info = attachments[0]

    # Build form data
    data = {}
    param_dict = params.model_dump()
    for param_key, api_key in EVIDENCE_POST_FIELD_MAP.items():
        value = param_dict.get(param_key)
        if value is not None and value != "":
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
    message: str = ""
    id: int | None = None


@app.action(
    description="Check the status of an evidence file upload",
    action_type="generic",
)
def check_evidence_status(params: CheckEvidenceStatusParams, soar: SOARClient, asset: Asset) -> CheckEvidenceStatusOutput:
    """Check the status of an evidence file upload."""
    logger.info(f"Checking evidence status for UUID: {params.uuid}")

    client = Analyst1Client(asset, asset.auth_state)
    try:
        response = client.get(f"/evidence/uploadStatus/{params.uuid}")
        return CheckEvidenceStatusOutput(
            message=_safe_str(response.get("message")) or "",
            id=_safe_int(response.get("id")),
        )
    finally:
        client.close()


class GetEvidenceParams(Params):
    page: int = Param(
        description="The specific page number to retrieve (1-indexed). Use 0 for all pages.",
        required=False,
        default=0,
    )
    desc_sort: bool = Param(
        description="Sort direction. True for descending, false for ascending.",
        required=False,
        default=True,
    )
    sort_by: str = Param(
        description="The value to sort results on.",
        required=False,
        default="id",
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
    evidence_type: str = Param(
        description="Filter results based on evidence type. Leave empty for all types.",
        required=False,
        default="",
        value_list=[
            "",
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
        description="Filter by indicators verified date from (ISO-8601).",
        required=False,
        default="",
    )
    indicators_verified_date_to: str = Param(
        description="Filter by indicators verified date to (ISO-8601).",
        required=False,
        default="",
    )
    analyzed_date_from: str = Param(
        description="Filter by analyzed date from (ISO-8601).",
        required=False,
        default="",
    )
    analyzed_date_to: str = Param(
        description="Filter by analyzed date to (ISO-8601).",
        required=False,
        default="",
    )
    nominated_for_incident: bool = Param(
        description="Filter by Nominated for Incident Response State.",
        required=False,
        default=False,
    )
    nominated_for_report: bool = Param(
        description="Filter by Nominated for Report State.",
        required=False,
        default=False,
    )


class EvidenceItemOutput(ActionOutput):
    """Single evidence item."""

    id: int
    title: str | None = None
    type: str | None = None
    tlp: str | None = None
    analyzedDate: str | None = None


class GetEvidenceOutput(ActionOutput):
    """Output for get_evidence action."""

    evidence_json: str = ""  # JSON string containing the evidence list
    total_retrieved: int = 0
    pages_processed: int = 0


@app.action(
    description="Browse and fetch evidence resources.",
    action_type="investigate",
)
def get_evidence(params: GetEvidenceParams, soar: SOARClient, asset: Asset) -> GetEvidenceOutput:
    """Get evidence resources with pagination support."""
    logger.info("Fetching evidence resources")

    client = Analyst1Client(asset, asset.auth_state)
    try:
        # Build parameters
        api_params: dict[str, Any] = {
            "descSort": params.desc_sort,
            "sortBy": params.sort_by,
            "pageSize": 100,
        }

        if params.evidence_type:
            api_params["type"] = params.evidence_type
        if params.analyzed_date_from:
            api_params["analyzedDateFrom"] = params.analyzed_date_from
        if params.analyzed_date_to:
            api_params["analyzedDateTo"] = params.analyzed_date_to
        if params.indicators_verified_date_from:
            api_params["indicatorsVerifiedDateFrom"] = params.indicators_verified_date_from
        if params.indicators_verified_date_to:
            api_params["indicatorsVerifiedDateTo"] = params.indicators_verified_date_to
        if params.nominated_for_incident:
            api_params["nominatedForIncident"] = params.nominated_for_incident
        if params.nominated_for_report:
            api_params["nominatedForReport"] = params.nominated_for_report

        # Determine pagination mode (0 = all pages up to limit)
        if params.page > 0:
            api_params["page"] = params.page
            max_pages = 1
            start_page = params.page
        else:
            api_params["page"] = 1
            max_pages = 10  # Limit to 10 pages (1000 items)
            start_page = 1

        all_evidence: list[dict] = []
        current_page = start_page
        pages_processed = 0

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
            if params.page > 0:
                break

            # Check if last page
            total_pages = response.get("totalPages", 1)
            if current_page >= total_pages:
                break

            current_page += 1

        logger.info(f"Total evidence retrieved: {len(all_evidence)}")
        return GetEvidenceOutput(
            evidence_json=json.dumps(all_evidence),
            total_retrieved=len(all_evidence),
            pages_processed=pages_processed,
        )
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
