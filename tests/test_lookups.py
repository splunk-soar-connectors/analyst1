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
"""The nine indicator lookup actions: found/not-found, runtime decorations, 1_1 payloads."""

import copy
import json

import pytest

from tests.conftest import BASE_URL, SYNTH_EMAIL, SYNTH_SHA256, oauth_asset


# (identifier, params, expected `type` query param) -- includes both lookup_ip branches.
FOUND_CASES = [
    ("lookup_domain", {"domain": "test.com"}, "domain"),
    ("lookup_email", {"email": "bad@example.com"}, "email"),
    ("lookup_hash", {"hash": "1111111111111111111111111111111111111111111111111111111111111111"}, "file"),
    ("lookup_ip", {"ip": "198.51.100.7"}, "ip"),
    ("lookup_ip", {"ip": "2001:db8::7"}, "ipv6"),
    ("lookup_ipv6", {"ipv6": "2001:db8::7"}, "ipv6"),
    ("lookup_url", {"url": "http://test.com/x"}, "url"),
    ("lookup_mutex", {"mutex": "Global\\mockmutex"}, "mutex"),
    ("lookup_string", {"string": "mockstring"}, "string"),
    ("lookup_http_request", {"http_request": "GET /index.html"}, "httpRequest"),
]

NOTFOUND_CASES = [
    ("lookup_domain", {"domain": "missing.com"}),
    ("lookup_email", {"email": "missing@example.com"}),
    ("lookup_hash", {"hash": "0000000000000000000000000000000000000000000000000000000000000000"}),
    ("lookup_ip", {"ip": "198.51.100.99"}),
    ("lookup_ipv6", {"ipv6": "2001:db8::99"}),
    ("lookup_url", {"url": "http://missing.example.com/x"}),
    ("lookup_mutex", {"mutex": "Global\\missingmutex"}),
    ("lookup_string", {"string": "missing-string"}),
    ("lookup_http_request", {"http_request": "GET /missing.html"}),
]


def _case_id(case: tuple) -> str:
    identifier, params = case[0], case[1]
    return f"{identifier}[{next(iter(params))}={next(iter(params.values()))}]"


@pytest.mark.parametrize(("identifier", "params", "expected_type"), FOUND_CASES, ids=[_case_id(c) for c in FOUND_CASES])
def test_lookup_found(api, run_action, identifier, params, expected_type):
    result = run_action(identifier, params)

    assert result["status"] is True
    assert len(result["data"]) == 1
    record = result["data"][0]
    assert record["id"] == 12345
    assert record["base_url"] == BASE_URL
    assert result["summary"] == {"id": 12345}

    (match_request,) = api.api_requests("/indicator/match")
    assert "/api/1_0/indicator/match/" in match_request["path"]
    assert match_request["params"]["type"] == expected_type
    assert match_request["params"]["value"] == next(iter(params.values()))


@pytest.mark.parametrize(("identifier", "params"), NOTFOUND_CASES, ids=[_case_id(c) for c in NOTFOUND_CASES])
def test_lookup_not_found(api, run_action, identifier, params):
    result = run_action(identifier, params)

    # Classic parity: a 404 from /indicator/match is a successful no-match run.
    assert result["status"] is True
    assert result["data"] == []
    assert result["summary"] == {}


def test_lookup_ip_invalid_value_fails_without_api_call(api, run_action):
    result = run_action("lookup_ip", {"ip": "not-an-ip"})

    assert result["status"] is False
    assert "does not appear to be an IPv4 or IPv6 address" in result["message"]
    assert api.requests == []


class TestLookupDomainDecorations:
    def test_actor_link_only_for_id_greater_than_one(self, api, run_action):
        result = run_action("lookup_domain", {"domain": "test.com"})

        actors = {actor["id"]: actor for actor in result["data"][0]["actors"]}
        assert actors[2]["link"] == f"{BASE_URL}/actors/2"
        assert actors[1]["link"] is None  # id 1 = Unattributed: never decorated

    def test_enrichment_friendly_name_mapping(self, api, run_action):
        result = run_action("lookup_domain", {"domain": "test.com"})

        names = {er["type"]: er["name"] for er in result["data"][0]["enrichmentResults"]}
        assert names["VIRUS_TOTAL"] == "VirusTotal"
        assert names["WHOIS_DOMAIN_REGISTRATION"] == "WHOIS Domain Registration"

    def test_enrichment_unknown_type_echoed_as_name(self, api, run_action):
        payload = copy.deepcopy(api.match_default)
        payload["enrichmentResults"] = [{"date": "2026-01-02", "format": "json", "type": "SOME_FUTURE_SOURCE", "result": "{}"}]
        api.match_map["unknown-enrich.example.com"] = payload

        result = run_action("lookup_domain", {"domain": "unknown-enrich.example.com"})

        (enrichment,) = result["data"][0]["enrichmentResults"]
        assert enrichment["name"] == "SOME_FUTURE_SOURCE"

    def test_enrichment_result_stays_raw_json_string(self, api, run_action):
        # Documented delta vs classic: json-format results are NOT parsed to an object.
        result = run_action("lookup_domain", {"domain": "test.com"})

        json_result = result["data"][0]["enrichmentResults"][0]["result"]
        assert isinstance(json_result, str)
        assert json.loads(json_result) == {"positives": 12, "total": 70}

    def test_1_0_payload_leaves_1_1_fields_none(self, api, run_action):
        result = run_action("lookup_domain", {"domain": "test.com"})

        record = result["data"][0]
        for field in ("activityRange", "reportedRange", "verifiedDateRange", "sources", "tags", "externalhitCount", "hitStatDetails"):
            assert record[field] is None, field


class TestLookupReal11Payloads:
    def test_lookup_hash_real_file_payload_oauth(self, api, run_action):
        result = run_action("lookup_hash", {"hash": SYNTH_SHA256}, asset=oauth_asset())

        assert result["status"] is True
        assert result["summary"] == {"id": 90000948}
        (match_request,) = api.api_requests("/indicator/match")
        assert "/api/1_1/indicator/match/" in match_request["path"]
        assert match_request["headers"]["authorization"] == "Bearer unit-token-1"

        record = result["data"][0]
        assert record["id"] == 90000948
        # 1_1 object-form links are normalized to the classic {rel, href} list, order preserved.
        assert record["links"] == [
            {"rel": "self", "href": "https://analyst1.example.com/api/1_1/indicator/90000948"},
            {"rel": "evidence", "href": "https://analyst1.example.com/api/1_1/indicator/90000948/evidence"},
            {"rel": "stix", "href": "https://analyst1.example.com/api/1_1/indicator/90000948/stix"},
        ]
        # 1_1-only fields populate from the real payload.
        assert record["externalhitCount"] == 0
        assert record["sources"][0]["id"] == 173
        assert [tag["id"] for tag in record["tags"]] == [257, 148, 265]
        assert record["fileSize"] == {"value": 157732, "classification": "U"}
        assert record["activityRange"] == {"classification": "U", "startDate": None, "endDate": None}
        assert record["verifications"][0]["evidenceId"] == 555
        assert record["stixObjects"][0]["reportingSourceId"] == 173
        # Live-evidenced 3-level hitStatDetails nesting survives the typed model.
        dimension_value = record["hitStatDetails"][0]["dimensions"][0]["dimensionValues"][0]
        assert dimension_value == {"id": 6001, "label": "value-a", "firstHit": "2024-09-11", "lastHit": "2024-09-11", "totalHits": 2}

    def test_lookup_email_real_payload_oauth(self, api, run_action):
        result = run_action("lookup_email", {"email": SYNTH_EMAIL}, asset=oauth_asset())

        assert result["status"] is True
        assert result["summary"] == {"id": 90000036}
        record = result["data"][0]
        assert record["id"] == 90000036
        assert record["activityRange"] == {"classification": "U", "startDate": "2026-06-27", "endDate": "2026-06-27"}
        assert record["tasked"] is True
        # Actor decoration also applies under the 1_1 serialization.
        assert record["actors"][0]["link"] == f"{BASE_URL}/actors/9001"
        assert record["links"][0] == {"rel": "self", "href": "https://analyst1.example.com/api/1_1/indicator/90000036"}
