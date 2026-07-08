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
"""Batch check action: envelope parsing, input normalization, URL-length cap."""

from tests.conftest import BATCH_ERROR_VALUE, BATCH_NOMATCH_VALUE


def test_batch_check_happy_path(api, run_action):
    result = run_action("batch_check", {"values": "example.com,8.8.8.8"})

    assert result["status"] is True
    assert result["summary"] == {"total_values": 2, "total_results": 2}

    row, null_row = result["data"]
    assert row["searchedValue"] == "example.com"
    assert row["matchedValue"] == "example.com"
    assert row["id"] == 12345
    assert row["entity"] == {"key": "INDICATOR", "title": "Indicator"}
    assert row["type"] == {"key": "DOMAIN", "title": "Domain"}
    assert row["benign"] is False
    assert row["indicatorRiskScore"]["title"] == "Malicious"
    assert row["actor"] == [{"id": 2, "title": "TEST-ACTOR-BEAR", "akas": ["TEST-BEAR-AKA"]}]
    assert row["malware"] == [{"id": 7, "title": "TEST-MALWARE", "akas": []}]
    assert row["system"] == []
    # Live rows commonly carry null benign/indicatorRiskScore; both map to None.
    assert null_row["searchedValue"] == "8.8.8.8"
    assert null_row["benign"] is None
    assert null_row["indicatorRiskScore"] is None
    assert null_row["system"] is None

    (batch_request,) = api.api_requests("/batchCheck")
    assert batch_request["path"] == "/api/1_0/batchCheck"
    assert batch_request["params"]["values"] == "example.com,8.8.8.8"


def test_batch_check_newline_input_normalized(api, run_action):
    result = run_action("batch_check", {"values": "example.com\n 8.8.8.8 \n\nexample.org,\n"})

    assert result["status"] is True
    assert result["summary"]["total_values"] == 3
    (batch_request,) = api.api_requests("/batchCheck")
    assert batch_request["params"]["values"] == "example.com,8.8.8.8,example.org"


def test_batch_check_empty_values_fails(api, run_action):
    result = run_action("batch_check", {"values": "  , \n , "})

    assert result["status"] is False
    assert "No values provided" in result["message"]
    assert api.requests == []


def test_batch_check_url_length_cap_fails(api, run_action):
    values = ",".join(f"host-{i}.example.com" for i in range(400))  # > 6000 chars normalized
    result = run_action("batch_check", {"values": values})

    assert result["status"] is False
    assert "URL length limit" in result["message"]
    assert api.requests == []


def test_batch_check_no_matches(api, run_action):
    result = run_action("batch_check", {"values": BATCH_NOMATCH_VALUE})

    assert result["status"] is True
    assert result["data"] == []
    assert result["summary"] == {"total_values": 1, "total_results": 0}


def test_batch_check_api_error(api, run_action):
    result = run_action("batch_check", {"values": f"example.com,{BATCH_ERROR_VALUE}"})

    assert result["status"] is False
    assert "API error. Status: 500" in result["message"]
