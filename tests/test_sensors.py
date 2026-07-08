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
"""Sensor actions: get_sensors pagination, taskings, config-to-vault, diff (incl. no-finalized-versions 500)."""

import json

import app as analyst1_app
from tests.conftest import ERROR_SENSOR_ID, MISSING_SENSOR_ID, NO_FINALIZED_SENSOR_ID, SENSOR_ID


class TestGetSensors:
    def test_single_page(self, api, run_action):
        result = run_action("get_sensors", {"page": 1})

        assert result["status"] is True
        assert [row["id"] for row in result["data"]] == [401, 402]
        assert result["summary"] == {"total_sensors": 2, "pages_processed": 1, "total_pages": 2}

        row = result["data"][0]
        assert row["name"] == "TEST-SENSOR-EDGE"
        assert row["org"] == {"id": 9, "name": "Test Org"}
        # `_links` is renamed to `links` and normalized to the classic {rel, href} list.
        assert row["links"] == [{"rel": "details", "href": "https://analyst1.example.com/api/1_1/sensors/401"}]
        # A row with null org/logicalLocation validates to None.
        null_row = result["data"][1]
        assert null_row["org"] is None
        assert null_row["logicalLocation"] is None

        (list_request,) = api.sensors_list_requests
        assert list_request["params"]["page"] == "1"
        assert list_request["params"]["pageSize"] == "50"
        assert list_request["params"]["sortBy"] == "id"
        assert list_request["params"]["descSort"] == "false"

    def test_auto_paginates_to_total_pages(self, api, run_action):
        result = run_action("get_sensors", {})

        assert result["status"] is True
        assert [row["id"] for row in result["data"]] == [401, 402, 403]
        assert result["summary"] == {"total_sensors": 3, "pages_processed": 2, "total_pages": 2}
        assert [r["params"]["page"] for r in api.sensors_list_requests] == ["1", "2"]

    def test_auto_pagination_caps_at_ten_pages(self, api, run_action):
        api.sensors_synthetic_total_pages = 12  # more pages than the cap allows

        result = run_action("get_sensors", {})

        assert result["status"] is True
        assert [r["params"]["page"] for r in api.sensors_list_requests] == [str(page) for page in range(1, 11)]
        assert len(result["data"]) == 20  # 10 pages x 2 rows
        assert result["summary"] == {"total_sensors": 20, "pages_processed": 10, "total_pages": 12}

    def test_page_zero_fails_without_api_call(self, api, run_action):
        result = run_action("get_sensors", {"page": 0})

        assert result["status"] is False
        assert "Page must be greater than 0" in result["message"]
        assert api.requests == []

    def test_empty_results(self, api, run_action):
        api.sensors_synthetic_total_pages = 0

        result = run_action("get_sensors", {})

        assert result["status"] is True
        assert result["data"] == []
        assert result["summary"] == {"total_sensors": 0, "pages_processed": 1, "total_pages": 0}


class TestGetSensorTaskings:
    def test_happy_path(self, api, run_action):
        result = run_action("get_sensor_taskings", {"sensor_id": SENSOR_ID})

        assert result["status"] is True
        assert result["summary"] == {"version": 4, "indicator_count": 2, "rule_count": 1}
        (record,) = result["data"]
        assert record["id"] == SENSOR_ID
        assert record["version"] == 4
        assert record["indicators"][0]["value"] == "198.51.100.7"
        # fileHashes arrives as an object keyed by algo; kept as a JSON string.
        assert json.loads(record["indicators"][1]["fileHashes"])["MD5"] == "00000000000000000000000000000001"
        assert record["rules"][0]["signature"].startswith("alert tcp")
        assert record["links"] == [{"rel": "self", "href": "https://analyst1.example.com/api/1_1/sensors/401/taskings"}]

        # The client forwards the extended XSOAR-parity timeout.
        (taskings_request,) = api.api_requests("/taskings")
        assert taskings_request["path"].endswith(f"/sensors/{SENSOR_ID}/taskings")
        assert taskings_request["timeout"]["read"] == 200.0

    def test_not_found(self, api, run_action):
        result = run_action("get_sensor_taskings", {"sensor_id": MISSING_SENSOR_ID})

        assert result["status"] is True
        assert result["data"] == []
        assert result["summary"] == {}


class TestGetSensorConfig:
    def test_writes_vault(self, api, run_action, mocker):
        soar_client = analyst1_app.app.soar_client
        create_spy = mocker.spy(soar_client.vault, "create_attachment")

        result = run_action("get_sensor_config", {"sensor_id": SENSOR_ID})

        assert result["status"] is True
        (record,) = result["data"]
        assert record["sensor_id"] == SENSOR_ID
        assert record["file_name"] == f"sensor{SENSOR_ID}Config.txt"
        assert record["config_text"] == api.sensor_config_text
        assert record["vault_id"]
        assert result["summary"] == {"vault_id": record["vault_id"], "file_name": f"sensor{SENSOR_ID}Config.txt"}

        create_spy.assert_called_once_with(soar_client.get_executing_container_id(), api.sensor_config_text, f"sensor{SENSOR_ID}Config.txt")
        # The local fallback vault is process-global; drop the attachment again.
        soar_client.vault.delete_attachment(vault_id=record["vault_id"])

    def test_not_found_skips_vault(self, api, run_action, mocker):
        create_spy = mocker.spy(analyst1_app.app.soar_client.vault, "create_attachment")

        result = run_action("get_sensor_config", {"sensor_id": MISSING_SENSOR_ID})

        assert result["status"] is True
        assert result["data"] == []
        assert result["summary"] == {}
        create_spy.assert_not_called()

    def test_api_error(self, api, run_action):
        result = run_action("get_sensor_config", {"sensor_id": ERROR_SENSOR_ID})

        assert result["status"] is False
        assert "API error. Status: 500" in result["message"]


class TestGetSensorDiff:
    def test_happy_path(self, api, run_action):
        result = run_action("get_sensor_diff", {"sensor_id": SENSOR_ID, "version": 2})

        assert result["status"] is True
        assert result["summary"] == {
            "version": 2,
            "latest_version": 4,
            "indicators_added": 1,
            "indicators_removed": 1,
            "rules_added": 1,
            "rules_removed": 0,
        }
        (record,) = result["data"]
        assert record["id"] == SENSOR_ID
        assert record["latestVersion"] == 4
        assert record["indicatorsAdded"][0]["value"] == "added.example.com"
        assert record["indicatorsRemoved"][0]["value"] == "198.51.100.7"
        assert record["rulesAdded"][0]["signature"].startswith("alert udp")
        assert record["rulesRemoved"] == []

        # The client forwards the extended XSOAR-parity timeout.
        (diff_request,) = api.api_requests("/taskings/diff/")
        assert diff_request["path"].endswith(f"/sensors/{SENSOR_ID}/taskings/diff/2")
        assert diff_request["timeout"]["read"] == 200.0

    def test_not_found(self, api, run_action):
        result = run_action("get_sensor_diff", {"sensor_id": MISSING_SENSOR_ID, "version": 2})

        assert result["status"] is True
        assert result["data"] == []
        assert result["summary"] == {}

    def test_no_finalized_versions_is_not_an_error(self, api, run_action):
        # A config-less sensor answers HTTP 500 "No finalized versions found..."
        # (verified live); the client swallows it and the action succeeds empty.
        result = run_action("get_sensor_diff", {"sensor_id": NO_FINALIZED_SENSOR_ID, "version": 1})

        assert result["status"] is True
        assert result["data"] == []
        assert result["summary"] == {}

    def test_other_api_error_propagates(self, api, run_action):
        # A 500 with any other message must fail the action (guards the narrow catch).
        result = run_action("get_sensor_diff", {"sensor_id": ERROR_SENSOR_ID, "version": 1})

        assert result["status"] is False
        assert "API error. Status: 500" in result["message"]
