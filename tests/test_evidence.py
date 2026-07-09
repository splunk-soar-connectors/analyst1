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
"""Evidence actions: upload_evidence_file, check_evidence_status, get_evidence pagination."""

import pytest

from tests.conftest import FAILED_INGEST_UUID, MISSING_STATUS_UUID


UPLOAD_PARAMS = {
    "evidence_file_classification": "unclass",
    "tlp": "amber",
    "source_id": 42,
    "source_title": "Unit Source",
    "source_url": "https://source.example.com/report",
}

UPLOAD_UUID = "11111111-2222-3333-4444-555555555555"


class TestUploadEvidenceFile:
    def test_success_sends_multipart_with_mapped_fields(self, api, run_action, vault_id):
        result = run_action("upload_evidence_file", {**UPLOAD_PARAMS, "vault_id": vault_id})

        assert result["status"] is True
        assert result["data"] == [{"uuid": UPLOAD_UUID}]
        assert result["summary"] == {"uuid": UPLOAD_UUID}

        (post_request,) = [r for r in api.requests if r["method"] == "POST"]
        assert post_request["path"] == "/api/1_0/evidence"
        body = post_request["content"]
        # The vault file itself is attached under the evidenceFile part.
        assert b'name="evidenceFile"' in body
        assert b'filename="unit_evidence.txt"' in body
        assert b"parity harness sample evidence file" in body
        # Params are translated through EVIDENCE_POST_FIELD_MAP to the API field names.
        for api_field, api_value in (
            (b"evidenceFileClassification", b"unclass"),
            (b"tlp", b"amber"),
            (b"sourceId", b"42"),
            (b"sourceTitle", b"Unit Source"),
            (b"sourceUrl", b"https://source.example.com/report"),
        ):
            assert b'name="' + api_field + b'"' in body
            assert api_value in body
        # Contributor fields were never exposed as action params (classic parity:
        # its field map defined them but analyst1.json never offered them, so
        # nothing was ever sent); the dead map entries were removed in 1.3.0.
        assert b"contibutorConsent" not in body
        assert b"contributorConsent" not in body
        assert b"contributorOrg" not in body
        # Falsy values are not sent (classic parity): default False stays home.
        assert b"disableIndicatorAutoEnrichment" not in body

    def test_missing_vault_id_fails_before_any_api_call(self, api, run_action):
        result = run_action("upload_evidence_file", {**UPLOAD_PARAMS, "vault_id": "no-such-vault-id"})

        assert result["status"] is False
        assert "File not found in vault: no-such-vault-id" in result["message"]
        assert api.requests == []


class TestCheckEvidenceStatus:
    def test_found(self, api, run_action):
        result = run_action("check_evidence_status", {"uuid": "abc-123-uuid"})

        assert result["status"] is True
        assert result["data"] == [{"message": "Evidence upload complete", "id": 777}]
        assert result["summary"] == {"message": "Evidence upload complete", "evidence_id": 777}
        (status_request,) = api.api_requests("/evidence/uploadStatus/")
        assert status_request["path"].endswith("/evidence/uploadStatus/abc-123-uuid")

    def test_not_found_passes_through_api_message(self, api, run_action):
        result = run_action("check_evidence_status", {"uuid": MISSING_STATUS_UUID})

        # A 404 body is passed through as the status message, not treated as an error.
        assert result["status"] is True
        assert result["data"] == [{"message": "The requested resource was not found.", "id": None}]
        assert result["summary"] == {"message": "The requested resource was not found.", "evidence_id": None}

    def test_still_processing_returns_null_id(self, api, run_action):
        # Per the OpenAPI spec, a 200 with a null id means ingest is still processing.
        api.evidence_status = {"id": None, "message": None}

        result = run_action("check_evidence_status", {"uuid": "abc-123-uuid"})

        assert result["status"] is True
        assert result["data"] == [{"message": None, "id": None}]
        assert result["summary"] == {"message": None, "evidence_id": None}

    def test_failed_ingest_204_reports_processing_failure(self, api, run_action):
        # Per the OpenAPI spec's 204 response description: "An error occurred
        # processing the Evidence. No Evidence record available." (spec-only;
        # never observed live). Must be distinguishable from still-processing.
        result = run_action("check_evidence_status", {"uuid": FAILED_INGEST_UUID})

        assert result["status"] is True
        assert result["data"] == [{"message": "Evidence processing failed (no evidence record available)", "id": None}]
        assert result["summary"] == {"message": "Evidence processing failed (no evidence record available)", "evidence_id": None}


class TestGetEvidence:
    def test_single_page(self, api, run_action):
        result = run_action("get_evidence", {"page": 2})

        assert result["status"] is True
        assert [item["id"] for item in result["data"]] == [103, 104]
        assert result["summary"] == {"page_requested": 2, "evidence_on_page": 2, "total_pages": 3, "total_results": 6}

        (list_request,) = api.evidence_list_requests
        assert list_request["params"]["page"] == "2"
        assert list_request["params"]["pageSize"] == "100"
        assert list_request["params"]["sortBy"] == "id"
        assert list_request["params"]["descSort"] == "true"

    def test_multi_page_pagination(self, api, run_action):
        result = run_action("get_evidence", {})

        assert result["status"] is True
        assert [item["id"] for item in result["data"]] == [101, 102, 103, 104, 105, 106]
        assert result["summary"] == {
            "total_evidence_retrieved": 6,
            "pages_processed": 3,
            "max_pages_limit": 10,
            "limited_by": "available_data",
        }
        assert [r["params"]["page"] for r in api.evidence_list_requests] == ["1", "2", "3"]

    def test_caps_at_ten_pages(self, api, run_action):
        api.evidence_synthetic_total_pages = 12  # more pages than the cap allows

        result = run_action("get_evidence", {})

        assert result["status"] is True
        assert [r["params"]["page"] for r in api.evidence_list_requests] == [str(page) for page in range(1, 11)]
        assert len(result["data"]) == 20  # 10 pages x 2 rows
        assert result["summary"]["pages_processed"] == 10
        assert result["summary"]["limited_by"] == "max_pages"
        assert "limited to 10 pages" in result["summary"]["note"]

    @pytest.mark.parametrize("page", [0, -1])
    def test_invalid_page_fails_without_api_call(self, api, run_action, page):
        result = run_action("get_evidence", {"page": page})

        assert result["status"] is False
        assert "Page must be greater than 0" in result["message"]
        assert api.requests == []
