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
"""By-id actions: get_indicator_by_id (lookup contract reuse), get_actor_by_id, get_malware_by_id."""

import pytest

from tests.conftest import ACTOR_ID, BASE_URL, BY_ID_ERROR_ID, MALWARE_ID, MATCH_INDICATOR_ID


class TestGetIndicatorById:
    def test_happy_path(self, api, run_action):
        result = run_action("get_indicator_by_id", {"indicator_id": str(MATCH_INDICATOR_ID)})

        assert result["status"] is True
        assert result["summary"] == {"id": MATCH_INDICATOR_ID}
        (record,) = result["data"]
        assert record["id"] == MATCH_INDICATOR_ID
        # The lookup runtime decorations apply identically to by-id fetches.
        assert record["base_url"] == BASE_URL
        actors = {actor["id"]: actor for actor in record["actors"]}
        assert actors[2]["link"] == f"{BASE_URL}/actors/2"
        assert actors[1]["link"] is None  # id 1 = Unattributed: never decorated
        names = {er["type"]: er["name"] for er in record["enrichmentResults"]}
        assert names["VIRUS_TOTAL"] == "VirusTotal"

        (by_id_request,) = api.api_requests("/indicator/")
        assert by_id_request["path"].endswith(f"/indicator/{MATCH_INDICATOR_ID}")

    def test_hash_suffix_stripped(self, api, run_action):
        result = run_action("get_indicator_by_id", {"indicator_id": f"{MATCH_INDICATOR_ID}-md5"})

        assert result["status"] is True
        assert result["summary"] == {"id": MATCH_INDICATOR_ID}
        (by_id_request,) = api.api_requests("/indicator/")
        assert by_id_request["path"].endswith(f"/indicator/{MATCH_INDICATOR_ID}")

    def test_not_found(self, api, run_action):
        result = run_action("get_indicator_by_id", {"indicator_id": "99999"})

        assert result["status"] is True
        assert result["data"] == []
        assert result["summary"] == {}


class TestGetActorById:
    def test_happy_path(self, api, run_action):
        result = run_action("get_actor_by_id", {"actor_id": ACTOR_ID})

        assert result["status"] is True
        assert result["summary"] == {"id": ACTOR_ID}
        (record,) = result["data"]
        assert record["id"] == ACTOR_ID
        assert record["title"] == {"name": "TEST-ACTOR-BEAR", "classification": "U"}
        # country/sponsor/primaryMotivation are {id, name, classification} triples.
        assert record["country"] == {"id": 3, "name": "Testland", "classification": "U"}
        assert record["sponsor"]["id"] == 5
        assert record["primaryMotivation"]["name"] == "Espionage"
        assert record["activityRange"]["startDate"] == "2020-01-01"
        assert record["campaigns"][0]["id"] == 11
        assert record["akas"][0]["name"] == "TEST-BEAR-AKA"
        # 1_1 object-form links are normalized to the classic {rel, href} list.
        assert record["links"] == [
            {"rel": "self", "href": "https://analyst1.example.com/api/1_1/actor/7"},
            {"rel": "evidence", "href": "https://analyst1.example.com/api/1_1/actor/7/evidence"},
        ]

        (by_id_request,) = api.api_requests("/actor/")
        assert by_id_request["path"].endswith(f"/actor/{ACTOR_ID}")

    def test_not_found(self, api, run_action):
        result = run_action("get_actor_by_id", {"actor_id": 99999})

        assert result["status"] is True
        assert result["data"] == []
        assert result["summary"] == {}


class TestGetMalwareById:
    def test_happy_path(self, api, run_action):
        result = run_action("get_malware_by_id", {"malware_id": MALWARE_ID})

        assert result["status"] is True
        assert result["summary"] == {"id": MALWARE_ID}
        (record,) = result["data"]
        assert record["id"] == MALWARE_ID
        assert record["title"]["name"] == "TEST-MALWARE-FAMILY"
        # category/stage are {id, name, classification} triples.
        assert record["category"] == {"id": 4, "name": "Trojan", "classification": "U"}
        assert record["stage"]["id"] == 6
        assert record["akas"][0]["name"] == "TEST-MALWARE-AKA"
        assert record["stixObjects"][0]["id"] == "malware--00000000-0000-0000-0000-000000000001"
        assert record["links"][0] == {"rel": "self", "href": "https://analyst1.example.com/api/1_1/malware/55"}

    def test_not_found(self, api, run_action):
        result = run_action("get_malware_by_id", {"malware_id": 99999})

        assert result["status"] is True
        assert result["data"] == []
        assert result["summary"] == {}


@pytest.mark.parametrize(
    ("identifier", "params"),
    [
        ("get_indicator_by_id", {"indicator_id": str(BY_ID_ERROR_ID)}),
        ("get_actor_by_id", {"actor_id": BY_ID_ERROR_ID}),
        ("get_malware_by_id", {"malware_id": BY_ID_ERROR_ID}),
    ],
)
def test_by_id_api_error(api, run_action, identifier, params):
    result = run_action(identifier, params)

    assert result["status"] is False
    assert "API error. Status: 500" in result["message"]
