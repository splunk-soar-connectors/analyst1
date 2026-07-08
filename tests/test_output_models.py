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
"""Direct output-model tests: the links normalizer and fixture round-trips."""

import pytest

import app as analyst1_app
from tests.conftest import load_fixture


class TestNormalizeLinks:
    def test_object_form_becomes_ordered_rel_href_list(self):
        links = {
            "self": {"href": "https://analyst1.example.com/api/1_1/indicator/1"},
            "evidence": {"href": "https://analyst1.example.com/api/1_1/indicator/1/evidence"},
            "stix": {"href": "https://analyst1.example.com/api/1_1/indicator/1/stix"},
        }

        output = analyst1_app.IndicatorOutput.model_validate({"links": links})

        assert [(link.rel, link.href) for link in output.links] == [
            ("self", "https://analyst1.example.com/api/1_1/indicator/1"),
            ("evidence", "https://analyst1.example.com/api/1_1/indicator/1/evidence"),
            ("stix", "https://analyst1.example.com/api/1_1/indicator/1/stix"),
        ]

    def test_list_form_passes_through_unchanged(self):
        links = [{"rel": "self", "href": "https://analyst1.example.com/api/1_0/indicator/1", "hreflang": None, "media": None}]

        output = analyst1_app.IndicatorOutput.model_validate({"links": links})

        assert len(output.links) == 1
        assert output.links[0].rel == "self"
        assert output.links[0].href == "https://analyst1.example.com/api/1_0/indicator/1"

    def test_none_stays_none(self):
        output = analyst1_app.IndicatorOutput.model_validate({"links": None})

        assert output.links is None

    def test_malformed_entry_yields_none_href_without_raising(self):
        output = analyst1_app.IndicatorOutput.model_validate({"links": {"self": "x"}})

        assert len(output.links) == 1
        assert output.links[0].rel == "self"
        assert output.links[0].href is None


class TestIndicatorOutputRoundTrip:
    @pytest.mark.parametrize("fixture_name", ["match_xsoar.json", "match_real_file.json", "match_real_email.json"])
    def test_fixture_validates_without_error(self, fixture_name):
        payload = load_fixture(fixture_name)

        output = analyst1_app.IndicatorOutput.model_validate(payload)

        assert output.id == payload["id"]
        assert output.value.name == payload["value"]["name"]

    def test_1_1_only_fields_populate_from_real_file_fixture(self):
        output = analyst1_app.IndicatorOutput.model_validate(load_fixture("match_real_file.json"))

        assert output.activityRange.classification == "U"
        assert output.reportedRange.startDate == "2026-07-08"
        assert output.sources[0].title == "Mock Indicator Feed"
        assert [tag.name for tag in output.tags] == ["Mock GIR: 1.1.6", "Mock GIR: 1.1.5", "Mock GIR: 1.4.1"]
        assert output.externalhitCount == 0
        assert output.expand == "hitStats,hitStatsDetails,sources,enrichmentResults,verifications"
        assert output.indicatorDerivation == "Extracted"
        assert output.integrationSources == ["Mock Integration Feed"]
        assert output.verifications[0].verifier == "mock.analyst"
        assert output.hitStatDetails[0].dimensions[1].dimensionValues[0].id == 6002

    def test_1_1_only_fields_default_none_on_1_0_fixture(self):
        output = analyst1_app.IndicatorOutput.model_validate(load_fixture("match_xsoar.json"))

        assert output.activityRange is None
        assert output.reportedRange is None
        assert output.verifiedDateRange is None
        assert output.sources is None
        assert output.tags is None
        assert output.externalhitCount is None
        assert output.firstExternalHit is None
        assert output.lastExternalHit is None
        assert output.expand is None
        assert output.hitStatDetails is None
        assert output.stixObjects is None
        assert output.verifications is None
