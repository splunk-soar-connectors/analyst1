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
"""display_indicators_view: context built from typed outputs, and full template rendering.

The module-level ``display_indicators_view`` is the SDK view wrapper (signature
``(action, all_app_runs, context) -> str``); the app's context-building function
is available as its ``__wrapped__`` attribute and takes ``list[IndicatorOutput]``.
"""

from soar_sdk.action_results import ActionResult

import app as analyst1_app
from tests.conftest import load_fixture


view_context_fn = analyst1_app.display_indicators_view.__wrapped__


def _output_from_fixture(name: str) -> analyst1_app.IndicatorOutput:
    return analyst1_app.IndicatorOutput.model_validate(load_fixture(name))


class TestViewContext:
    def test_renders_from_typed_nested_output(self):
        context = view_context_fn([_output_from_fixture("match_real_file.json")])

        assert context["title1"] == "Analyst1 Indicator Lookup"
        assert context["title2"] == "Threat Intelligence"
        # title_logo must NOT be set: the platform supplies themed app_resource
        # logo paths in the view context and a handler value overrides them.
        assert "title_logo" not in context
        (result,) = context["results"]
        (record,) = result["data"]
        assert record["id"] == 90000948
        assert record["value"]["name"].startswith("AAAABBBB")
        assert record["hashes"][0]["type"] == "SHA256"
        # Fields the template iterates are guaranteed present even when absent
        # from the payload (exclude_none dumps would otherwise drop them).
        assert record["campaigns"] == []
        assert record["actors"] == []
        assert record["confidenceLevel"] == {}

    def test_filters_records_without_id(self):
        context = view_context_fn([analyst1_app.IndicatorOutput()])

        # No renderable record: the template gets the "No matches found" row.
        assert context["results"] == [{"data": []}]

    def test_mixed_outputs_keep_only_records_with_id(self):
        outputs = [analyst1_app.IndicatorOutput(), _output_from_fixture("match_xsoar.json")]

        context = view_context_fn(outputs)

        assert len(context["results"]) == 1
        assert context["results"][0]["data"][0]["id"] == 12345

    def test_template_sort_and_compare_defaults(self):
        # The template compares element.id > 0 and sorts by name/value; the view
        # must backfill those keys on elements that lack them.
        output = analyst1_app.IndicatorOutput(
            id=7,
            actors=[analyst1_app.ActorOutput(name="No Id Actor")],
            malwares=[analyst1_app.MalwareRefOutput(name="No Id Malware")],
            ports=[analyst1_app.PortOutput(classification="U")],
            originatingIps=[analyst1_app.ClassifiedName(classification="U")],
            subjects=[analyst1_app.ClassifiedName(classification="U")],
            fileNames=[analyst1_app.ClassifiedName(classification="U")],
        )

        record = view_context_fn([output])["results"][0]["data"][0]

        assert record["actors"][0]["id"] == 0
        assert record["malwares"][0]["id"] == 0
        assert record["ports"][0]["value"] == 0
        assert record["originatingIps"][0]["name"] == ""
        assert record["subjects"][0]["name"] == ""
        assert record["fileNames"][0]["name"] == ""


class TestViewTemplateRendering:
    def test_wrapper_renders_html_from_action_results(self):
        action_result = ActionResult(True, "")
        action_result.add_data(load_fixture("match_xsoar.json"))
        context = {"QS": {}, "container": 1, "app": 1, "no_connection": True, "google_maps_key": False}

        html = analyst1_app.display_indicators_view(
            "lookup_domain",
            [({"total_objects": 1, "total_objects_successful": 1}, [action_result])],
            context,
        )

        assert isinstance(html, str)
        # No title-text assertion: templates render no title/subtitle blocks
        # (the platform paints the centered app logo in the same title bar;
        # text there would overlap it).
        assert "Intelligence Overview" in html
        assert "test.com" in html
        assert "Failed to render" not in html
        assert "Error in view function" not in html
        assert context["prerender"] is True
