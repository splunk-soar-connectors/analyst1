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
"""Every view template rendered through the real SDK Jinja renderer.

Covers the two platform contracts that shipped broken once and must never
regress, plus per-view content checks:

* Widget injection: the SOAR widgets pane injects the rendered response via
  jQuery ``$(data)[0]`` and requires the widget div to be the first parsed
  node. Our templates must therefore render nothing before the parent
  chrome's first node. (The locally installed SDK wheel's parent template
  carries its own leading HTML comment; the platform build does not, so the
  check strips leading comments before requiring the div.)
* Autoescaping: API-sourced text (descriptions, enrichment results, searched
  values) must render entity-escaped; no ``|safe`` anywhere.
"""

import copy
import re

import pytest
from soar_sdk.views.template_renderer import get_template_renderer

import app as analyst1_app
from tests.conftest import FIXTURES_DIR, REPO_ROOT, load_fixture


TEMPLATES_DIR = str(REPO_ROOT / "templates")

_LEADING_COMMENTS = re.compile(r"\A(\s*<!--.*?-->)*\s*", re.S)


def render(template: str, context: dict) -> str:
    renderer = get_template_renderer("jinja", TEMPLATES_DIR)
    return renderer.render_template(template, {"title1": "t1", "title2": "t2", **context})


def assert_injection_contract(html: str) -> None:
    """Nothing of ours may render before the widget root div."""
    assert "Copyright (c) 2026 Analyst1" not in html, "license header leaked into rendered output"
    stripped = _LEADING_COMMENTS.sub("", html, count=1)
    assert stripped.startswith("<div"), f"first non-comment content is not the widget div: {stripped[:120]!r}"


# ---------------------------------------------------------------------------
# Context builders: (handler, template, populated outputs)
# ---------------------------------------------------------------------------


def indicator_outputs():
    return [analyst1_app.IndicatorOutput.model_validate(load_fixture("match_real_file.json"))]


def batch_outputs():
    return [analyst1_app.BatchCheckResultOutput.model_validate(row) for row in load_fixture("batch_check.json")["results"]]


def actor_outputs():
    return [analyst1_app.ActorResourceOutput.model_validate(load_fixture("actor_resource.json"))]


def malware_outputs():
    return [analyst1_app.MalwareResourceOutput.model_validate(load_fixture("malware_resource.json"))]


def evidence_upload_outputs():
    return [analyst1_app.UploadEvidenceFileOutput.model_validate(load_fixture("evidence_upload_response.json"))]


def evidence_status_outputs():
    return [analyst1_app.CheckEvidenceStatusOutput.model_validate(load_fixture("evidence_status.json"))]


def evidence_list_outputs():
    return [analyst1_app.EvidenceItemOutput.model_validate(row) for row in load_fixture("evidence_pages.json")["pages"][0]]


def sensor_outputs():
    rows = copy.deepcopy(load_fixture("sensors_pages.json")["pages"][0])
    for row in rows:  # the client renames _links -> links before validation
        row["links"] = row.pop("_links", None)
    return [analyst1_app.SensorOutput.model_validate(row) for row in rows]


def sensor_taskings_outputs():
    return [analyst1_app.SensorTaskingsOutput.model_validate(load_fixture("sensor_taskings.json"))]


def sensor_config_outputs():
    return [
        analyst1_app.SensorConfigOutput(
            sensor_id=401,
            vault_id="0123456789abcdef",
            file_name="sensor401Config.txt",
            config_text=(FIXTURES_DIR / "sensor_config.txt").read_text(),
        )
    ]


def sensor_diff_outputs():
    return [analyst1_app.SensorDiffOutput.model_validate(load_fixture("sensor_diff.json"))]


VIEWS = {
    "indicators": (analyst1_app.display_indicators_view, "display_indicators.html", indicator_outputs),
    "batch": (analyst1_app.display_batch_results_view, "display_batch_results.html", batch_outputs),
    "actor": (analyst1_app.display_actor_view, "display_actor.html", actor_outputs),
    "malware": (analyst1_app.display_malware_view, "display_malware.html", malware_outputs),
    "evidence_upload": (analyst1_app.display_evidence_upload_view, "display_evidence_upload.html", evidence_upload_outputs),
    "evidence_status": (analyst1_app.display_evidence_status_view, "display_evidence_status.html", evidence_status_outputs),
    "evidence_list": (analyst1_app.display_evidence_list_view, "display_evidence_list.html", evidence_list_outputs),
    "sensors": (analyst1_app.display_sensors_view, "display_sensors.html", sensor_outputs),
    "sensor_taskings": (analyst1_app.display_sensor_taskings_view, "display_sensor_taskings.html", sensor_taskings_outputs),
    "sensor_config": (analyst1_app.display_sensor_config_view, "display_sensor_config.html", sensor_config_outputs),
    "sensor_diff": (analyst1_app.display_sensor_diff_view, "display_sensor_diff.html", sensor_diff_outputs),
}


class TestEveryView:
    @pytest.mark.parametrize("name", VIEWS)
    def test_populated_render_meets_injection_contract(self, name):
        handler, template, outputs = VIEWS[name]
        html = render(template, handler.__wrapped__(outputs()))
        assert_injection_contract(html)
        assert "|safe" not in html

    @pytest.mark.parametrize("name", VIEWS)
    def test_empty_outputs_render_without_error(self, name):
        handler, template, _ = VIEWS[name]
        html = render(template, handler.__wrapped__([]))
        assert_injection_contract(html)
        # every view has an explicit empty state, not a blank body
        assert re.search(r"No |not found|no matches", html, re.IGNORECASE)


class TestEscaping:
    def test_indicator_description_is_escaped(self):
        payload = copy.deepcopy(load_fixture("match_real_file.json"))
        payload["description"] = {"name": "line one\nline two <script>alert(1)</script>"}
        output = analyst1_app.IndicatorOutput.model_validate(payload)
        html = render("display_indicators.html", analyst1_app.display_indicators_view.__wrapped__([output]))
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html

    def test_batch_searched_value_is_escaped(self):
        output = analyst1_app.BatchCheckResultOutput(searchedValue='<img src=x onerror="alert(1)">')
        html = render("display_batch_results.html", analyst1_app.display_batch_results_view.__wrapped__([output]))
        assert "<img src=x" not in html
        assert "&lt;img" in html

    def test_hostile_link_scheme_never_becomes_href(self):
        payload = copy.deepcopy(load_fixture("actor_resource.json"))
        payload["links"] = {"self": {"href": "javascript:alert(1)//x/api/1_1/actor/7"}}
        output = analyst1_app.ActorResourceOutput.model_validate(payload)
        context = analyst1_app.display_actor_view.__wrapped__([output])
        assert context["records"][0]["url"] == ""
        html = render("display_actor.html", context)
        assert "javascript:" not in html

    def test_actor_description_is_escaped(self):
        payload = copy.deepcopy(load_fixture("actor_resource.json"))
        payload["description"] = {"name": "<b>bold</b> claims"}
        output = analyst1_app.ActorResourceOutput.model_validate(payload)
        html = render("display_actor.html", analyst1_app.display_actor_view.__wrapped__([output]))
        assert "<b>bold</b>" not in html
        assert "&lt;b&gt;bold&lt;/b&gt;" in html


class TestViewContent:
    def test_actor_detail_shows_entity(self):
        html = render("display_actor.html", analyst1_app.display_actor_view.__wrapped__(actor_outputs()))
        fixture = load_fixture("actor_resource.json")
        assert fixture["title"]["name"] in html
        assert fixture["country"]["name"] in html

    def test_malware_detail_shows_entity(self):
        html = render("display_malware.html", analyst1_app.display_malware_view.__wrapped__(malware_outputs()))
        fixture = load_fixture("malware_resource.json")
        assert fixture["title"]["name"] in html

    def test_batch_table_has_row_per_result(self):
        outputs = batch_outputs()
        html = render("display_batch_results.html", analyst1_app.display_batch_results_view.__wrapped__(outputs))
        for output in outputs:
            assert output.searchedValue in html

    def test_evidence_list_shows_count_and_rows(self):
        outputs = evidence_list_outputs()
        html = render("display_evidence_list.html", analyst1_app.display_evidence_list_view.__wrapped__(outputs))
        assert f"{len(outputs)} evidence record" in html

    def test_evidence_status_states(self):
        ingested = analyst1_app.CheckEvidenceStatusOutput(message="Evidence ingest complete", id=42)
        failed = analyst1_app.CheckEvidenceStatusOutput(message="Evidence processing failed (no evidence record available)", id=None)
        processing = analyst1_app.CheckEvidenceStatusOutput(message="Evidence is being processed", id=None)
        context = analyst1_app.display_evidence_status_view.__wrapped__([ingested, failed, processing])
        states = [record["state"] for record in context["records"]]
        assert states == ["Ingested", "Failed", "Processing"]
        html = render("display_evidence_status.html", context)
        for state in states:
            assert state in html

    def test_sensor_config_shows_text(self):
        html = render("display_sensor_config.html", analyst1_app.display_sensor_config_view.__wrapped__(sensor_config_outputs()))
        assert "sensor401Config.txt" in html

    def test_sensor_diff_indicator_ids_link_to_portal(self):
        context = analyst1_app.display_sensor_diff_view.__wrapped__(sensor_diff_outputs())
        record = context["records"][0]
        linked = [row for row in record["indicators_added"] + record["indicators_removed"] if row["id"]]
        assert linked, "expected diff fixture to carry indicator rows with ids"
        for row in linked:
            assert row["url"].endswith(f"/indicators/{row['id']}")
        html = render("display_sensor_diff.html", context)
        assert f'href="{linked[0]["url"]}"' in html

    def test_sensor_taskings_indicator_ids_link_to_portal(self):
        context = analyst1_app.display_sensor_taskings_view.__wrapped__(sensor_taskings_outputs())
        linked = [row for row in context["records"][0]["indicators"] if row["id"]]
        assert linked
        for row in linked:
            assert row["url"].endswith(f"/indicators/{row['id']}")
        html = render("display_sensor_taskings.html", context)
        assert f'href="{linked[0]["url"]}"' in html

    def test_sensor_diff_sections(self):
        html = render("display_sensor_diff.html", analyst1_app.display_sensor_diff_view.__wrapped__(sensor_diff_outputs()))
        fixture = load_fixture("sensor_diff.json")
        if fixture.get("indicatorsAdded"):
            assert "Indicators added" in html
        if fixture.get("rulesRemoved"):
            assert "Rules removed" in html

    def test_evidence_live_shape_classified_objects_unwrap(self):
        # live rows carry title/reportedDate as {name|date, classification}
        # objects (the sanitized fixture has plain strings); both must render
        # as bare values, never as printed dicts
        row = {
            "id": 1701519,
            "title": {"name": "June 2026 CVE Landscape", "classification": "U"},
            "reportedDate": {"date": "2026-07-10", "classification": "U"},
            "analyzedDate": None,
            "type": "pdf",
            "tlp": "white",
            "base_url": "https://a1.unit.test",
        }
        output = analyst1_app.EvidenceItemOutput.model_validate(row)
        context = analyst1_app.display_evidence_list_view.__wrapped__([output])
        assert context["rows"][0]["title"] == "June 2026 CVE Landscape"
        assert context["rows"][0]["reported"] == "2026-07-10"
        html = render("display_evidence_list.html", context)
        assert "classification" not in html
        assert "June 2026 CVE Landscape" in html

    def test_sensor_rows_link_to_portal_sensor_page(self):
        outputs = sensor_outputs()
        context = analyst1_app.display_sensors_view.__wrapped__(outputs)
        linked = [row for row in context["rows"] if row["url"]]
        assert linked, "expected at least one sensor row with a portal link"
        for row in linked:
            assert row["url"].endswith(f"/sensors/{row['id']}")
            assert row["url"].startswith("http")
        html = render("display_sensors.html", context)
        assert f'href="{linked[0]["url"]}"' in html

    def test_evidence_rows_link_to_portal_files_page(self):
        rows = copy.deepcopy(load_fixture("evidence_pages.json")["pages"][0])
        for row in rows:  # the action injects the asset server before validation
            row["base_url"] = "https://a1.unit.test"
        outputs = [analyst1_app.EvidenceItemOutput.model_validate(row) for row in rows]
        context = analyst1_app.display_evidence_list_view.__wrapped__(outputs)
        for row in context["rows"]:
            assert row["url"] == f"https://a1.unit.test/files/{row['id']}"
        html = render("display_evidence_list.html", context)
        assert f'href="{context["rows"][0]["url"]}"' in html

    def test_batch_rows_link_to_portal_indicator_page(self):
        rows = copy.deepcopy(load_fixture("batch_check.json")["results"])
        for row in rows:
            row["base_url"] = "https://a1.unit.test"
        outputs = [analyst1_app.BatchCheckResultOutput.model_validate(row) for row in rows]
        context = analyst1_app.display_batch_results_view.__wrapped__(outputs)
        linked = [row for row in context["rows"] if row["id"]]
        for row in linked:
            assert row["url"] == f"https://a1.unit.test/indicators/{row['id']}"
        html = render("display_batch_results.html", context)
        assert f'href="{linked[0]["url"]}"' in html

    def test_sensor_config_links_sensor_id(self):
        outputs = sensor_config_outputs()
        context = analyst1_app.display_sensor_config_view.__wrapped__(outputs)
        assert context["records"][0]["url"] == ""  # no base_url on the synthetic output
        outputs[0].base_url = "https://a1.unit.test"
        context = analyst1_app.display_sensor_config_view.__wrapped__(outputs)
        assert context["records"][0]["url"] == "https://a1.unit.test/sensors/401"
        html = render("display_sensor_config.html", context)
        assert 'href="https://a1.unit.test/sensors/401"' in html

    def test_indicator_view_shows_verdict_badges(self):
        html = render("display_indicators.html", analyst1_app.display_indicators_view.__wrapped__(indicator_outputs()))
        assert "a1-badge" in html
