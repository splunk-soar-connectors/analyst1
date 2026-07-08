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
"""Guards for manifest metadata injected through app.app_meta_info.

The contributors entry rides on an SDK internal: ManifestProcessor.build
copies every app_meta_info key onto the generated AppMeta via setattr. If an
SDK upgrade reshapes that path, Splunk's contribution checks would reject the
app long after the silent drop — so assert the round-trip here.

Also guards the contains (cef_types) contract that powers contextual action
pivots: the custom analyst1 indicator/actor/malware/sensor id contains must
land on exactly the intended params and datapaths. The id-bearing sub-models
subclass the shared ClassifiedIdName solely to tag their `id`; a careless
refactor that tags ClassifiedIdName itself would mistag campaigns, targets,
cves, attackPatterns, akas, and more — pinned here.
"""

from soar_sdk.meta.app import AppMeta

from src.app import app


def _action_meta(identifier: str) -> dict:
    """Serialize one action's manifest metadata via the SDK's own serializer."""
    return app.get_actions()[identifier].meta.model_dump()


def _datapath_contains(meta: dict, data_path: str) -> list[str] | None:
    """Return the contains list declared for a datapath (None when untagged)."""
    for spec in meta["output"]:
        if spec["data_path"] == data_path:
            return spec.get("contains")
    raise AssertionError(f"datapath {data_path} is not declared")


def test_contributors_round_trip_into_manifest():
    app_meta = AppMeta(
        description="test",
        app_version="0.0.0",
        license="test",
        package_name="test",
        project_name="test",
    )
    # Mirror ManifestProcessor.build's app_meta_info propagation.
    for field, value in app.app_meta_info.items():
        setattr(app_meta, field, value)

    manifest = app_meta.to_json_manifest()
    assert manifest["contributors"] == [{"name": "Mike Forgione (Analyst1)"}]


def test_by_id_param_contains():
    assert _action_meta("get_indicator_by_id")["parameters"]["indicator_id"]["contains"] == ["analyst1 indicator id"]
    assert _action_meta("get_actor_by_id")["parameters"]["actor_id"]["contains"] == ["analyst1 actor id"]
    assert _action_meta("get_malware_by_id")["parameters"]["malware_id"]["contains"] == ["analyst1 malware id"]


def test_sensor_param_contains():
    for identifier in ("get_sensor_taskings", "get_sensor_config", "get_sensor_diff"):
        assert _action_meta(identifier)["parameters"]["sensor_id"]["contains"] == ["analyst1 sensor id"]


def test_batch_check_values_param_contains_broad_indicator_types():
    contains = _action_meta("batch_check")["parameters"]["values"]["contains"]
    assert set(contains) >= {"ip", "domain", "url", "hash", "email"}


def test_indicator_output_id_tagged_without_mistagging_shared_model():
    # lookup_domain returns an IndicatorOutput subclass: its own id pivots,
    # while the ClassifiedIdName-typed lists must stay untagged...
    meta = _action_meta("lookup_domain")
    assert _datapath_contains(meta, "action_result.data.*.id") == ["analyst1 indicator id"]
    assert _datapath_contains(meta, "action_result.data.*.campaigns.*.id") is None
    assert _datapath_contains(meta, "action_result.data.*.targets.*.id") is None
    assert _datapath_contains(meta, "action_result.data.*.attackPatterns.*.id") is None
    # ...and the actor/malware sub-model overrides carry their own tags.
    assert _datapath_contains(meta, "action_result.data.*.actors.*.id") == ["analyst1 actor id"]
    assert _datapath_contains(meta, "action_result.data.*.malwares.*.id") == ["analyst1 malware id"]


def test_get_indicator_by_id_output_id_tagged():
    meta = _action_meta("get_indicator_by_id")
    assert _datapath_contains(meta, "action_result.data.*.id") == ["analyst1 indicator id"]


def test_actor_resource_output_contains():
    meta = _action_meta("get_actor_by_id")
    assert _datapath_contains(meta, "action_result.data.*.id") == ["analyst1 actor id"]
    assert _datapath_contains(meta, "action_result.data.*.malware.*.id") == ["analyst1 malware id"]
    assert _datapath_contains(meta, "action_result.data.*.akas.*.id") is None
    assert _datapath_contains(meta, "action_result.data.*.cves.*.id") is None


def test_malware_resource_output_id_tagged():
    meta = _action_meta("get_malware_by_id")
    assert _datapath_contains(meta, "action_result.data.*.id") == ["analyst1 malware id"]
    assert _datapath_contains(meta, "action_result.data.*.akas.*.id") is None


def test_batch_check_output_id_tagged():
    meta = _action_meta("batch_check")
    assert _datapath_contains(meta, "action_result.data.*.id") == ["analyst1 indicator id"]


def test_sensor_output_ids_tagged():
    assert _datapath_contains(_action_meta("get_sensors"), "action_result.data.*.id") == ["analyst1 sensor id"]
    assert _datapath_contains(_action_meta("get_sensor_config"), "action_result.data.*.sensor_id") == ["analyst1 sensor id"]

    taskings = _action_meta("get_sensor_taskings")
    assert _datapath_contains(taskings, "action_result.data.*.id") == ["analyst1 sensor id"]
    assert _datapath_contains(taskings, "action_result.data.*.indicators.*.id") == ["analyst1 indicator id"]

    diff = _action_meta("get_sensor_diff")
    assert _datapath_contains(diff, "action_result.data.*.id") == ["analyst1 sensor id"]
    assert _datapath_contains(diff, "action_result.data.*.indicatorsAdded.*.id") == ["analyst1 indicator id"]
    assert _datapath_contains(diff, "action_result.data.*.indicatorsRemoved.*.id") == ["analyst1 indicator id"]
