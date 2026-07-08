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
"""Guards for manifest metadata injected through app.app_meta_info.

The contributors entry rides on an SDK internal: ManifestProcessor.build
copies every app_meta_info key onto the generated AppMeta via setattr. If an
SDK upgrade reshapes that path, Splunk's contribution checks would reject the
app long after the silent drop — so assert the round-trip here.
"""

from soar_sdk.meta.app import AppMeta

from src.app import app


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
