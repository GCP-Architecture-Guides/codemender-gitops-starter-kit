# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Test-session environment, applied before any test module imports backend code.

1. Production-like project: the service refuses to run without GOOGLE_CLOUD_PROJECT
   (main.py startup guard, cm subprocess env), so tests run with this deployment's project.
2. Credential isolation: point ADC and the gcloud config at empty locations so no test can
   pick up the machine's global gcloud identity or ADC and reach real Google Cloud APIs.
   Clients that need credentials fail to initialize and the code under test sees None.
"""
import os
import tempfile

_ISOLATED = tempfile.mkdtemp(prefix="codemender-tests-")

os.environ.setdefault("GOOGLE_CLOUD_PROJECT", "YOUR_PROJECT_ID")
os.environ.setdefault("GOOGLE_CLOUD_LOCATION", "global")
os.environ.setdefault("GOOGLE_GENAI_USE_VERTEXAI", "true")
os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = os.path.join(_ISOLATED, "no-adc.json")
os.environ["CLOUDSDK_CONFIG"] = os.path.join(_ISOLATED, "gcloud")
