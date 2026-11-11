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
"""Imports the real ``main`` module for route-level tests."""
import os
import sys
import types

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)


def import_real_main():
    """Import main with the real backend modules, even if earlier tests installed stand-ins.

    Some test modules register lightweight stand-ins (types.ModuleType without __file__) for
    backend modules such as `database`. main needs the real ones, so the stand-ins are set aside
    for the import and put back afterwards; the tests that rely on them are unaffected.
    """
    stand_ins = {
        name: mod for name, mod in list(sys.modules.items())
        if isinstance(mod, types.ModuleType) and getattr(mod, "__file__", None) is None
        and os.path.exists(os.path.join(BACKEND_DIR, f"{name}.py"))
    }
    for name in stand_ins:
        del sys.modules[name]
    try:
        import main as real_main
    finally:
        sys.modules.update(stand_ins)
    return real_main
