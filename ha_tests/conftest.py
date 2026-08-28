"""Fixtures for tests running inside a real Home Assistant core."""

from pathlib import Path
import sys

import pytest

pytest_plugins = "pytest_homeassistant_custom_component"

ROOT = Path(__file__).parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    """Allow loading the repository's custom integration."""
    yield
