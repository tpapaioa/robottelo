"""Pytest plugin for Feature Matrix integration.

This plugin provides pytest hooks and fixtures for version-aware testing
using the feature matrix system.
"""

from robottelo.config import settings
from robottelo.features import VersionFeatureChecker


def pytest_configure(config):
    """Register feature matrix markers."""
    config.addinivalue_line(
        "markers",
        "requires_feature(feature_name=NAME): Mark test as requiring a specific version-based feature",
    )
    config.addinivalue_line(
        "markers",
        "satellite_version_range(min_version=MIN, max_version=MAX): Mark test for specific version range",
    )


def pytest_collection_modifyitems(session, items, config):
    """Filter tests based on Satellite version range or feature.

    Args:
        session: pytest session object
        items: list of collected test items
        config: pytest configuration object
    """
    selected = []
    deselected = []

    checker = VersionFeatureChecker(settings.server.version.release)
    for item in items:
        if marker := item.get_closest_marker('requires_feature'):
            feature_name = marker.kwargs.get('feature_name')
            selected.append(item) if checker.has_feature(feature_name) else deselected.append(item)
            continue
        if marker := item.get_closest_marker('satellite_version_range'):
            selected.append(item) if checker.version_match(**marker.kwargs) else deselected.append(
                item
            )
            continue
        selected.append(item)

    if deselected:
        config.hook.pytest_deselected(items=deselected)
    items[:] = selected
