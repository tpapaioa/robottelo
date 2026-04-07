"""Feature Matrix for Satellite version-specific capabilities.

This module provides a centralized registry of features that vary across
Satellite versions, enabling tests to adapt automatically to the target
Satellite version without explicit version checks scattered throughout the code.

Usage in tests:
    from robottelo.features import VersionFeatureChecker

    # Create checker for Satellite version
    checker = VersionFeatureChecker(target_sat.version)

    # Check if feature is available
    if checker.has_feature('activation_key.auto_attach'):
        # Use auto_attach field
        ak = target_sat.api.ActivationKey(auto_attach=False).create()
"""

from packaging.version import Version


class FeatureDefinition:
    """Definition of a feature and its version-specific availability.

    Attributes:
        name: Unique identifier
        min_version: Minimum Satellite version (inclusive, None = all versions before max_version)
        max_version: Maximum Satellite version (inclusive, None = all versions after min_version)
        description: Human-readable description
        replacement: Name of feature that replaces this feature in later versions (optional)

    Example - Feature removed in 6.19:
        FeatureDefinition(
            name='activation_key.auto_attach',
            max_version='6.18',
            description='Auto-attach functionality',
        )
    """

    def __init__(
        self,
        name,
        min_version=None,
        max_version=None,
        description="",
        replacement=None,
    ):
        self.name = name
        self.min_version = min_version
        self.max_version = max_version
        self.description = description
        self.replacement = replacement if replacement is not None else ''


FEATURE_DEFS = [
    # Activation Key Features
    FeatureDefinition(
        name='activation_key.auto_attach',
        max_version='6.18',
        description='Automatically attach subscriptions when host registers',
        replacement='activation_key.simple_content_access',
    ),
    FeatureDefinition(
        name='activation_key.simple_content_access',
        min_version='6.19',
        description='Simple Content Access mode',
    ),
    FeatureDefinition(
        name='activation_key.add_remove_subscriptions',
        max_version='6.18',
        description='Add or remove subscriptions on activation key',
        replacement='activation_key.host_collections',
    ),
    FeatureDefinition(
        name='activation_key.host_collections',
        min_version='6.19',
        description='Manage host collections via activation key',
    ),
    FeatureDefinition(
        name='activation_key.content_view',
        max_version='6.19',
        description='Single content_view field on ActivationKey',
    ),
    # Content View Features
    FeatureDefinition(
        name='contentview.rolling',
        min_version='6.18',
        description='Rolling content views for automated publishing',
    ),
    # IoP Features
    FeatureDefinition(
        name='iop.vulnerability',
        min_version='6.18',
        description='IoP vulnerability scanning',
    ),
    FeatureDefinition(
        name='iop.advisor',
        min_version='6.18',
        description='IoP advisor recommendations',
    ),
]

FEATURE_MATRIX = {fd.name: fd for fd in FEATURE_DEFS}


class VersionFeatureChecker:
    """Check feature availability for a specific Satellite version.

    Instantiate with a Satellite version, then query features with has_feature().
    """

    def __init__(self, satellite_version):
        """Initialize checker with Satellite version.

        Args:
            satellite_version: Satellite version string (e.g., '6.18.0', '6.19')
        """
        self.satellite_version = satellite_version

    def version_match(self, min_version=None, max_version=None):
        """Check whether the given Satellite version falls between the given
        (min_version, max_version) range. The endpoints are inclusive, including
        .z versions.

        Special case: 'stream' is treated as the latest version (newer than any max_version).

        For example,
        version='6.18.6', min_version='6.17', max_version='6.18' returns True
        version='6.18', min_version='6.18', max_version='6.19' returns True
        version='stream', min_version='6.19' returns True (always passes min_version)
        version='stream', max_version='6.19' returns False (always fails max_version)
        """
        if self.satellite_version == 'stream':
            # Stream passes min_version checks (it's newer than any released version)
            # Stream fails max_version checks (it's newer than any max_version)
            return max_version is None

        version_obj = Version(self.satellite_version)

        next_version = None
        if max_version:
            v = Version(max_version)
            next_version = f"{v.major}.{v.minor + 1}"

        return not (
            (min_version and version_obj < Version(min_version))
            or (next_version and version_obj >= Version(next_version))
        )

    def has_feature(self, feature_name):
        """Check if feature is available in this Satellite version.

        Args:
            feature_name: Name of the feature

        Returns:
            True if feature is available
        """
        if not (feature := FEATURE_MATRIX.get(feature_name)):
            # Unknown features are assumed unavailable
            return False

        return self.version_match(min_version=feature.min_version, max_version=feature.max_version)
