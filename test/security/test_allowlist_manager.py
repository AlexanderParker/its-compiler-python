"""
Tests for AllowlistManager security functionality.
"""

import json
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from its_compiler.security import (
    AllowlistManager,
    TrustLevel,
    SchemaEntry,
    SecurityConfig,
)


@pytest.fixture
def temp_config_dir():
    """Create temporary config directory."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


@pytest.fixture
def security_config(temp_config_dir):
    """Create security config with temp directory."""
    config = SecurityConfig.for_development()
    config.allowlist.allowlist_file = str(temp_config_dir / "test_allowlist.json")
    return config


@pytest.fixture
def allowlist_manager(security_config):
    """Create allowlist manager with test config."""
    return AllowlistManager(security_config)


class TestAllowlistManager:
    """Test AllowlistManager functionality."""

    def test_initialization(self, allowlist_manager):
        """Test manager initializes correctly."""
        assert allowlist_manager.entries == {}
        assert allowlist_manager.session_allowed == set()

    def test_builtin_trusted_patterns(self, allowlist_manager):
        """Test built-in trusted schema patterns."""
        official_schema = "https://alexanderparker.github.io/instruction-template-specification/schema/v1.0/its-base-schema-v1.json"
        github_schema = "https://raw.githubusercontent.com/alexanderparker/instruction-template-specification/main/schema.json"
        untrusted_schema = "https://evil.com/malicious.json"

        assert allowlist_manager._is_builtin_trusted(official_schema)
        assert allowlist_manager._is_builtin_trusted(github_schema)
        assert not allowlist_manager._is_builtin_trusted(untrusted_schema)

    def test_add_trusted_url_permanent(self, allowlist_manager):
        """Test adding permanently trusted URL."""
        url = "https://company.com/schemas/types.json"
        notes = "Company schema"

        allowlist_manager.add_trusted_url(url, TrustLevel.PERMANENT, notes)

        assert url in allowlist_manager.entries
        entry = allowlist_manager.entries[url]
        assert entry.trust_level == TrustLevel.PERMANENT
        assert entry.notes == notes
        assert entry.use_count == 0

    def test_add_trusted_url_session(self, allowlist_manager):
        """Test adding session-only trusted URL."""
        url = "https://test.com/temp.json"

        allowlist_manager.add_trusted_url(url, TrustLevel.SESSION)

        # Session URLs don't go in entries, they go in session_allowed
        assert url not in allowlist_manager.entries
        assert url in allowlist_manager.session_allowed

    def test_remove_url_from_entries(self, allowlist_manager):
        """Test removing URL from permanent entries."""
        url = "https://company.com/schema.json"
        allowlist_manager.add_trusted_url(url, TrustLevel.PERMANENT)

        assert allowlist_manager.remove_url(url)
        assert url not in allowlist_manager.entries

    def test_remove_url_from_session(self, allowlist_manager):
        """Test removing URL from session allowlist."""
        url = "https://test.com/temp.json"
        allowlist_manager.session_allowed.add(url)

        assert allowlist_manager.remove_url(url)
        assert url not in allowlist_manager.session_allowed

    def test_remove_nonexistent_url(self, allowlist_manager):
        """Test removing URL that doesn't exist."""
        assert not allowlist_manager.remove_url("https://nonexistent.com/schema.json")

    def test_is_allowed_permanent(self, allowlist_manager):
        """Test URL allowed via permanent entry."""
        url = "https://trusted.com/schema.json"
        allowlist_manager.add_trusted_url(url, TrustLevel.PERMANENT)

        assert allowlist_manager.is_allowed(url)

        # Check usage stats updated
        entry = allowlist_manager.entries[url]
        assert entry.use_count == 1

    def test_is_allowed_never(self, allowlist_manager):
        """Test URL blocked via never entry."""
        url = "https://blocked.com/schema.json"
        allowlist_manager.add_trusted_url(url, TrustLevel.NEVER)

        assert not allowlist_manager.is_allowed(url)

    def test_is_allowed_session(self, allowlist_manager):
        """Test URL allowed via session entry."""
        url = "https://session.com/schema.json"
        allowlist_manager.session_allowed.add(url)

        assert allowlist_manager.is_allowed(url)

    def test_is_allowed_builtin_trusted(self, allowlist_manager):
        """Test built-in trusted URLs are allowed."""
        url = "https://alexanderparker.github.io/instruction-template-specification/schema/v1.0/its-base-schema-v1.json"

        assert allowlist_manager.is_allowed(url)

    @patch("builtins.input", return_value="1")
    def test_interactive_prompt_permanent(self, mock_input, allowlist_manager):
        """Test interactive prompt choosing permanent trust."""
        url = "https://new.com/schema.json"

        # Enable interactive mode
        allowlist_manager.config.allowlist.interactive_mode = True
        allowlist_manager.config.allowlist.require_confirmation = True

        result = allowlist_manager.is_allowed(url)

        assert result
        assert url in allowlist_manager.entries
        assert allowlist_manager.entries[url].trust_level == TrustLevel.PERMANENT

    @patch("builtins.input", return_value="2")
    def test_interactive_prompt_session(self, mock_input, allowlist_manager):
        """Test interactive prompt choosing session trust."""
        url = "https://new.com/schema.json"

        allowlist_manager.config.allowlist.interactive_mode = True
        allowlist_manager.config.allowlist.require_confirmation = True

        result = allowlist_manager.is_allowed(url)

        assert result
        assert url not in allowlist_manager.entries
        assert url in allowlist_manager.session_allowed

    @patch("builtins.input", return_value="3")
    def test_interactive_prompt_deny(self, mock_input, allowlist_manager):
        """Test interactive prompt choosing deny."""
        url = "https://new.com/schema.json"

        allowlist_manager.config.allowlist.interactive_mode = True
        allowlist_manager.config.allowlist.require_confirmation = True

        result = allowlist_manager.is_allowed(url)

        assert not result
        assert url in allowlist_manager.entries
        assert allowlist_manager.entries[url].trust_level == TrustLevel.NEVER

    def test_non_interactive_mode(self, allowlist_manager):
        """Test non-interactive mode blocks unknown URLs."""
        url = "https://unknown.com/schema.json"

        allowlist_manager.config.allowlist.interactive_mode = False

        result = allowlist_manager.is_allowed(url)

        assert not result

    def test_ci_auto_approve_mode(self, allowlist_manager):
        """Test CI auto-approve mode allows unknown URLs as session."""
        url = "https://unknown.com/schema.json"

        allowlist_manager.config.allowlist.interactive_mode = False
        allowlist_manager.config.allowlist.auto_approve_in_ci = True

        result = allowlist_manager.is_allowed(url)

        assert result
        assert url in allowlist_manager.session_allowed

    def test_update_fingerprint(self, allowlist_manager):
        """Test updating schema fingerprint."""
        url = "https://company.com/schema.json"
        content = '{"instructionTypes": {"test": {"template": "test"}}}'

        allowlist_manager.add_trusted_url(url, TrustLevel.PERMANENT)
        allowlist_manager.update_fingerprint(url, content)

        entry = allowlist_manager.entries[url]
        assert entry.fingerprint is not None
        assert len(entry.fingerprint) == 16  # SHA256 first 16 chars

    def test_fingerprint_change_detection(self, allowlist_manager):
        """Test detection of fingerprint changes."""
        url = "https://company.com/schema.json"
        old_content = '{"version": "1.0"}'
        new_content = '{"version": "2.0"}'

        allowlist_manager.add_trusted_url(url, TrustLevel.PERMANENT)
        allowlist_manager.update_fingerprint(url, old_content)

        # Update with different content
        allowlist_manager.update_fingerprint(url, new_content)

    def test_get_stats(self, allowlist_manager):
        """Test getting allowlist statistics."""
        # Add various entries
        allowlist_manager.add_trusted_url(
            "https://perm1.com/s.json", TrustLevel.PERMANENT
        )
        allowlist_manager.add_trusted_url(
            "https://perm2.com/s.json", TrustLevel.PERMANENT
        )
        allowlist_manager.add_trusted_url("https://never.com/s.json", TrustLevel.NEVER)
        allowlist_manager.session_allowed.add("https://session.com/s.json")

        stats = allowlist_manager.get_stats()

        assert stats["total_entries"] == 3
        assert stats["permanent_allowed"] == 2
        assert stats["denied"] == 1
        assert stats["session_allowed"] == 1

    def test_cleanup_old_entries(self, allowlist_manager):
        """Test cleanup of old unused entries."""
        now = datetime.now(timezone.utc)
        old_time = datetime(2020, 1, 1, tzinfo=timezone.utc)

        # Add old unused entry
        old_entry = SchemaEntry(
            url="https://old.com/schema.json",
            trust_level=TrustLevel.PERMANENT,
            added_date=old_time,
            last_used=old_time,
            use_count=0,
        )
        allowlist_manager.entries[old_entry.url] = old_entry

        # Add recent entry
        recent_entry = SchemaEntry(
            url="https://recent.com/schema.json",
            trust_level=TrustLevel.PERMANENT,
            added_date=now,
            last_used=now,
            use_count=0,
        )
        allowlist_manager.entries[recent_entry.url] = recent_entry

        removed_count = allowlist_manager.cleanup_old_entries(days=90)

        assert removed_count == 1
        assert old_entry.url not in allowlist_manager.entries
        assert recent_entry.url in allowlist_manager.entries

    def test_persistence_save_and_load(self, allowlist_manager, temp_config_dir):
        """Test saving and loading allowlist to/from file."""
        url = "https://company.com/schema.json"
        allowlist_manager.add_trusted_url(url, TrustLevel.PERMANENT, "Test schema")

        # Save should happen automatically
        allowlist_file = temp_config_dir / "test_allowlist.json"
        assert allowlist_file.exists()

        # Load into new manager
        new_manager = AllowlistManager(allowlist_manager.config)

        assert url in new_manager.entries
        entry = new_manager.entries[url]
        assert entry.trust_level == TrustLevel.PERMANENT
        assert entry.notes == "Test schema"

    def test_persistence_backup_on_change(self, allowlist_manager, temp_config_dir):
        """Test backup creation on changes."""
        allowlist_manager.config.allowlist.backup_on_change = True

        # Create initial file
        url1 = "https://first.com/schema.json"
        allowlist_manager.add_trusted_url(url1, TrustLevel.PERMANENT)

        allowlist_file = temp_config_dir / "test_allowlist.json"
        backup_file = temp_config_dir / "test_allowlist.bak"

        # Add another entry (should create backup)
        url2 = "https://second.com/schema.json"
        allowlist_manager.add_trusted_url(url2, TrustLevel.PERMANENT)

        assert backup_file.exists()

    def test_export_import_allowlist(self, allowlist_manager, temp_config_dir):
        """Test exporting and importing allowlist."""
        # Add some entries
        allowlist_manager.add_trusted_url(
            "https://export1.com/s.json", TrustLevel.PERMANENT
        )
        allowlist_manager.add_trusted_url(
            "https://export2.com/s.json", TrustLevel.NEVER
        )

        # Export
        export_path = temp_config_dir / "exported.json"
        allowlist_manager.export_allowlist(export_path)

        assert export_path.exists()

        # Create new manager and import
        new_config = SecurityConfig.for_development()
        new_config.allowlist.allowlist_file = str(
            temp_config_dir / "new_allowlist.json"
        )
        new_manager = AllowlistManager(new_config)

        imported_count = new_manager.import_allowlist(export_path)

        assert imported_count == 2
        assert "https://export1.com/s.json" in new_manager.entries
        assert "https://export2.com/s.json" in new_manager.entries

    def test_import_merge_mode(self, allowlist_manager, temp_config_dir):
        """Test importing with merge mode."""
        # Add existing entry
        existing_url = "https://existing.com/s.json"
        allowlist_manager.add_trusted_url(existing_url, TrustLevel.PERMANENT)

        # Create export with overlapping entry
        export_data = {
            "entries": {
                existing_url: {
                    "url": existing_url,
                    "trust_level": "never",  # Different trust level
                    "added_date": "2025-01-01T00:00:00+00:00",
                    "last_used": "2025-01-01T00:00:00+00:00",
                    "use_count": 5,
                },
                "https://new.com/s.json": {
                    "url": "https://new.com/s.json",
                    "trust_level": "permanent",
                    "added_date": "2025-01-01T00:00:00+00:00",
                    "last_used": "2025-01-01T00:00:00+00:00",
                    "use_count": 0,
                },
            }
        }

        export_path = temp_config_dir / "import_test.json"
        with open(export_path, "w") as f:
            json.dump(export_data, f)

        # Import with merge=True (should update existing)
        imported_count = allowlist_manager.import_allowlist(export_path, merge=True)

        assert imported_count == 2
        # Existing entry should be updated
        assert allowlist_manager.entries[existing_url].trust_level == TrustLevel.NEVER
        assert allowlist_manager.entries[existing_url].use_count == 5

    def test_import_no_merge_mode(self, allowlist_manager, temp_config_dir):
        """Test importing without merge mode."""
        # Add existing entry
        existing_url = "https://existing.com/s.json"
        allowlist_manager.add_trusted_url(existing_url, TrustLevel.PERMANENT)
        original_use_count = allowlist_manager.entries[existing_url].use_count

        # Create export with overlapping entry
        export_data = {
            "entries": {
                existing_url: {
                    "url": existing_url,
                    "trust_level": "never",
                    "added_date": "2025-01-01T00:00:00+00:00",
                    "last_used": "2025-01-01T00:00:00+00:00",
                    "use_count": 5,
                },
                "https://new.com/s.json": {
                    "url": "https://new.com/s.json",
                    "trust_level": "permanent",
                    "added_date": "2025-01-01T00:00:00+00:00",
                    "last_used": "2025-01-01T00:00:00+00:00",
                    "use_count": 0,
                },
            }
        }

        export_path = temp_config_dir / "import_test.json"
        with open(export_path, "w") as f:
            json.dump(export_data, f)

        # Import with merge=False (should skip existing)
        imported_count = allowlist_manager.import_allowlist(export_path, merge=False)

        assert imported_count == 1  # Only new entry
        # Existing entry should be unchanged
        assert (
            allowlist_manager.entries[existing_url].trust_level == TrustLevel.PERMANENT
        )
        assert allowlist_manager.entries[existing_url].use_count == original_use_count

    def test_error_handling_corrupted_file(self, security_config, temp_config_dir):
        """Test handling of corrupted allowlist file."""
        # Create corrupted file
        allowlist_file = temp_config_dir / "test_allowlist.json"
        with open(allowlist_file, "w") as f:
            f.write("invalid json content")

        # Should handle gracefully and start with empty allowlist
        manager = AllowlistManager(security_config)
        assert manager.entries == {}

    def test_file_permission_error_handling(self, allowlist_manager):
        """Test handling of file permission errors."""
        # Try to save to read-only location (simulated by mocking)
        with patch("builtins.open", side_effect=PermissionError("Access denied")):
            allowlist_manager.add_trusted_url(
                "https://test.com/s.json", TrustLevel.PERMANENT
            )
