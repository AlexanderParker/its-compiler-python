"""
Interactive schema allowlist management for ITS Compiler.
"""

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from .config import SecurityConfig


class TrustLevel(Enum):
    """Trust levels for schema URLs."""

    NEVER = "never"
    SESSION = "session"
    PERMANENT = "permanent"


@dataclass
class SchemaEntry:
    """Entry in the schema allowlist."""

    url: str
    trust_level: TrustLevel
    added_date: datetime
    last_used: datetime
    use_count: int = 0
    fingerprint: Optional[str] = None
    notes: Optional[str] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        data = asdict(self)
        data["trust_level"] = self.trust_level.value
        data["added_date"] = self.added_date.isoformat()
        data["last_used"] = self.last_used.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: Dict) -> "SchemaEntry":
        """Create from dictionary."""
        return cls(
            url=data["url"],
            trust_level=TrustLevel(data["trust_level"]),
            added_date=datetime.fromisoformat(data["added_date"]),
            last_used=datetime.fromisoformat(data["last_used"]),
            use_count=data.get("use_count", 0),
            fingerprint=data.get("fingerprint"),
            notes=data.get("notes"),
        )


class AllowlistManager:
    """Manages the interactive schema allowlist."""

    def __init__(self, config: SecurityConfig):
        self.config = config
        self.allowlist_path = config.get_allowlist_path()
        self.entries: Dict[str, SchemaEntry] = {}
        self.session_allowed: Set[str] = set()
        self._load_allowlist()

    def _load_allowlist(self) -> None:
        """Load allowlist from file."""
        try:
            if self.allowlist_path.exists():
                with open(self.allowlist_path, "r", encoding="utf-8") as f:
                    data = json.load(f)

                for url, entry_data in data.get("entries", {}).items():
                    self.entries[url] = SchemaEntry.from_dict(entry_data)
        except Exception as e:
            print(f"Warning: Failed to load allowlist: {e}")

    def _save_allowlist(self) -> None:
        """Save allowlist to file."""
        if not self.config.allowlist.auto_save:
            return

        try:
            # Create backup if enabled
            if self.config.allowlist.backup_on_change and self.allowlist_path.exists():
                backup_path = self.allowlist_path.with_suffix(".bak")
                backup_path.write_bytes(self.allowlist_path.read_bytes())

            # Prepare data
            data = {
                "version": "1.0",
                "updated": datetime.now(timezone.utc).isoformat(),
                "entries": {url: entry.to_dict() for url, entry in self.entries.items()},
            }

            # Create directory if needed
            self.allowlist_path.parent.mkdir(parents=True, exist_ok=True)

            # Write atomically
            temp_path = self.allowlist_path.with_suffix(".tmp")
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            temp_path.replace(self.allowlist_path)

        except Exception as e:
            print(f"Warning: Failed to save allowlist: {e}")

    def _calculate_fingerprint(self, content: str) -> str:
        """Calculate content fingerprint."""
        return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]

    def _prompt_user(self, url: str) -> Tuple[bool, TrustLevel]:
        """Prompt user for schema approval."""
        if not self.config.allowlist.interactive_mode:
            return False, TrustLevel.NEVER

        parsed = urlparse(url)
        domain = parsed.netloc

        print(f"\n{'='*60}")
        print("SCHEMA ALLOWLIST DECISION REQUIRED")
        print(f"{'='*60}")
        print(f"URL: {url}")
        print(f"Domain: {domain}")
        print(f"Scheme: {parsed.scheme}")
        print()
        print("This schema is not in your allowlist. Do you want to:")
        print("1. Allow permanently (saved to allowlist)")
        print("2. Allow for this session only")
        print("3. Deny (compilation will fail)")
        print()

        if self.config.allowlist.require_confirmation:
            while True:
                choice = input("Enter choice (1/2/3): ").strip()
                if choice == "1":
                    return True, TrustLevel.PERMANENT
                elif choice == "2":
                    return True, TrustLevel.SESSION
                elif choice == "3":
                    return False, TrustLevel.NEVER
                else:
                    print("Invalid choice. Please enter 1, 2, or 3.")
        else:
            # Auto-approve in CI mode
            if self.config.allowlist.auto_approve_in_ci:
                return True, TrustLevel.SESSION
            return False, TrustLevel.NEVER

    def is_allowed(self, url: str) -> bool:
        """Check if a schema URL is allowed."""
        # Check permanent allowlist
        if url in self.entries:
            entry = self.entries[url]
            if entry.trust_level == TrustLevel.PERMANENT:
                # Update usage stats
                entry.last_used = datetime.now(timezone.utc)
                entry.use_count += 1
                return True
            elif entry.trust_level == TrustLevel.NEVER:
                return False

        # Check session allowlist
        if url in self.session_allowed:
            return True

        # Check built-in trusted patterns
        if self._is_builtin_trusted(url):
            return True

        # Prompt user for decision
        approved, trust_level = self._prompt_user(url)

        if approved:
            now = datetime.now(timezone.utc)

            if trust_level == TrustLevel.PERMANENT:
                # Add to permanent allowlist
                self.entries[url] = SchemaEntry(
                    url=url,
                    trust_level=trust_level,
                    added_date=now,
                    last_used=now,
                    use_count=1,
                )
                self._save_allowlist()

            elif trust_level == TrustLevel.SESSION:
                # Add to session allowlist
                self.session_allowed.add(url)

        else:
            # Add to permanent deny list if requested
            if trust_level == TrustLevel.NEVER:
                now = datetime.now(timezone.utc)
                self.entries[url] = SchemaEntry(
                    url=url,
                    trust_level=trust_level,
                    added_date=now,
                    last_used=now,
                    use_count=0,
                )
                self._save_allowlist()

        return approved

    def _is_builtin_trusted(self, url: str) -> bool:
        """Check if URL matches built-in trusted patterns."""
        trusted_patterns = [
            "https://alexanderparker.github.io/instruction-template-specification/",
            "https://raw.githubusercontent.com/alexanderparker/instruction-template-specification/",
        ]

        return any(url.startswith(pattern) for pattern in trusted_patterns)

    def add_trusted_url(
        self,
        url: str,
        trust_level: TrustLevel = TrustLevel.PERMANENT,
        notes: Optional[str] = None,
    ) -> None:
        """Manually add a trusted URL."""
        now = datetime.now(timezone.utc)

        self.entries[url] = SchemaEntry(
            url=url,
            trust_level=trust_level,
            added_date=now,
            last_used=now,
            use_count=0,
            notes=notes,
        )

        if trust_level == TrustLevel.PERMANENT:
            self._save_allowlist()

    def remove_url(self, url: str) -> bool:
        """Remove a URL from the allowlist."""
        if url in self.entries:
            del self.entries[url]
            self._save_allowlist()
            return True

        if url in self.session_allowed:
            self.session_allowed.remove(url)
            return True

        return False

    def update_fingerprint(self, url: str, content: str) -> None:
        """Update schema content fingerprint."""
        if url in self.entries:
            fingerprint = self._calculate_fingerprint(content)

            # Check for changes
            if self.entries[url].fingerprint and self.entries[url].fingerprint != fingerprint:
                print(f"Warning: Schema content changed for {url}")

            self.entries[url].fingerprint = fingerprint
            self._save_allowlist()

    def get_stats(self) -> Dict:
        """Get allowlist statistics."""
        permanent_count = sum(1 for e in self.entries.values() if e.trust_level == TrustLevel.PERMANENT)
        denied_count = sum(1 for e in self.entries.values() if e.trust_level == TrustLevel.NEVER)
        session_count = len(self.session_allowed)

        return {
            "total_entries": len(self.entries),
            "permanent_allowed": permanent_count,
            "denied": denied_count,
            "session_allowed": session_count,
            "most_used": self._get_most_used_schemas(5),
        }

    def _get_most_used_schemas(self, limit: int) -> List[Dict]:
        """Get most frequently used schemas."""
        sorted_entries = sorted(self.entries.values(), key=lambda e: e.use_count, reverse=True)

        return [
            {
                "url": entry.url,
                "use_count": entry.use_count,
                "last_used": entry.last_used.isoformat(),
            }
            for entry in sorted_entries[:limit]
        ]

    def cleanup_old_entries(self, days: int = 90) -> int:
        """Remove old unused entries."""
        cutoff = datetime.now(timezone.utc).timestamp() - (days * 24 * 3600)
        removed_count = 0

        urls_to_remove = []
        for url, entry in self.entries.items():
            if entry.last_used.timestamp() < cutoff and entry.use_count == 0:
                urls_to_remove.append(url)

        for url in urls_to_remove:
            del self.entries[url]
            removed_count += 1

        if removed_count > 0:
            self._save_allowlist()

        return removed_count

    def export_allowlist(self, path: Path) -> None:
        """Export allowlist to a file."""
        data = {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "entries": {url: entry.to_dict() for url, entry in self.entries.items()},
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def import_allowlist(self, path: Path, merge: bool = True) -> int:
        """Import allowlist from a file."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        imported_count = 0
        for url, entry_data in data.get("entries", {}).items():
            if not merge and url in self.entries:
                continue

            self.entries[url] = SchemaEntry.from_dict(entry_data)
            imported_count += 1

        self._save_allowlist()
        return imported_count
