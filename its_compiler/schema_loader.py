"""
Schema loading and caching for ITS Compiler.
"""

import json
import time
import hashlib
from pathlib import Path
from typing import Dict, Any, Optional
from urllib.parse import urlparse, urljoin
from urllib.request import urlopen
from urllib.error import URLError, HTTPError

from .models import ITSConfig
from .exceptions import ITSSchemaError


class SchemaLoader:
    """Handles loading and caching of ITS schemas."""

    def __init__(self, config: ITSConfig):
        self.config = config
        self.cache_dir = None
        self._setup_cache()

    def _setup_cache(self):
        """Setup cache directory if caching is enabled."""
        if not self.config.cache_enabled:
            return

        if self.config.cache_directory:
            self.cache_dir = Path(self.config.cache_directory).expanduser()
        else:
            # Default cache directory
            home = Path.home()
            self.cache_dir = home / ".cache" / "its-compiler"

        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def load_schema(self, schema_url: str) -> Dict[str, Any]:
        """Load a schema from URL or cache."""

        # Security checks
        self._validate_schema_url(schema_url)

        # Try cache first
        if self.config.cache_enabled:
            cached_schema = self._load_from_cache(schema_url)
            if cached_schema is not None:
                return cached_schema

        # Load from URL
        try:
            schema = self._load_from_url(schema_url)
        except Exception as e:
            raise ITSSchemaError(
                f"Failed to load schema from {schema_url}: {e}", schema_url=schema_url
            )

        # Validate schema structure
        self._validate_schema_structure(schema, schema_url)

        # Cache if enabled
        if self.config.cache_enabled:
            self._save_to_cache(schema_url, schema)

        return schema

    def _validate_schema_url(self, url: str):
        """Validate schema URL against security policies."""
        parsed = urlparse(url)

        # Check protocol
        if not self.config.allow_http and parsed.scheme == "http":
            raise ITSSchemaError(
                f"HTTP not allowed for schema URLs: {url}", schema_url=url
            )

        if parsed.scheme not in ("http", "https", "file"):
            raise ITSSchemaError(
                f"Unsupported schema URL scheme: {parsed.scheme}", schema_url=url
            )

        # Check domain allowlist
        if (
            self.config.domain_allowlist
            and parsed.scheme in ("http", "https")
            and parsed.netloc not in self.config.domain_allowlist
        ):
            raise ITSSchemaError(
                f"Domain not in allowlist: {parsed.netloc}", schema_url=url
            )

    def _load_from_url(self, url: str) -> Dict[str, Any]:
        """Load schema from URL."""
        try:
            with urlopen(url, timeout=self.config.request_timeout) as response:
                # Check content length
                content_length = response.headers.get("content-length")
                if content_length and int(content_length) > self.config.max_schema_size:
                    raise ITSSchemaError(
                        f"Schema too large: {content_length} bytes", schema_url=url
                    )

                data = response.read()

                # Check actual size
                if len(data) > self.config.max_schema_size:
                    raise ITSSchemaError(
                        f"Schema too large: {len(data)} bytes", schema_url=url
                    )

                return json.loads(data.decode("utf-8"))

        except HTTPError as e:
            raise ITSSchemaError(
                f"HTTP error loading schema: {e.code} {e.reason}",
                schema_url=url,
                http_status=e.code,
            )
        except URLError as e:
            raise ITSSchemaError(
                f"URL error loading schema: {e.reason}", schema_url=url
            )
        except json.JSONDecodeError as e:
            raise ITSSchemaError(f"Invalid JSON in schema: {e}", schema_url=url)

    def _validate_schema_structure(self, schema: Dict[str, Any], url: str):
        """Basic validation of schema structure."""
        if not isinstance(schema, dict):
            raise ITSSchemaError("Schema must be a JSON object", schema_url=url)

        # Check for instructionTypes if this is a type extension schema
        if "instructionTypes" in schema:
            if not isinstance(schema["instructionTypes"], dict):
                raise ITSSchemaError(
                    "instructionTypes must be an object", schema_url=url
                )

            # Validate each instruction type
            for type_name, type_def in schema["instructionTypes"].items():
                if not isinstance(type_def, dict):
                    raise ITSSchemaError(
                        f"Instruction type '{type_name}' must be an object",
                        schema_url=url,
                    )

                if "template" not in type_def:
                    raise ITSSchemaError(
                        f"Instruction type '{type_name}' missing required 'template' field",
                        schema_url=url,
                    )

    def _get_cache_path(self, url: str) -> Path:
        """Get cache file path for a URL."""
        # Create a safe filename from URL
        url_hash = hashlib.md5(url.encode()).hexdigest()
        return self.cache_dir / f"{url_hash}.json"

    def _load_from_cache(self, url: str) -> Optional[Dict[str, Any]]:
        """Load schema from cache if valid."""
        if not self.cache_dir:
            return None

        cache_path = self._get_cache_path(url)

        if not cache_path.exists():
            return None

        # Check cache age
        cache_age = time.time() - cache_path.stat().st_mtime
        if cache_age > self.config.cache_ttl:
            # Cache expired, remove it
            cache_path.unlink(missing_ok=True)
            return None

        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                cache_data = json.load(f)

            # Return the cached schema
            return cache_data.get("schema")

        except (json.JSONDecodeError, KeyError, IOError):
            # Corrupted cache, remove it
            cache_path.unlink(missing_ok=True)
            return None

    def _save_to_cache(self, url: str, schema: Dict[str, Any]):
        """Save schema to cache."""
        if not self.cache_dir:
            return

        cache_path = self._get_cache_path(url)

        cache_data = {"url": url, "cached_at": time.time(), "schema": schema}

        try:
            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump(cache_data, f, indent=2)
        except IOError:
            # Ignore cache write errors
            pass

    def clear_cache(self):
        """Clear all cached schemas."""
        if not self.cache_dir or not self.cache_dir.exists():
            return

        for cache_file in self.cache_dir.glob("*.json"):
            cache_file.unlink(missing_ok=True)
