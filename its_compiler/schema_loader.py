"""
Schema loading and caching for ITS Compiler with core security enhancements.
Fixed to handle gzip-compressed responses properly.
"""

import gzip
import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .exceptions import ITSSchemaError
from .models import ITSConfig
from .security import AllowlistManager, SecurityConfig, URLValidator


class SchemaLoader:
    """Handles loading and caching of ITS schemas with security controls."""

    def __init__(
        self, config: ITSConfig, security_config: Optional[SecurityConfig] = None
    ):
        self.config = config
        self.cache_dir: Optional[Path] = None
        self._setup_cache()

        # Security components
        self.security_config = security_config or SecurityConfig.from_environment()
        self.url_validator = URLValidator(self.security_config)
        self.allowlist_manager = (
            AllowlistManager(self.security_config)
            if self.security_config.enable_allowlist
            else None
        )

    def _setup_cache(self) -> None:
        """Setup cache directory if caching is enabled."""
        if not self.config.cache_enabled:
            return

        if self.config.cache_directory:
            self.cache_dir = Path(self.config.cache_directory).expanduser()
        else:
            # Default cache directory
            home = Path.home()
            self.cache_dir = home / ".cache" / "its-compiler"

        if self.cache_dir:
            self.cache_dir.mkdir(parents=True, exist_ok=True)

    def load_schema(self, schema_url: str) -> Dict[str, Any]:
        """Load a schema from URL or cache with security validation."""

        # Security validation
        self._validate_schema_security(schema_url)

        # Check allowlist
        if self.allowlist_manager and not self.allowlist_manager.is_allowed(schema_url):
            raise ITSSchemaError(
                f"Schema not in allowlist and user denied access: {schema_url}",
                schema_url=schema_url,
            )

        # Try cache first
        if self.config.cache_enabled:
            cached_schema = self._load_from_cache(schema_url)
            if cached_schema is not None:
                print(f"Schema cache hit: {schema_url}")
                return cached_schema

        # Load from URL with security controls
        try:
            print(f"Fetching schema: {schema_url}")
            schema = self._load_from_url_secure(schema_url)
            print(f"Schema fetch successful: {schema_url}")

        except Exception as e:
            print(f"Schema fetch failed: {schema_url} - {e}")
            raise ITSSchemaError(
                f"Failed to load schema from {schema_url}: {e}", schema_url=schema_url
            )

        # Validate schema structure
        self._validate_schema_structure(schema, schema_url)

        # Update allowlist fingerprint
        if self.allowlist_manager:
            self.allowlist_manager.update_fingerprint(
                schema_url, json.dumps(schema, sort_keys=True)
            )

        # Cache if enabled
        if self.config.cache_enabled:
            self._save_to_cache(schema_url, schema)

        return schema

    def _validate_schema_security(self, url: str) -> None:
        """Validate schema URL against security policies."""

        # URL validation with SSRF protection
        self.url_validator.validate_url(url)

        # Block dangerous file extensions
        dangerous_extensions = {".exe", ".bat", ".cmd", ".scr", ".php", ".jsp"}
        if any(url.lower().endswith(ext) for ext in dangerous_extensions):
            print(f"Dangerous file extension in schema URL: {url}")
            raise ITSSchemaError(
                f"Dangerous file extension in schema URL: {url}", schema_url=url
            )

        # Validate path doesn't contain suspicious patterns
        suspicious_patterns = ["..", "%2e%2e", "etc/passwd", "windows/system32"]
        if any(pattern in url.lower() for pattern in suspicious_patterns):
            print(f"Suspicious path pattern in schema URL: {url}")
            raise ITSSchemaError(
                f"Suspicious path pattern in schema URL: {url}", schema_url=url
            )

    def _load_from_url_secure(self, url: str) -> Dict[str, Any]:
        """Load schema from URL with enhanced security controls and gzip support."""

        # Create request with security headers and gzip support
        headers = {
            "User-Agent": "ITS-Compiler-Python/1.0",
            "Accept": "application/json, text/plain",
            "Accept-Encoding": "gzip, deflate",  # Accept compressed responses
            "Cache-Control": "no-cache",
        }

        request = Request(url, headers=headers)

        try:
            with urlopen(
                request, timeout=self.security_config.network.request_timeout
            ) as response:
                # Validate response
                self._validate_response_security(response, url)

                # Read with size limits and handle compression
                data = self._read_response_safely(response, url)

                # Parse JSON
                try:
                    schema_data = json.loads(data.decode("utf-8"))
                    # Add type check to ensure it's a dictionary
                    if not isinstance(schema_data, dict):
                        raise ITSSchemaError(
                            f"Schema must be a JSON object, got {type(schema_data).__name__}",
                            schema_url=url,
                        )
                    return schema_data  # Now mypy knows this is Dict[str, Any]
                except json.JSONDecodeError as e:
                    raise ITSSchemaError(f"Invalid JSON in schema: {e}", schema_url=url)

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

    def _validate_response_security(self, response: Any, url: str) -> None:
        """Validate HTTP response for security."""

        # Check content type
        content_type = response.headers.get("content-type", "").lower()
        allowed_types = ["application/json", "text/json", "text/plain"]

        if not any(allowed_type in content_type for allowed_type in allowed_types):
            print(f"Invalid content type for schema: {content_type}")
            raise ITSSchemaError(
                f"Invalid content type for schema: {content_type}", schema_url=url
            )

        # Check content length
        content_length = response.headers.get("content-length")
        if content_length:
            size = int(content_length)
            if size > self.security_config.network.max_response_size:
                raise ITSSchemaError(f"Schema too large: {size} bytes", schema_url=url)

        # Check for suspicious headers
        suspicious_headers = ["x-powered-by", "server"]
        for header in suspicious_headers:
            value = response.headers.get(header, "").lower()
            if any(dangerous in value for dangerous in ["php", "asp", "jsp", "cgi"]):
                print(f"Warning: Suspicious server header detected: {header}={value}")

    def _read_response_safely(self, response: Any, url: str) -> bytes:
        """Read response data with size and timeout controls, handling gzip compression."""

        max_size = self.security_config.network.max_response_size
        chunk_size = 8192
        data = b""

        # Read the response data
        while True:
            chunk = response.read(chunk_size)
            if not chunk:
                break

            data += chunk

            if len(data) > max_size:
                raise ITSSchemaError(
                    f"Schema response too large: {len(data)} bytes", schema_url=url
                )

        # Handle decompression if needed
        content_encoding = response.headers.get("content-encoding", "").lower()

        if "gzip" in content_encoding:
            try:
                # Decompress gzip data
                data = gzip.decompress(data)
            except gzip.BadGzipFile as e:
                raise ITSSchemaError(
                    f"Invalid gzip data in schema response: {e}", schema_url=url
                )
            except Exception as e:
                raise ITSSchemaError(
                    f"Failed to decompress schema response: {e}", schema_url=url
                )
        elif "deflate" in content_encoding:
            try:
                # Handle deflate compression
                import zlib

                data = zlib.decompress(data)
            except Exception as e:
                raise ITSSchemaError(
                    f"Failed to decompress deflate schema response: {e}", schema_url=url
                )
        else:
            # Check if data might be gzip even without proper header
            # Some servers send gzip data without setting the header
            if data.startswith(b"\x1f\x8b"):
                try:
                    data = gzip.decompress(data)
                except Exception:
                    # If decompression fails, use original data
                    pass

        return data

    def _validate_schema_structure(self, schema: Dict[str, Any], url: str) -> None:
        """Enhanced validation of schema structure."""

        # Basic structure validation
        if not isinstance(schema, dict):
            raise ITSSchemaError("Schema must be a JSON object", schema_url=url)

        # Check for dangerous keys
        dangerous_keys = {"__proto__", "constructor", "prototype"}
        if any(key in schema for key in dangerous_keys):
            print(f"Warning: Dangerous keys found in schema: {url}")

        # Validate instructionTypes if present
        if "instructionTypes" in schema:
            if not isinstance(schema["instructionTypes"], dict):
                raise ITSSchemaError(
                    "instructionTypes must be an object", schema_url=url
                )

            # Validate each instruction type
            for type_name, type_def in schema["instructionTypes"].items():
                self._validate_instruction_type(type_name, type_def, url)

    def _validate_instruction_type(
        self, type_name: str, type_def: Dict[str, Any], url: str
    ) -> None:
        """Validate individual instruction type definition."""

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

        # Validate template content for security
        template = type_def["template"]
        if not isinstance(template, str):
            raise ITSSchemaError(
                f"Instruction type '{type_name}' template must be a string",
                schema_url=url,
            )

        # Check template for dangerous patterns
        dangerous_patterns = ["<script", "javascript:", "data:text/html", "eval("]
        for pattern in dangerous_patterns:
            if pattern.lower() in template.lower():
                print(f"Warning: Potentially dangerous pattern in template: {pattern}")

    def _get_cache_path(self, url: str) -> Path:
        """Get cache file path for a URL."""
        if not self.cache_dir:
            raise ValueError("Cache directory not configured")
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

            # Ensure cache_data is a dict and has the expected structure
            if not isinstance(cache_data, dict) or "schema" not in cache_data:
                # Corrupted cache, remove it
                cache_path.unlink(missing_ok=True)
                return None

            schema = cache_data.get("schema")
            # Ensure the schema is a dict
            if not isinstance(schema, dict):
                # Corrupted cache, remove it
                cache_path.unlink(missing_ok=True)
                return None

            return schema  # Now mypy knows this is Dict[str, Any]

        except (json.JSONDecodeError, KeyError, IOError):
            # Corrupted cache, remove it
            cache_path.unlink(missing_ok=True)
            return None

    def _save_to_cache(self, url: str, schema: Dict[str, Any]) -> None:
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
            print("Warning: Failed to write schema cache")

    def clear_cache(self) -> None:
        """Clear all cached schemas."""
        if not self.cache_dir or not self.cache_dir.exists():
            return

        for cache_file in self.cache_dir.glob("*.json"):
            cache_file.unlink(missing_ok=True)

        print("Schema cache cleared")

    def get_security_status(self) -> Dict[str, Any]:
        """Get security status and statistics."""

        status: Dict[str, Any] = {
            "security_enabled": True,
            "allowlist_enabled": self.allowlist_manager is not None,
        }

        if self.allowlist_manager:
            allowlist_stats = self.allowlist_manager.get_stats()
            status["allowlist_stats"] = allowlist_stats

        return status
