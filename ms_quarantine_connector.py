"""
MS Quarantine Manager - Splunk SOAR Custom App
==============================================

Manages Microsoft Defender quarantined emails by calling an Azure Function
that executes Exchange Online PowerShell cmdlets on behalf of SOAR Cloud.

Documentation references
------------------------
Splunk SOAR
  - Connector module development:
    https://help.splunk.com/en/splunk-soar/soar-cloud/develop-apps/develop-apps/app-structure/connector-module-development
  - App JSON metadata schema:
    https://docs.splunk.com/Documentation/SOAR/current/DevelopApps/Metadata
  - Contains parameter (contextual actions):
    https://docs.splunk.com/Documentation/SOAR/current/DevelopApps/Contains
  - Vault file usage in apps:
    https://docs.splunk.com/Documentation/SOAR/current/PlaybookAPI/VaultAPI

Microsoft (PowerShell cmdlets used by the Azure Function)
  - Get-QuarantineMessage:
    https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-quarantinemessage
  - Export-QuarantineMessage:
    https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/export-quarantinemessage
  - Release-QuarantineMessage:
    https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/release-quarantinemessage

Architecture
------------
    Splunk SOAR Cloud
         |
         | HTTPS + function key (header / query / none)
         v
    Azure Function (customer's Azure tenant)
         |
         | ExchangeOnlineManagement PowerShell module
         v
    Exchange Online / Microsoft Defender

Export modes
------------
The 'get quarantine message' action supports two output modes via the
export_mode asset configuration:

  vault (default, recommended)
      The decoded EML is stored in the SOAR Vault as a binary file.
      The action result contains vault_id, file_name, sha256, sha1, md5,
      and size. Other apps that take 'vault id' as input (e.g. ANY.RUN
      Cloud Sandbox, VirusTotal File Reputation) can consume it directly.

  inline (legacy / direct forwarding)
      The base64-encoded EML is returned in action_result.data.*.eml.
      Useful when forwarding to a third-party HTTP API that does not
      accept Vault references (e.g. a custom REST scanner).

Author:  Custom
Version: 1.3.0
"""

import base64
import hashlib
import json
import os
import tempfile
import urllib.parse

import requests
import phantom.app as phantom

from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

# Vault helpers. The phantom.rules module exposes vault_add() in modern SOAR.
# Importing at module top-level keeps the dependency explicit.
# Reference: https://docs.splunk.com/Documentation/SOAR/current/PlaybookAPI/VaultAPI
try:
    import phantom.rules as phrules
except ImportError:
    phrules = None  # Tests may run without the SOAR runtime


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Authentication methods for the Azure Function key.
AUTH_HEADER = "header"
AUTH_QUERY  = "query"
AUTH_NONE   = "none"
VALID_AUTH_METHODS = {AUTH_HEADER, AUTH_QUERY, AUTH_NONE}

# Export modes for the get-quarantine-message action.
EXPORT_VAULT  = "vault"
EXPORT_INLINE = "inline"
VALID_EXPORT_MODES = {EXPORT_VAULT, EXPORT_INLINE}

# Azure Function URL paths.
ENDPOINT_HEALTH  = "/health"
ENDPOINT_LIST    = "/list"
ENDPOINT_EXPORT  = "/export/{identity}"
ENDPOINT_RELEASE = "/release/{identity}"
ENDPOINT_DENY    = "/deny/{identity}"

# Defaults matching the JSON manifest.
DEFAULT_AUTH_METHOD = AUTH_HEADER
DEFAULT_VERIFY_SSL  = True
DEFAULT_TIMEOUT     = 120
DEFAULT_EXPORT_MODE = EXPORT_VAULT

# EML field name variants (PowerShell PascalCase vs normalized).
EML_FIELD_VARIANTS = ("eml", "Eml", "EML")


# ---------------------------------------------------------------------------
# Connector
# ---------------------------------------------------------------------------

class MSQuarantineConnector(BaseConnector):
    """
    Splunk SOAR connector for Microsoft Defender Quarantine management.
    See module docstring for architecture and references.
    """

    def __init__(self):
        super().__init__()
        self._base_url     = None
        self._function_key = None
        self._auth_method  = None
        self._verify_ssl   = None
        self._timeout      = None
        self._export_mode  = None

    # -----------------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------------

    def initialize(self):
        config = self.get_config()

        self._base_url = config.get("function_base_url", "").rstrip("/")
        if not self._base_url.startswith("https://"):
            return self.set_status(
                phantom.APP_ERROR,
                "function_base_url must start with https://."
            )

        self._function_key = config.get("function_key", "").strip()

        self._auth_method = config.get("auth_method", DEFAULT_AUTH_METHOD).strip().lower()
        if self._auth_method not in VALID_AUTH_METHODS:
            return self.set_status(
                phantom.APP_ERROR,
                f"auth_method must be one of: {', '.join(sorted(VALID_AUTH_METHODS))}. "
                f"Got: '{self._auth_method}'"
            )

        self._export_mode = config.get("export_mode", DEFAULT_EXPORT_MODE).strip().lower()
        if self._export_mode not in VALID_EXPORT_MODES:
            return self.set_status(
                phantom.APP_ERROR,
                f"export_mode must be one of: {', '.join(sorted(VALID_EXPORT_MODES))}. "
                f"Got: '{self._export_mode}'"
            )

        if self._auth_method == AUTH_NONE and self._function_key:
            self.save_progress(
                "Warning: auth_method is 'none' but function_key is set. "
                "The key will be ignored."
            )
        if self._auth_method != AUTH_NONE and not self._function_key:
            self.save_progress(
                f"Warning: auth_method is '{self._auth_method}' but function_key "
                "is empty. Requests will likely be rejected with HTTP 401."
            )

        self._verify_ssl = config.get("verify_ssl", DEFAULT_VERIFY_SSL)
        self._timeout    = int(config.get("timeout", DEFAULT_TIMEOUT))

        return phantom.APP_SUCCESS

    # -----------------------------------------------------------------------
    # HTTP client helpers
    # -----------------------------------------------------------------------

    def _build_url(self, path_template, identity=None):
        if identity is not None:
            encoded_identity = urllib.parse.quote(identity, safe="")
            path = path_template.format(identity=encoded_identity)
        else:
            path = path_template
        return f"{self._base_url}{path}"

    def _build_headers(self):
        headers = {
            "Content-Type": "application/json",
            "Accept":       "application/json",
        }
        if self._auth_method == AUTH_HEADER and self._function_key:
            headers["x-functions-key"] = self._function_key
        return headers

    def _build_params(self):
        if self._auth_method == AUTH_QUERY and self._function_key:
            return {"code": self._function_key}
        return None

    def _make_request(self, method, path_template, identity=None):
        url    = self._build_url(path_template, identity)
        params = self._build_params()
        self.save_progress(f"{method} {url}")

        try:
            response = requests.request(
                method=method, url=url,
                headers=self._build_headers(),
                params=params, timeout=self._timeout,
                verify=self._verify_ssl,
            )
        except requests.exceptions.SSLError as exc:
            return False, f"SSL certificate verification failed: {exc}."
        except requests.exceptions.ConnectionError as exc:
            return False, f"Cannot connect to Azure Function: {exc}."
        except requests.exceptions.Timeout:
            return False, (
                f"Request timed out after {self._timeout}s. "
                "Increase timeout in asset settings."
            )
        except requests.exceptions.RequestException as exc:
            return False, f"HTTP request failed: {exc}"

        if response.status_code == 401:
            return False, "Authentication failed (HTTP 401). Check function_key and auth_method."
        if response.status_code == 403:
            return False, "Access forbidden (HTTP 403). Check function key permissions."
        if response.status_code == 404:
            return False, f"Endpoint not found (HTTP 404): {url}"
        if response.status_code == 400:
            detail = self._extract_detail(response)
            return False, f"Bad request (HTTP 400): {detail}"
        if response.status_code == 502:
            detail = self._extract_detail(response)
            return False, f"Azure Function error (HTTP 502): {detail}"
        if response.status_code == 504:
            return False, "Azure Function timed out (HTTP 504)."
        if not response.ok:
            return False, f"Unexpected HTTP {response.status_code}: {response.text[:500]}"

        if not response.text.strip():
            return True, {}

        try:
            return True, response.json()
        except ValueError:
            return False, f"Failed to parse JSON response: {response.text[:200]}"

    def _extract_detail(self, response):
        try:
            return response.json().get("detail", response.text)
        except Exception:
            return response.text[:500]

    def _extract_eml(self, data):
        """Extract base64 EML field tolerating 'eml', 'Eml', 'EML' variants."""
        if isinstance(data, list):
            if not data:
                return ""
            data = data[0]
        if not isinstance(data, dict):
            return str(data) if data else ""
        for key in EML_FIELD_VARIANTS:
            if key in data:
                value = data[key]
                if isinstance(value, dict) and "value" in value:
                    return str(value["value"])
                return str(value) if value is not None else ""
        return ""

    # -----------------------------------------------------------------------
    # Vault helpers
    # -----------------------------------------------------------------------

    def _safe_filename_from_identity(self, identity):
        """
        Build a filesystem-safe filename from a quarantine identity.

        Identity has the form GUID1\\GUID2. We use the first 8 chars of
        GUID1 to keep the filename short but identifying. The full identity
        is still preserved in action_result.parameter.identity.
        """
        # Take the part before the backslash, strip non-alphanumerics
        first_part = identity.split("\\", 1)[0] if "\\" in identity else identity
        safe = "".join(c for c in first_part if c.isalnum() or c == "-")[:36]
        return f"quarantine_{safe}.eml"

    def _calculate_hashes(self, data_bytes):
        """Calculate MD5, SHA1, SHA256 of the raw EML bytes."""
        return {
            "md5":    hashlib.md5(data_bytes).hexdigest(),
            "sha1":   hashlib.sha1(data_bytes).hexdigest(),
            "sha256": hashlib.sha256(data_bytes).hexdigest(),
        }

    def _store_in_vault(self, eml_bytes, identity, action_result):
        """
        Decode the base64 EML, write to a temp file, add to the SOAR Vault.

        Returns:
            tuple(success: bool, vault_metadata: dict | error_message: str)
        """
        if phrules is None:
            return False, (
                "phantom.rules is not available. The Vault API requires the "
                "SOAR runtime. Switch export_mode to 'inline' for testing."
            )

        file_name = self._safe_filename_from_identity(identity)

        # Write to a temp file inside the SOAR vault tmp directory.
        # phantom.rules expects a real file path on disk.
        try:
            vault_tmp_dir = phrules.Vault.get_vault_tmp_dir()
        except Exception:
            # Fallback for older SOAR versions
            vault_tmp_dir = tempfile.gettempdir()

        # Use a unique temp file to avoid collisions when multiple
        # instances of this action run in parallel.
        fd, tmp_path = tempfile.mkstemp(
            suffix=".eml",
            prefix="quarantine_",
            dir=vault_tmp_dir,
        )

        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(eml_bytes)

            # Add to vault. Container ID identifies which container the
            # file belongs to; SOAR resolves this at runtime.
            success, message, vault_id = phrules.vault_add(
                container=self.get_container_id(),
                file_location=tmp_path,
                file_name=file_name,
                metadata={
                    "source":   "MS Quarantine Manager",
                    "identity": identity,
                },
            )
        finally:
            # Remove temp file - SOAR has copied it into the vault
            try:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
            except Exception:
                pass

        if not success:
            return False, f"Vault add failed: {message}"

        return True, {
            "vault_id":  vault_id,
            "file_name": file_name,
        }

    # -----------------------------------------------------------------------
    # Action: test connectivity
    # -----------------------------------------------------------------------

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress(f"Testing connectivity to: {self._base_url}/health")
        self.save_progress(f"Auth method: {self._auth_method}")
        self.save_progress(f"Export mode: {self._export_mode}")

        ok, data = self._make_request("GET", ENDPOINT_HEALTH)
        if not ok:
            return action_result.set_status(
                phantom.APP_ERROR,
                f"Connectivity test failed: {data}"
            )

        service = data.get("service", "unknown") if isinstance(data, dict) else "unknown"
        return action_result.set_status(
            phantom.APP_SUCCESS,
            f"Successfully connected to Azure Function (service: {service})"
        )

    # -----------------------------------------------------------------------
    # Action: list quarantine requests
    # -----------------------------------------------------------------------

    def _handle_list_quarantine_requests(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("Requesting quarantine messages with ReleaseStatus = Requested...")

        ok, data = self._make_request("GET", ENDPOINT_LIST)
        if not ok:
            return action_result.set_status(
                phantom.APP_ERROR,
                f"Failed to list quarantine requests: {data}"
            )

        if isinstance(data, dict):
            messages = data.get("messages", [])
        elif isinstance(data, list):
            messages = data
        else:
            messages = []

        for msg in messages:
            action_result.add_data({
                "Identity":         msg.get("Identity", ""),
                "SenderAddress":    msg.get("SenderAddress", ""),
                "RecipientAddress": msg.get("RecipientAddress", ""),
                "Subject":          msg.get("Subject", ""),
                "Type":             msg.get("Type", ""),
                "ReceivedTime":     msg.get("ReceivedTime", ""),
                "Expires":          msg.get("Expires", ""),
                "PolicyName":       msg.get("PolicyName", ""),
                "ReleaseStatus":    msg.get("ReleaseStatus", ""),
            })

        total = len(messages)
        action_result.update_summary({"total_found": total})
        return action_result.set_status(
            phantom.APP_SUCCESS,
            f"Found {total} message(s) with release status 'Requested'"
        )

    # -----------------------------------------------------------------------
    # Action: get quarantine message
    # -----------------------------------------------------------------------

    def _handle_get_quarantine_message(self, param):
        """
        Export a quarantined message.

        Two return modes controlled by the export_mode asset config:

        - vault (default): decode base64 EML, store as file in SOAR Vault,
          return vault_id, file_name, hashes, size.

        - inline: return base64 EML in action_result.data.*.eml.
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        identity = param.get("identity", "").strip()
        if not identity:
            return action_result.set_status(
                phantom.APP_ERROR,
                "The 'identity' parameter is required."
            )

        self.save_progress(f"Exporting quarantine message: {identity}")
        self.save_progress(f"Export mode: {self._export_mode}")

        ok, data = self._make_request("GET", ENDPOINT_EXPORT, identity=identity)
        if not ok:
            return action_result.set_status(
                phantom.APP_ERROR,
                f"Failed to export message '{identity}': {data}"
            )

        eml_base64 = self._extract_eml(data)
        if not eml_base64:
            return action_result.set_status(
                phantom.APP_ERROR,
                f"Azure Function returned no EML content for '{identity}'"
            )

        # Decode for hash calculation and (in vault mode) for file storage.
        # We do this in both modes so playbooks always have hashes available
        # for IOC enrichment regardless of export mode.
        try:
            eml_bytes = base64.b64decode(eml_base64)
        except Exception as exc:
            return action_result.set_status(
                phantom.APP_ERROR,
                f"Azure Function returned invalid base64 EML: {exc}"
            )

        hashes = self._calculate_hashes(eml_bytes)
        size = len(eml_bytes)

        if self._export_mode == EXPORT_VAULT:
            ok, result = self._store_in_vault(eml_bytes, identity, action_result)
            if not ok:
                return action_result.set_status(phantom.APP_ERROR, result)

            action_result.add_data({
                "vault_id":  result["vault_id"],
                "file_name": result["file_name"],
                "size":      size,
                **hashes,
            })
            action_result.update_summary({"export_mode": EXPORT_VAULT})
            return action_result.set_status(
                phantom.APP_SUCCESS,
                f"Message '{identity}' stored in vault (id: {result['vault_id']})"
            )

        # Inline mode
        action_result.add_data({
            "eml":  eml_base64,
            "size": size,
            **hashes,
        })
        action_result.update_summary({"export_mode": EXPORT_INLINE})
        return action_result.set_status(
            phantom.APP_SUCCESS,
            f"Message '{identity}' returned inline as base64"
        )

    # -----------------------------------------------------------------------
    # Action: release quarantine message
    # -----------------------------------------------------------------------

    def _handle_release_quarantine_message(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        identity = param.get("identity", "").strip()
        if not identity:
            return action_result.set_status(
                phantom.APP_ERROR,
                "The 'identity' parameter is required."
            )

        self.save_progress(f"Releasing quarantine message: {identity}")
        ok, data = self._make_request("POST", ENDPOINT_RELEASE, identity=identity)
        if not ok:
            return action_result.set_status(
                phantom.APP_ERROR,
                f"Failed to release message '{identity}': {data}"
            )

        result = data if isinstance(data, dict) else {"status": "released"}
        action_result.add_data(result)
        return action_result.set_status(
            phantom.APP_SUCCESS,
            f"Message '{identity}' released to all original recipients"
        )

    # -----------------------------------------------------------------------
    # Action: deny quarantine release
    # -----------------------------------------------------------------------

    def _handle_deny_quarantine_release(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        identity = param.get("identity", "").strip()
        if not identity:
            return action_result.set_status(
                phantom.APP_ERROR,
                "The 'identity' parameter is required."
            )

        self.save_progress(f"Denying release request for message: {identity}")
        ok, data = self._make_request("POST", ENDPOINT_DENY, identity=identity)
        if not ok:
            return action_result.set_status(
                phantom.APP_ERROR,
                f"Failed to deny release for message '{identity}': {data}"
            )

        result = data if isinstance(data, dict) else {"status": "denied"}
        action_result.add_data(result)
        return action_result.set_status(
            phantom.APP_SUCCESS,
            f"Release request for message '{identity}' denied"
        )

    # -----------------------------------------------------------------------
    # Action dispatcher
    # -----------------------------------------------------------------------

    def handle_action(self, param):
        action = self.get_action_identifier()
        handlers = {
            "test_connectivity":          self._handle_test_connectivity,
            "list_quarantine_requests":   self._handle_list_quarantine_requests,
            "get_quarantine_message":     self._handle_get_quarantine_message,
            "release_quarantine_message": self._handle_release_quarantine_message,
            "deny_quarantine_release":    self._handle_deny_quarantine_release,
        }
        handler = handlers.get(action)
        if handler:
            return handler(param)
        self.save_progress(f"Unknown action: {action}")
        return phantom.APP_ERROR


# ---------------------------------------------------------------------------
# Standalone CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    with open(sys.argv[1]) as f:
        in_json = f.read()
    in_json = json.loads(in_json)
    print(json.dumps(in_json, indent=4))
    connector = MSQuarantineConnector()
    connector.print_progress_message = True
    connector._handle_action(json.dumps(in_json), None)
    print(json.dumps(json.loads(connector.get_action_results()), indent=4))
    sys.exit(0)
