# MS Quarantine Manager – Splunk SOAR App

**Version:** 1.3.0 | **Min SOAR:** 6.2.0 | **Python:** 3

A Splunk SOAR Custom App for managing Microsoft Defender quarantined emails
via an Azure Function execution layer. Supports both **SOAR Vault** integration
(default, recommended) and **inline base64** mode for direct API forwarding.

---

## Table of Contents

- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [App Installation](#app-installation)
- [Asset Configuration](#asset-configuration)
- [Test Connectivity](#test-connectivity)
- [Actions](#actions)
- [Export Modes Explained](#export-modes-explained)
- [Identity Format](#identity-format)
- [Example Playbook Flows](#example-playbook-flows)
- [Error Reference](#error-reference)
- [Troubleshooting](#troubleshooting)
- [Implementation Notes](#implementation-notes)
- [Testing](#testing)
- [Files](#files)
- [Changelog](#changelog)

---

## Architecture

```
Splunk SOAR Cloud
      │
      │  HTTPS + function key
      ▼
Azure Function (customer's Azure tenant)
      │
      │  ExchangeOnlineManagement PowerShell
      ▼
Exchange Online / Microsoft Defender
```

For exports, the connector additionally writes the decoded EML to the
SOAR Vault by default:

```
Azure Function returns base64 EML
      │
      ▼
Connector decodes to bytes
      │
      ▼ (vault mode, default)
SOAR Vault (vault_id, hashes, size)
      │
      ▼
Other apps (ANY.RUN, VirusTotal, Hybrid Analysis...)
```

---

## Prerequisites

### Azure side

| Requirement | Notes |
|---|---|
| Azure Function App | Python or PowerShell runtime with `/health`, `/list`, `/export/{identity}`, `/release/{identity}`, `/deny/{identity}` endpoints |
| Function Key | Function-level or Host key recommended; or Anonymous auth level |
| Exchange Online permissions | The identity the Function runs as needs `Security Reader` + `Quarantine Administrator` (or Global Admin) in the Microsoft 365 tenant |
| TLS | The Azure Function must be served over HTTPS (`https://`) |

### SOAR side

| Requirement | Notes |
|---|---|
| Splunk SOAR | ≥ 6.2.0 |
| Python | 3 (tested with 3.13) |
| `requests` | Auto-installed via `pip3_dependencies` in the app manifest |
| Network | SOAR must be able to reach the Azure Function App URL outbound over TCP 443 |

**No system-level binary dependencies.** The connector is pure Python.

---

## App Installation

1. Download `ms_quarantine_azfunc_v1.3.0.zip` from this repository.
2. In SOAR, go to **Apps → Install App**.
3. Upload the ZIP file.
4. After installation, go to **Apps → MS Quarantine Manager → Configure New Asset**.
5. Fill in the asset configuration fields (see next section).
6. Click **Save** and then **Test Connectivity**.

> **Note:** Do not extract the ZIP before uploading. SOAR expects a flat ZIP archive
> with all app files at the root level.

---

## Asset Configuration

| Field | Required | Default | Description |
|---|---|---|---|
| `function_base_url` | ✅ | – | Azure Function App API base URL, **no trailing slash**. Example: `https://contoso-quarantine.azurewebsites.net/api` |
| `function_key` | ❌ | – | Azure Function key. Leave empty only if the Function auth level is `Anonymous` |
| `auth_method` | ❌ | `header` | How to send the key: `header` (x-functions-key, recommended), `query` (?code=), or `none` |
| `verify_ssl` | ❌ | `true` | Verify the Azure Function SSL certificate. Always `true` in production |
| `timeout` | ❌ | `120` | HTTP timeout in seconds. PowerShell cold starts and EXO cmdlets are slow — minimum 60 s recommended |
| `export_mode` | ❌ | `vault` | `vault` (recommended) stores EML in SOAR Vault and returns `vault_id`; `inline` returns base64 EML directly |

---

## Test Connectivity

The **test connectivity** action calls `GET /health` on the Azure Function and
verifies a `200 OK` response. It does **not** test Exchange Online connectivity —
only the SOAR → Azure Function leg.

To run: **Apps → MS Quarantine Manager → \<your asset\> → Test Connectivity**

A successful response logs:
```
Successfully connected to Azure Function (service: ms-quarantine-manager)
```

---

## Actions

### `test connectivity`

| | |
|---|---|
| Type | `test` |
| Endpoint | `GET /health` |
| Parameters | — |

---

### `list quarantine requests`

| | |
|---|---|
| Type | `investigate` |
| Endpoint | `GET /list` |
| PowerShell | `Get-QuarantineMessage -ReleaseStatus Requested` |
| Parameters | — |

**Output fields:**

| Data Path | Type | Description |
|---|---|---|
| `action_result.data.*.Identity` | string | Quarantine identity (GUID1\\GUID2) |
| `action_result.data.*.SenderAddress` | string | Sender email address |
| `action_result.data.*.RecipientAddress` | string | Recipient email address |
| `action_result.data.*.Subject` | string | Email subject |
| `action_result.data.*.Type` | string | Quarantine type (HighConfPhish, Spam, Malware, …) |
| `action_result.data.*.ReceivedTime` | string | ISO 8601 timestamp |
| `action_result.data.*.Expires` | string | ISO 8601 expiry timestamp |
| `action_result.data.*.PolicyName` | string | Applied quarantine policy |
| `action_result.data.*.ReleaseStatus` | string | e.g. `REQUESTED` |
| `action_result.summary.total_found` | numeric | Number of messages returned |

---

### `get quarantine message`

| | |
|---|---|
| Type | `investigate` |
| Endpoint | `GET /export/{identity}` |
| PowerShell | `Export-QuarantineMessage -Identity <identity>` |

**Parameters:**

| Name | Required | Description |
|---|---|---|
| `identity` | ✅ | Quarantine identity in format `GUID1\GUID2` (from list action output) |

**Output fields (vault mode):**

| Data Path | Type | Description |
|---|---|---|
| `action_result.data.*.vault_id` | string | SOAR Vault file ID (contains: vault id, sha1) |
| `action_result.data.*.file_name` | string | Vault file name, e.g. `quarantine_c14401cf.eml` |
| `action_result.data.*.size` | numeric | EML size in bytes |
| `action_result.data.*.sha256` | string | SHA-256 hash of the EML |
| `action_result.data.*.sha1` | string | SHA-1 hash of the EML |
| `action_result.data.*.md5` | string | MD5 hash of the EML |

**Output fields (inline mode):**

| Data Path | Type | Description |
|---|---|---|
| `action_result.data.*.eml` | string | Base64-encoded raw EML |
| `action_result.data.*.size` | numeric | EML size in bytes |
| `action_result.data.*.sha256` | string | SHA-256 hash |
| `action_result.data.*.sha1` | string | SHA-1 hash |
| `action_result.data.*.md5` | string | MD5 hash |

---

### `release quarantine message`

| | |
|---|---|
| Type | `correct` |
| Endpoint | `POST /release/{identity}` |
| PowerShell | `Release-QuarantineMessage -Identity <id> -ReleaseToAll` |

> ⚠️ **Irreversible.** The message is delivered to all original recipients immediately.

**Parameters:**

| Name | Required | Description |
|---|---|---|
| `identity` | ✅ | Quarantine identity in format `GUID1\GUID2` |

---

### `deny quarantine release`

| | |
|---|---|
| Type | `correct` |
| Endpoint | `POST /deny/{identity}` |
| PowerShell | `Release-QuarantineMessage -Identity <id> -ActionType Deny` |

**Parameters:**

| Name | Required | Description |
|---|---|---|
| `identity` | ✅ | Quarantine identity in format `GUID1\GUID2` |

---

## Export Modes Explained

### Mode `vault` (default, recommended)

The connector decodes the base64 EML, writes it to a temporary file,
and adds it to the SOAR Vault via `phantom.rules.vault_add()`.

**Action result:**
```json
{
  "vault_id":  "a1b2c3d4e5f6abcdef1234567890abcdef123456",
  "file_name": "quarantine_c14401cf.eml",
  "size":      4521,
  "sha256":    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "sha1":      "da39a3ee5e6b4b0d3255bfef95601890afd80709",
  "md5":       "d41d8cd98f00b204e9800998ecf8427e"
}
```

The `vault_id` field is annotated with `contains: ["vault id", "sha1"]` so downstream
apps (ANY.RUN, VirusTotal, Hybrid Analysis) display it as a context option in the SOAR UI.

**Use this mode when:**
- Sending the EML to ANY.RUN / VirusTotal / any file-based scanner
- Forensic preservation of the EML in the SOAR container
- IOC enrichment workflows that consume hashes

### Mode `inline`

The connector returns the base64 EML directly in the action result.

**Action result:**
```json
{
  "eml":    "RnJvbTogYXR0YWNrZXJAZXZpbC5jb20...",
  "size":   4521,
  "sha256": "...",
  "sha1":   "...",
  "md5":    "..."
}
```

**Use this mode when:**
- POSTing directly to a third-party HTTP API that does not support the Vault
- Avoiding writes to the vault (privacy, retention policy)

> **Note:** Hashes (sha256, sha1, md5) and size are computed and returned in
> **both** modes, so IOC lookups work regardless of which export mode is active.

---

## Identity Format

```
GUID1\GUID2
Example: c14401cf-aa9a-465b-cfd5-08d0f0ca37c5\4c2ca98e-94ea-db3a-7eb8-3b63657d4db7
```

Per Microsoft documentation, this is the canonical format returned by
`Get-QuarantineMessage`. The connector URL-encodes the backslash to `%5C`
automatically when building request URLs.

---

## Example Playbook Flows

### Flow A: Vault mode → ANY.RUN Sandbox

```
[list quarantine requests]
        │
        ▼  for each Identity
[get quarantine message]           (export_mode = vault)
   identity = msg.Identity
        │
        ▼
   action_result.data[0].vault_id
        │
        ▼
[ANY.RUN Cloud Sandbox: detonate file]
   vault_id = <from above>
        │
        ▼
   Verdict: malicious / suspicious / no threat
        │
   ┌────┴────┐
 clean   malicious
   │         │
   ▼         ▼
[release]  [deny]
```

### Flow B: Inline mode → Custom REST scanner

```
[list quarantine requests]
        │
        ▼  for each Identity
[get quarantine message]           (export_mode = inline)
   identity = msg.Identity
        │
        ▼
   action_result.data[0].eml (base64)
        │
        ▼
[HTTP POST: custom-scanner.example.com/v1/scan]
   body: { "eml": "<base64>" }
        │
        ▼
   Verdict → [release] or [deny]
```

### Flow C: Hash-based pre-check (vault mode)

```
[get quarantine message]           (export_mode = vault)
        │
        ▼
   action_result.data[0].sha256
        │
        ▼
[VirusTotal: file reputation]      ── known malicious?
        │
   ┌────┴────────────────┐
 unknown               known bad
   │                       │
   ▼                       ▼
[detonate in sandbox]  [deny without sandboxing]
```

---

## Error Reference

| Error | Cause | Fix |
|---|---|---|
| HTTP 400 | Malformed identity | Check the identity format: `GUID1\GUID2` |
| HTTP 401 | Wrong or missing function key | Verify `function_key` and `auth_method` in asset settings |
| HTTP 403 | Key valid but no permission | Try a Host key instead of a Function-level key |
| HTTP 404 | URL or function not found | Check `function_base_url` and that the function is deployed |
| HTTP 502 | PowerShell execution failed | Check Azure Function logs in the Azure Portal |
| HTTP 504 | PowerShell timed out | Increase `timeout` in asset settings; check Exchange Online health |
| Connection error | Cannot reach Azure Function | Check network/firewall from SOAR to Azure Function URL |
| SSL error | Certificate mismatch or untrusted CA | Verify HTTPS certificate; set `verify_ssl=false` only for testing |
| Vault add failed | SOAR Vault write error | Check SOAR container permissions; switch to `inline` mode to isolate |
| Invalid base64 EML | Azure Function returned malformed data | Check Azure Function implementation and PowerShell output |

---

## Troubleshooting

### Test Connectivity fails with HTTP 401

The function key is missing, wrong, or sent via the wrong method.

1. Open the Azure Function App in the Azure Portal → **Functions → \<function\> → Function Keys**.
2. Copy a valid key.
3. In the SOAR asset, paste the key into `function_key`.
4. Confirm `auth_method` matches how the Function expects it: `header` (x-functions-key) or `query` (?code=).

### Test Connectivity fails with "Cannot connect"

SOAR Cloud cannot reach the Azure Function App URL.

1. Confirm the `function_base_url` is correct and accessible from the public internet.
2. Check the Azure Function App → **Networking** — if inbound access restrictions are set, add the SOAR egress IP(s).

### `get quarantine message` returns "No EML content"

The Azure Function returned an empty or missing `eml` / `Eml` / `EML` field.

1. Test the `/export/{identity}` endpoint directly with curl or Postman.
2. Check Azure Function logs for PowerShell errors (`Export-QuarantineMessage` failure).
3. Confirm the identity exists and has not already expired.

### Vault mode fails: "phantom.rules not available"

You are running the connector outside the SOAR runtime (e.g. local `python3` test).
Switch `export_mode` to `inline` in the test JSON, or run via `phenv python3`.

### PowerShell cold starts cause timeouts

Azure Functions on a Consumption plan spin down after inactivity. The first call
after a cold start can take 30–60 s for PowerShell + the ExchangeOnlineManagement
module to initialise. Increase `timeout` to 180 s or consider a Premium plan / Always On.

---

## Implementation Notes

### EML field case tolerance
PowerShell `Export-QuarantineMessage` returns `.Eml` (PascalCase). The connector
accepts `eml`, `Eml`, and `EML` from the Azure Function and normalises internally.

### Hash calculation in both modes
Even in inline mode the connector decodes the EML bytes to compute hashes.
This costs minimal CPU but enables hash-based IOC lookups without additional apps.

### Filename generation
The vault file name is derived from the first 8 characters of GUID1 of the identity,
prefixed with `quarantine_` and suffixed with `.eml` (e.g. `quarantine_c14401cf.eml`).
The full identity is preserved in `action_result.parameter.identity` and in vault metadata.

### Vault metadata
```python
{
  "source":   "MS Quarantine Manager",
  "identity": "<full identity>"
}
```

### Privacy considerations
Vault files persist in the container until manually deleted. EML content may include
phishing payloads, sensitive sender information, or PII. If your retention policy
requires earlier deletion, use `inline` mode or add a vault cleanup step at the end
of the playbook.

---

## Testing

```bash
pip install pytest requests-mock
pytest test_connector.py -v
```

**48 tests across 9 categories:**

| Category | Tests | What is verified |
|---|---|---|
| `TestInitialize` | 5 | Asset config, default `export_mode=vault` |
| `TestAuthMethods` | 3 | All three auth methods |
| `TestConnectivity` | 2 | Health endpoint |
| `TestList` | 2 | List action and summary |
| `TestExportVaultMode` | 10 | Vault file storage, hashes, metadata, size |
| `TestExportInlineMode` | 7 | Base64 in action result, no vault call |
| `TestExportCommon` | 5 | Errors common to both modes |
| `TestRelease` / `TestDeny` | 4 | Success, POST method, error handling |
| `TestErrorHandling` | 7 | All HTTP error codes + timeout |
| `TestFilenameSafety` | 3 | Vault filename construction |

**Local on-SOAR testing** (`phenv` required):

```bash
# Example test JSON: /tmp/test_export.json
{
  "identifier": "get_quarantine_message",
  "asset_id": "1",
  "parameters": [{"identity": "GUID1\\GUID2"}],
  "config": {
    "function_base_url": "https://contoso-quarantine.azurewebsites.net/api",
    "function_key": "YOUR_KEY",
    "auth_method": "header",
    "export_mode": "inline"
  }
}

cd /opt/phantom/apps/phantom_ms_quarantine_azfunc_*/
phenv python3 ms_quarantine_connector.py /tmp/test_export.json
```

---

## Files

| File | Description |
|---|---|
| `ms_quarantine.json` | App manifest (actions, asset config, output schema) |
| `ms_quarantine_connector.py` | Connector (v1.3.0) |
| `test_connector.py` | 48 unit tests (pytest + requests-mock) |
| `ms_quarantine_azfunc_v1.3.0.zip` | **Installable SOAR app package** — upload this to SOAR |
| `ms_quarantine.png` | Light theme icon |
| `ms_quarantine_dark.png` | Dark theme icon |
| `__init__.py` | Required by SOAR app packaging (empty) |

---

## Changelog

### 1.3.0
- **Vault mode (default):** exported EMLs are stored as files in the SOAR Vault.
  The action returns `vault_id`, `file_name`, `sha256`, `sha1`, `md5`, and `size`.
  Apps like ANY.RUN Cloud Sandbox, VirusTotal File Reputation, and Hybrid Analysis
  can consume the vault file directly.
- **Inline mode:** base64 EML still available via `export_mode=inline` for use cases
  that POST directly to a third-party HTTP API without Vault support.
- **Hashes always present:** MD5 / SHA1 / SHA256 and size are returned in both modes.
- **`__init__.py` added** to the package (required by SOAR app loader).
- **`pudb` debug dependency removed** from the CLI entrypoint.
- `export_mode` added to asset configuration with dropdown (`vault` / `inline`).

### 1.2.0
- Initial release.
- Actions: test connectivity, list quarantine requests, get quarantine message,
  release quarantine message, deny quarantine release.
- Inline base64 EML export only.
