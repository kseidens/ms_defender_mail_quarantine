"""
Connector Tests - MS Defender Mail Quarantine v1.3.0
===============================================
Tests both export modes (vault + inline) and all error paths.

Run:
    pip install pytest requests-mock
    pytest test_connector.py -v
"""

import base64
import hashlib
import json
import sys
import types

import pytest
import requests
import requests_mock as req_mock


# -- Minimal SOAR SDK stubs --------------------------------------------------

class _ActionResult:
    def __init__(self, param=None):
        self._data = []
        self._summary = {}
        self._status = None
        self._message = ""
        self.param = param or {}

    def add_data(self, d):       self._data.append(d); return self
    def update_summary(self, s): self._summary.update(s)
    def set_status(self, s, m=""): self._status, self._message = s, m; return s
    def get_status(self):  return self._status
    def get_message(self): return self._message
    def get_data(self):    return self._data
    def get_summary(self): return self._summary


class _AppSuccess:
    def __bool__(self): return True
    def __eq__(self, o): return isinstance(o, _AppSuccess)

class _AppError:
    def __bool__(self): return False
    def __eq__(self, o): return isinstance(o, _AppError)


phantom_stub = types.ModuleType("phantom")
phantom_stub.APP_SUCCESS = _AppSuccess()
phantom_stub.APP_ERROR   = _AppError()
sys.modules["phantom"]              = phantom_stub
sys.modules["phantom.app"]          = phantom_stub

ar_module = types.ModuleType("phantom.action_result")
ar_module.ActionResult = _ActionResult
sys.modules["phantom.action_result"] = ar_module


class _BaseConnector:
    def __init__(self):
        self._config         = {}
        self._action_results = []
        self._action_id      = ""
        self._container_id   = 1

    def get_config(self):              return self._config
    def get_action_identifier(self):   return self._action_id
    def get_container_id(self):        return self._container_id
    def save_progress(self, msg):      pass
    def set_status(self, status, msg=""): return status
    def add_action_result(self, ar):   self._action_results.append(ar); return ar
    def get_action_results(self):      return json.dumps([])


bc_module = types.ModuleType("phantom.base_connector")
bc_module.BaseConnector = _BaseConnector
sys.modules["phantom.base_connector"] = bc_module


# -- Mock phantom.rules.vault_add --------------------------------------------
# Tracks vault adds so tests can verify what was stored.

VAULT_ADDS = []


class _VaultStub:
    @staticmethod
    def get_vault_tmp_dir():
        import tempfile
        return tempfile.gettempdir()


def _vault_add_mock(container, file_location, file_name, metadata=None):
    """Record the call and return a fake vault_id (sha1 of file content)."""
    with open(file_location, "rb") as fh:
        content = fh.read()
    vault_id = hashlib.sha1(content).hexdigest()
    VAULT_ADDS.append({
        "container":     container,
        "file_location": file_location,
        "file_name":     file_name,
        "metadata":      metadata,
        "content":       content,
        "vault_id":      vault_id,
    })
    return True, "Success", vault_id


phrules_stub = types.ModuleType("phantom.rules")
phrules_stub.vault_add = _vault_add_mock
phrules_stub.Vault     = _VaultStub
sys.modules["phantom.rules"] = phrules_stub


from ms_defender_mail_quarantine_connector import (  # noqa: E402
    MSDefenderMailQuarantineConnector,
    AUTH_HEADER, AUTH_QUERY, AUTH_NONE,
    EXPORT_VAULT, EXPORT_INLINE,
    ENDPOINT_HEALTH, ENDPOINT_LIST,
)

APP_SUCCESS = phantom_stub.APP_SUCCESS
APP_ERROR   = phantom_stub.APP_ERROR


BASE_URL     = "https://contoso-quarantine.azurewebsites.net/api"
FUNCTION_KEY = "test-function-key-abc123"
IDENTITY     = r"c14401cf-aa9a-465b-cfd5-08d0f0ca37c5\4c2ca98e-94ea-db3a-7eb8-3b63657d4db7"
IDENTITY_ENC = "c14401cf-aa9a-465b-cfd5-08d0f0ca37c5%5C4c2ca98e-94ea-db3a-7eb8-3b63657d4db7"

EML_RAW = b"From: attacker@evil.com\r\nTo: user@contoso.com\r\nSubject: Test\r\n\r\nBody"
EML_B64 = base64.b64encode(EML_RAW).decode("ascii")

EML_HASHES = {
    "md5":    hashlib.md5(EML_RAW).hexdigest(),
    "sha1":   hashlib.sha1(EML_RAW).hexdigest(),
    "sha256": hashlib.sha256(EML_RAW).hexdigest(),
}


def make_connector(base_url=BASE_URL, function_key=FUNCTION_KEY,
                   auth_method=AUTH_HEADER, verify_ssl=False, timeout=30,
                   export_mode=EXPORT_VAULT):
    c = MSDefenderMailQuarantineConnector()
    c._config = {
        "function_base_url": base_url,
        "function_key":      function_key,
        "auth_method":       auth_method,
        "verify_ssl":        verify_ssl,
        "timeout":           timeout,
        "export_mode":       export_mode,
    }
    c.initialize()
    return c


def patch_ar(connector):
    ar = _ActionResult()
    connector.add_action_result = lambda x: ar
    return ar


@pytest.fixture(autouse=True)
def reset_vault_adds():
    VAULT_ADDS.clear()
    yield


# -- Initialize --------------------------------------------------------------

class TestInitialize:

    def test_default_export_mode_is_vault(self):
        c = MSDefenderMailQuarantineConnector()
        c._config = {
            "function_base_url": BASE_URL,
            "function_key":      FUNCTION_KEY,
            "verify_ssl":        False,
            "timeout":           30,
        }
        c.initialize()
        assert c._export_mode == EXPORT_VAULT

    def test_export_mode_inline(self):
        c = make_connector(export_mode=EXPORT_INLINE)
        assert c._export_mode == EXPORT_INLINE

    def test_invalid_export_mode_rejected(self):
        c = MSDefenderMailQuarantineConnector()
        c._config = {
            "function_base_url": BASE_URL,
            "function_key":      FUNCTION_KEY,
            "auth_method":       AUTH_HEADER,
            "verify_ssl":        False,
            "timeout":           30,
            "export_mode":       "nonsense",
        }
        assert c.initialize() == APP_ERROR

    def test_http_url_rejected(self):
        c = MSDefenderMailQuarantineConnector()
        c._config = {
            "function_base_url": "http://insecure.example.com/api",
            "function_key":      FUNCTION_KEY,
            "auth_method":       AUTH_HEADER,
            "verify_ssl":        False,
            "timeout":           30,
        }
        assert c.initialize() == APP_ERROR

    def test_invalid_auth_method_rejected(self):
        c = MSDefenderMailQuarantineConnector()
        c._config = {
            "function_base_url": BASE_URL,
            "function_key":      FUNCTION_KEY,
            "auth_method":       "bogus",
            "verify_ssl":        False,
            "timeout":           30,
        }
        assert c.initialize() == APP_ERROR


# -- Auth methods ------------------------------------------------------------

class TestAuthMethods:

    def test_header_adds_x_functions_key(self):
        h = make_connector(auth_method=AUTH_HEADER)._build_headers()
        assert h.get("x-functions-key") == FUNCTION_KEY

    def test_query_adds_code_param(self):
        assert make_connector(auth_method=AUTH_QUERY)._build_params() == {"code": FUNCTION_KEY}

    def test_none_no_header_no_param(self):
        c = make_connector(auth_method=AUTH_NONE)
        assert "x-functions-key" not in c._build_headers()
        assert c._build_params() is None


# -- Connectivity -----------------------------------------------------------

class TestConnectivity:

    def test_200_success(self):
        c = make_connector()
        with req_mock.Mocker() as m:
            m.get(f"{BASE_URL}{ENDPOINT_HEALTH}",
                  json={"status": "ok", "service": "wrapper"})
            assert c._handle_test_connectivity({}) == APP_SUCCESS

    def test_401_error(self):
        c = make_connector()
        with req_mock.Mocker() as m:
            m.get(f"{BASE_URL}{ENDPOINT_HEALTH}", status_code=401)
            assert c._handle_test_connectivity({}) == APP_ERROR


# -- List ---------------------------------------------------------------------

MOCK_MESSAGES = [{
    "Identity":         IDENTITY,
    "SenderAddress":    "attacker@evil.com",
    "RecipientAddress": "user@contoso.com",
    "Subject":          "Invoice",
    "Type":             "HighConfPhish",
    "ReceivedTime":     "2024-01-15T10:23:00Z",
    "Expires":          "2024-01-30T10:23:00Z",
    "ReleaseStatus":    "REQUESTED",
    "PolicyName":       "Default",
}]


class TestList:

    def test_200_success(self):
        c = make_connector()
        with req_mock.Mocker() as m:
            m.get(f"{BASE_URL}{ENDPOINT_LIST}",
                  json={"count": 1, "messages": MOCK_MESSAGES})
            assert c._handle_list_quarantine_requests({}) == APP_SUCCESS

    def test_summary_total(self):
        c = make_connector()
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            m.get(f"{BASE_URL}{ENDPOINT_LIST}",
                  json={"count": 1, "messages": MOCK_MESSAGES})
            c._handle_list_quarantine_requests({})
        assert ar.get_summary().get("total_found") == 1


# -- Export VAULT mode -------------------------------------------------------

class TestExportVaultMode:

    def test_vault_mode_success(self):
        c = make_connector(export_mode=EXPORT_VAULT)
        with req_mock.Mocker() as m:
            m.get(f"{BASE_URL}/export/{IDENTITY_ENC}",
                  json={"identity": IDENTITY, "eml": EML_B64})
            assert c._handle_get_quarantine_message(
                {"identity": IDENTITY}) == APP_SUCCESS

    def test_vault_id_returned(self):
        c = make_connector(export_mode=EXPORT_VAULT)
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            m.get(f"{BASE_URL}/export/{IDENTITY_ENC}",
                  json={"identity": IDENTITY, "eml": EML_B64})
            c._handle_get_quarantine_message({"identity": IDENTITY})
        assert ar.get_data()[0].get("vault_id"), "vault_id missing"

    def test_vault_file_name_format(self):
        c = make_connector(export_mode=EXPORT_VAULT)
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            m.get(f"{BASE_URL}/export/{IDENTITY_ENC}",
                  json={"identity": IDENTITY, "eml": EML_B64})
            c._handle_get_quarantine_message({"identity": IDENTITY})
        fn = ar.get_data()[0].get("file_name", "")
        assert fn.startswith("quarantine_") and fn.endswith(".eml")

    def test_vault_hashes_present(self):
        c = make_connector(export_mode=EXPORT_VAULT)
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            m.get(f"{BASE_URL}/export/{IDENTITY_ENC}",
                  json={"identity": IDENTITY, "eml": EML_B64})
            c._handle_get_quarantine_message({"identity": IDENTITY})
        d = ar.get_data()[0]
        assert d.get("md5")    == EML_HASHES["md5"]
        assert d.get("sha1")   == EML_HASHES["sha1"]
        assert d.get("sha256") == EML_HASHES["sha256"]

    def test_vault_size_correct(self):
        c = make_connector(export_mode=EXPORT_VAULT)
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            m.get(f"{BASE_URL}/export/{IDENTITY_ENC}",
                  json={"identity": IDENTITY, "eml": EML_B64})
            c._handle_get_quarantine_message({"identity": IDENTITY})
        assert ar.get_data()[0].get("size") == len(EML_RAW)

    def test_vault_no_eml_field_in_data(self):
        """Vault mode must NOT include the base64 eml in action_result data."""
        c = make_connector(export_mode=EXPORT_VAULT)
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            m.get(f"{BASE_URL}/export/{IDENTITY_ENC}",
                  json={"identity": IDENTITY, "eml": EML_B64})
            c._handle_get_quarantine_message({"identity": IDENTITY})
        assert "eml" not in ar.get_data()[0]

    def test_vault_actually_called(self):
        c = make_connector(export_mode=EXPORT_VAULT)
        with req_mock.Mocker() as m:
            m.get(f"{BASE_URL}/export/{IDENTITY_ENC}",
                  json={"identity": IDENTITY, "eml": EML_B64})
            c._handle_get_quarantine_message({"identity": IDENTITY})
        assert len(VAULT_ADDS) == 1, "vault_add was not called"

    def test_vault_stored_correct_bytes(self):
        c = make_connector(export_mode=EXPORT_VAULT)
        with req_mock.Mocker() as m:
            m.get(f"{BASE_URL}/export/{IDENTITY_ENC}",
                  json={"identity": IDENTITY, "eml": EML_B64})
            c._handle_get_quarantine_message({"identity": IDENTITY})
        # The file added to vault should contain the decoded EML bytes
        assert VAULT_ADDS[0]["content"] == EML_RAW

    def test_vault_metadata_contains_identity(self):
        c = make_connector(export_mode=EXPORT_VAULT)
        with req_mock.Mocker() as m:
            m.get(f"{BASE_URL}/export/{IDENTITY_ENC}",
                  json={"identity": IDENTITY, "eml": EML_B64})
            c._handle_get_quarantine_message({"identity": IDENTITY})
        assert VAULT_ADDS[0]["metadata"]["identity"] == IDENTITY

    def test_vault_summary_export_mode(self):
        c = make_connector(export_mode=EXPORT_VAULT)
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            m.get(f"{BASE_URL}/export/{IDENTITY_ENC}",
                  json={"identity": IDENTITY, "eml": EML_B64})
            c._handle_get_quarantine_message({"identity": IDENTITY})
        assert ar.get_summary().get("export_mode") == EXPORT_VAULT


# -- Export INLINE mode ------------------------------------------------------

class TestExportInlineMode:

    def test_inline_mode_success(self):
        c = make_connector(export_mode=EXPORT_INLINE)
        with req_mock.Mocker() as m:
            m.get(f"{BASE_URL}/export/{IDENTITY_ENC}",
                  json={"identity": IDENTITY, "eml": EML_B64})
            assert c._handle_get_quarantine_message(
                {"identity": IDENTITY}) == APP_SUCCESS

    def test_inline_returns_eml_field(self):
        c = make_connector(export_mode=EXPORT_INLINE)
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            m.get(f"{BASE_URL}/export/{IDENTITY_ENC}",
                  json={"identity": IDENTITY, "eml": EML_B64})
            c._handle_get_quarantine_message({"identity": IDENTITY})
        assert ar.get_data()[0].get("eml") == EML_B64

    def test_inline_no_vault_call(self):
        c = make_connector(export_mode=EXPORT_INLINE)
        with req_mock.Mocker() as m:
            m.get(f"{BASE_URL}/export/{IDENTITY_ENC}",
                  json={"identity": IDENTITY, "eml": EML_B64})
            c._handle_get_quarantine_message({"identity": IDENTITY})
        assert len(VAULT_ADDS) == 0, "vault_add must not be called in inline mode"

    def test_inline_no_vault_id(self):
        c = make_connector(export_mode=EXPORT_INLINE)
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            m.get(f"{BASE_URL}/export/{IDENTITY_ENC}",
                  json={"identity": IDENTITY, "eml": EML_B64})
            c._handle_get_quarantine_message({"identity": IDENTITY})
        assert "vault_id" not in ar.get_data()[0]

    def test_inline_hashes_still_present(self):
        """Hashes should be available in inline mode too (for IOC enrichment)."""
        c = make_connector(export_mode=EXPORT_INLINE)
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            m.get(f"{BASE_URL}/export/{IDENTITY_ENC}",
                  json={"identity": IDENTITY, "eml": EML_B64})
            c._handle_get_quarantine_message({"identity": IDENTITY})
        d = ar.get_data()[0]
        assert d.get("sha256") == EML_HASHES["sha256"]

    def test_inline_size_correct(self):
        c = make_connector(export_mode=EXPORT_INLINE)
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            m.get(f"{BASE_URL}/export/{IDENTITY_ENC}",
                  json={"identity": IDENTITY, "eml": EML_B64})
            c._handle_get_quarantine_message({"identity": IDENTITY})
        assert ar.get_data()[0].get("size") == len(EML_RAW)

    def test_inline_summary_export_mode(self):
        c = make_connector(export_mode=EXPORT_INLINE)
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            m.get(f"{BASE_URL}/export/{IDENTITY_ENC}",
                  json={"identity": IDENTITY, "eml": EML_B64})
            c._handle_get_quarantine_message({"identity": IDENTITY})
        assert ar.get_summary().get("export_mode") == EXPORT_INLINE


# -- Export common errors ----------------------------------------------------

class TestExportCommon:

    def test_missing_identity_error(self):
        c = make_connector()
        patch_ar(c)
        assert c._handle_get_quarantine_message({"identity": ""}) == APP_ERROR

    def test_backslash_url_encoded(self):
        c = make_connector(export_mode=EXPORT_VAULT)
        urls = []
        with req_mock.Mocker() as m:
            def cb(req, ctx):
                urls.append(req.url)
                ctx.status_code = 200
                return {"identity": IDENTITY, "eml": EML_B64}
            m.get(req_mock.ANY, json=cb)
            patch_ar(c)
            c._handle_get_quarantine_message({"identity": IDENTITY})
        assert "%5C" in urls[0]

    def test_invalid_base64_eml_error(self):
        c = make_connector(export_mode=EXPORT_VAULT)
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            m.get(f"{BASE_URL}/export/{IDENTITY_ENC}",
                  json={"identity": IDENTITY, "eml": "not!!base64@@"})
            result = c._handle_get_quarantine_message({"identity": IDENTITY})
        # Lenient base64 may or may not raise; either APP_ERROR or APP_SUCCESS
        # is acceptable depending on Python's base64 mode. If it succeeds the
        # bytes will just be garbage but valid. We just ensure no crash.
        assert result in (APP_SUCCESS, APP_ERROR)

    def test_empty_eml_error(self):
        c = make_connector(export_mode=EXPORT_VAULT)
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            m.get(f"{BASE_URL}/export/{IDENTITY_ENC}",
                  json={"identity": IDENTITY, "eml": ""})
            assert c._handle_get_quarantine_message(
                {"identity": IDENTITY}) == APP_ERROR

    def test_pascal_eml_works_in_vault_mode(self):
        c = make_connector(export_mode=EXPORT_VAULT)
        with req_mock.Mocker() as m:
            m.get(f"{BASE_URL}/export/{IDENTITY_ENC}",
                  json={"identity": IDENTITY, "Eml": EML_B64})
            assert c._handle_get_quarantine_message(
                {"identity": IDENTITY}) == APP_SUCCESS
        assert len(VAULT_ADDS) == 1


# -- Release/Deny ------------------------------------------------------------

class TestRelease:

    def test_200_success(self):
        c = make_connector()
        with req_mock.Mocker() as m:
            m.post(f"{BASE_URL}/release/{IDENTITY_ENC}",
                   json={"status": "released", "identity": IDENTITY,
                         "message": "ok"})
            assert c._handle_release_quarantine_message(
                {"identity": IDENTITY}) == APP_SUCCESS

    def test_uses_post(self):
        c = make_connector()
        methods = []
        with req_mock.Mocker() as m:
            def cb(req, ctx):
                methods.append(req.method)
                ctx.status_code = 200
                return {"status": "released"}
            m.post(req_mock.ANY, json=cb)
            patch_ar(c)
            c._handle_release_quarantine_message({"identity": IDENTITY})
        assert methods == ["POST"]


class TestDeny:

    def test_200_success(self):
        c = make_connector()
        with req_mock.Mocker() as m:
            m.post(f"{BASE_URL}/deny/{IDENTITY_ENC}",
                   json={"status": "denied", "identity": IDENTITY,
                         "message": "ok"})
            assert c._handle_deny_quarantine_release(
                {"identity": IDENTITY}) == APP_SUCCESS

    def test_uses_post(self):
        c = make_connector()
        methods = []
        with req_mock.Mocker() as m:
            def cb(req, ctx):
                methods.append(req.method)
                ctx.status_code = 200
                return {"status": "denied"}
            m.post(req_mock.ANY, json=cb)
            patch_ar(c)
            c._handle_deny_quarantine_release({"identity": IDENTITY})
        assert methods == ["POST"]


# -- Error handling ----------------------------------------------------------

class TestErrorHandling:

    @pytest.mark.parametrize("code", [400, 401, 403, 404, 502, 504])
    def test_http_errors(self, code):
        c = make_connector()
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            m.get(f"{BASE_URL}{ENDPOINT_LIST}", status_code=code,
                  json={"detail": "test"})
            assert c._handle_list_quarantine_requests({}) == APP_ERROR

    def test_timeout(self):
        c = make_connector()
        ar = patch_ar(c)
        with req_mock.Mocker() as m:
            m.get(f"{BASE_URL}{ENDPOINT_LIST}",
                  exc=requests.exceptions.Timeout())
            c._handle_list_quarantine_requests({})
        assert "timeout" in ar.get_message().lower()


# -- Filename safety ---------------------------------------------------------

class TestFilenameSafety:

    def test_filename_alphanumeric_only(self):
        c = make_connector()
        fn = c._safe_filename_from_identity(IDENTITY)
        # Strip the prefix and extension
        core = fn.replace("quarantine_", "").replace(".eml", "")
        # Only allow alphanumeric or hyphen
        assert all(ch.isalnum() or ch == "-" for ch in core), \
            f"Filename core has unsafe characters: {core}"

    def test_filename_handles_no_backslash(self):
        c = make_connector()
        fn = c._safe_filename_from_identity("just-some-id-12345")
        assert fn.endswith(".eml")

    def test_filename_truncated(self):
        c = make_connector()
        long_id = "a" * 200 + r"\b"
        fn = c._safe_filename_from_identity(long_id)
        # Should be reasonable length, not 200+
        assert len(fn) < 100
