# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Unit tests for shared V2 Data Policy REST and ADC token utilities."""

from __future__ import annotations

import io
import json
import os
import sys
import types
import unittest
from unittest import mock
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# pylint: disable=g-import-not-at-top,g-bad-import-order
from google.api_core import exceptions
import rest_utils

# pylint: enable=g-import-not-at-top,g-bad-import-order


class _FakeCredentials:
  """Hermetic credential stub tracking refresh invocations and expiry state."""

  def __init__(self, token: str = "token-1", valid: bool = True) -> None:
    self.token = token
    self.valid = valid
    self.refresh_count = 0

  def refresh(self, request: object) -> None:
    del request
    self.refresh_count += 1
    self.valid = True
    self.token = f"refreshed-token-{self.refresh_count}"


def _make_http_response(body: bytes) -> io.BytesIO:
  """Builds a context-manager byte stream mimicking `urllib.request.urlopen`."""
  return io.BytesIO(body)


class _RaisingHttpResponse:
  """Context-manager HTTP response double whose `read()` raises an error."""

  def __init__(self, error: BaseException) -> None:
    self._error = error

  def read(self) -> bytes:
    raise self._error

  def __enter__(self) -> _RaisingHttpResponse:
    return self

  def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
    del exc_type, exc_val, exc_tb
    return False


class RestUtilsTest(unittest.TestCase):
  """Tests endpoint resolution, ADC token reuse, and `/v2/` HTTP handling."""

  # Verifies custom GAPIC transport hosts without schemes get `https://` while
  # default clients fall back to `bigquerydatapolicy.googleapis.com`.
  def test_resolve_datapolicy_endpoint_honors_custom_transport_host(self):
    self.assertEqual(
        rest_utils.resolve_datapolicy_endpoint(None),
        "https://bigquerydatapolicy.googleapis.com",
    )
    psc_client = types.SimpleNamespace(
        transport=types.SimpleNamespace(
            host="bigquerydatapolicy-psc.p.googleapis.com/"
        )
    )
    self.assertEqual(
        rest_utils.resolve_datapolicy_endpoint(psc_client),
        "https://bigquerydatapolicy-psc.p.googleapis.com",
    )

  # Verifies cached ADC tokens are reused across calls and refreshed only when
  # `credentials.valid` becomes `False`.
  @mock.patch("google.auth.transport.requests.Request", autospec=True)
  @mock.patch("google.auth.default", autospec=True)
  def test_get_bearer_token_reuses_valid_token_and_refreshes_on_expiry(
      self, mock_auth_default, mock_auth_request
  ):
    fake_creds = _FakeCredentials()
    mock_auth_default.return_value = (fake_creds, "proj")
    client = rest_utils.DataPolicyRestClient()

    # First call initializes ADC and performs initial refresh; second call
    # reuses the valid token without calling `google.auth.default` or `refresh`.
    first_token = client.get_bearer_token()
    second_token = client.get_bearer_token()
    self.assertEqual(first_token, "refreshed-token-1")
    self.assertEqual(second_token, "refreshed-token-1")
    mock_auth_default.assert_called_once()
    mock_auth_request.assert_called_once()
    self.assertEqual(fake_creds.refresh_count, 1)

    # Simulate token expiration (`valid = False`) and confirm `refresh` runs.
    fake_creds.valid = False
    third_token = client.get_bearer_token()
    self.assertEqual(third_token, "refreshed-token-2")
    self.assertEqual(fake_creds.refresh_count, 2)

  # Verifies `get_data_policy_v2` supports both `return_none` (for creator
  # pre-checks) and `raise_not_found` (for deleter probes) on HTTP 404.
  @mock.patch("urllib.request.urlopen", autospec=True)
  @mock.patch("google.auth.transport.requests.Request", autospec=True)
  @mock.patch("google.auth.default", autospec=True)
  def test_get_data_policy_v2_404_modes(
      self, mock_auth_default, unused_request, mock_urlopen
  ):
    mock_auth_default.return_value = (_FakeCredentials(), "proj")
    client = rest_utils.DataPolicyRestClient()

    def make_404() -> urllib.error.HTTPError:
      return urllib.error.HTTPError(
          url="https://bigquerydatapolicy.googleapis.com/v2/p",
          code=404,
          msg="Not Found",
          hdrs=None,
          fp=io.BytesIO(b"policy missing"),
      )

    mock_urlopen.side_effect = [make_404(), make_404()]
    self.assertIsNone(
        client.get_data_policy_v2(
            "projects/p/locations/us/dataPolicies/pol1",
            not_found_behavior="return_none",
        )
    )
    with self.assertRaises(exceptions.NotFound):
      client.get_data_policy_v2(
          "projects/p/locations/us/dataPolicies/pol1",
          not_found_behavior="raise_not_found",
      )

  # Verifies `create_data_policy_v2` translates snake_case `plan.json` keys to
  # V2 camelCase JSON and maps HTTP 409 Conflict to `exceptions.AlreadyExists`.
  @mock.patch("urllib.request.urlopen", autospec=True)
  @mock.patch("google.auth.transport.requests.Request", autospec=True)
  @mock.patch("google.auth.default", autospec=True)
  def test_create_data_policy_v2_payload_translation_and_409(
      self, mock_auth_default, unused_request, mock_urlopen
  ):
    mock_auth_default.return_value = (_FakeCredentials(), "proj")
    client = rest_utils.DataPolicyRestClient()
    mock_urlopen.return_value = _make_http_response(
        b'{"name": "projects/p/locations/us/dataPolicies/mask_p"}'
    )

    created = client.create_data_policy_v2(
        "projects/p/locations/us",
        "mask_p",
        {
            "data_policy_id": "mask_p",
            "data_policy_type": "DATA_MASKING_POLICY",
            "data_governance_tag": {"key": "p/k", "value": "v"},
            "data_masking_policy": {"predefined_expression": "SHA256"},
            "grantees": ["principal://goog/subject/u@example.com"],
        },
    )
    self.assertEqual(
        created["name"], "projects/p/locations/us/dataPolicies/mask_p"
    )
    sent_request = mock_urlopen.call_args[0][0]
    sent_json = json.loads(sent_request.data.decode("utf-8"))
    self.assertEqual(sent_json["dataPolicyId"], "mask_p")
    self.assertNotIn("data_policy_id", sent_json["dataPolicy"])
    self.assertEqual(
        sent_json["dataPolicy"]["dataMaskingPolicy"]["predefinedExpression"],
        "SHA256",
    )

    http_409 = urllib.error.HTTPError(
        url="https://bigquerydatapolicy.googleapis.com/v2/p",
        code=409,
        msg="Conflict",
        hdrs=None,
        fp=io.BytesIO(b"already exists"),
    )
    mock_urlopen.side_effect = [http_409]
    with self.assertRaises(exceptions.AlreadyExists):
      client.create_data_policy_v2(
          "projects/p/locations/us",
          "mask_p",
          {"data_policy_type": "RAW_DATA_ACCESS_POLICY"},
      )

  # Plaintext `http://` transport overrides must raise `ValueError` so OAuth2
  # bearer tokens cannot be transmitted unencrypted.
  def test_resolve_datapolicy_endpoint_rejects_plaintext_http(self):
    http_client = types.SimpleNamespace(
        transport=types.SimpleNamespace(
            host="http://insecure.example.com:8080/"
        )
    )
    with self.assertRaisesRegex(
        ValueError,
        "Insecure 'http://' endpoint override.*http://insecure.example.com",
    ):
      rest_utils.resolve_datapolicy_endpoint(http_client)

  # Paginated `list_data_policies_v2` must re-acquire a valid bearer token per
  # page and normalize terminal `HTTPError` responses into `RuntimeError`.
  @mock.patch("urllib.request.urlopen", autospec=True)
  @mock.patch("google.auth.transport.requests.Request", autospec=True)
  @mock.patch("google.auth.default", autospec=True)
  def test_list_data_policies_v2_refreshes_expired_token_and_wraps_http_error(
      self, mock_auth_default, unused_request, mock_urlopen
  ):
    fake_creds = _FakeCredentials()
    mock_auth_default.return_value = (fake_creds, "proj")
    client = rest_utils.DataPolicyRestClient()

    def urlopen_pages(request, timeout=30.0):
      del timeout
      if "pageToken=p2" not in request.full_url:
        # Expire credentials after page 1 so page 2 must refresh the token.
        fake_creds.valid = False
        return _make_http_response(
            b'{"dataPolicies": [{"name": "pol-1"}], "nextPageToken": "p2"}'
        )
      return _make_http_response(b'{"dataPolicies": [{"name": "pol-2"}]}')

    mock_urlopen.side_effect = urlopen_pages
    policies = client.list_data_policies_v2("proj", "us")

    # Confirm both pages returned and page 2 sent the refreshed token.
    self.assertEqual([item["name"] for item in policies], ["pol-1", "pol-2"])
    first_req = mock_urlopen.call_args_list[0].args[0]
    second_req = mock_urlopen.call_args_list[1].args[0]
    self.assertEqual(
        first_req.get_header("Authorization"), "Bearer refreshed-token-1"
    )
    self.assertEqual(
        second_req.get_header("Authorization"), "Bearer refreshed-token-2"
    )

    # Confirm non-retryable HTTP 403 wraps into RuntimeError for callers.
    http_403 = urllib.error.HTTPError(
        url="https://bigquerydatapolicy.googleapis.com/v2/projects/proj",
        code=403,
        msg="Forbidden",
        hdrs=None,
        fp=io.BytesIO(b"missing list permission"),
    )
    mock_urlopen.side_effect = [http_403]
    with self.assertRaisesRegex(
        RuntimeError, "HTTP Error 403.*projects/proj/locations/us"
    ):
      client.list_data_policies_v2("proj", "us")

  # Socket read `TimeoutError` and `ConnectionResetError` (`OSError`) raised
  # outside `URLError` must retry with backoff and normalize terminal failures
  # into `RuntimeError` across all `/v2/` REST operations.
  @mock.patch("time.sleep", autospec=True)
  @mock.patch("urllib.request.urlopen", autospec=True)
  @mock.patch("google.auth.transport.requests.Request", autospec=True)
  @mock.patch("google.auth.default", autospec=True)
  def test_socket_timeout_and_oserror_retry_and_wrap_into_runtime_error(
      self, mock_auth_default, unused_request, mock_urlopen, mock_sleep
  ):
    mock_auth_default.return_value = (_FakeCredentials(), "proj")
    client = rest_utils.DataPolicyRestClient(max_attempts=2, base_delay=0.25)

    # Simulate a mid-body socket read timeout on attempt 1 (`response.read()`
    # raises bare `TimeoutError` in Python 3.10+) followed by success on retry.
    timed_out_body = _RaisingHttpResponse(TimeoutError("read timed out"))
    mock_urlopen.side_effect = [
        timed_out_body,
        _make_http_response(b'{"dataPolicies": [{"name": "pol-ok"}]}'),
    ]

    listed = client.list_data_policies_v2("proj", "us")
    self.assertEqual([item["name"] for item in listed], ["pol-ok"])
    mock_sleep.assert_called_once_with(0.25)

    # Exhausted `TimeoutError` / `ConnectionResetError` across list, get,
    # create, and delete must raise `RuntimeError` so per-item batch loops
    # record clean failures rather than crashing with uncaught `OSError`.
    cases = [
        (
            lambda: client.list_data_policies_v2("proj", "us"),
            TimeoutError("list socket timeout"),
            "Network error listing Data Policies for proj/us: list socket",
        ),
        (
            lambda: client.get_data_policy_v2(
                "projects/proj/locations/us/dataPolicies/pol1"
            ),
            ConnectionResetError("peer reset"),
            "Network error getting Data Policy.*pol1.*peer reset",
        ),
        (
            lambda: client.create_data_policy_v2(
                "projects/proj/locations/us",
                "pol1",
                {"data_policy_type": "RAW_DATA_ACCESS_POLICY"},
            ),
            TimeoutError("create socket timeout"),
            "Network error creating Data Policy pol1: create socket timeout",
        ),
        (
            lambda: client.delete_data_policy_v2(
                "projects/proj/locations/us/dataPolicies/pol1"
            ),
            ConnectionResetError("delete peer reset"),
            "Network error deleting Data Policy.*pol1.*delete peer reset",
        ),
    ]
    for call_fn, raised_error, expected_regex in cases:
      mock_urlopen.side_effect = [raised_error, raised_error]
      with self.assertRaisesRegex(RuntimeError, expected_regex):
        call_fn()


if __name__ == "__main__":
  unittest.main()
