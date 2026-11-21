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

"""Shared BigQuery Data Policy V2 REST client and ADC token caching utilities.

Architectural Role & Mixed-Version SDK Resilience:
--------------------------------------------------
Older installations of `google-cloud-bigquery-datapolicies` either omit the `v2`
subpackage or ship compiled protobuf descriptors lacking newer Data Governance
Tag fields (`data_governance_tag` and inline `grantees`). Across all phases of
the PT-to-DGT migration tool (`analyzer.py`, `creator.py`, `deleter.py`, and
`swapper.py`), callers use the GAPIC client first when supported and fall back
to authenticated raw `/v2/` JSON REST requests when the local SDK cannot
serialize or deserialize V2 Data Policy fields.

This module centralizes:
  1. Endpoint resolution (`resolve_datapolicy_endpoint`), honoring custom
     Private Service Connect (PSC), mTLS, or VPC Service Controls (VPC-SC)
     hosts configured on `data_policy_client.transport.host`.
  2. Per-instance Application Default Credentials (ADC) bearer-token caching
     (`DataPolicyRestClient.get_bearer_token`), guarded by a thread lock so
     concurrent `ThreadPoolExecutor` lookups reuse valid tokens instead of
     re-discovering and refreshing credentials on every HTTP call.
  3. Uniform exponential backoff retries (`429`, `500`, `502`, `503`, `504`,
     and `urllib.error.URLError`) and deterministic `404` / `409` handling
     across `LIST`, `GET`, `POST`, and `DELETE` operations.
"""

from __future__ import annotations

import copy
import json
import logging
import threading
import time
from typing import Any
import urllib.error
import urllib.parse
import urllib.request

from google.api_core import exceptions
import google.auth
import google.auth.transport.requests

logger = logging.getLogger(__name__)

CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
DEFAULT_DATAPOLICY_ENDPOINT = "https://bigquerydatapolicy.googleapis.com"
RETRYABLE_HTTP_STATUS_CODES = frozenset({429, 500, 502, 503, 504})


def resolve_datapolicy_endpoint(data_policy_client: Any) -> str:
  """Returns the HTTPS base URL for BigQuery Data Policy Service `/v2/` calls.

  Inspects `data_policy_client.transport.host` when available so custom
  regional, PSC, mTLS, or VPC-SC endpoints passed via `--datapolicy-endpoint`
  are honored by raw REST fallback calls.

  Args:
    data_policy_client: Configured `DataPolicyServiceClient` instance, or
      `None`.

  Returns:
    Base endpoint URL without a trailing slash.

  Raises:
    ValueError: If `data_policy_client.transport.host` specifies an insecure
      `http://` scheme override.
  """
  endpoint = DEFAULT_DATAPOLICY_ENDPOINT
  if (
      data_policy_client is not None
      and hasattr(data_policy_client, "transport")
      and hasattr(data_policy_client.transport, "host")
      and isinstance(data_policy_client.transport.host, str)
      and data_policy_client.transport.host.strip()
  ):
    host = data_policy_client.transport.host.strip().rstrip("/")
    if host.lower().startswith("http://"):
      raise ValueError(
          f"Insecure 'http://' endpoint override '{host}' is not supported;"
          " use 'https://' or a bare hostname."
      )
    endpoint = (
        host if host.lower().startswith("https://") else f"https://{host}"
    )
  return endpoint


def _read_http_error_body(http_error: urllib.error.HTTPError) -> str:
  """Extracts a UTF-8 error response body from `http_error` when readable."""
  if not hasattr(http_error, "read"):
    return ""
  try:
    raw_bytes = http_error.read()
    if isinstance(raw_bytes, bytes):
      return raw_bytes.decode("utf-8", errors="replace")
    return str(raw_bytes or "")
  except Exception:  # pylint: disable=broad-exception-caught
    return ""


def translate_v2_create_payload(
    policy_id: str, snake_case_payload: dict[str, Any]
) -> dict[str, Any]:
  """Translates a `plan.json` V2 policy payload into REST camelCase wire JSON.

  In the BigQuery Data Policy V2 REST API, `CreateDataPolicyRequest` wraps the
  policy body inside `"dataPolicy"` alongside top-level `"dataPolicyId"` and
  expects camelCase keys (`dataGovernanceTag`, `dataPolicyType`, and
  `dataMaskingPolicy.predefinedExpression`).

  Args:
    policy_id: Target `data_policy_id` (`1-200` alphanumeric/underscore chars).
    snake_case_payload: The `api_payload` dictionary from `plan.json`.

  Returns:
    JSON-serializable REST request dictionary for `POST /v2/.../dataPolicies`.
  """
  rest_data_policy = copy.deepcopy(snake_case_payload)
  if "data_governance_tag" in rest_data_policy:
    rest_data_policy["dataGovernanceTag"] = rest_data_policy.pop(
        "data_governance_tag"
    )
  if "data_policy_type" in rest_data_policy:
    rest_data_policy["dataPolicyType"] = rest_data_policy.pop(
        "data_policy_type"
    )
  # `data_policy_id` is OUTPUT_ONLY inside the nested V2 `DataPolicy` message
  # and must be supplied at the top level as `dataPolicyId`.
  rest_data_policy.pop("data_policy_id", None)
  if "data_masking_policy" in rest_data_policy:
    rest_data_policy["dataMaskingPolicy"] = rest_data_policy.pop(
        "data_masking_policy"
    )
    masking_dict = rest_data_policy["dataMaskingPolicy"]
    if isinstance(masking_dict, dict) and (
        "predefined_expression" in masking_dict
    ):
      masking_dict["predefinedExpression"] = masking_dict.pop(
          "predefined_expression"
      )
  return {
      "dataPolicyId": policy_id,
      "dataPolicy": rest_data_policy,
  }


class DataPolicyRestClient:
  """Authenticated `/v2/` REST helper with per-instance ADC token caching.

  Reuses Application Default Credentials across sequential and multi-threaded
  REST calls on the same phase runner (`Analyzer`, `Creator`, `Deleter`, or
  `Swapper`), refreshing the OAuth2 bearer token lazily on first use and
  whenever the cached token expires (`credentials.valid is False`) or is absent.
  """

  def __init__(
      self,
      data_policy_client: Any = None,
      *,
      timeout: float = 30.0,
      max_attempts: int = 3,
      base_delay: float = 1.0,
      backoff_multiplier: float = 2.0,
  ) -> None:
    """Initializes the REST helper without making eager ADC or network calls.

    Args:
      data_policy_client: GAPIC `DataPolicyServiceClient` used to inspect custom
        `transport.host` endpoint overrides.
      timeout: Per-attempt socket timeout in seconds (default: `30.0`).
      max_attempts: Maximum attempts for retryable HTTP/network errors.
      base_delay: Initial backoff sleep in seconds before the first retry.
      backoff_multiplier: Exponential multiplier applied after each retry.
    """
    self._data_policy_client = data_policy_client
    self._timeout = timeout
    self._max_attempts = max_attempts
    self._base_delay = base_delay
    self._backoff_multiplier = backoff_multiplier
    self._credentials: Any | None = None
    self._auth_request: Any | None = None
    self._token_lock = threading.Lock()

  def set_data_policy_client(self, data_policy_client: Any) -> None:
    """Updates the GAPIC client inspected for custom endpoint host overrides."""
    self._data_policy_client = data_policy_client

  def get_endpoint(self) -> str:
    """Returns the resolved BigQuery Data Policy Service HTTPS base URL."""
    return resolve_datapolicy_endpoint(self._data_policy_client)

  def get_bearer_token(self, *, force_refresh: bool = False) -> str:
    """Returns a valid OAuth2 bearer token, reusing cached ADC when valid.

    Thread-safe across concurrent `ThreadPoolExecutor` workers: initializes
    `google.auth.default` and performs the initial `refresh()` once on first
    use, then reuses `credentials.token` until `credentials.valid` becomes
    `False` or `force_refresh` is requested. If credential discovery or refresh
    raises an exception, no partial state is cached so callers fail closed
    cleanly.

    Args:
      force_refresh: When True, forces `credentials.refresh()` even if a token
        is already cached.

    Returns:
      Bearer token string from Application Default Credentials.
    """
    with self._token_lock:
      if self._credentials is None:
        credentials, _ = google.auth.default(scopes=[CLOUD_PLATFORM_SCOPE])
        auth_request = google.auth.transport.requests.Request()
        credentials.refresh(auth_request)
        self._credentials = credentials
        self._auth_request = auth_request
        return str(credentials.token or "")

      token_missing = not getattr(self._credentials, "token", None)
      # Check `isinstance(valid_attr, bool)` so real `Credentials` refresh on
      # expiry while mock credential doubles without a boolean `valid` attribute
      # are not refreshed redundantly on every call.
      valid_attr = getattr(self._credentials, "valid", True)
      token_expired = isinstance(valid_attr, bool) and not valid_attr
      if force_refresh or token_missing or token_expired:
        if self._auth_request is None:
          self._auth_request = google.auth.transport.requests.Request()
        self._credentials.refresh(self._auth_request)
      return str(self._credentials.token or "")

  def urlopen_json_with_retry(
      self,
      request: urllib.request.Request,
      *,
      timeout: float | None = None,
      max_attempts: int | None = None,
  ) -> dict[str, Any]:
    """Executes a prepared `urllib.request.Request` with exponential backoff.

    Retries transient HTTP `429`, `500`, `502`, `503`, `504` and network
    `URLError` failures while propagating non-retryable `HTTPError` responses
    (`400`, `403`, `404`, `409`) immediately to the caller.

    Args:
      request: Prepared `urllib.request.Request` instance.
      timeout: Optional per-attempt socket timeout override in seconds.
      max_attempts: Optional retry count override.

    Returns:
      Parsed JSON response dictionary (or `{}` on an empty HTTP 200/204 body).
    """
    effective_timeout = self._timeout if timeout is None else timeout
    effective_attempts = (
        self._max_attempts if max_attempts is None else max_attempts
    )
    delay = self._base_delay
    for attempt in range(effective_attempts):
      try:
        with urllib.request.urlopen(
            request, timeout=effective_timeout
        ) as response:
          raw_bytes = response.read()
          if not raw_bytes:
            return {}
          raw_text = (
              raw_bytes.decode("utf-8")
              if isinstance(raw_bytes, bytes)
              else str(raw_bytes)
          )
          return json.loads(raw_text) if raw_text.strip() else {}
      except urllib.error.HTTPError as http_error:
        if (
            http_error.code in RETRYABLE_HTTP_STATUS_CODES
            and attempt < effective_attempts - 1
        ):
          time.sleep(delay)
          delay *= self._backoff_multiplier
          continue
        raise
      except (urllib.error.URLError, TimeoutError, OSError):
        # Socket read timeouts (`response.read()`) and mid-stream TLS/socket
        # resets (`ConnectionResetError`) raise `TimeoutError` or `OSError`
        # directly rather than `URLError`; `HTTPError` is caught above first so
        # non-retryable HTTP 4xx responses still raise immediately.
        if attempt < effective_attempts - 1:
          time.sleep(delay)
          delay *= self._backoff_multiplier
          continue
        raise
    return {}

  def list_data_policies_v2(
      self, project_id: str, location: str
  ) -> list[dict[str, Any]]:
    """Lists all regional V2 Data Policies across paginated `/v2/` responses.

    Refreshes the OAuth2 bearer token inside the pagination loop if needed and
    normalizes HTTP and network transport errors into `RuntimeError` so callers
    fail closed consistently across SDK and REST fallback paths.

    Args:
      project_id: Target GCP project ID hosting V2 Data Policies.
      location: Regional location string (e.g., `'us'`, `'eu'`).

    Returns:
      Combined list of raw JSON `DataPolicy` dictionaries across all pages.

    Raises:
      RuntimeError: If any `/v2/` list request fails with an HTTP or network
        transport error.
    """
    base_url = (
        f"{self.get_endpoint()}/v2/projects/{project_id}/"
        f"locations/{location}/dataPolicies"
    )
    policies: list[dict[str, Any]] = []
    page_token: str | None = None

    while True:
      token = self.get_bearer_token()
      headers = {"Authorization": f"Bearer {token}"}
      url = base_url
      if page_token:
        url = f"{base_url}?pageToken={urllib.parse.quote(page_token)}"
      request = urllib.request.Request(url, headers=headers, method="GET")
      try:
        data = self.urlopen_json_with_retry(request)
      except urllib.error.HTTPError as http_error:
        error_body = _read_http_error_body(http_error)
        raise RuntimeError(
            f"HTTP Error {http_error.code} listing Data Policies for"
            f" projects/{project_id}/locations/{location}:"
            f" {http_error.reason} - {error_body}"
        ) from http_error
      except (urllib.error.URLError, TimeoutError, OSError) as transport_error:
        raise RuntimeError(
            f"Network error listing Data Policies for {project_id}/{location}:"
            f" {transport_error}"
        ) from transport_error
      policies.extend(data.get("dataPolicies", []))
      page_token = data.get("nextPageToken")
      if not page_token:
        break

    return policies

  def get_data_policy_v2(
      self,
      policy_resource_name: str,
      *,
      not_found_behavior: str = "return_none",
  ) -> dict[str, Any] | None:
    """Fetches a single V2 Data Policy resource via `GET /v2/{name}`.

    Args:
      policy_resource_name: Full V2 Data Policy resource path
        (`projects/{project}/locations/{region}/dataPolicies/{policy_id}`).
      not_found_behavior: Controls HTTP `404` handling: `'return_none'` returns
        `None`; `'raise_not_found'` raises `google.api_core.exceptions.NotFound`
        (matching GAPIC client semantics); `'raise_runtime'` raises
        `RuntimeError`.

    Returns:
      Parsed JSON policy dictionary, or `None` on HTTP `404` when
      `not_found_behavior == 'return_none'`.

    Raises:
      exceptions.NotFound: On HTTP `404` when
        `not_found_behavior == 'raise_not_found'`.
      RuntimeError: On non-retryable HTTP/network errors or exhausted retries.
    """
    token = self.get_bearer_token()
    url = f"{self.get_endpoint()}/v2/{policy_resource_name}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
      data = self.urlopen_json_with_retry(request)
      return data if data else {"name": policy_resource_name}
    except urllib.error.HTTPError as http_error:
      error_body = _read_http_error_body(http_error)
      if http_error.code == 404:
        if not_found_behavior == "return_none":
          return None
        if not_found_behavior == "raise_not_found":
          raise exceptions.NotFound(
              error_body or f"Data Policy {policy_resource_name} not found"
          ) from http_error
      raise RuntimeError(
          f"HTTP Error {http_error.code}: {http_error.reason} - {error_body}"
      ) from http_error
    except (urllib.error.URLError, TimeoutError, OSError) as transport_error:
      raise RuntimeError(
          f"Network error getting Data Policy {policy_resource_name}:"
          f" {transport_error}"
      ) from transport_error

  def create_data_policy_v2(
      self,
      parent: str,
      policy_id: str,
      snake_case_payload: dict[str, Any],
  ) -> dict[str, Any]:
    """Creates a V2 Data Policy via `POST /v2/{parent}/dataPolicies`.

    Args:
      parent: Regional parent path (`projects/{project}/locations/{region}`).
      policy_id: Target `data_policy_id`.
      snake_case_payload: Planned `api_payload` dictionary from `plan.json`.

    Returns:
      Parsed JSON dictionary representing the created V2 Data Policy.

    Raises:
      exceptions.AlreadyExists: On HTTP `409 Conflict`.
      RuntimeError: On non-retryable HTTP/network errors or exhausted retries.
    """
    token = self.get_bearer_token()
    url = f"{self.get_endpoint()}/v2/{parent}/dataPolicies"
    rest_payload = translate_v2_create_payload(policy_id, snake_case_payload)
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    request_body = json.dumps(rest_payload).encode("utf-8")
    request = urllib.request.Request(
        url, data=request_body, headers=headers, method="POST"
    )
    try:
      return self.urlopen_json_with_retry(request)
    except urllib.error.HTTPError as http_error:
      error_body = _read_http_error_body(http_error)
      if http_error.code == 409:
        raise exceptions.AlreadyExists(error_body) from http_error
      logger.error("REST API Error: %s - %s", http_error.code, error_body)
      raise RuntimeError(
          f"HTTP Error {http_error.code}: {http_error.reason} - {error_body}"
      ) from http_error
    except (urllib.error.URLError, TimeoutError, OSError) as transport_error:
      raise RuntimeError(
          f"Network error creating Data Policy {policy_id}: {transport_error}"
      ) from transport_error

  def delete_data_policy_v2(self, policy_resource_name: str) -> None:
    """Deletes a V2 Data Policy via `DELETE /v2/{name}`.

    Args:
      policy_resource_name: Full V2 Data Policy resource path
        (`projects/{project}/locations/{region}/dataPolicies/{policy_id}`).

    Raises:
      exceptions.NotFound: On HTTP `404 Not Found`.
      RuntimeError: On non-retryable HTTP/network errors or exhausted retries.
    """
    token = self.get_bearer_token()
    url = f"{self.get_endpoint()}/v2/{policy_resource_name}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    request = urllib.request.Request(url, headers=headers, method="DELETE")
    try:
      self.urlopen_json_with_retry(request)
    except urllib.error.HTTPError as http_error:
      error_body = _read_http_error_body(http_error)
      if http_error.code == 404:
        raise exceptions.NotFound(
            error_body or f"Data Policy {policy_resource_name} not found"
        ) from http_error
      raise RuntimeError(
          f"HTTP Error {http_error.code}: {http_error.reason} - {error_body}"
      ) from http_error
    except (urllib.error.URLError, TimeoutError, OSError) as transport_error:
      raise RuntimeError(
          f"Network error deleting Data Policy {policy_resource_name}:"
          f" {transport_error}"
      ) from transport_error
