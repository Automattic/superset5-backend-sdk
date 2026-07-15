"""
Test authentication mechanisms.
"""

from typing import Dict

import pytest
from requests.exceptions import HTTPError
from requests_mock.mocker import Mocker

from preset_cli.auth.main import Auth


class TokenMintingAuth(Auth):
    """
    Auth that mints a new token on every ``auth()`` call.
    """

    def __init__(self):
        super().__init__()
        self.auth_calls = 0

    def get_headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer token-{self.auth_calls}"}

    def auth(self) -> None:
        self.auth_calls += 1


class HTTPLoginAuth(Auth):
    """
    Auth whose ``auth()`` performs an HTTP login through the session.
    """

    def auth(self) -> None:
        response = self.session.post("https://example.org/login")
        response.raise_for_status()
        self.session.headers["Authorization"] = "Bearer fresh"


def test_auth() -> None:
    """
    Tests for the base class ``Auth``.
    """
    auth = Auth()
    assert auth.reauth in auth.session.hooks["response"]


def test_reauth_not_implemented(requests_mock: Mocker) -> None:
    """
    A 401 is returned as-is when the mechanism can't re-authenticate.
    """
    requests_mock.get("http://example.org/", status_code=401)

    # the base class has no reauth
    auth = Auth()
    response = auth.session.get("http://example.org/")
    assert response.status_code == 401
    assert len(requests_mock.request_history) == 1


def test_reauth_retries_once_with_fresh_headers(requests_mock: Mocker) -> None:
    """
    A 401 triggers a re-auth and a single retry carrying the fresh credentials.
    """
    requests_mock.get("https://example.org/", status_code=401)
    requests_mock.get(
        "https://example.org/",
        request_headers={"Authorization": "Bearer token-1"},
        json={"hello": "world"},
    )

    auth = TokenMintingAuth()
    response = auth.session.get("https://example.org/")

    assert response.status_code == 200
    assert auth.auth_calls == 1
    assert len(requests_mock.request_history) == 2
    retried_request = requests_mock.request_history[1]
    assert retried_request.headers["Authorization"] == "Bearer token-1"
    assert auth.session.headers["Authorization"] == "Bearer token-1"


def test_reauth_gives_up_after_one_retry(requests_mock: Mocker) -> None:
    """
    A request that keeps returning 401 after a successful re-auth is not
    retried again: the second 401 is returned to the caller.
    """
    requests_mock.get("https://example.org/", status_code=401)

    auth = TokenMintingAuth()
    response = auth.session.get("https://example.org/")

    assert response.status_code == 401
    assert auth.auth_calls == 1
    assert len(requests_mock.request_history) == 2


def test_reauth_restores_the_hook(requests_mock: Mocker) -> None:
    """
    The hook is re-enabled after a re-auth, so a later 401 is handled too.
    """
    requests_mock.get("https://example.org/", status_code=401)

    auth = TokenMintingAuth()
    auth.session.get("https://example.org/")
    auth.session.get("https://example.org/")

    assert auth.auth_calls == 2
    assert len(requests_mock.request_history) == 4


def test_401_during_auth_does_not_reauth(requests_mock: Mocker) -> None:
    """
    A 401 from a request made inside ``auth()`` (e.g. a failed login) surfaces
    to the caller instead of triggering another re-authentication.
    """
    requests_mock.get("https://example.org/data", status_code=401)
    requests_mock.post("https://example.org/login", status_code=401)

    auth = HTTPLoginAuth()
    with pytest.raises(HTTPError):
        auth.session.get("https://example.org/data")

    # one data request plus one login attempt; no loop
    assert len(requests_mock.request_history) == 2
    # the hook is restored even though ``auth()`` raised
    assert auth.reauth in auth.session.hooks["response"]
