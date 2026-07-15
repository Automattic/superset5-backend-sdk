"""
Test username:password authentication mechanism.
"""

import pytest
from pytest_mock import MockerFixture
from requests.exceptions import HTTPError
from requests_mock.mocker import Mocker
from yarl import URL

from preset_cli.auth.superset import SupersetJWTAuth, UsernamePasswordAuth


def test_username_password_auth(requests_mock: Mocker) -> None:
    """
    Tests for the username/password authentication mechanism.
    """
    csrf_token = "CSRF_TOKEN"
    requests_mock.post(
        "https://superset.example.org/api/v1/security/login",
        json={"access_token": "ACCESS_TOKEN"},
    )
    requests_mock.get(
        "https://superset.example.org/api/v1/security/csrf_token/",
        json={"result": csrf_token},
    )

    auth = UsernamePasswordAuth(
        URL("https://superset.example.org/"),
        "admin",
        "password123",
    )
    assert auth.get_headers() == {
        "X-CSRFToken": csrf_token,
    }
    assert auth.session.headers["Authorization"] == "Bearer ACCESS_TOKEN"
    assert auth.session.headers["X-CSRFToken"] == csrf_token

    login_request = requests_mock.request_history[0]
    assert login_request.json() == {
        "username": "admin",
        "password": "password123",
        "provider": "ldap",
    }


def test_username_password_auth_custom_provider(requests_mock: Mocker) -> None:
    """
    Tests that the login provider can be overridden.
    """
    requests_mock.post(
        "https://superset.example.org/api/v1/security/login",
        json={"access_token": "ACCESS_TOKEN"},
    )
    requests_mock.get(
        "https://superset.example.org/api/v1/security/csrf_token/",
        json={"result": "CSRF_TOKEN"},
    )

    UsernamePasswordAuth(
        URL("https://superset.example.org/"),
        "admin",
        "password123",
        provider="db",
    )

    login_request = requests_mock.request_history[0]
    assert login_request.json()["provider"] == "db"


def test_username_password_auth_no_csrf(requests_mock: Mocker) -> None:
    """
    Tests for the username/password authentication mechanism.
    """
    requests_mock.post(
        "https://superset.example.org/api/v1/security/login",
        json={"access_token": "ACCESS_TOKEN"},
    )
    requests_mock.get(
        "https://superset.example.org/api/v1/security/csrf_token/",
        json={"result": None},
    )

    auth = UsernamePasswordAuth(
        URL("https://superset.example.org/"),
        "admin",
        "password123",
    )
    # pylint: disable=use-implicit-booleaness-not-comparison
    assert auth.get_headers() == {}
    assert auth.session.headers["Authorization"] == "Bearer ACCESS_TOKEN"
    assert "X-CSRFToken" not in auth.session.headers


def test_username_password_auth_reauth_on_expired_token(requests_mock: Mocker) -> None:
    """
    A 401 mid-run triggers a fresh login, and the failed request is retried
    once with the new token (not the stale one).
    """
    requests_mock.post(
        "https://superset.example.org/api/v1/security/login",
        [
            {"json": {"access_token": "TOKEN_1"}},
            {"json": {"access_token": "TOKEN_2"}},
        ],
    )
    requests_mock.get(
        "https://superset.example.org/api/v1/security/csrf_token/",
        json={"result": "CSRF_TOKEN"},
    )
    requests_mock.get(
        "https://superset.example.org/api/v1/chart/",
        request_headers={"Authorization": "Bearer TOKEN_1"},
        status_code=401,
    )
    requests_mock.get(
        "https://superset.example.org/api/v1/chart/",
        request_headers={"Authorization": "Bearer TOKEN_2"},
        json={"result": []},
    )

    auth = UsernamePasswordAuth(
        URL("https://superset.example.org/"),
        "admin",
        "password123",
    )
    response = auth.session.get("https://superset.example.org/api/v1/chart/")

    assert response.status_code == 200
    assert auth.session.headers["Authorization"] == "Bearer TOKEN_2"

    # the re-login request must not carry the stale Bearer token
    login_requests = [
        request
        for request in requests_mock.request_history
        if request.path == "/api/v1/security/login"
    ]
    assert len(login_requests) == 2
    assert "Authorization" not in login_requests[1].headers


def test_username_password_auth_login_failure(requests_mock: Mocker) -> None:
    """
    A 401 from the login endpoint itself fails with an ``HTTPError`` instead
    of looping into another re-authentication.
    """
    requests_mock.post(
        "https://superset.example.org/api/v1/security/login",
        status_code=401,
    )

    with pytest.raises(HTTPError):
        UsernamePasswordAuth(
            URL("https://superset.example.org/"),
            "admin",
            "bad-password",
        )

    # the 401 on the initial login triggers the reauth hook once; the login it
    # attempts (with the hook disabled) fails and surfaces -- two requests, no loop
    assert len(requests_mock.request_history) == 2


def test_jwt_auth_superset(mocker: MockerFixture) -> None:
    """
    Test the ``JWTAuth`` authentication mechanism for Superset tenant.
    """
    auth = SupersetJWTAuth("my-token", URL("https://example.org/"))
    mocker.patch.object(auth, "get_csrf_token", return_value="myCSRFToken")

    assert auth.get_headers() == {
        "Authorization": "Bearer my-token",
        "X-CSRFToken": "myCSRFToken",
    }


def test_get_csrf_token(requests_mock: Mocker) -> None:
    """
    Test the get_csrf_token method.
    """
    auth = SupersetJWTAuth("my-token", URL("https://example.org/"))
    requests_mock.get(
        "https://example.org/api/v1/security/csrf_token/",
        json={"result": "myCSRFToken"},
    )

    assert auth.get_csrf_token("my-token") == "myCSRFToken"
