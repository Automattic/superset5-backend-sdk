"""
Test username:password authentication mechanism.
"""

from pytest_mock import MockerFixture
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
