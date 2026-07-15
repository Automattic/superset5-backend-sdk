"""
Mechanisms for authentication and authorization.
"""

from typing import Any, Dict, cast

from requests import Response, Session
from requests.adapters import HTTPAdapter
from urllib3.util import Retry


class Auth:  # pylint: disable=too-few-public-methods
    """
    An authentication/authorization mechanism.
    """

    def __init__(self):
        self.session = Session()
        self.session.hooks["response"].append(self.reauth)

        retries = Retry(
            total=3,  # max retries count
            backoff_factor=1,  # delay factor between attempts
            respect_retry_after_header=True,
        )

        self.session.mount("https://", HTTPAdapter(max_retries=retries))

    def get_headers(self) -> Dict[str, str]:
        """
        Return headers for auth.
        """
        return {}

    def auth(self) -> None:
        """
        Perform authentication, fetching JWT tokens, CSRF tokens, cookies, etc.
        """
        raise NotImplementedError("Must be implemented for reauthorizing")

    # pylint: disable=invalid-name, unused-argument
    def reauth(self, r: Response, *args: Any, **kwargs: Any) -> Response:
        """
        Catch 401, re-authenticate, and retry the request once.

        This hook disables itself while it runs, so requests made during
        ``auth()`` (login, CSRF token) can never re-enter it: a 401 there
        surfaces to the caller instead of triggering yet another
        re-authentication. The hook is also stripped from the retried request
        (session hooks were merged into it when it was prepared), so a second
        401 is returned as-is instead of looping.
        """
        if r.status_code != 401:
            return r

        session_hooks = self.session.hooks["response"]
        self.session.hooks["response"] = [
            hook for hook in session_hooks if hook != self.reauth
        ]
        try:
            try:
                self.auth()
            except NotImplementedError:
                return r

            # Refresh the credential headers on the session and on the request
            # being retried. ``get_headers()`` covers mechanisms that expose
            # credentials directly (e.g. token auths); ``Authorization`` is
            # copied from the session for mechanisms that store the fresh token
            # there (e.g. username/password auth) -- retrying with the stale
            # ``Authorization`` header would just 401 again.
            self.session.headers.update(self.get_headers())
            r.request.headers.update(self.get_headers())
            authorization = self.session.headers.get("Authorization")
            if authorization is not None:
                r.request.headers["Authorization"] = cast(str, authorization)

            r.request.hooks["response"] = [
                hook for hook in r.request.hooks["response"] if hook != self.reauth
            ]
            # ``kwargs`` are the original send kwargs (verify, timeout, ...),
            # passed through by ``dispatch_hook``.
            return self.session.send(r.request, **kwargs)
        finally:
            self.session.hooks["response"] = session_hooks
