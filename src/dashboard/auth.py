"""Password gate for the dashboard.

The dashboard shows attacker credentials, recordings and malware metadata, and (on a demo machine) can launch attacks
and start processes, so it must not be reachable without a login once it is exposed beyond localhost.

Set CERDA_DASHBOARD_PASSWORD (or CERDA_DASHBOARD_PASSWORD_FILE, e.g. a Docker secret). When neither is set the
dashboard stays open, as before, and says so: that is only acceptable bound to 127.0.0.1 (the compose file does).
Failed logins are throttled across all browser sessions, so a script cannot guess passwords in parallel tabs.
"""
import hmac
import os
import threading
import time

import streamlit as st

MAX_FAILURES = 5  # in a row, across every session...
LOCKOUT_SECONDS = 60  # ...then no attempts are accepted for this long


def configured_password() -> str:
    path = os.environ.get("CERDA_DASHBOARD_PASSWORD_FILE")
    if path:
        try:
            with open(path, encoding="utf-8") as f:
                return f.read().strip()
        except OSError:
            st.error(f"CERDA_DASHBOARD_PASSWORD_FILE is set but unreadable ({path}). The dashboard stays locked.")
            st.stop()
    return os.environ.get("CERDA_DASHBOARD_PASSWORD", "")


class _Throttle:
    def __init__(self):
        self._lock = threading.Lock()
        self.failures, self.locked_until = 0, 0.0

    def remaining(self) -> float:
        with self._lock:
            return max(0.0, self.locked_until - time.monotonic())

    def record(self, ok: bool):
        with self._lock:
            if ok:
                self.failures = 0
                return
            self.failures += 1
            if self.failures >= MAX_FAILURES:
                self.locked_until, self.failures = time.monotonic() + LOCKOUT_SECONDS, 0


@st.cache_resource
def _throttle() -> _Throttle:
    return _Throttle()  # one per server process, shared by all browser sessions


def check(password: str, attempt: str) -> bool:
    return hmac.compare_digest(password.encode("utf-8"), attempt.encode("utf-8"))


def require_login() -> None:
    """Stop the script until the visitor has logged in (no-op when no password is configured)."""
    password = configured_password()
    if not password:
        st.sidebar.warning("No dashboard password is set (CERDA_DASHBOARD_PASSWORD). Only run it bound to localhost.")
        return
    if st.session_state.get("cerda_authenticated"):
        if st.sidebar.button("Log out"):
            st.session_state.cerda_authenticated = False
            st.rerun()
        return
    st.title("CERDA dashboard")
    wait = _throttle().remaining()
    with st.form("cerda_login"):
        attempt = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Log in")
    if wait:
        st.error(f"Too many failed attempts. Try again in {int(wait) + 1} seconds.")
    elif submitted:
        ok = check(password, attempt)
        _throttle().record(ok)
        if ok:
            st.session_state.cerda_authenticated = True
            st.rerun()
        st.error("Wrong password.")
    st.stop()
