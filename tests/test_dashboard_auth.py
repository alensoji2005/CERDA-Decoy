"""Gap 8 (hardening): dashboard password gate, and the range tab degrading when the demo attackers are not installed."""
import os

import pandas as pd
import pytest
import streamlit as st
from streamlit.testing.v1 import AppTest

from src.dashboard import auth


def gated_page():
    import streamlit as st
    from src.dashboard.auth import require_login
    require_login()
    st.write("SECRET CONTENT")


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    for name in ("CERDA_DASHBOARD_PASSWORD", "CERDA_DASHBOARD_PASSWORD_FILE"):
        monkeypatch.delenv(name, raising=False)
    st.cache_resource.clear()  # the throttle is shared per process: start every test with a fresh one
    yield
    st.cache_resource.clear()


def run(**state):
    return AppTest.from_function(gated_page).run(timeout=30)


def shows_secret(at):
    return any("SECRET CONTENT" in m.value for m in at.markdown)


def log_in(at, attempt):
    at.text_input[0].set_value(attempt)
    at.button[0].click()
    return at.run(timeout=30)


def test_g1_without_a_password_the_dashboard_is_open_and_says_so():
    at = run()
    assert shows_secret(at) and any("No dashboard password" in w.value for w in at.sidebar.warning)


def test_g2_with_a_password_nothing_shows_until_it_is_entered(monkeypatch):
    monkeypatch.setenv("CERDA_DASHBOARD_PASSWORD", "correct horse")
    at = run()
    assert not shows_secret(at) and len(at.text_input) == 1
    at = log_in(at, "wrong")
    assert not shows_secret(at) and any("Wrong password" in e.value for e in at.error)
    at = log_in(at, "correct horse")
    assert shows_secret(at) and not at.exception
    assert any(b.label == "Log out" for b in at.sidebar.button)


def test_g3_failed_attempts_lock_out_even_the_right_password(monkeypatch):
    monkeypatch.setenv("CERDA_DASHBOARD_PASSWORD", "correct horse")
    at = run()
    for _ in range(auth.MAX_FAILURES):
        at = log_in(at, "guess")
    at = log_in(at, "correct horse")  # locked: the right password is not even tried
    assert not shows_secret(at) and any("Too many failed attempts" in e.value for e in at.error)
    # and the lockout is shared: a brand new browser session is locked too
    assert any("Too many failed attempts" in e.value for e in run().error)


def test_g4_password_can_come_from_a_file(monkeypatch, tmp_path):
    secret = tmp_path / "pw"
    secret.write_text("from file\n")
    monkeypatch.setenv("CERDA_DASHBOARD_PASSWORD_FILE", str(secret))
    at = run()
    assert not shows_secret(at)
    assert shows_secret(log_in(at, "from file"))
    monkeypatch.setenv("CERDA_DASHBOARD_PASSWORD_FILE", str(tmp_path / "missing"))
    locked = run()
    assert not shows_secret(locked) and any("unreadable" in e.value for e in locked.error)  # fails closed


def test_g5_comparison_helper():
    assert auth.check("pässword", "pässword") and not auth.check("a", "b") and not auth.check("a", "")


def test_g6_range_tab_without_the_demo_attackers_is_an_info_not_a_crash(tmp_path):
    def page():
        import streamlit as st
        import pandas as pd
        from src.dashboard import panels
        panels.RANGE_SCRIPT = r"C:\definitely\not\here\live_range.py"
        panels.render_range_tab(pd.DataFrame())

    at = AppTest.from_function(page).run(timeout=30)
    assert not at.exception and any("not part of this installation" in i.value for i in at.info)
    assert len(at.button) == 0  # nothing that could start a second decoy or an attack
