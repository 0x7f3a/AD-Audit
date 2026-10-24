"""Collection settings: fail closed on missing or unsafe configuration."""

from __future__ import annotations

import pytest

from adaudit.cli import UsageError, _resolve_password
from adaudit.collection import CollectionError, LDAPSettings


def test_settings_require_server_and_base_dn():
    with pytest.raises(CollectionError):
        LDAPSettings(server="", base_dn="DC=corp,DC=example")
    with pytest.raises(CollectionError):
        LDAPSettings(server="ldaps://dc01.corp.example", base_dn="")


def test_settings_reject_non_ldap_scheme():
    with pytest.raises(CollectionError) as excinfo:
        LDAPSettings(server="https://dc01.corp.example", base_dn="DC=corp,DC=example")
    assert "ldap://" in str(excinfo.value)


def test_settings_accept_ldaps_and_tls_validation():
    settings = LDAPSettings(
        server="ldaps://dc01.corp.example:636",
        base_dn="DC=corp,DC=example",
        verify_tls=True,
    )
    assert settings.server == "ldaps://dc01.corp.example:636"
    assert settings.verify_tls is True


def test_password_from_file(tmp_path):
    secret = tmp_path / "pw"
    secret.write_text("hunter2\n", encoding="utf-8")
    args = _args(password_file=str(secret))
    assert _resolve_password(args) == "hunter2"


def test_password_from_environment(monkeypatch):
    monkeypatch.setenv("AUDIT_PW", "from-env")
    assert _resolve_password(_args(password_env="AUDIT_PW")) == "from-env"


def test_missing_password_is_an_error(monkeypatch):
    monkeypatch.delenv("ADAUDIT_PASSWORD", raising=False)
    with pytest.raises(UsageError) as excinfo:
        _resolve_password(_args(bind_dn="CN=Audit,OU=Service,DC=corp,DC=example"))
    assert "password is required" in str(excinfo.value)


def test_empty_password_file_is_an_error(tmp_path):
    secret = tmp_path / "pw"
    secret.write_text("\n", encoding="utf-8")
    with pytest.raises(UsageError):
        _resolve_password(_args(password_file=str(secret)))


def test_password_never_comes_from_argv():
    import inspect

    from adaudit import cli

    source = inspect.getsource(cli.build_parser)
    assert '"--password"' not in source
    assert "--password-file" in source


def test_unreadable_password_file_is_an_error(tmp_path):
    with pytest.raises(UsageError) as excinfo:
        _resolve_password(_args(password_file=str(tmp_path / "missing")))
    assert "cannot read" in str(excinfo.value)


def test_ask_password_prompts_without_echo(monkeypatch):
    monkeypatch.delenv("ADAUDIT_PASSWORD", raising=False)
    monkeypatch.setattr("adaudit.cli.getpass.getpass", lambda prompt: "prompted")
    assert _resolve_password(_args(ask_password=True)) == "prompted"


def test_anonymous_bind_allowed_without_password(monkeypatch):
    monkeypatch.delenv("ADAUDIT_PASSWORD", raising=False)
    assert _resolve_password(_args()) is None


def _args(**overrides):
    class Args:
        password_file = None
        password_env = "ADAUDIT_PASSWORD"
        ask_password = False
        bind_dn = None

    args = Args()
    for key, value in overrides.items():
        setattr(args, key, value)
    return args
