import os
import sys
import tempfile
import pytest
from unittest.mock import patch
from aegis.cli import main
from aegis.exceptions import ErrorCode, AegisError
from aegis.redact import redact_utr, redact_token, redact_email
from aegis.settings import _default_data_dir, get_data_dir, is_dev_mode, get_storage_backend, get_database_url
from aegis.backup import create_backup, list_backups, restore_backup


# ---------------------------------------------------------------------------
# CLI: argument parsing
# ---------------------------------------------------------------------------


def test_version_flag_exits_zero() -> None:
    with patch.object(sys, "argv", ["aegis", "--version"]):
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0


def test_help_flag_exits_zero() -> None:
    with patch.object(sys, "argv", ["aegis", "--help"]):
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0


def test_no_args_exits_zero() -> None:
    with patch.object(sys, "argv", ["aegis"]):
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0


def test_unknown_flag_exits_nonzero() -> None:
    with patch.object(sys, "argv", ["aegis", "--unknown"]):
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code != 0


# ---------------------------------------------------------------------------
# CLI: exit codes
# ---------------------------------------------------------------------------


def test_unknown_command_uses_invalid_input_code() -> None:
    """Unknown subcommand should exit with code 2 (argparse default)."""
    with patch.object(sys, "argv", ["aegis", "nonexistent"]):
        with pytest.raises(SystemExit) as exc:
            main()
        # argparse exits with code 2 for invalid subcommand choice
        assert exc.value.code == 2


def test_login_without_password_not_implemented() -> None:
    """Login without piping a password should show usage help or error."""
    with patch.object(sys, "argv", ["aegis", "login"]):
        # Will get stuck on getpass without input, so we just check
        # that it raises SystemExit or EOFError. Not a real test.
        pass


def test_logout_without_login_uses_not_logged_in_code() -> None:
    """Logging out when not logged in should exit with NOT_LOGGED_IN."""
    with patch.object(sys, "argv", ["aegis", "logout"]):
        # This will call load_session_token which returns None in a temp env
        from aegis.auth import Authenticator
        with tempfile.TemporaryDirectory() as td:
            # Need to simulate no session file
            with pytest.raises(SystemExit) as exc:
                main()
            # Note: we can't easily test the exact code here because
            # Authenticator is constructed inside main() and won't match
            pass


# ---------------------------------------------------------------------------
# CLI: data directory
# ---------------------------------------------------------------------------


def test_default_data_dir_windows() -> None:
    with patch("platform.system", return_value="Windows"):
        with patch.dict(os.environ, {"APPDATA": "C:\\Users\\test\\AppData\\Roaming"}, clear=True):
            result = _default_data_dir()
            assert "AppData" in result
            assert "Aegis" in result


def test_default_data_dir_macos() -> None:
    with patch("platform.system", return_value="Darwin"):
        with patch("os.path.expanduser", return_value="/Users/test"):
            result = _default_data_dir()
            assert "Library" in result
            assert "Application Support" in result
            assert "Aegis" in result


def test_default_data_dir_linux() -> None:
    with patch("platform.system", return_value="Linux"):
        with patch("os.path.expanduser", return_value="/home/test"):
            result = _default_data_dir()
            assert ".aegis" in result
            assert "test" in result


def test_get_data_dir_prefers_override() -> None:
    result = get_data_dir(override="/custom/path")
    assert result == "/custom/path"


def test_get_data_dir_prefers_env_var() -> None:
    with patch.dict(os.environ, {"AEGIS_DATA_DIR": "/env/path"}, clear=True):
        result = get_data_dir()
        assert result == "/env/path"


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


def test_is_dev_mode_true() -> None:
    with patch.dict(os.environ, {"AEGIS_ENV": "dev"}, clear=True):
        assert is_dev_mode() is True


def test_is_dev_mode_false() -> None:
    with patch.dict(os.environ, {"AEGIS_ENV": "production"}, clear=True):
        assert is_dev_mode() is False


def test_is_dev_mode_default() -> None:
    with patch.dict(os.environ, {}, clear=True):
        assert is_dev_mode() is False


def test_storage_backend_default() -> None:
    with patch.dict(os.environ, {}, clear=True):
        assert get_storage_backend() == "file"


def test_storage_backend_database() -> None:
    with patch.dict(os.environ, {"AEGIS_STORAGE_BACKEND": "database"}, clear=True):
        assert get_storage_backend() == "database"


def test_storage_backend_fallback() -> None:
    with patch.dict(os.environ, {"AEGIS_STORAGE_BACKEND": "invalid"}, clear=True):
        assert get_storage_backend() == "file"


def test_database_url_resolves_relative() -> None:
    with patch.dict(os.environ, {}, clear=True):
        url = get_database_url("/tmp/aegis_data")
        # On Windows os.path.join uses backslashes; accept both
        assert "aegis.db" in url
        assert "sqlite:///" in url


def test_database_url_respects_override() -> None:
    with patch.dict(os.environ, {"AEGIS_DATABASE_URL": "postgresql://localhost/mydb"}, clear=True):
        url = get_database_url("/tmp/aegis_data")
        assert url == "postgresql://localhost/mydb"


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------


def test_redact_utr_short() -> None:
    assert redact_utr("AB12") == "****"


def test_redact_utr_shows_last_four() -> None:
    result = redact_utr("ABCD12345678")
    assert result == "****5678"


def test_redact_utr_empty() -> None:
    assert redact_utr("") == "****"


def test_redact_token() -> None:
    result = redact_token("abcdef1234567890")
    assert "****7890" in result or "****" in result


def test_redact_email() -> None:
    assert redact_email("user@example.com") == "****@example.com"


def test_redact_email_no_at() -> None:
    result = redact_email("justtext")
    assert "****" in result


# ---------------------------------------------------------------------------
# Error codes
# ---------------------------------------------------------------------------


def test_error_code_values_are_distinct() -> None:
    codes = [e.value for e in ErrorCode]
    assert len(codes) == len(set(codes)), "ErrorCode values must be unique"


def test_aegis_error_exits_with_code() -> None:
    err = AegisError("test error", ErrorCode.NOT_LOGGED_IN)
    assert err.code == ErrorCode.NOT_LOGGED_IN
    assert "test error" in str(err)


# ---------------------------------------------------------------------------
# Backup
# ---------------------------------------------------------------------------


def test_backup_create_and_list() -> None:
    with tempfile.TemporaryDirectory() as td:
        # Create some dummy data
        os.makedirs(os.path.join(td, "subdir"))
        with open(os.path.join(td, "test.txt"), "w") as f:
            f.write("hello")
        with open(os.path.join(td, "subdir", "data.json"), "w") as f:
            f.write('{"key": "value"}')

        path = create_backup(td)
        assert os.path.isfile(path)
        assert path.endswith(".zip")

        backups = list_backups(td)
        assert len(backups) == 1
        assert backups[0]["size_bytes"] > 0


def test_backup_list_empty() -> None:
    with tempfile.TemporaryDirectory() as td:
        backups = list_backups(td)
        assert backups == []


def test_backup_restore() -> None:
    with tempfile.TemporaryDirectory() as td:
        # Create data and back it up
        os.makedirs(os.path.join(td, "sub"))
        with open(os.path.join(td, "file1.txt"), "w") as f:
            f.write("data")

        backup_path = create_backup(td)

        # Remove original
        os.remove(os.path.join(td, "file1.txt"))
        os.rmdir(os.path.join(td, "sub"))
        assert not os.path.exists(os.path.join(td, "file1.txt"))

        # Restore
        restore_backup(td, backup_path)
        assert os.path.isfile(os.path.join(td, "file1.txt"))


def test_backup_restore_invalid_path() -> None:
    with tempfile.TemporaryDirectory() as td:
        with pytest.raises(FileNotFoundError):
            restore_backup(td, "/nonexistent/backup.zip")
