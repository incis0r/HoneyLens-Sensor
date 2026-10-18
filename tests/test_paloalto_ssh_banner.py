"""The PAN-OS SSH decoy's identification string.

A client reads this before it authenticates, so it is the decoy's most exposed single
string. asyncssh's default advertises "AsyncSSH_<version>", which gave the whole PAN-OS
persona away to one ``ssh-keyscan``; these tests pin the three things that matter:
the default is OpenSSH-shaped, an operator can override it, and a malformed override
cannot stop the decoy from starting.
"""

from __future__ import annotations

import importlib

import pytest

asyncssh = pytest.importorskip("asyncssh")

MODULE = "honeylens.honeypots.honeypot_paloalto_ssh"


def _banner(monkeypatch, value: str | None) -> str:
    """Re-read the banner with PALOALTO_SSH_BANNER set (or unset) to ``value``."""
    if value is None:
        monkeypatch.delenv("PALOALTO_SSH_BANNER", raising=False)
    else:
        monkeypatch.setenv("PALOALTO_SSH_BANNER", value)
    mod = importlib.import_module(MODULE)
    return mod._ssh_banner()


def test_default_is_openssh_shaped(monkeypatch):
    """Unset, the decoy must still not announce itself as a Python SSH library."""
    banner = _banner(monkeypatch, None)
    assert banner.startswith("OpenSSH_")
    assert "asyncssh" not in banner.lower()


def test_override_is_honoured(monkeypatch):
    assert _banner(monkeypatch, "OpenSSH_9.6") == "OpenSSH_9.6"


@pytest.mark.parametrize("raw", ["  OpenSSH_9.6", "OpenSSH_9.6  ", "OpenSSH_9.6\n"])
def test_surrounding_whitespace_is_normalised_not_rejected(monkeypatch, raw):
    """A stray newline from an editor or a shell heredoc is a usable value, not a fault."""
    assert _banner(monkeypatch, raw) == "OpenSSH_9.6"


@pytest.mark.parametrize("prefix", ["SSH-2.0-", "ssh-2.0-"])
def test_protocol_prefix_is_stripped(monkeypatch, prefix):
    """asyncssh prepends SSH-2.0- itself, so keeping it would double the prefix."""
    assert _banner(monkeypatch, f"{prefix}OpenSSH_8.4") == "OpenSSH_8.4"


# A NUL byte is deliberately absent: os.environ rejects one outright, so it can never
# reach this code through the environment in the first place.
@pytest.mark.parametrize("bad", ["", "   ", "SSH-2.0-", "OpenSSH_\t8.0", "OpenSSH_8.4\x7f", "Ωpen"])
def test_unusable_override_falls_back_instead_of_crashing(monkeypatch, bad):
    """A control character or empty value must not become a failed start.

    asyncssh refuses a non-printable server_version, and this decoy exits 1 on a bad
    start under Restart=always — i.e. a silent permanent crash loop. A cosmetic setting
    must never be able to cause that.
    """
    mod = importlib.import_module(MODULE)
    assert _banner(monkeypatch, bad) == mod.DEFAULT_SSH_BANNER


def test_banner_is_acceptable_to_asyncssh(monkeypatch):
    """The default must be a legal SSH identification string, not merely plausible."""
    banner = _banner(monkeypatch, None)
    assert banner.isascii() and banner.isprintable()
    # RFC 4253: the whole "SSH-2.0-<version>" line stays under 255 bytes including CRLF.
    assert len(f"SSH-2.0-{banner}\r\n".encode()) < 255
