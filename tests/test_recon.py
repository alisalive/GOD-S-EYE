"""
Tests for modules/recon.py — mock socket port scan.
"""

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.orchestrator import EngagementState, Mode
from modules.recon import port_scan, dns_lookup, get_service_name, run_recon, _check_ssl_expiry_days


# ── Unit tests ────────────────────────────────────────────────────────────────

def test_get_service_name_known():
    assert get_service_name(80) == "HTTP"
    assert get_service_name(443) == "HTTPS"
    assert get_service_name(22) == "SSH"
    assert get_service_name(445) == "SMB"
    assert get_service_name(3389) == "RDP"


def test_get_service_name_unknown():
    result = get_service_name(12345)
    assert result == "port-12345"


def test_dns_lookup_invalid():
    result = dns_lookup("this-does-not-exist-xyz-abc.invalid")
    assert "error" in result or result["ips"] == []


def test_dns_lookup_loopback():
    result = dns_lookup("127.0.0.1")
    assert result["hostname"] == "127.0.0.1"


@pytest.mark.asyncio
async def test_port_scan_closed_ports():
    """All ports on 127.0.0.1 range should be closed (except listening ones)."""
    open_ports = await port_scan("127.0.0.1", ports=[1, 2, 3, 4, 5], timeout=0.2)
    # Just verify it returns a dict (some may be open on CI, that's fine)
    assert isinstance(open_ports, dict)


@pytest.mark.asyncio
async def test_port_scan_returns_service_names():
    """Port scan dict values should have 'service' and 'banner' keys."""
    with patch("asyncio.open_connection") as mock_conn:
        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"SSH-2.0-OpenSSH")
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()
        mock_conn.return_value = (mock_reader, mock_writer)

        open_ports = await port_scan("127.0.0.1", ports=[22], timeout=1.0)
        if 22 in open_ports:
            assert "service" in open_ports[22]
            assert "banner" in open_ports[22]


@pytest.mark.asyncio
async def test_run_recon_basic():
    """run_recon should complete and populate state.recon_data."""
    state = EngagementState(target="127.0.0.1", mode=Mode.PENTEST, scope=["127.0.0.1"])

    # Return a non-web port (SSH) so the GOD'S EYE / web-fingerprint branch
    # is never entered — keeps the test isolated from external imports.
    with patch("modules.recon.port_scan", new_callable=AsyncMock) as mock_scan:
        mock_scan.return_value = {22: {"service": "SSH", "banner": "SSH-2.0-OpenSSH_9.0"}}
        await run_recon(state, console=None)

    assert "open_ports" in state.recon_data
    assert "dns" in state.recon_data
    assert 22 in state.recon_data["open_ports"]


# ── _check_ssl_expiry_days unit tests ─────────────────────────────────────────

class TestCheckSslExpiryDays:
    def test_returns_int_on_success(self):
        """When TLS check succeeds it should return a non-negative int."""
        import datetime
        future = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) + datetime.timedelta(days=60)
        fake_cert = {"notAfter": future.strftime("%b %d %H:%M:%S %Y GMT")}

        with patch("ssl.create_default_context") as mock_ctx_fn:
            mock_ctx = MagicMock()
            mock_ctx_fn.return_value = mock_ctx
            # Simulate the context manager chain: ctx.wrap_socket(sock, ...)
            mock_tls_sock = MagicMock()
            mock_tls_sock.getpeercert.return_value = fake_cert
            mock_tls_sock.__enter__ = MagicMock(return_value=mock_tls_sock)
            mock_tls_sock.__exit__ = MagicMock(return_value=False)
            mock_ctx.wrap_socket.return_value = mock_tls_sock

            mock_raw_sock = MagicMock()
            mock_raw_sock.__enter__ = MagicMock(return_value=mock_raw_sock)
            mock_raw_sock.__exit__ = MagicMock(return_value=False)

            with patch("socket.create_connection", return_value=mock_raw_sock):
                result = _check_ssl_expiry_days("example.com", 443)

        assert isinstance(result, int)
        assert 58 <= result <= 62  # allow ±2 days for test timing

    def test_returns_minus_one_on_connection_failure(self):
        """Connection failure should return -1 (check suppressed)."""
        import socket
        with patch("socket.create_connection", side_effect=OSError("refused")):
            result = _check_ssl_expiry_days("192.0.2.1", 443)  # TEST-NET, unreachable
        assert result == -1

    def test_returns_minus_one_on_tls_error(self):
        """TLS handshake error should return -1."""
        import ssl
        mock_raw_sock = MagicMock()
        mock_raw_sock.__enter__ = MagicMock(return_value=mock_raw_sock)
        mock_raw_sock.__exit__ = MagicMock(return_value=False)

        with patch("socket.create_connection", return_value=mock_raw_sock):
            with patch("ssl.create_default_context") as mock_ctx_fn:
                mock_ctx = MagicMock()
                mock_ctx.wrap_socket.side_effect = ssl.SSLError("cert verify failed")
                mock_ctx_fn.return_value = mock_ctx
                result = _check_ssl_expiry_days("untrusted.example.com", 443)

        assert result == -1

    def test_cert_expiring_in_10_days(self):
        """Cert expiring in 10 days → returns ≈10."""
        import datetime
        soon = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) + datetime.timedelta(days=10)
        fake_cert = {"notAfter": soon.strftime("%b %d %H:%M:%S %Y GMT")}

        with patch("ssl.create_default_context") as mock_ctx_fn:
            mock_ctx = MagicMock()
            mock_ctx_fn.return_value = mock_ctx
            mock_tls_sock = MagicMock()
            mock_tls_sock.getpeercert.return_value = fake_cert
            mock_tls_sock.__enter__ = MagicMock(return_value=mock_tls_sock)
            mock_tls_sock.__exit__ = MagicMock(return_value=False)
            mock_ctx.wrap_socket.return_value = mock_tls_sock
            mock_raw_sock = MagicMock()
            mock_raw_sock.__enter__ = MagicMock(return_value=mock_raw_sock)
            mock_raw_sock.__exit__ = MagicMock(return_value=False)

            with patch("socket.create_connection", return_value=mock_raw_sock):
                result = _check_ssl_expiry_days("example.com", 443)

        assert 8 <= result <= 12
