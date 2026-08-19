from pathlib import Path
import ssl

import httpx
import pytest

from honeypot.config_core import RuntimeConfig
from honeypot.exporter_runner import SmtpExporter, TelegramExporter, WebhookExporter
from honeypot.exporter_runner.pinned_http import PinnedHttpTransport, PinnedNetworkBackend
from honeypot.exporter_runner.smtp_exporter import _PinnedSmtpSslClient
from honeypot.runtime_egress import enforce_runtime_egress_policy, planned_egress_targets


PUBLIC_V4 = "93.184.216.34"
PUBLIC_V6 = "2606:2800:220:1:248:1893:25c8:1946"


def write_locale_bundle(root: Path, locale: str) -> None:
    locale_dir = root / "resources" / "locales" / "attacker-ui"
    locale_dir.mkdir(parents=True, exist_ok=True)
    (locale_dir / f"{locale}.json").write_text("{}", encoding="utf-8")


def test_planned_egress_targets_normalize_tls_exporter_destinations() -> None:
    targets = planned_egress_targets(
        {
            "webhook": WebhookExporter(url="https://collector.example.net:8443/hook"),
            "smtp": SmtpExporter(
                host="mail.example.net",
                mail_from="alerts@example.net",
                rcpt_to="soc@example.net",
            ),
            "telegram": TelegramExporter(bot_token="token-1", chat_id="chat-9"),
        }
    )

    assert tuple(target.spec for target in targets) == (
        "webhook:collector.example.net:8443",
        "smtp:mail.example.net:465",
        "telegram:api.telegram.org:443",
    )


@pytest.mark.parametrize(
    "url",
    (
        "http://collector.example.net/hook",
        "http://collector.example.net:443/hook",
        "ftp://collector.example.net:443/hook",
        "file://collector.example.net:443/hook",
        "//collector.example.net:443/hook",
        "https://operator@collector.example.net/hook",
        "https://operator:secret@collector.example.net/hook",
    ),
)
def test_planned_egress_targets_reject_non_https_and_userinfo(url: str) -> None:
    with pytest.raises(RuntimeError, match="HTTPS|userinfo"):
        planned_egress_targets({"webhook": WebhookExporter(url=url)})


def test_rejected_url_does_not_leak_embedded_credentials_or_query_tokens() -> None:
    secret_url = "http://operator:secret@collector.example.net/hook?token=private-token"

    with pytest.raises(RuntimeError) as captured:
        planned_egress_targets({"webhook": WebhookExporter(url=secret_url)})

    assert "secret" not in str(captured.value)
    assert "private-token" not in str(captured.value)


def test_enforce_runtime_egress_policy_rejects_unapproved_targets(tmp_path: Path, monkeypatch) -> None:
    write_locale_bundle(tmp_path, "en")
    monkeypatch.chdir(tmp_path)
    config = RuntimeConfig(_env_file=None, approved_egress_cidrs="93.184.216.0/24")

    with pytest.raises(RuntimeError, match="APPROVED_EGRESS_TARGETS"):
        enforce_runtime_egress_policy(
            config=config,
            exporters={"webhook": WebhookExporter(url="https://collector.example.net/hook")},
            resolver=lambda host, port: (PUBLIC_V4,),
        )


def test_enforce_runtime_egress_policy_requires_independent_cidr_allowlist(
    tmp_path: Path,
    monkeypatch,
) -> None:
    write_locale_bundle(tmp_path, "en")
    monkeypatch.chdir(tmp_path)
    config = RuntimeConfig(
        _env_file=None,
        approved_egress_targets="webhook:collector.example.net:443",
    )

    with pytest.raises(RuntimeError, match="APPROVED_EGRESS_CIDRS"):
        enforce_runtime_egress_policy(
            config=config,
            exporters={"webhook": WebhookExporter(url="https://collector.example.net/hook")},
            resolver=lambda host, port: (PUBLIC_V4,),
        )


@pytest.mark.parametrize(
    "unsafe_address",
    (
        "127.0.0.1",
        "10.23.4.5",
        "169.254.1.2",
        "224.0.0.1",
        "0.0.0.0",
        "240.0.0.1",
        "100.64.0.1",
        "::1",
        "fe80::1",
        "ff02::1",
        "::",
        "fc00::1",
    ),
)
def test_enforce_runtime_egress_policy_rejects_unsafe_ipv4_and_ipv6(
    tmp_path: Path,
    monkeypatch,
    unsafe_address: str,
) -> None:
    write_locale_bundle(tmp_path, "en")
    monkeypatch.chdir(tmp_path)
    config = RuntimeConfig(
        _env_file=None,
        approved_egress_targets="webhook:collector.example.net:443",
        approved_egress_cidrs="0.0.0.0/1,128.0.0.0/1,::/1,8000::/1",
    )

    with pytest.raises(RuntimeError, match="nicht-globales Egress-Ziel"):
        enforce_runtime_egress_policy(
            config=config,
            exporters={"webhook": WebhookExporter(url="https://collector.example.net/hook")},
            resolver=lambda host, port: (unsafe_address,),
        )


def test_enforce_runtime_egress_policy_rejects_mixed_safe_and_unsafe_dns_answers(
    tmp_path: Path,
    monkeypatch,
) -> None:
    write_locale_bundle(tmp_path, "en")
    monkeypatch.chdir(tmp_path)
    config = RuntimeConfig(
        _env_file=None,
        approved_egress_targets="webhook:collector.example.net:443",
        approved_egress_cidrs="93.184.216.0/24",
    )

    with pytest.raises(RuntimeError, match="nicht-globales Egress-Ziel"):
        enforce_runtime_egress_policy(
            config=config,
            exporters={"webhook": WebhookExporter(url="https://collector.example.net/hook")},
            resolver=lambda host, port: (PUBLIC_V4, "127.0.0.1"),
        )


def test_enforce_runtime_egress_policy_rejects_address_outside_independent_cidr_allowlist(
    tmp_path: Path,
    monkeypatch,
) -> None:
    write_locale_bundle(tmp_path, "en")
    monkeypatch.chdir(tmp_path)
    config = RuntimeConfig(
        _env_file=None,
        approved_egress_targets="webhook:collector.example.net:443",
        approved_egress_cidrs="142.250.0.0/15",
    )

    with pytest.raises(RuntimeError, match="APPROVED_EGRESS_CIDRS"):
        enforce_runtime_egress_policy(
            config=config,
            exporters={"webhook": WebhookExporter(url="https://collector.example.net/hook")},
            resolver=lambda host, port: (PUBLIC_V4,),
        )


def test_prohibited_ot_cidr_overrides_explicit_target_and_network_approval(
    tmp_path: Path,
    monkeypatch,
) -> None:
    write_locale_bundle(tmp_path, "en")
    monkeypatch.chdir(tmp_path)
    config = RuntimeConfig(
        _env_file=None,
        approved_egress_targets="webhook:collector.example.net:443",
        approved_egress_cidrs="93.184.216.0/24",
        prohibited_ot_cidrs=f"{PUBLIC_V4}/32",
    )

    with pytest.raises(RuntimeError, match="PROHIBITED_OT_CIDRS"):
        enforce_runtime_egress_policy(
            config=config,
            exporters={"webhook": WebhookExporter(url="https://collector.example.net/hook")},
            resolver=lambda host, port: (PUBLIC_V4,),
        )


def test_enforce_runtime_egress_policy_accepts_and_pins_all_allowed_addresses(
    tmp_path: Path,
    monkeypatch,
) -> None:
    write_locale_bundle(tmp_path, "en")
    monkeypatch.chdir(tmp_path)
    config = RuntimeConfig(
        _env_file=None,
        approved_egress_targets=(
            "webhook:collector.example.net:443",
            "smtp:mail.example.net:465",
        ),
        approved_egress_cidrs="93.184.216.0/24,2606:2800:220::/48,142.250.0.0/15",
    )
    webhook = WebhookExporter(url="https://collector.example.net/hook")
    smtp = SmtpExporter(
        host="mail.example.net",
        mail_from="alerts@example.net",
        rcpt_to="soc@example.net",
    )
    answers = {
        "collector.example.net": (PUBLIC_V4, PUBLIC_V6),
        "mail.example.net": ("142.250.74.5",),
    }

    approved_targets = enforce_runtime_egress_policy(
        config=config,
        exporters={"webhook": webhook, "smtp": smtp},
        resolver=lambda host, port: answers[host],
    )

    assert approved_targets == (
        "webhook:collector.example.net:443",
        "smtp:mail.example.net:465",
    )
    assert isinstance(webhook.transport, PinnedHttpTransport)
    assert smtp.pinned_addresses == ("142.250.74.5",)


def test_pinned_network_backend_connects_only_to_vetted_ip_not_rebound_hostname() -> None:
    connected_hosts: list[str] = []

    class FakeBackend:
        def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
            del port, timeout, local_address, socket_options
            connected_hosts.append(host)
            return object()

    backend = PinnedNetworkBackend(
        pinned_hosts={"collector.example.net": (PUBLIC_V4,)},
        backend=FakeBackend(),
    )

    stream = backend.connect_tcp("collector.example.net", 443)

    assert stream is not None
    assert connected_hosts == [PUBLIC_V4]
    with pytest.raises(RuntimeError, match="nicht freigegeben"):
        backend.connect_tcp("rebound.example.net", 443)


def test_pinned_http_transport_preserves_tls_hostname_while_connecting_to_vetted_ip() -> None:
    connected_hosts: list[str] = []
    tls_hostnames: list[str] = []

    class FakeStream:
        def __init__(self) -> None:
            self.response_pending = True

        def start_tls(self, ssl_context, server_hostname=None, timeout=None):
            del ssl_context, timeout
            tls_hostnames.append(server_hostname)
            return self

        def write(self, buffer, timeout=None):
            del buffer, timeout

        def read(self, max_bytes, timeout=None):
            del max_bytes, timeout
            if not self.response_pending:
                return b""
            self.response_pending = False
            return b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"

        def close(self):
            return None

        def get_extra_info(self, info):
            if info == "is_readable":
                return False
            return None

    class FakeBackend:
        def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
            del port, timeout, local_address, socket_options
            connected_hosts.append(host)
            return FakeStream()

    transport = PinnedHttpTransport(
        host="collector.example.net",
        addresses=(PUBLIC_V4,),
        backend=FakeBackend(),
    )

    with httpx.Client(transport=transport, trust_env=False) as client:
        response = client.post("https://collector.example.net/hook", json={"ok": True})

    assert response.status_code == 204
    assert connected_hosts == [PUBLIC_V4]
    assert tls_hostnames == ["collector.example.net"]


def test_pinned_smtp_ssl_connects_to_vetted_ip_with_original_hostname_for_tls(
    monkeypatch,
) -> None:
    connected_addresses: list[tuple[str, int]] = []
    server_names: list[str] = []

    class FakeRawSocket:
        def close(self) -> None:
            raise AssertionError("successful socket must not be closed before TLS owns it")

    class FakeContext:
        check_hostname = True
        verify_mode = ssl.CERT_REQUIRED

        def wrap_socket(self, raw_socket, *, server_hostname):
            server_names.append(server_hostname)
            return (raw_socket, server_hostname)

    monkeypatch.setattr(
        "honeypot.exporter_runner.smtp_exporter.socket.create_connection",
        lambda address, timeout: connected_addresses.append(address) or FakeRawSocket(),
    )
    client = object.__new__(_PinnedSmtpSslClient)
    client._tls_hostname = "mail.example.net"
    client._pinned_addresses = ("142.250.74.5",)
    client.context = FakeContext()

    wrapped_socket = client._get_socket("mail.example.net", 465, 5.0)

    assert connected_addresses == [("142.250.74.5", 465)]
    assert server_names == ["mail.example.net"]
    assert wrapped_socket[1] == "mail.example.net"
    assert client.context.check_hostname is True
    assert client.context.verify_mode == ssl.CERT_REQUIRED


def test_pinned_smtp_ssl_fails_closed_without_tls_and_never_downgrades(
    monkeypatch,
) -> None:
    closed = False

    class FakeRawSocket:
        def close(self) -> None:
            nonlocal closed
            closed = True

    class RejectingTlsContext:
        def wrap_socket(self, raw_socket, *, server_hostname):
            del raw_socket, server_hostname
            raise ssl.SSLError("plaintext peer")

    monkeypatch.setattr(
        "honeypot.exporter_runner.smtp_exporter.socket.create_connection",
        lambda address, timeout: FakeRawSocket(),
    )
    client = object.__new__(_PinnedSmtpSslClient)
    client._tls_hostname = "mail.example.net"
    client._pinned_addresses = ("142.250.74.5",)
    client.context = RejectingTlsContext()

    with pytest.raises(ssl.SSLError, match="plaintext peer"):
        client._get_socket("mail.example.net", 465, 5.0)

    assert closed is True
