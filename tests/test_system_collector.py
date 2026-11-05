from unittest.mock import MagicMock, patch
import pytest

from agent.system_collector import (
    SystemCollector,
    collect_metrics,
    collect_system_info,
    get_cpu_percent,
    get_disk_percent,
    get_hostname,
    get_ip_address,
    get_memory_percent,
    get_os_info,
    get_uptime_seconds,
)


def test_get_hostname_real():
    hostname = get_hostname()
    assert isinstance(hostname, str)
    assert len(hostname) > 0


def test_get_hostname_fallback():
    with patch("socket.gethostname", side_effect=OSError("network down")):
        with patch("platform.node", return_value="fallback-host"):
            assert get_hostname() == "fallback-host"

    with patch("socket.gethostname", side_effect=OSError("network down")):
        with patch("platform.node", return_value=""):
            with patch("pathlib.Path.is_file", return_value=False):
                assert get_hostname() == "unknown-host"


def test_get_ip_address_real():
    ip = get_ip_address()
    assert ip is None or isinstance(ip, str)
    if ip is not None:
        assert not ip.startswith("127.")


def test_get_ip_address_mocked_udp():
    mock_sock = MagicMock()
    mock_sock.getsockname.return_value = ("192.168.1.100", 54321)
    with patch("socket.socket") as mock_socket_cls:
        mock_socket_cls.return_value.__enter__.return_value = mock_sock
        ip = get_ip_address()
        assert ip == "192.168.1.100"


def test_get_ip_address_fallback_interfaces():
    with patch("socket.socket", side_effect=OSError("no route")):
        mock_addr = MagicMock()
        mock_addr.family = 2  # socket.AF_INET
        mock_addr.address = "10.0.0.42"
        with patch("psutil.net_if_addrs", return_value={"eth0": [mock_addr]}):
            ip = get_ip_address()
            assert ip == "10.0.0.42"


def test_get_os_info_real():
    os_name = get_os_info()
    assert isinstance(os_name, str)
    assert len(os_name) > 0


def test_get_os_info_fallback():
    with patch("platform.freedesktop_os_release", side_effect=AttributeError("no freedesktop")):
        with patch("pathlib.Path.is_file", return_value=False):
            with patch("platform.system", return_value="Linux"):
                with patch("platform.release", return_value="6.6.0-kali"):
                    assert get_os_info() == "Linux 6.6.0-kali"


def test_get_cpu_percent_real():
    cpu = get_cpu_percent(interval=0.01)
    assert isinstance(cpu, float)
    assert 0.0 <= cpu <= 100.0


def test_get_cpu_percent_clamping_and_error():
    with patch("psutil.cpu_percent", return_value=125.4):
        assert get_cpu_percent() == 100.0

    with patch("psutil.cpu_percent", return_value=-5.0):
        assert get_cpu_percent() == 0.0

    with patch("psutil.cpu_percent", side_effect=Exception("cpu error")):
        assert get_cpu_percent() == 0.0


def test_get_memory_percent_real():
    mem = get_memory_percent()
    assert isinstance(mem, float)
    assert 0.0 <= mem <= 100.0


def test_get_disk_percent_real():
    disk = get_disk_percent("/")
    assert isinstance(disk, float)
    assert 0.0 <= disk <= 100.0


def test_get_disk_percent_permission_error_handling():
    with patch("psutil.disk_usage", side_effect=PermissionError("Permission denied")):
        assert get_disk_percent("/root/secret") == 0.0


def test_get_uptime_seconds_real():
    uptime = get_uptime_seconds()
    assert isinstance(uptime, float)
    assert uptime >= 0.0


def test_collect_metrics_structure():
    metrics = collect_metrics(cpu_interval=0.01)
    assert set(metrics.keys()) == {
        "cpu_percent",
        "memory_percent",
        "disk_percent",
        "uptime_seconds",
    }
    for k, v in metrics.items():
        assert isinstance(v, (int, float))
        assert v >= 0.0
        if k != "uptime_seconds":
            assert v <= 100.0


def test_collect_system_info_heartbeat_payload():
    info = collect_system_info(agent_id="lab-agent-01", agent_version="1.2.3", cpu_interval=0.01)
    assert info["agent_id"] == "lab-agent-01"
    assert info["agent_version"] == "1.2.3"
    assert isinstance(info["hostname"], str)
    assert info["ip_address"] is None or isinstance(info["ip_address"], str)
    assert isinstance(info["os"], str)
    assert "metrics" in info
    assert set(info["metrics"].keys()) == {
        "cpu_percent",
        "memory_percent",
        "disk_percent",
        "uptime_seconds",
    }


def test_system_collector_class():
    collector = SystemCollector(
        agent_id="agent-class-test",
        agent_version="0.5.0",
        disk_path="/",
        cpu_interval=0.01,
    )
    assert collector.get_hostname() == get_hostname()
    assert collector.get_os_info() == get_os_info()
    assert 0.0 <= collector.get_cpu_percent() <= 100.0
    assert 0.0 <= collector.get_memory_percent() <= 100.0
    assert 0.0 <= collector.get_disk_percent() <= 100.0
    assert collector.get_uptime_seconds() >= 0.0

    info = collector.collect_system_info()
    assert info["agent_id"] == "agent-class-test"
    assert info["agent_version"] == "0.5.0"
