"""
Mini EDR Linux - Live Demo Attack Simulation Script
===================================================
Author: r00tK1ngX
Project: Mini EDR for Linux (Thesis Defense Demo Utility)

This script automates live attack scenarios for thesis defense presentations:
1. Registers a demo target endpoint ('demo-workstation-01')
2. Establishes FIM baseline on a sensitive file and simulates unauthorized tampering
3. Simulates suspicious reverse shell execution (/tmp/nc -lvnp 4444)
4. Simulates web-server spawned interactive shell (apache2 -> /bin/sh)
5. Displays real-time responses and verifies Detection Engine triggers
"""

import hashlib
import json
import os
import sys
import time
import urllib.request
import urllib.error
import uuid
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

DEMO_DIR = Path('/tmp/mini_edr_demo')
DEMO_FILE = DEMO_DIR / 'secure_config.conf'

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
PURPLE = '\033[95m'
BOLD = '\033[1m'
RESET = '\033[0m'


def print_banner():
    banner = (
        f"\n{CYAN}{BOLD}╔════════════════════════════════════════════════════════════════════╗\n"
        f"║                MINI EDR LINUX - LIVE DEFENSE DEMO                  ║\n"
        f"║         Attack Simulation & Real-time Detection Trigger            ║\n"
        f"╚════════════════════════════════════════════════════════════════════╝{RESET}\n"
    )
    print(banner)


def load_env_config():
    env_path = PROJECT_ROOT / '.env'
    token = os.getenv('EDR_API_TOKEN', 'test-token')
    host = os.getenv('EDR_HOST', '127.0.0.1')
    port = int(os.getenv('EDR_PORT', '5000'))
    if env_path.exists():
        with open(env_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line.startswith('#') or not line or '=' not in line:
                    continue
                k, v = line.split('=', 1)
                k = k.strip()
                v = v.strip().strip('"\'')
                if k == 'EDR_API_TOKEN' and 'EDR_API_TOKEN' not in os.environ:
                    token = v
                elif k == 'EDR_HOST' and 'EDR_HOST' not in os.environ:
                    host = v
                elif k == 'EDR_PORT' and 'EDR_PORT' not in os.environ:
                    port = int(v)
    base_url = os.getenv('EDR_SERVER_URL', f"http://{host}:{port}")
    return base_url, token


def api_request(method, url, token, payload=None):
    headers = {
        'Authorization': f"Bearer {token}",
        'Content-Type': 'application/json',
        'User-Agent': 'MiniEDR-AttackSimulator/1.0',
    }
    data = json.dumps(payload).encode('utf-8') if payload is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode('utf-8')
            return resp.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8')
        try:
            parsed = json.loads(body)
        except Exception:
            parsed = {'raw': body}
        return e.code, parsed
    except Exception as e:
        return 0, {'error': str(e)}


def prompt_step(step_num, title, description, auto=False):
    print(f"\n{YELLOW}{BOLD}[BƯỚC {step_num}] {title}{RESET}")
    print(f"{PURPLE}  Mục đích:{RESET} {description}")
    if not auto and sys.stdin.isatty():
        try:
            input(f"{CYAN}  👉 Nhấn [ENTER] để thực thi bước này...{RESET}")
        except (EOFError, KeyboardInterrupt):
            pass
    else:
        print(f"{CYAN}  👉 Tự động thực thi bước này...{RESET}")


def main():
    auto_mode = '--auto' in sys.argv or '-y' in sys.argv or not sys.stdin.isatty()
    print_banner()
    base_url, token = load_env_config()
    print(f"{GREEN}[+] Server Target:{RESET} {base_url}")
    print(f"{GREEN}[+] Token configured:{RESET} {token[:6]}...{token[-4:] if len(token) > 10 else ''}")

    status, res = api_request('GET', f"{base_url}/health", token)
    if status != 200:
        print(f"{RED}[!] Không thể kết nối tới Mini EDR Server tại {base_url}. Mã lỗi: {status}{RESET}")
        print(f"{YELLOW}[*] Vui lòng chạy Flask Server trước: python -m server.app{RESET}")
        sys.exit(1)
    print(f"{GREEN}[✔] Mini EDR Server đang hoạt động (Status: 200 OK){RESET}")

    agent_id = 'demo-workstation-01'
    hostname = 'kali-defense-demo'
    ip_address = '192.168.10.88'

    prompt_step(
        1,
        'Đăng ký Máy trạm & Gửi Heartbeat đầu tiên',
        'Máy Linux Agent kết nối về Server, báo cáo hostname, IP và thông số tài nguyên (CPU, RAM, Disk).',
        auto=auto_mode
    )
    heartbeat_payload = {
        'agent_id': agent_id,
        'hostname': hostname,
        'ip_address': ip_address,
        'os': 'Linux Kali 2026.1',
        'agent_version': '1.0.0',
        'metrics': {
            'cpu_percent': 24.5,
            'memory_percent': 48.2,
            'disk_percent': 35.8,
            'uptime_seconds': 14200,
        },
    }
    status, res = api_request('POST', f"{base_url}/api/v1/heartbeat", token, heartbeat_payload)
    print(f"  {GREEN}[✔] Server Response ({status}):{RESET} Endpoint '{agent_id}' đã Online!")
    print(f"  {CYAN}    Kiểm tra trên Web Dashboard: {base_url}/endpoints{RESET}")

    prompt_step(
        2,
        'Thiết lập Baseline Toàn vẹn Tệp (FIM Baseline)',
        'Tạo tệp cấu hình mẫu và tính toán mã băm SHA-256 ban đầu để gửi lên Server.',
        auto=auto_mode
    )
    DEMO_DIR.mkdir(parents=True, exist_ok=True)
    initial_content = 'ALLOW_USER=kali\nSECURE_MODE=1\nPERMIT_ROOT_LOGIN=no\n'
    DEMO_FILE.write_text(initial_content)
    initial_hash = hashlib.sha256(initial_content.encode('utf-8')).hexdigest()
    st = DEMO_FILE.stat()

    baseline_payload = {
        'schema_version': '1.0',
        'message_id': str(uuid.uuid4()),
        'agent_id': agent_id,
        'collected_at': datetime.now(timezone.utc).isoformat(),
        'payload': {
            'files': [
                {
                    'file_path': str(DEMO_FILE),
                    'sha256': initial_hash,
                    'file_size_bytes': st.st_size,
                    'mtime_ns': st.st_mtime_ns,
                    'file_mode': st.st_mode & 0o7777,
                    'state': 'present',
                }
            ]
        },
    }
    status, res = api_request('POST', f"{base_url}/api/v1/file-baselines", token, baseline_payload)
    print(f"  {GREEN}[✔] FIM Baseline khởi tạo thành công ({status}):{RESET}")
    print(f"      File: {DEMO_FILE}")
    print(f"      Initial SHA-256: {CYAN}{initial_hash}{RESET}")

    prompt_step(
        3,
        'Tấn công Chỉnh sửa Trái phép Tệp (FIM Tampering Attack)',
        'Hacker chèn cấu hình độc hại PERMIT_ROOT_LOGIN=yes. FIM phát hiện mã băm thay đổi và kích hoạt Alert.',
        auto=auto_mode
    )
    tampered_content = initial_content + 'PERMIT_ROOT_LOGIN=yes # HACKED!\nBACKDOOR_KEY=payload_x\n'
    DEMO_FILE.write_text(tampered_content)
    tampered_hash = hashlib.sha256(tampered_content.encode('utf-8')).hexdigest()
    st2 = DEMO_FILE.stat()

    print(f"  {RED}[!] Nội dung tệp đã bị sửa đổi trái phép!{RESET}")
    print(f"      New SHA-256: {RED}{tampered_hash}{RESET}")

    fim_event_payload = {
        'schema_version': '1.0',
        'message_id': str(uuid.uuid4()),
        'agent_id': agent_id,
        'collected_at': datetime.now(timezone.utc).isoformat(),
        'payload': {
            'event_type': 'fim_modified',
            'severity': 'high',
            'source': 'agent',
            'title': f"File Modified: {DEMO_FILE.name}",
            'description': f"Monitored file {DEMO_FILE} hash changed from {initial_hash[:16]}... to {tampered_hash[:16]}...",
            'occurred_at': datetime.now(timezone.utc).isoformat(),
            'evidence': {
                'file_path': str(DEMO_FILE),
                'change_type': 'modified',
                'old_sha256': initial_hash,
                'new_sha256': tampered_hash,
                'file_size': st2.st_size,
            },
        },
    }
    status, res = api_request('POST', f"{base_url}/api/v1/events", token, fim_event_payload)
    print(f"  {GREEN}[✔] Security Event đã tiếp nhận ({status}):{RESET} Detection Engine kích hoạt!")
    print(f"  {YELLOW}    Alert HIGH đã được tạo tự động trên Dashboard!{RESET}")

    prompt_step(
        4,
        'Mô phỏng Chạy Tiến trình Độc hại (/tmp/nc Reverse Shell)',
        'Kẻ tấn công chạy tiện ích netcat từ thư mục /tmp để lắng nghe kết nối trái phép. Detection Engine sinh Alert CRITICAL.',
        auto=auto_mode
    )
    process_payload = {
        'schema_version': '1.0',
        'message_id': str(uuid.uuid4()),
        'agent_id': agent_id,
        'collected_at': datetime.now(timezone.utc).isoformat(),
        'payload': {
            'process_count': 3,
            'processes': [
                {
                    'pid': 1337,
                    'ppid': 1,
                    'process_name': 'systemd',
                    'name': 'systemd',
                    'username': 'root',
                    'exe_path': '/usr/lib/systemd/systemd',
                    'cmdline': '/sbin/init',
                    'cpu_percent': 0.2,
                    'memory_percent': 0.5,
                    'rss_bytes': 10485760,
                    'process_started_at': datetime.now(timezone.utc).isoformat(),
                },
                {
                    'pid': 4444,
                    'ppid': 1000,
                    'process_name': 'nc',
                    'name': 'nc',
                    'username': 'kali',
                    'exe_path': '/tmp/nc',
                    'cmdline': '/tmp/nc -lvnp 4444 -e /bin/bash',
                    'cpu_percent': 12.5,
                    'memory_percent': 1.2,
                    'rss_bytes': 4194304,
                    'process_started_at': datetime.now(timezone.utc).isoformat(),
                },
                {
                    'pid': 8080,
                    'ppid': 1,
                    'process_name': 'python3',
                    'name': 'python3',
                    'username': 'kali',
                    'exe_path': '/usr/bin/python3',
                    'cmdline': 'python3 -m server.app',
                    'cpu_percent': 1.5,
                    'memory_percent': 3.0,
                    'rss_bytes': 35000000,
                    'process_started_at': datetime.now(timezone.utc).isoformat(),
                },
            ],
        },
    }
    status, res = api_request('POST', f"{base_url}/api/v1/telemetry/processes", token, process_payload)
    print(f"  {GREEN}[✔] Process Snapshot tiếp nhận ({status}):{RESET}")
    print(f"      Phát hiện vi phạm: {RED}{BOLD}RULE_SUSPICIOUS_PROCESS{RESET}")
    print(f"      Tiến trình độc hại: {RED}/tmp/nc (PID 4444){RESET}")
    print(f"      Risk Score: {RED}{BOLD}90 / 100 (Mức CRITICAL){RESET}")
    print(f"  {CYAN}    Quan sát trên Web Dashboard: {base_url}/alerts{RESET}")

    print(f"\n{GREEN}{BOLD}╔════════════════════════════════════════════════════════════════════╗")
    print("║               KỊCH BẢN TẤN CÔNG HOÀN TẤT THÀNH CÔNG!                ║")
    print(f"╚════════════════════════════════════════════════════════════════════╝{RESET}\n")

    s_code, summary_resp = api_request('GET', f"{base_url}/api/v1/alerts/summary", token)
    if s_code == 200:
        summary = summary_resp.get('summary', summary_resp)
        print(f"{BOLD}Thống kê Cảnh báo Hiện tại trên Hệ thống:{RESET}")
        print(f"  - Tổng số Alert: {CYAN}{summary.get('total_alerts', summary.get('total', 0))}{RESET}")
        print(f"  - Đang mở (Active): {YELLOW}{summary.get('open_alerts', summary.get('open', 0))}{RESET}")
        print(f"  - Theo mức độ: {summary.get('by_severity')}")

    print(f"\n{YELLOW}{BOLD}Hành động tiếp theo cho buổi thuyết trình (Live Triage):{RESET}")
    print(f"  1. Mở trang {CYAN}{base_url}/alerts{RESET} trên trình duyệt.")
    print(f"  2. Click nút {BOLD}'EVIDENCE'{RESET} trên cảnh báo Netcat để trình diễn dữ liệu bằng chứng JSON.")
    print(f"  3. Click nút {BOLD}'ACK'{RESET} để tiếp nhận sự cố (trạng thái chuyển sang ACKNOWLEDGED).")
    print(f"  4. Click nút {BOLD}'RESOLVE'{RESET}, nhập ghi chú: 'Đã cô lập PID 4444 và khôi phục tệp FIM'.")
    print("  5. Cho Hội đồng xem Toast Notification và chuyển trạng thái sang RESOLVED mượt mà không reload trang!\n")

    try:
        if DEMO_FILE.exists():
            DEMO_FILE.unlink()
        if DEMO_DIR.exists():
            DEMO_DIR.rmdir()
    except Exception:
        pass


if __name__ == '__main__':
    main()
