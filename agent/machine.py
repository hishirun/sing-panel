"""Linux host measurements. Missing values remain null rather than fictional zeroes."""
import os
import platform
import re
import shutil
import socket
import threading
import time
from pathlib import Path

_lock = threading.Lock()
_previous = None


def interfaces(text, device_names, default_names, previous=None, elapsed=0):
    result = []
    previous = previous or {}
    for line in text.splitlines()[2:]:
        if ':' not in line:
            continue
        name, values = line.split(':', 1)
        name, values = name.strip(), values.split()
        if name == 'lo' or len(values) < 9:
            continue
        rx_total, tx_total = int(values[0]), int(values[8])
        virtual = re.match(r'^(?:lo$|docker|veth|br-|virbr|tun|tap|wg|tailscale|cni|flannel|kube|zt)', name)
        billable = not virtual and (name in device_names or name in default_names)
        old = previous.get(name)
        rx = max(0, (rx_total - old[0]) / elapsed) if old and elapsed > 0 else None
        tx = max(0, (tx_total - old[1]) / elapsed) if old and elapsed > 0 else None
        result.append(dict(name=name, rx_total=rx_total, tx_total=tx_total, rx=rx, tx=tx, billable=bool(billable)))
    return result


def snapshot(directory):
    global _previous
    now = time.monotonic()
    cpu = memory = uptime = rx = tx = received = sent = None
    network = []
    boot_id = ''
    try:
        values = [int(v) for v in Path('/proc/stat').read_text().splitlines()[0].split()[1:9]]
        total, idle = sum(values), values[3] + values[4]
        boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        device_names = {p.name for p in Path('/sys/class/net').iterdir() if (p / 'device').exists()}
        default_names = {line.split()[0] for line in Path('/proc/net/route').read_text().splitlines()[1:]
                         if len(line.split()) > 1 and line.split()[1] == '00000000'}
        try:
            for line in Path('/proc/net/ipv6_route').read_text().splitlines():
                columns = line.split()
                if len(columns) >= 10 and columns[0] == '0' * 32 and columns[1] == '00':
                    default_names.add(columns[-1])
        except FileNotFoundError:
            pass
        with _lock:
            previous_interfaces, elapsed = {}, 0
            if _previous:
                stamp, old_total, old_idle, previous_interfaces, previous_boot = _previous
                if previous_boot != boot_id:
                    previous_interfaces = {}
                elapsed = now - stamp
                if total > old_total:
                    cpu = round(100 * (1 - (idle - old_idle) / (total - old_total)), 1)
            network = interfaces(Path('/proc/net/dev').read_text(), device_names, default_names, previous_interfaces, elapsed)
            billable = [item for item in network if item['billable']]
            received, sent = sum(item['rx_total'] for item in billable), sum(item['tx_total'] for item in billable)
            if billable and all(item['rx'] is not None for item in billable):
                rx, tx = sum(item['rx'] for item in billable), sum(item['tx'] for item in billable)
            _previous = now, total, idle, {item['name']: (item['rx_total'], item['tx_total']) for item in network}, boot_id
        mem = {line.split(':')[0]: int(line.split()[1]) * 1024 for line in Path('/proc/meminfo').read_text().splitlines()}
        memory = {'total': mem['MemTotal'], 'used': mem['MemTotal'] - mem['MemAvailable'],
                  'percent': round(100 * (1 - mem['MemAvailable'] / mem['MemTotal']), 1)}
        uptime = int(float(Path('/proc/uptime').read_text().split()[0]))
    except (OSError, ValueError, KeyError, IndexError):
        pass
    disk = shutil.disk_usage(directory)
    return dict(hostname=socket.gethostname()[:128], os=platform.system(), arch=platform.machine(),
                boot_id=boot_id, sampled_at=time.time(), interfaces=network,
                rx_total=received, tx_total=sent, cpu=cpu, memory=memory, uptime=uptime,
                rx=rx, tx=tx, cores=os.cpu_count(), load=[round(v, 2) for v in os.getloadavg()],
                disk={'used': disk.used, 'total': disk.total, 'percent': round(disk.used / disk.total * 100, 1)})
