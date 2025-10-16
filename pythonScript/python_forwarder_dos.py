#!/usr/bin/env python3

import time
import requests
import json
import psutil
import socket
from collections import deque, defaultdict

LOKI_URL = "http://localhost:3100/loki/api/v1/push"

# --- Configuration ---
SAMPLE_INTERVAL = 1          # seconds between samples
WINDOW_SECONDS = 10          # rolling window size for network rate checks
THRESH_NET_BYTES_PER_SEC = 100_000_000   # 100 MB/s (example threshold)
THRESH_CPU_PERCENT = 85      # 85% CPU considered suspicious
ALERT_CONSECUTIVE = 2        # how many consecutive samples before alert
ALERT_COOLDOWN = 1          # seconds before new alert allowed
JOB_LABEL = "python-forwarder"
ENV_LABEL = "lab"

# Track connections per IP
connection_tracker = defaultdict(int)
ip_traffic_tracker = defaultdict(lambda: {'bytes': 0, 'last_seen': 0})

# --- helper: push logs to Loki ---
def push_to_loki(messages):
    """
    messages: list of tuples (timestamp_epoch_ns, text_message, level)
    Sends all logs in one stream.
    """
    if not messages:
        return

    stream = {"job": JOB_LABEL, "env": ENV_LABEL}
    values = [[str(ts), text] for ts, text, _level in messages]
    payload = {"streams": [{"stream": stream, "values": values}]}

    try:
        resp = requests.post(LOKI_URL, json=payload, timeout=5)
        if resp.status_code not in (200, 204):
            print(f"[WARN] Loki push returned {resp.status_code}: {resp.text}")
    except Exception as e:
        print(f"[ERROR] Failed to push to Loki: {e}")


# --- helper functions ---
def now_ns():
    return int(time.time() * 1e9)

def get_host_ip():
    """Get the actual host IP address."""
    try:
        hostname = socket.gethostname()
        host_ip = socket.gethostbyname(hostname)
        return host_ip
    except Exception:
        return "127.0.0.1"

def get_active_source_ips():
    """
    Get list of unique source IPs from active incoming connections.
    Returns list of (ip, connection_count) tuples.
    """
    try:
        connections = psutil.net_connections(kind='inet')
        ip_counts = defaultdict(int)
        host_ip = get_host_ip()
        
        for conn in connections:
            # Only count ESTABLISHED incoming connections
            if conn.status == 'ESTABLISHED' and conn.raddr:
                remote_ip = conn.raddr.ip
                # Filter out localhost and our own IP
                if remote_ip not in ('::1',):
                    ip_counts[remote_ip] += 1
        
        return [(ip, count) for ip, count in ip_counts.items()]
    except Exception as e:
        print(f"[WARN] Could not get connections: {e}")
        return []

def get_top_traffic_ips(top_n=5):
    """Get the top N IPs by recent traffic activity."""
    now = time.time()
    # Filter IPs seen in last 10 seconds
    recent_ips = {ip: data for ip, data in ip_traffic_tracker.items() 
                  if now - data['last_seen'] < 10}
    
    if not recent_ips:
        return []
    
    # Sort by bytes, return top N
    sorted_ips = sorted(recent_ips.items(), key=lambda x: x[1]['bytes'], reverse=True)
    return [ip for ip, _ in sorted_ips[:top_n]]

def metric_message(cpu_pct, net_bps, src_ip, conn_count=1):
    ts = time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime())
    return f"METRIC ts={ts} src={src_ip} cpu={cpu_pct:.1f} net_bps={int(net_bps)} connections={conn_count}"

def alert_message(reason, cpu_pct=None, net_bps=None, src_ip=None, conn_count=None):
    ts = time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime())
    parts = [f"ALERT ts={ts}", f"reason={reason}"]
    if src_ip:
        parts.append(f"src={src_ip}")
    if cpu_pct is not None:
        parts.append(f"cpu={cpu_pct:.1f}")
    if net_bps is not None:
        parts.append(f"net_bps={int(net_bps)}")
    if conn_count is not None:
        parts.append(f"connections={conn_count}")
    return " ".join(parts)

def event_message(event_type, description):
    ts = time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime())
    return f"EVENT ts={ts} type={event_type} desc={description}"


# --- main loop ---
def main():
    net_snaps = deque(maxlen=WINDOW_SECONDS)
    last_alert_time = 0
    last_event_time = 0
    consecutive_alert_windows = 0

    host_ip = get_host_ip()
    print(f"Monitoring host IP: {host_ip}")
    print("Starting forwarder – Smart IP attribution enabled...")
    print("Note: Run with sudo/admin privileges for full connection tracking\n")

    net0 = psutil.net_io_counters()
    prev_bytes = net0.bytes_sent + net0.bytes_recv
    prev_time = time.time()

    while True:
        try:
            time.sleep(SAMPLE_INTERVAL)
            now = time.time()

            # CPU + network
            cpu_pct = psutil.cpu_percent(interval=None)
            net = psutil.net_io_counters()
            total_bytes = net.bytes_sent + net.bytes_recv
            dt = now - prev_time if prev_time else 1.0
            bytes_delta = max(0, total_bytes - prev_bytes)
            bps = bytes_delta / dt if dt > 0 else 0.0

            # Get active source IPs
            source_ips = get_active_source_ips()
            
            # Update traffic tracker
            for src_ip, _ in source_ips:
                ip_traffic_tracker[src_ip]['bytes'] += bytes_delta / max(1, len(source_ips))
                ip_traffic_tracker[src_ip]['last_seen'] = now

            # Push metrics for each active connection
            logs_to_push = []
            if source_ips:
                for src_ip, conn_count in source_ips:
                    metric_log = metric_message(cpu_pct, bps, src_ip, conn_count)
                    logs_to_push.append((now_ns(), metric_log, "metric"))
                    connection_tracker[src_ip] = conn_count
            else:
                # No external connections - log from host
                metric_log = metric_message(cpu_pct, bps, host_ip, 0)
                logs_to_push.append((now_ns(), metric_log, "metric"))
            
            push_to_loki(logs_to_push)

            # Print active connections (only if there are external ones)
            if source_ips:
                print(f"[ACTIVE] {len(source_ips)} source IP(s): {', '.join([f'{ip}({cnt})' for ip, cnt in source_ips])}")

            net_snaps.append(bps)
            prev_bytes = total_bytes
            prev_time = now
            avg_bps = sum(net_snaps) / len(net_snaps) if net_snaps else 0.0

            # --- Detection logic ---
            net_trigger = avg_bps >= THRESH_NET_BYTES_PER_SEC
            cpu_trigger = cpu_pct >= THRESH_CPU_PERCENT

            if net_trigger or cpu_trigger:
                consecutive_alert_windows += 1
            else:
                consecutive_alert_windows = 0

            # --- SMART Alert generation ---
            if consecutive_alert_windows >= ALERT_CONSECUTIVE:
                now_ts = time.time()
                if now_ts - last_alert_time >= ALERT_COOLDOWN:
                    alert_logs = []
                    
                    # CPU ALERT - attribute to localhost (CPU is local resource)
                    if cpu_trigger and not net_trigger:
                        alert_log = alert_message(
                            "HIGH_CPU", 
                            cpu_pct=cpu_pct, 
                            net_bps=avg_bps, 
                            src_ip=host_ip,
                            conn_count=0
                        )
                        alert_logs.append((now_ns(), alert_log, "alert"))
                        print(f"[ALERT] {alert_log}")
                    
                    # NETWORK ALERT - attribute to top traffic sources
                    elif net_trigger and not cpu_trigger:
                        top_ips = get_top_traffic_ips(top_n=3)
                        if not top_ips:
                            top_ips = [host_ip]  # Fallback to host
                        
                        for src_ip in top_ips:
                            conn_count = connection_tracker.get(src_ip, 0)
                            alert_log = alert_message(
                                "NET_SPIKE", 
                                cpu_pct=cpu_pct, 
                                net_bps=avg_bps, 
                                src_ip=src_ip,
                                conn_count=conn_count
                            )
                            alert_logs.append((now_ns(), alert_log, "alert"))
                            print(f"[ALERT] {alert_log}")
                    
                    # BOTH - could be DoS, log top offenders
                    else:
                        top_ips = get_top_traffic_ips(top_n=3)
                        if not top_ips:
                            top_ips = [host_ip]
                        
                        for src_ip in top_ips:
                            conn_count = connection_tracker.get(src_ip, 0)
                            alert_log = alert_message(
                                "HIGH_CPU_AND_NET", 
                                cpu_pct=cpu_pct, 
                                net_bps=avg_bps, 
                                src_ip=src_ip,
                                conn_count=conn_count
                            )
                            alert_logs.append((now_ns(), alert_log, "alert"))
                            print(f"[ALERT] {alert_log}")
                    
                    push_to_loki(alert_logs)
                    last_alert_time = now_ts
                    consecutive_alert_windows = 0
                    
        except KeyboardInterrupt:
            print("\nStopping forwarder.")
            print(f"\nConnection summary:")
            for ip, count in sorted(connection_tracker.items(), key=lambda x: x[1], reverse=True):
                print(f"  {ip}: {count} connections")
            break
        except Exception as e:
            print(f"[ERROR] main loop exception: {e}")
            time.sleep(1)


if __name__ == "__main__":
    main()
