#!/usr/bin/env python3

import socket
import threading
import time
import sys
import os
from concurrent.futures import ThreadPoolExecutor

# Configuration
TARGET_IP = '127.0.0.1'
TARGET_PORT = 9999
SOURCE_IPS = ['127.0.0.2', '127.0.0.3', '127.0.0.4', '127.0.0.5']
CONNECTIONS_PER_IP = 600
CONNECTION_DURATION = 30  # seconds
DATA_SIZE = 1024 * 100  # 100KB per packet
PACKETS_PER_SEC = 50    # Send 50 packets/sec = ~5MB/s per IP

class NetworkAttacker:
    def __init__(self, source_ip, target_ip, target_port):
        self.source_ip = source_ip
        self.target_ip = target_ip
        self.target_port = target_port
        self.success_count = 0
        self.fail_count = 0
        self.bytes_sent = 0
        
    def single_connection(self, conn_id):
        """Create one connection that sends continuous data."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind to specific source IP
            sock.bind((self.source_ip, 0))
            
            # Connect to target
            sock.connect((self.target_ip, self.target_port))
            
            self.success_count += 1
            
            # Send continuous data to generate network traffic
            data = b'X' * DATA_SIZE  # 100KB of data
            start_time = time.time()
            
            while time.time() - start_time < CONNECTION_DURATION:
                try:
                    sent = sock.send(data)
                    self.bytes_sent += sent
                    time.sleep(1.0 / PACKETS_PER_SEC)  # Control packet rate
                except Exception as e:
                    break
            
            sock.close()
            return True
            
        except Exception as e:
            self.fail_count += 1
            if conn_id == 0:
                print(f"  [{self.source_ip}] Connection failed: {e}")
            return False
    
    def launch_attack(self, num_connections):
        """Launch multiple connections from this IP."""
        print(f"[{self.source_ip}] Launching {num_connections} connections with traffic flood...")
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(self.single_connection, i) 
                      for i in range(num_connections)]
            
            # Wait a bit for connections to establish
            time.sleep(2)
            
            # Show progress
            print(f"[{self.source_ip}] {self.success_count} connections active, flooding data...")
            
            # Wait for all to complete
            for future in futures:
                future.result()
        
        mb_sent = self.bytes_sent / (1024 * 1024)
        print(f"[{self.source_ip}] Complete! Success: {self.success_count}, "
              f"Data sent: {mb_sent:.2f} MB")

def check_prerequisites():
    """Check if everything is setup correctly."""
    print("Checking prerequisites...")
    
    # Check if source IPs exist
    missing_ips = []
    for ip in SOURCE_IPS:
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.bind((ip, 0))
            test_sock.close()
        except Exception as e:
            missing_ips.append(ip)
    
    if missing_ips:
        print("\nMissing IP aliases! Run these commands:\n")
        for ip in missing_ips:
            print(f"  sudo ip addr add {ip}/8 dev lo")
        print("\nThen run this script again.\n")
        return False
    
    print("All source IPs configured")
    
    # Check if target port is listening
    try:
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_sock.settimeout(1)
        test_sock.connect((TARGET_IP, TARGET_PORT))
        test_sock.close()
        print(f"✓ Target {TARGET_IP}:{TARGET_PORT} is listening")
    except:
        print(f"\nWarning: {TARGET_IP}:{TARGET_PORT} is not listening")
        print("  Start a listener first:")
        print(f"    ncat -l {TARGET_PORT} --keep-open\n")
        return False
    
    return True

def main():
    print("="*70)
    print("Enhanced DoS Simulator - Network Stress")
    print("="*70)
    print(f"Target: {TARGET_IP}:{TARGET_PORT}")
    print(f"Source IPs: {', '.join(SOURCE_IPS)}")
    print(f"Connections per IP: {CONNECTIONS_PER_IP}")
    print(f"Total connections: {len(SOURCE_IPS) * CONNECTIONS_PER_IP}")
    print(f"Network traffic: ~{DATA_SIZE * PACKETS_PER_SEC / 1024 / 1024:.1f} MB/s per IP")
    print(f"Total traffic: ~{DATA_SIZE * PACKETS_PER_SEC * len(SOURCE_IPS) / 1024 / 1024:.1f} MB/s")
    print(f"Duration: {CONNECTION_DURATION}s")
    print("="*70)
    print()
    
    if not check_prerequisites():
        sys.exit(1)
    
    print("\nStarting attack simulation...\n")
    
    # Create network attackers for each source IP
    attackers = [NetworkAttacker(ip, TARGET_IP, TARGET_PORT) for ip in SOURCE_IPS]
    
    # Launch network attacks in parallel threads
    attack_threads = []
    for attacker in attackers:
        thread = threading.Thread(
            target=attacker.launch_attack, 
            args=(CONNECTIONS_PER_IP,)
        )
        thread.start()
        attack_threads.append(thread)
        time.sleep(0.5)  # Stagger starts slightly
    
    print("\n")
    print("Network flood active")
    print("Check your monitoring script - you should see HIGH_CPU_AND_NET alerts!\n")
    
    # Wait for network attacks to complete
    for thread in attack_threads:
        thread.join()
    
    print("\n" + "="*70)
    print("Attack Simulation Complete!")
    print("="*70)
    
    # Summary
    total_success = sum(a.success_count for a in attackers)
    total_fail = sum(a.fail_count for a in attackers)
    total_bytes = sum(a.bytes_sent for a in attackers)
    total_mb = total_bytes / (1024 * 1024)
    
    print(f"\nResults:")
    print(f"  Total successful connections: {total_success}")
    print(f"  Total failed connections: {total_fail}")
    print(f"  Total data transferred: {total_mb:.2f} MB")
    print(f"  Average throughput: {total_mb / CONNECTION_DURATION:.2f} MB/s")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(0)
