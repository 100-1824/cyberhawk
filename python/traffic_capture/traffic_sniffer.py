from scapy.all import sniff, IP, TCP, UDP, conf, get_if_list
import json
import time
from threading import Thread, Lock
import os
import sys
import numpy as np
from datetime import datetime

OUTPUT_FILE = r"E:/xampp/htdocs/cyberhawk/assets/data/traffic_log.json"

# Flow tracking dictionaries
flow_table = {}
flow_lock = Lock()
packet_count = 0

# Flow timeout (seconds) - flows inactive for this duration are considered complete
FLOW_TIMEOUT = 120  # 2 minutes
MAX_FLOWS = 1000  # Maximum flows to track simultaneously


class FlowStatistics:
    """Track statistics for network flows"""
    
    def __init__(self, first_packet, src_ip, dst_ip, src_port, dst_port, protocol):
        # Flow identifiers
        self.flow_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        
        # Timestamps
        self.flow_start_time = first_packet['timestamp']
        self.flow_last_seen = first_packet['timestamp']
        
        # Packet counts
        self.total_fwd_packets = 0
        self.total_bwd_packets = 0
        
        # Packet lengths
        self.fwd_packet_lengths = []
        self.bwd_packet_lengths = []
        
        # Inter-arrival times
        self.fwd_iat = []  # Forward inter-arrival times
        self.bwd_iat = []  # Backward inter-arrival times
        self.flow_iat = []  # Overall flow inter-arrival times
        
        # Flags tracking (TCP)
        self.fwd_psh_flags = 0
        self.bwd_psh_flags = 0
        self.fwd_urg_flags = 0
        self.bwd_urg_flags = 0
        self.fin_flag_count = 0
        self.syn_flag_count = 0
        self.rst_flag_count = 0
        self.ack_flag_count = 0
        self.psh_flag_count = 0
        self.urg_flag_count = 0
        self.ece_flag_count = 0
        self.cwr_flag_count = 0
        
        # Header lengths
        self.fwd_header_lengths = []
        self.bwd_header_lengths = []
        
        # Timing
        self.last_fwd_packet_time = None
        self.last_bwd_packet_time = None
        self.last_packet_time = first_packet['timestamp']
        
    def update_flow(self, packet_info, is_forward):
        """Update flow statistics with new packet"""
        timestamp = packet_info['timestamp']
        packet_len = packet_info['length']
        
        # Update last seen
        self.flow_last_seen = timestamp
        
        # Calculate inter-arrival time for overall flow
        if self.last_packet_time:
            iat = timestamp - self.last_packet_time
            self.flow_iat.append(iat)
        
        self.last_packet_time = timestamp
        
        if is_forward:
            self.total_fwd_packets += 1
            self.fwd_packet_lengths.append(packet_len)
            
            # Forward inter-arrival time
            if self.last_fwd_packet_time:
                fwd_iat = timestamp - self.last_fwd_packet_time
                self.fwd_iat.append(fwd_iat)
            self.last_fwd_packet_time = timestamp
            
            # Header length
            if 'header_len' in packet_info:
                self.fwd_header_lengths.append(packet_info['header_len'])
                
            # TCP Flags for forward packets
            if packet_info.get('tcp_flags'):
                if 'P' in packet_info['tcp_flags']:
                    self.fwd_psh_flags += 1
                if 'U' in packet_info['tcp_flags']:
                    self.fwd_urg_flags += 1
                    
        else:  # Backward packet
            self.total_bwd_packets += 1
            self.bwd_packet_lengths.append(packet_len)
            
            # Backward inter-arrival time
            if self.last_bwd_packet_time:
                bwd_iat = timestamp - self.last_bwd_packet_time
                self.bwd_iat.append(bwd_iat)
            self.last_bwd_packet_time = timestamp
            
            # Header length
            if 'header_len' in packet_info:
                self.bwd_header_lengths.append(packet_info['header_len'])
                
            # TCP Flags for backward packets
            if packet_info.get('tcp_flags'):
                if 'P' in packet_info['tcp_flags']:
                    self.bwd_psh_flags += 1
                if 'U' in packet_info['tcp_flags']:
                    self.bwd_urg_flags += 1
        
        # Update TCP flags (regardless of direction)
        if packet_info.get('tcp_flags'):
            flags = packet_info['tcp_flags']
            if 'F' in flags:
                self.fin_flag_count += 1
            if 'S' in flags:
                self.syn_flag_count += 1
            if 'R' in flags:
                self.rst_flag_count += 1
            if 'A' in flags:
                self.ack_flag_count += 1
            if 'P' in flags:
                self.psh_flag_count += 1
            if 'U' in flags:
                self.urg_flag_count += 1
            if 'E' in flags:
                self.ece_flag_count += 1
            if 'C' in flags:
                self.cwr_flag_count += 1
    
    def calculate_statistics(self):
        """Calculate ONLY REAL flow statistics from captured data"""
        flow_duration = self.flow_last_seen - self.flow_start_time
        
        # Total packets and bytes - REAL
        total_packets = self.total_fwd_packets + self.total_bwd_packets
        total_fwd_bytes = sum(self.fwd_packet_lengths) if self.fwd_packet_lengths else 0
        total_bwd_bytes = sum(self.bwd_packet_lengths) if self.bwd_packet_lengths else 0
        
        # Packet length statistics - ALL REAL
        all_packet_lengths = self.fwd_packet_lengths + self.bwd_packet_lengths
        
        # Forward packet statistics - REAL
        fwd_pkt_len_max = max(self.fwd_packet_lengths) if self.fwd_packet_lengths else 0
        fwd_pkt_len_min = min(self.fwd_packet_lengths) if self.fwd_packet_lengths else 0
        fwd_pkt_len_mean = np.mean(self.fwd_packet_lengths) if self.fwd_packet_lengths else 0
        fwd_pkt_len_std = np.std(self.fwd_packet_lengths) if len(self.fwd_packet_lengths) > 1 else 0
        
        # Backward packet statistics - REAL
        bwd_pkt_len_max = max(self.bwd_packet_lengths) if self.bwd_packet_lengths else 0
        bwd_pkt_len_min = min(self.bwd_packet_lengths) if self.bwd_packet_lengths else 0
        bwd_pkt_len_mean = np.mean(self.bwd_packet_lengths) if self.bwd_packet_lengths else 0
        bwd_pkt_len_std = np.std(self.bwd_packet_lengths) if len(self.bwd_packet_lengths) > 1 else 0
        
        # Flow bytes/packets per second - REAL CALCULATIONS
        if flow_duration > 0:
            flow_bytes_per_sec = (total_fwd_bytes + total_bwd_bytes) / flow_duration
            flow_pkts_per_sec = total_packets / flow_duration
        else:
            flow_bytes_per_sec = 0
            flow_pkts_per_sec = 0
        
        # Inter-arrival time statistics - ALL REAL
        flow_iat_mean = np.mean(self.flow_iat) if self.flow_iat else 0
        flow_iat_std = np.std(self.flow_iat) if len(self.flow_iat) > 1 else 0
        flow_iat_max = max(self.flow_iat) if self.flow_iat else 0
        flow_iat_min = min(self.flow_iat) if self.flow_iat else 0
        
        fwd_iat_mean = np.mean(self.fwd_iat) if self.fwd_iat else 0
        fwd_iat_std = np.std(self.fwd_iat) if len(self.fwd_iat) > 1 else 0
        fwd_iat_max = max(self.fwd_iat) if self.fwd_iat else 0
        fwd_iat_min = min(self.fwd_iat) if self.fwd_iat else 0
        
        bwd_iat_mean = np.mean(self.bwd_iat) if self.bwd_iat else 0
        bwd_iat_std = np.std(self.bwd_iat) if len(self.bwd_iat) > 1 else 0
        bwd_iat_max = max(self.bwd_iat) if self.bwd_iat else 0
        bwd_iat_min = min(self.bwd_iat) if self.bwd_iat else 0
        
        # Header length statistics - REAL
        fwd_header_len = np.mean(self.fwd_header_lengths) if self.fwd_header_lengths else 0
        bwd_header_len = np.mean(self.bwd_header_lengths) if self.bwd_header_lengths else 0
        
        # Overall packet statistics - REAL
        pkt_len_min = min(all_packet_lengths) if all_packet_lengths else 0
        pkt_len_max = max(all_packet_lengths) if all_packet_lengths else 0
        pkt_len_mean = np.mean(all_packet_lengths) if all_packet_lengths else 0
        pkt_len_std = np.std(all_packet_lengths) if len(all_packet_lengths) > 1 else 0
        pkt_len_var = np.var(all_packet_lengths) if all_packet_lengths else 0
        
        # Packet size ratios - REAL CALCULATION
        if self.total_bwd_packets > 0:
            down_up_ratio = self.total_fwd_packets / self.total_bwd_packets
        else:
            down_up_ratio = self.total_fwd_packets if self.total_fwd_packets > 0 else 0
        
        # Average packet size - REAL
        avg_packet_size = np.mean(all_packet_lengths) if all_packet_lengths else 0
        
        # Segment size averages - REAL
        fwd_seg_size_avg = np.mean(self.fwd_packet_lengths) if self.fwd_packet_lengths else 0
        bwd_seg_size_avg = np.mean(self.bwd_packet_lengths) if self.bwd_packet_lengths else 0
        
        # Build feature dictionary with ONLY REAL DATA
        features = {
            # Flow identifiers - ALL REAL
            "Flow ID": self.flow_id,
            "Src IP": self.src_ip,
            "Src Port": self.src_port,
            "Dst IP": self.dst_ip,
            "Dst Port": self.dst_port,
            "Protocol": self.protocol,
            "Timestamp": datetime.fromtimestamp(self.flow_start_time).isoformat(),
            
            # Flow features - ALL REAL
            "Flow Duration": flow_duration * 1000000,  # Convert to microseconds
            "Total Fwd Packets": self.total_fwd_packets,
            "Total Backward Packets": self.total_bwd_packets,
            "Total Length of Fwd Packets": total_fwd_bytes,
            "Total Length of Bwd Packets": total_bwd_bytes,
            
            # Packet length statistics - ALL REAL
            "Fwd Packet Length Max": fwd_pkt_len_max,
            "Fwd Packet Length Min": fwd_pkt_len_min,
            "Fwd Packet Length Mean": fwd_pkt_len_mean,
            "Fwd Packet Length Std": fwd_pkt_len_std,
            
            "Bwd Packet Length Max": bwd_pkt_len_max,
            "Bwd Packet Length Min": bwd_pkt_len_min,
            "Bwd Packet Length Mean": bwd_pkt_len_mean,
            "Bwd Packet Length Std": bwd_pkt_len_std,
            
            # Flow rates - REAL CALCULATIONS
            "Flow Bytes/s": flow_bytes_per_sec,
            "Flow Packets/s": flow_pkts_per_sec,
            
            # Inter-arrival times - ALL REAL
            "Flow IAT Mean": flow_iat_mean,
            "Flow IAT Std": flow_iat_std,
            "Flow IAT Max": flow_iat_max,
            "Flow IAT Min": flow_iat_min,
            
            "Fwd IAT Mean": fwd_iat_mean,
            "Fwd IAT Std": fwd_iat_std,
            "Fwd IAT Max": fwd_iat_max,
            "Fwd IAT Min": fwd_iat_min,
            
            "Bwd IAT Mean": bwd_iat_mean,
            "Bwd IAT Std": bwd_iat_std,
            "Bwd IAT Max": bwd_iat_max,
            "Bwd IAT Min": bwd_iat_min,
            
            # TCP Flags - ALL REAL COUNTS
            "FIN Flag Count": self.fin_flag_count,
            "SYN Flag Count": self.syn_flag_count,
            "RST Flag Count": self.rst_flag_count,
            "PSH Flag Count": self.psh_flag_count,
            "ACK Flag Count": self.ack_flag_count,
            "URG Flag Count": self.urg_flag_count,
            "ECE Flag Count": self.ece_flag_count,
            "CWR Flag Count": self.cwr_flag_count,
            
            "Fwd PSH Flags": self.fwd_psh_flags,
            "Bwd PSH Flags": self.bwd_psh_flags,
            "Fwd URG Flags": self.fwd_urg_flags,
            "Bwd URG Flags": self.bwd_urg_flags,
            
            # Header lengths - REAL
            "Fwd Header Length": fwd_header_len,
            "Bwd Header Length": bwd_header_len,
            
            # Additional statistics - ALL REAL
            "Packet Length Min": pkt_len_min,
            "Packet Length Max": pkt_len_max,
            "Packet Length Mean": pkt_len_mean,
            "Packet Length Std": pkt_len_std,
            "Packet Length Variance": pkt_len_var,
            
            "Down/Up Ratio": down_up_ratio,
            "Average Packet Size": avg_packet_size,
            "Avg Fwd Segment Size": fwd_seg_size_avg,
            "Avg Bwd Segment Size": bwd_seg_size_avg
            
            # REMOVED: "Label" - This was synthetic/placeholder
            # Label should be predicted by your ML model, not hardcoded
        }
        
        return features


def get_active_interface():
    """Get the best available network interface using Scapy"""
    try:
        print("\n[*] Detecting network interfaces...")
        
        if hasattr(conf, 'ifaces'):
            wifi_interfaces = []
            ethernet_interfaces = []
            other_interfaces = []
            
            for name, iface in conf.ifaces.items():
                try:
                    desc = getattr(iface, 'description', '').lower()
                    ip = getattr(iface, 'ip', None)
                    
                    if not ip or ip == '0.0.0.0' or ip.startswith('169.254'):
                        continue
                    
                    if any(x in desc for x in ['loopback', 'vmware', 'hyper-v', 'virtual', 'miniport']):
                        continue
                    
                    print(f"    ✓ {name}: {iface.description} (IP: {ip})")
                    
                    if 'wi-fi' in desc or 'wireless' in desc or '802.11' in desc:
                        wifi_interfaces.append((name, iface, ip))
                    elif 'ethernet' in desc:
                        ethernet_interfaces.append((name, iface, ip))
                    else:
                        other_interfaces.append((name, iface, ip))
                        
                except Exception as e:
                    continue
            
            selected = None
            if wifi_interfaces:
                selected = wifi_interfaces[0]
                print(f"\n[✓] Selected Wi-Fi interface: {selected[0]}")
            elif ethernet_interfaces:
                selected = ethernet_interfaces[0]
                print(f"\n[✓] Selected Ethernet interface: {selected[0]}")
            elif other_interfaces:
                selected = other_interfaces[0]
                print(f"\n[✓] Selected interface: {selected[0]}")
            
            if selected:
                print(f"    Description: {selected[1].description}")
                print(f"    IP Address: {selected[2]}")
                return selected[0]
        
        print(f"\n[!] Could not detect suitable interface, using default")
        return conf.iface
        
    except Exception as e:
        print(f"[!] Error detecting interfaces: {e}")
        return conf.iface


def packet_callback(pkt):
    """Process each captured packet and update flow statistics"""
    global packet_count
    
    try:
        packet_count += 1
        
        if not pkt.haslayer(IP):
            return

        # Extract packet information - ALL REAL FROM PACKET
        timestamp = float(pkt.time)
        ip_layer = pkt[IP]
        ip_src = ip_layer.src
        ip_dst = ip_layer.dst
        ip_proto = ip_layer.proto
        packet_len = len(pkt)
        
        # Default values
        src_port = dst_port = 0
        tcp_flags = None
        header_len = ip_layer.ihl * 4  # IP header length - REAL
        
        # Extract TCP/UDP info - REAL FROM PACKET
        if pkt.haslayer(TCP):
            tcp_layer = pkt[TCP]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            tcp_flags = tcp_layer.flags.flagrepr() if hasattr(tcp_layer.flags, 'flagrepr') else str(tcp_layer.flags)
            header_len += tcp_layer.dataofs * 4  # Add TCP header length - REAL
            
        elif pkt.haslayer(UDP):
            udp_layer = pkt[UDP]
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            header_len += 8  # UDP header is always 8 bytes - REAL
        
        # Create packet info dictionary
        packet_info = {
            'timestamp': timestamp,
            'length': packet_len,
            'tcp_flags': tcp_flags,
            'header_len': header_len
        }
        
        # Generate bidirectional flow key
        if (ip_src < ip_dst) or (ip_src == ip_dst and src_port < dst_port):
            flow_key = f"{ip_src}:{src_port}-{ip_dst}:{dst_port}-{ip_proto}"
            is_fwd = True
        else:
            flow_key = f"{ip_dst}:{dst_port}-{ip_src}:{src_port}-{ip_proto}"
            is_fwd = False
        
        # Update flow statistics
        with flow_lock:
            current_time = time.time()
            
            # Clean up old flows
            expired_flows = []
            for fkey, flow in flow_table.items():
                if current_time - flow.flow_last_seen > FLOW_TIMEOUT:
                    expired_flows.append(fkey)
            
            # Remove expired flows and save their statistics
            for fkey in expired_flows:
                save_completed_flow(flow_table[fkey])
                del flow_table[fkey]
            
            # Create new flow or update existing
            if flow_key not in flow_table:
                # Limit maximum flows
                if len(flow_table) >= MAX_FLOWS:
                    # Remove oldest flow
                    oldest_key = min(flow_table.keys(), 
                                   key=lambda k: flow_table[k].flow_last_seen)
                    save_completed_flow(flow_table[oldest_key])
                    del flow_table[oldest_key]
                
                # Create new flow
                if is_fwd:
                    flow_table[flow_key] = FlowStatistics(
                        packet_info, ip_src, ip_dst, src_port, dst_port, ip_proto
                    )
                else:
                    flow_table[flow_key] = FlowStatistics(
                        packet_info, ip_dst, ip_src, dst_port, src_port, ip_proto
                    )
            
            # Update flow with packet
            flow_table[flow_key].update_flow(packet_info, is_fwd)
            
            # Print packet info
            direction = "→" if is_fwd else "←"
            print(f"[+] #{packet_count}: {ip_src}:{src_port} {direction} {ip_dst}:{dst_port} | "
                  f"Proto: {ip_proto} | {packet_len}B | Flow: {flow_table[flow_key].total_fwd_packets}f/{flow_table[flow_key].total_bwd_packets}b")

    except Exception as e:
        print(f"[!] Error parsing packet #{packet_count}: {e}")
        import traceback
        traceback.print_exc()


completed_flows = []
completed_flows_lock = Lock()


def save_completed_flow(flow_stats):
    """Save completed flow statistics"""
    try:
        features = flow_stats.calculate_statistics()
        with completed_flows_lock:
            completed_flows.append(features)
            # Keep only recent flows
            if len(completed_flows) > 500:
                completed_flows.pop(0)
        print(f"[✓] Flow completed: {flow_stats.flow_id} - "
              f"{flow_stats.total_fwd_packets}f/{flow_stats.total_bwd_packets}b packets")
    except Exception as e:
        print(f"[!] Error saving flow: {e}")


def write_flows_periodically():
    """Write flow statistics to JSON file every 5 seconds"""
    while True:
        time.sleep(5)
        try:
            # Get current active flows
            with flow_lock:
                active_flow_features = []
                for flow_key, flow_stats in flow_table.items():
                    if flow_stats.total_fwd_packets > 0 or flow_stats.total_bwd_packets > 0:
                        features = flow_stats.calculate_statistics()
                        active_flow_features.append(features)
            
            # Combine completed and active flows
            with completed_flows_lock:
                all_flows = completed_flows[-200:] + active_flow_features  # Keep last 200 completed + active
            
            # Write to file
            if all_flows:
                with open(OUTPUT_FILE, "w") as f:
                    json.dump(all_flows, f, indent=2)
                print(f"[💾] Written {len(all_flows)} flows to JSON "
                      f"({len(completed_flows)} completed, {len(active_flow_features)} active)")
            else:
                print(f"[⏳] No flows to write yet...")
                
        except Exception as e:
            print(f"[!] Failed to write flows: {e}")


def check_permissions():
    """Check if running with appropriate permissions"""
    error_log = r"E:/xampp/htdocs/cyberhawk/assets/data/sniffer_error.log"
    
    if os.name == 'nt':
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                error_msg = """
============================================================
ERROR: NOT RUNNING AS ADMINISTRATOR!
============================================================
Packet capture requires Administrator privileges.

SOLUTION:
1. Close this and use start_cyberhawk.bat instead
   (Right-click > Run as Administrator)

OR

2. Run XAMPP Control Panel as Administrator:
   - Close XAMPP
   - Right-click xampp-control.exe
   - Select "Run as administrator"
   - Start Apache
   - Then click "Start Logs" in dashboard
============================================================
"""
                print(error_msg)
                # Log to file so web interface can detect
                with open(error_log, 'w') as f:
                    f.write(f"ADMIN_REQUIRED\n")
                    f.write(f"Timestamp: {datetime.now().isoformat()}\n")
                    f.write(error_msg)
                # Exit with error
                sys.exit(1)
            else:
                # Clear error log if running as admin
                if os.path.exists(error_log):
                    os.remove(error_log)
        except Exception as e:
            print(f"[!] Permission check failed: {e}")
    else:
        if os.geteuid() != 0:
            print("[!] WARNING: Not running as root!")
            print("[!] Try: sudo python3 traffic_sniffer.py")
            return False
    return True


if __name__ == "__main__":
    print("="*60)
    print("🦅 CyberHawk Traffic Sniffer v3.0 - REAL DATA ONLY")
    print("="*60)
    print("[*] This version captures ONLY REAL packet data")
    print("    No synthetic values or placeholders")
    print("="*60)
    
    # Check permissions
    has_perms = check_permissions()
    
    # Clear old logs
    try:
        os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
        with open(OUTPUT_FILE, "w") as f:
            json.dump([], f)
        print("\n[✓] Cleared old traffic logs")
        print(f"[✓] Output file: {OUTPUT_FILE}")
    except Exception as e:
        print(f"[!] Failed to initialize logs: {e}")
        sys.exit(1)

    # Get active interface
    iface = get_active_interface()

    # Start background writer thread
    writer_thread = Thread(target=write_flows_periodically, daemon=True)
    writer_thread.start()
    print("[✓] Flow statistics writer started")

    try:
        print("\n" + "="*60)
        print("🔴 LIVE FLOW CAPTURE ACTIVE - Press Ctrl+C to stop")
        print("="*60)
        print("\n💡 Tips:")
        print("   • ALL data shown is REAL from actual packets")
        print("   • Flows timeout after 2 minutes of inactivity")
        print("   • Statistics update every 5 seconds")
        print("   • Generate traffic: browse web, ping, download files")
        print("="*60 + "\n")
        
        # Start capture
        sniff(iface=iface, prn=packet_callback, store=False)
        
    except KeyboardInterrupt:
        print("\n" + "="*60)
        print(f"✅ Capture stopped.")
        print(f"   Total packets: {packet_count}")
        print(f"   Active flows: {len(flow_table)}")
        print(f"   Completed flows: {len(completed_flows)}")
        
        # Save final statistics
        with flow_lock:
            final_flows = []
            for flow_key, flow_stats in flow_table.items():
                features = flow_stats.calculate_statistics()
                final_flows.append(features)
            
        with completed_flows_lock:
            all_final_flows = completed_flows + final_flows
            
        if all_final_flows:
            with open(OUTPUT_FILE, "w") as f:
                json.dump(all_final_flows, f, indent=2)
            print(f"[✓] Saved {len(all_final_flows)} total flows to {OUTPUT_FILE}")
        
        print("="*60)
        
    except PermissionError:
        print("\n[!] PERMISSION DENIED! Run as Administrator.")
    except Exception as e:
        print(f"\n[!] Capture error: {e}")
        import traceback
        traceback.print_exc()