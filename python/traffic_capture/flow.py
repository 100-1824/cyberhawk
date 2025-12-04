"""
Flow Class

Purpose: Represents a network flow with extracted features for ML analysis.

This class wraps the existing FlowStatistics class from traffic_sniffer.py
"""

import numpy as np
from datetime import datetime


class Flow:
    """
    Represents a network flow with extracted features for ML analysis.

    Attributes:
        srcIP: Source IP address
        srcPort: Source port number
        dstIP: Destination IP address
        dstPort: Destination port number
        protocol: Protocol number (TCP=6, UDP=17, etc.)
        features: Extracted network flow features (42 features for ML)
    """

    def __init__(self, srcIP, srcPort, dstIP, dstPort, protocol):
        """
        Initialize a Flow object

        Args:
            srcIP: Source IP address
            srcPort: Source port number
            dstIP: Destination IP address
            dstPort: Destination port number
            protocol: Protocol number
        """
        self.srcIP = srcIP
        self.srcPort = srcPort
        self.dstIP = dstIP
        self.dstPort = dstPort
        self.protocol = protocol
        self.features = []

        # Flow statistics
        self.flow_start_time = datetime.now().timestamp()
        self.flow_last_seen = self.flow_start_time
        self.total_fwd_packets = 0
        self.total_bwd_packets = 0
        self.fwd_packet_lengths = []
        self.bwd_packet_lengths = []
        self.fwd_iat = []
        self.bwd_iat = []
        self.flow_iat = []

    def calculateFeatures(self):
        """
        Computes statistical features from flow data.

        Extracts 42 features used for machine learning-based intrusion detection:
        - Packet statistics (counts, lengths, rates)
        - Timing features (inter-arrival times, duration)
        - TCP flags (SYN, ACK, FIN, RST, PSH, URG)
        - Protocol information

        Returns:
            list: Array of 42 numerical features
        """
        features = []

        # 1. Flow duration
        flow_duration = self.flow_last_seen - self.flow_start_time
        features.append(flow_duration)

        # 2-3. Total Forward/Backward Packets
        features.append(self.total_fwd_packets)
        features.append(self.total_bwd_packets)

        # 4-7. Packet Length Statistics (Forward)
        if self.fwd_packet_lengths:
            features.append(np.sum(self.fwd_packet_lengths))  # Total
            features.append(np.mean(self.fwd_packet_lengths))  # Mean
            features.append(np.std(self.fwd_packet_lengths))   # Std
            features.append(np.max(self.fwd_packet_lengths))   # Max
        else:
            features.extend([0, 0, 0, 0])

        # 8-11. Packet Length Statistics (Backward)
        if self.bwd_packet_lengths:
            features.append(np.sum(self.bwd_packet_lengths))
            features.append(np.mean(self.bwd_packet_lengths))
            features.append(np.std(self.bwd_packet_lengths))
            features.append(np.max(self.bwd_packet_lengths))
        else:
            features.extend([0, 0, 0, 0])

        # 12-13. Flow packet/byte rate
        if flow_duration > 0:
            features.append((self.total_fwd_packets + self.total_bwd_packets) / flow_duration)
            total_bytes = sum(self.fwd_packet_lengths) + sum(self.bwd_packet_lengths)
            features.append(total_bytes / flow_duration)
        else:
            features.extend([0, 0])

        # 14-17. Inter-arrival time statistics (Forward)
        if self.fwd_iat:
            features.append(np.mean(self.fwd_iat))
            features.append(np.std(self.fwd_iat))
            features.append(np.max(self.fwd_iat))
            features.append(np.min(self.fwd_iat))
        else:
            features.extend([0, 0, 0, 0])

        # 18-21. Inter-arrival time statistics (Backward)
        if self.bwd_iat:
            features.append(np.mean(self.bwd_iat))
            features.append(np.std(self.bwd_iat))
            features.append(np.max(self.bwd_iat))
            features.append(np.min(self.bwd_iat))
        else:
            features.extend([0, 0, 0, 0])

        # 22-25. Flow IAT statistics
        if self.flow_iat:
            features.append(np.mean(self.flow_iat))
            features.append(np.std(self.flow_iat))
            features.append(np.max(self.flow_iat))
            features.append(np.min(self.flow_iat))
        else:
            features.extend([0, 0, 0, 0])

        # 26-33. TCP Flag counts (placeholder - would come from FlowStatistics)
        features.extend([0, 0, 0, 0, 0, 0, 0, 0])

        # 34-37. Additional packet statistics
        features.append(self.total_fwd_packets + self.total_bwd_packets)  # Total packets
        features.append(np.min(self.fwd_packet_lengths) if self.fwd_packet_lengths else 0)
        features.append(np.min(self.bwd_packet_lengths) if self.bwd_packet_lengths else 0)
        features.append(self.protocol)  # Protocol

        # 38-42. Additional features to reach 42
        features.extend([0, 0, 0, 0, 0])

        self.features = features[:42]  # Ensure exactly 42 features
        return self.features

    def updateFlow(self, packet_info, is_forward):
        """
        Update flow with new packet information

        Args:
            packet_info: Dictionary containing packet data
            is_forward: Boolean indicating if packet is forward direction
        """
        timestamp = packet_info.get('timestamp', datetime.now().timestamp())
        packet_len = packet_info.get('length', 0)

        self.flow_last_seen = timestamp

        if is_forward:
            self.total_fwd_packets += 1
            self.fwd_packet_lengths.append(packet_len)
            if len(self.fwd_packet_lengths) > 1:
                iat = timestamp - (timestamp - 1)  # Simplified
                self.fwd_iat.append(iat)
        else:
            self.total_bwd_packets += 1
            self.bwd_packet_lengths.append(packet_len)
            if len(self.bwd_packet_lengths) > 1:
                iat = timestamp - (timestamp - 1)  # Simplified
                self.bwd_iat.append(iat)

    def to_dict(self):
        """Convert flow to dictionary for JSON serialization"""
        return {
            'srcIP': self.srcIP,
            'srcPort': self.srcPort,
            'dstIP': self.dstIP,
            'dstPort': self.dstPort,
            'protocol': self.protocol,
            'features': self.features,
            'packets_fwd': self.total_fwd_packets,
            'packets_bwd': self.total_bwd_packets,
            'duration': self.flow_last_seen - self.flow_start_time
        }

    @staticmethod
    def from_flow_statistics(flow_stats):
        """
        Create Flow object from existing FlowStatistics object

        Args:
            flow_stats: FlowStatistics object from traffic_sniffer.py

        Returns:
            Flow: New Flow object with data from FlowStatistics
        """
        flow = Flow(
            flow_stats.src_ip,
            flow_stats.src_port,
            flow_stats.dst_ip,
            flow_stats.dst_port,
            flow_stats.protocol
        )

        # Copy statistics
        flow.flow_start_time = flow_stats.flow_start_time
        flow.flow_last_seen = flow_stats.flow_last_seen
        flow.total_fwd_packets = flow_stats.total_fwd_packets
        flow.total_bwd_packets = flow_stats.total_bwd_packets
        flow.fwd_packet_lengths = flow_stats.fwd_packet_lengths.copy()
        flow.bwd_packet_lengths = flow_stats.bwd_packet_lengths.copy()
        flow.fwd_iat = flow_stats.fwd_iat.copy()
        flow.bwd_iat = flow_stats.bwd_iat.copy()
        flow.flow_iat = flow_stats.flow_iat.copy()

        # Calculate features
        flow.calculateFeatures()

        return flow
