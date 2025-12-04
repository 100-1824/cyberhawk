"""
RansomwareMonitor Class

Purpose: Specialized monitoring for ransomware activity.

This class wraps the existing RansomwareDetector from ransomware_monitor.py
"""

import os
import sys
import subprocess
from pathlib import Path
from datetime import datetime


class RansomwareMonitor:
    """
    Real-time ransomware detection and monitoring system.

    Monitors file system for ransomware behavior patterns:
    - Rapid file encryption
    - Suspicious file extensions
    - Ransom note creation
    - High entropy file modifications
    """

    def __init__(self, monitored_paths=None):
        """
        Initialize RansomwareMonitor

        Args:
            monitored_paths: List of paths to monitor (default: Documents, Downloads, Desktop)
        """
        self.monitored_paths = monitored_paths or self._getDefaultPaths()
        self.monitor_process = None
        self.is_monitoring = False
        self.suspicious_extensions = [
            '.encrypted', '.locked', '.crypto', '.crypt', '.crypted',
            '.enc', '.locky', '.zepto', '.cerber', '.wannacry'
        ]

    def _getDefaultPaths(self):
        """Get default monitoring paths"""
        home = os.path.expanduser('~')
        return [
            os.path.join(home, 'Documents'),
            os.path.join(home, 'Downloads'),
            os.path.join(home, 'Desktop')
        ]

    def startMonitoring(self):
        """
        Begins monitoring for ransomware behavior.

        Starts the ransomware_monitor.py script which uses watchdog
        to monitor file system events in real-time.

        Returns:
            dict: Status dictionary with success/error information
        """
        if self.is_monitoring:
            return {
                'success': False,
                'message': 'Monitoring already active'
            }

        try:
            # Get path to ransomware_monitor.py
            monitor_script = Path(__file__).parent / "ransomware_monitor.py"

            if not monitor_script.exists():
                return {
                    'success': False,
                    'message': f'Monitor script not found at {monitor_script}'
                }

            # Get Python executable
            project_root = Path(__file__).resolve().parent.parent.parent
            python_exe = project_root / "fyp" / "Scripts" / "python.exe"

            if not python_exe.exists():
                python_exe = "python"  # Fallback to system python

            # Start monitor process in background
            if os.name == 'nt':  # Windows
                self.monitor_process = subprocess.Popen(
                    [str(python_exe), str(monitor_script)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
            else:  # Unix/Linux
                self.monitor_process = subprocess.Popen(
                    [str(python_exe), str(monitor_script)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True
                )

            self.is_monitoring = True

            # Save PID for later reference
            self._savePID(self.monitor_process.pid)

            return {
                'success': True,
                'message': 'Ransomware monitoring started',
                'pid': self.monitor_process.pid,
                'monitored_paths': self.monitored_paths
            }

        except Exception as e:
            return {
                'success': False,
                'message': f'Failed to start monitoring: {str(e)}'
            }

    def detectSuspiciousFile(self, file):
        """
        Identifies suspicious file activity.

        Checks for ransomware indicators:
        - Suspicious file extensions
        - Rapid file modifications
        - High entropy (encryption indicator)
        - Ransom note patterns

        Args:
            file: Path to file to analyze

        Returns:
            dict: Detection results
        """
        results = {
            'is_suspicious': False,
            'indicators': [],
            'risk_level': 'low'
        }

        if not os.path.exists(file):
            return results

        filename = os.path.basename(file)
        _, ext = os.path.splitext(filename)

        # Check extension
        if ext.lower() in self.suspicious_extensions:
            results['is_suspicious'] = True
            results['indicators'].append(f"Suspicious extension: {ext}")
            results['risk_level'] = 'high'

        # Check for ransom note patterns
        ransom_keywords = [
            'decrypt', 'bitcoin', 'ransom', 'encrypted', 'restore',
            'payment', 'cryptocurrency', 'files have been locked'
        ]

        if ext.lower() in ['.txt', '.html', '.rtf']:
            try:
                with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read().lower()
                    for keyword in ransom_keywords:
                        if keyword in content:
                            results['is_suspicious'] = True
                            results['indicators'].append("Possible ransom note detected")
                            results['risk_level'] = 'critical'
                            break
            except:
                pass

        # Check file entropy (requires reading file)
        try:
            entropy = self._calculateEntropy(file)
            if entropy > 7.5:  # High entropy suggests encryption
                results['is_suspicious'] = True
                results['indicators'].append(f"High entropy: {entropy:.2f}")
                if results['risk_level'] != 'critical':
                    results['risk_level'] = 'high'
        except:
            pass

        return results

    def quarantineFile(self, file):
        """
        Isolates suspicious files.

        Moves the file to quarantine directory for isolation.

        Args:
            file: Path to file to quarantine

        Returns:
            dict: Quarantine operation result
        """
        from ..malware.quarantine import QuarantineFile

        filename = os.path.basename(file)
        quarantine_obj = QuarantineFile(filename, file, 'ransomware')
        return quarantine_obj.quarantine()

    def stopMonitoring(self):
        """
        Stop ransomware monitoring

        Returns:
            dict: Status dictionary
        """
        if not self.is_monitoring:
            return {
                'success': False,
                'message': 'No monitoring active'
            }

        try:
            if self.monitor_process:
                self.monitor_process.terminate()
                self.monitor_process.wait(timeout=5)

            self.is_monitoring = False
            self._removePID()

            return {
                'success': True,
                'message': 'Monitoring stopped'
            }

        except Exception as e:
            return {
                'success': False,
                'message': f'Failed to stop monitoring: {str(e)}'
            }

    def getStatus(self):
        """
        Get monitoring status

        Returns:
            dict: Current status information
        """
        # Check if process is still running
        if self.monitor_process and self.monitor_process.poll() is not None:
            self.is_monitoring = False

        return {
            'monitoring': self.is_monitoring,
            'pid': self.monitor_process.pid if self.monitor_process else None,
            'monitored_paths': self.monitored_paths,
            'suspicious_extensions': len(self.suspicious_extensions)
        }

    def _calculateEntropy(self, filePath, sample_size=1024*1024):
        """
        Calculate file entropy (Shannon entropy)

        Args:
            filePath: Path to file
            sample_size: Number of bytes to sample

        Returns:
            float: Entropy value (0-8)
        """
        import math

        try:
            with open(filePath, 'rb') as f:
                data = f.read(sample_size)

            if not data:
                return 0

            # Count byte frequencies
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1

            # Calculate entropy
            entropy = 0
            data_len = len(data)

            for count in byte_counts:
                if count > 0:
                    p_x = count / data_len
                    entropy += -p_x * math.log2(p_x)

            return entropy

        except Exception as e:
            print(f"Entropy calculation error: {str(e)}")
            return 0

    def _savePID(self, pid):
        """Save process ID to file"""
        try:
            current_dir = Path(__file__).resolve().parent
            project_root = current_dir.parent.parent
            pid_file = project_root / "assets" / "data" / "ransomware_pid.json"

            import json
            with open(pid_file, 'w') as f:
                json.dump({
                    'monitor_pid': pid,
                    'started_at': datetime.now().isoformat(),
                    'status': 'running'
                }, f, indent=4)

        except Exception as e:
            print(f"Failed to save PID: {str(e)}")

    def _removePID(self):
        """Remove PID file"""
        try:
            current_dir = Path(__file__).resolve().parent
            project_root = current_dir.parent.parent
            pid_file = project_root / "assets" / "data" / "ransomware_pid.json"

            if pid_file.exists():
                os.remove(pid_file)

        except Exception as e:
            print(f"Failed to remove PID: {str(e)}")

    @staticmethod
    def getThreatStatistics():
        """
        Get ransomware threat statistics

        Returns:
            dict: Statistics on detected threats
        """
        try:
            current_dir = Path(__file__).resolve().parent
            project_root = current_dir.parent.parent
            stats_file = project_root / "assets" / "data" / "ransomware_stats.json"

            if stats_file.exists():
                import json
                with open(stats_file, 'r') as f:
                    return json.load(f)

            return {
                'files_scanned': 0,
                'threats_detected': 0,
                'quarantined': 0
            }

        except:
            return {}
