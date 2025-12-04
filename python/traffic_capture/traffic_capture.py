"""
TrafficCapture Class

Purpose: Captures live network traffic for analysis.

This class wraps the existing traffic_sniffer.py functionality
"""

import subprocess
import os
import json
from pathlib import Path
from .flow import Flow


class TrafficCapture:
    """
    Captures live network traffic using Scapy and exports flows for analysis.

    This class interfaces with the existing traffic_sniffer.py script
    to provide network packet capture and flow extraction capabilities.
    """

    def __init__(self, output_file=None):
        """
        Initialize TrafficCapture

        Args:
            output_file: Path to output JSON file for captured flows
        """
        self.output_file = output_file or self._get_default_output_path()
        self.capture_process = None
        self.is_capturing = False

    def _get_default_output_path(self):
        """Get default output path for traffic logs"""
        # Navigate up to project root and find assets/data
        current_dir = Path(__file__).resolve().parent
        project_root = current_dir.parent.parent
        return project_root / "assets" / "data" / "traffic_log.json"

    def startCapture(self):
        """
        Begins packet capture process.

        Starts the traffic_sniffer.py script to capture network packets
        and extract flow statistics.

        Returns:
            dict: Status dictionary with success/error information
        """
        if self.is_capturing:
            return {
                'success': False,
                'message': 'Capture already running'
            }

        try:
            # Get path to traffic_sniffer.py
            sniffer_script = Path(__file__).parent / "traffic_sniffer.py"

            if not sniffer_script.exists():
                return {
                    'success': False,
                    'message': f'Sniffer script not found at {sniffer_script}'
                }

            # Get Python executable (assumes venv or system python)
            project_root = Path(__file__).resolve().parent.parent.parent
            python_exe = project_root / "fyp" / "Scripts" / "python.exe"

            if not python_exe.exists():
                python_exe = "python"  # Fallback to system python

            # Start capture process in background
            self.capture_process = subprocess.Popen(
                [str(python_exe), str(sniffer_script)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )

            self.is_capturing = True

            return {
                'success': True,
                'message': 'Traffic capture started',
                'pid': self.capture_process.pid
            }

        except Exception as e:
            return {
                'success': False,
                'message': f'Failed to start capture: {str(e)}'
            }

    def stopCapture(self):
        """
        Stops packet capture.

        Terminates the running traffic_sniffer.py process.

        Returns:
            dict: Status dictionary
        """
        if not self.is_capturing:
            return {
                'success': False,
                'message': 'No capture running'
            }

        try:
            if self.capture_process:
                self.capture_process.terminate()
                self.capture_process.wait(timeout=5)

            self.is_capturing = False

            return {
                'success': True,
                'message': 'Traffic capture stopped'
            }

        except Exception as e:
            return {
                'success': False,
                'message': f'Failed to stop capture: {str(e)}'
            }

    def exportFlows(self):
        """
        Exports captured flows as JSON.

        Reads the captured flow data from the output file and returns
        it as a JSON-compatible data structure.

        Returns:
            dict: JSON data containing captured flows
        """
        try:
            if not os.path.exists(self.output_file):
                return {
                    'success': False,
                    'message': 'No capture data available',
                    'flows': []
                }

            with open(self.output_file, 'r') as f:
                flows_data = json.load(f)

            return {
                'success': True,
                'message': f'Exported {len(flows_data)} flows',
                'flows': flows_data,
                'count': len(flows_data)
            }

        except json.JSONDecodeError:
            return {
                'success': False,
                'message': 'Invalid JSON in capture file',
                'flows': []
            }
        except Exception as e:
            return {
                'success': False,
                'message': f'Failed to export flows: {str(e)}',
                'flows': []
            }

    def getFlowCount(self):
        """Get count of captured flows"""
        try:
            if not os.path.exists(self.output_file):
                return 0

            with open(self.output_file, 'r') as f:
                flows = json.load(f)
                return len(flows) if isinstance(flows, list) else 0
        except:
            return 0

    def clearCapture(self):
        """Clear captured flow data"""
        try:
            with open(self.output_file, 'w') as f:
                json.dump([], f)
            return {'success': True, 'message': 'Capture data cleared'}
        except Exception as e:
            return {'success': False, 'message': f'Failed to clear data: {str(e)}'}

    def isCapturing(self):
        """Check if capture is currently running"""
        if not self.is_capturing:
            return False

        # Verify process is still alive
        if self.capture_process and self.capture_process.poll() is not None:
            self.is_capturing = False
            return False

        return True

    def getStatus(self):
        """Get current capture status"""
        return {
            'capturing': self.isCapturing(),
            'output_file': str(self.output_file),
            'flow_count': self.getFlowCount(),
            'pid': self.capture_process.pid if self.capture_process else None
        }
