import socket
import threading
from datetime import datetime
import time
from typing import List, Dict

class PortScanner:
    def __init__(self, target: str):
        self.target = target
        self.open_ports = []

        # Common ports to scan
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080
        ]

    def scan_ports(self, port_range: str = None) -> List[Dict]:
        vulnerabilities = []

        try:
            # Resolve target IP
            target_ip = socket.gethostbyname(self.target)
        except socket.gaierror:
            return [{
                'type': 'DNS Resolution Error',
                'severity': 'High',
                'title': 'Cannot resolve hostname',
                'description': f'Unable to resolve hostname: {self.target}',
                'url': self.target
            }]

        # Determine ports to scan
        if port_range:
            if '-' in port_range:
                start, end = map(int, port_range.split('-'))
                ports_to_scan = range(start, end + 1)
            else:
                ports_to_scan = [int(port_range)]
        else:
            ports_to_scan = self.common_ports

        # Scan ports using threading for speed
        threads = []
        for port in ports_to_scan:
            thread = threading.Thread(target=self._scan_single_port, args=(target_ip, port))
            thread.start()
            threads.append(thread)

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Generate vulnerability reports for open ports
        for port in self.open_ports:
            severity = self._get_port_risk_level(port)
            service = self._get_service_name(port)

            vulnerabilities.append({
                'type': 'Open Port',
                'severity': severity,
                'title': f'Open port {port} ({service})',
                'description': f'Port {port} is open and running {service} service',
                'url': f'{target_ip}:{port}'
            })

        return vulnerabilities

    def _scan_single_port(self, target_ip: str, port: int):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target_ip, port))

            if result == 0:
                self.open_ports.append(port)

            sock.close()
        except socket.error:
            pass

    def _get_port_risk_level(self, port: int) -> str:
        high_risk_ports = [21, 23, 135, 139, 445, 1433, 3306, 3389, 5432]
        medium_risk_ports = [22, 25, 110, 143, 993, 995, 1723]

        if port in high_risk_ports:
            return 'High'
        elif port in medium_risk_ports:
            return 'Medium'
        else:
            return 'Low'

    def _get_service_name(self, port: int) -> str:
        services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            111: 'RPC',
            135: 'RPC',
            139: 'NetBIOS',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            993: 'IMAPS',
            995: 'POP3S',
            1433: 'MSSQL',
            1723: 'PPTP',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            8080: 'HTTP-Alt'
        }

        return services.get(port, 'Unknown')
