"""
Depurador - Advanced Detector Module
Ultra-aggressive detection for RATs, backdoors, and advanced malware
Version: 2.1.0
"""

import re
import json
from pathlib import Path
from typing import Dict, List, Tuple


class AdvancedDetector:
    """Detector ultra-agresivo para RATs y malware avanzado"""
    
    def __init__(self, signatures_dir):
        self.signatures_dir = Path(signatures_dir)
        self.enhanced_rules = self._load_enhanced_rules()
        
        # Umbral ultra-agresivo: 2 indicadores = sospechoso
        self.suspicion_threshold = 2
        self.malicious_threshold = 4
    
    def _load_enhanced_rules(self):
        """Cargar reglas mejoradas"""
        enhanced_file = self.signatures_dir / "enhanced_signatures.json"
        
        if enhanced_file.exists():
            with open(enhanced_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        
        # Reglas por defecto si no existe el archivo
        return self._get_default_rules()
    
    def _get_default_rules(self):
        """Reglas por defecto ultra-agresivas"""
        return {
            "rat_signatures": {
                "api_patterns": [
                    "GetAsyncKeyState", "SetWindowsHookEx", "GetForegroundWindow",
                    "GetClipboardData", "CreateRemoteThread", "WriteProcessMemory",
                    "VirtualAllocEx", "OpenProcess", "RegSetValueEx", "InternetOpenUrl",
                    "socket", "connect", "send", "recv", "WSAStartup"
                ],
                "string_patterns": [
                    "RAT", "backdoor", "remote", "keylog", "screen capture",
                    "webcam", "reverse shell", "bind shell", "victim", "payload",
                    "stub", "crypter", "FUD", "bypass", "persistence", "stealth",
                    "inject", "hollowing"
                ]
            }
        }
    
    def deep_scan_file(self, file_path: str, content: bytes, file_info: Dict) -> Dict:
        """
        Escaneo profundo ultra-agresivo
        
        Args:
            file_path: Ruta del archivo
            content: Contenido binario del archivo
            file_info: Información del archivo (hashes, tamaño, etc.)
        
        Returns:
            Dict con resultados de detección avanzada
        """
        results = {
            'is_rat': False,
            'is_backdoor': False,
            'confidence': 0.0,
            'rat_indicators': [],
            'suspicious_apis': [],
            'suspicious_strings': [],
            'network_indicators': [],
            'evasion_techniques': [],
            'persistence_mechanisms': [],
            'severity': 'CLEAN'
        }
        
        # Contador de indicadores
        indicator_count = 0
        
        # 1. Análisis de APIs (ultra-agresivo)
        api_indicators = self._detect_rat_apis(content)
        if api_indicators:
            results['suspicious_apis'] = api_indicators
            indicator_count += len(api_indicators)
            results['rat_indicators'].append(f"Found {len(api_indicators)} RAT-related APIs")
        
        # 2. Análisis de strings sospechosos
        string_indicators = self._detect_suspicious_strings(content)
        if string_indicators:
            results['suspicious_strings'] = string_indicators
            indicator_count += len(string_indicators)
            results['rat_indicators'].append(f"Found {len(string_indicators)} suspicious strings")
        
        # 3. Detección de redes/C2
        network_indicators = self._detect_network_behavior(content)
        if network_indicators:
            results['network_indicators'] = network_indicators
            indicator_count += len(network_indicators) * 2  # Peso doble
            results['rat_indicators'].append("Network/C2 behavior detected")
        
        # 4. Técnicas de evasión
        evasion_indicators = self._detect_evasion_techniques(content)
        if evasion_indicators:
            results['evasion_techniques'] = evasion_indicators
            indicator_count += len(evasion_indicators)
            results['rat_indicators'].append("Evasion techniques detected")
        
        # 5. Mecanismos de persistencia
        persistence_indicators = self._detect_persistence(content)
        if persistence_indicators:
            results['persistence_mechanisms'] = persistence_indicators
            indicator_count += len(persistence_indicators) * 2  # Peso doble
            results['rat_indicators'].append("Persistence mechanisms detected")
        
        # 6. Detección de familias de RAT conocidas
        rat_family = self._detect_rat_family(content, file_path)
        if rat_family:
            results['rat_indicators'].append(f"Possible {rat_family} RAT family")
            indicator_count += 5  # Peso muy alto
            results['is_rat'] = True
        
        # 7. Análisis de nombre de archivo sospechoso
        if self._is_suspicious_filename(file_path):
            results['rat_indicators'].append("Suspicious filename pattern")
            indicator_count += 1
        
        # 8. Detección de empaquetamiento
        if file_info.get('entropy', 0) > 7.0:
            results['rat_indicators'].append("High entropy (possibly packed)")
            indicator_count += 1
        
        # 9. Tamaño sospechoso
        size = file_info.get('size', 0)
        if 10000 < size < 100000:  # RATs típicamente entre 10KB-100KB
            results['rat_indicators'].append("Size typical of RAT stub")
            indicator_count += 1
        
        # Cálculo de confianza y severidad (ULTRA-AGRESIVO)
        if indicator_count >= self.malicious_threshold:
            results['is_rat'] = True
            results['is_backdoor'] = True
            results['confidence'] = min(1.0, indicator_count / 10.0)
            results['severity'] = 'CRITICAL'
        elif indicator_count >= self.suspicion_threshold:
            results['is_rat'] = True
            results['confidence'] = min(0.8, indicator_count / 8.0)
            results['severity'] = 'HIGH'
        
        return results
    
    def _detect_rat_apis(self, content: bytes) -> List[str]:
        """Detectar APIs relacionadas con RATs"""
        found_apis = []
        
        try:
            # Convertir a string ignorando errores
            content_str = content.decode('utf-8', errors='ignore').lower()
            
            apis = self.enhanced_rules.get('rat_signatures', {}).get('api_patterns', [])
            
            for api in apis:
                if api.lower() in content_str:
                    found_apis.append(api)
        
        except Exception:
            pass
        
        return found_apis
    
    def _detect_suspicious_strings(self, content: bytes) -> List[str]:
        """Detectar strings sospechosos"""
        found_strings = []
        
        try:
            content_str = content.decode('utf-8', errors='ignore').lower()
            
            patterns = self.enhanced_rules.get('rat_signatures', {}).get('string_patterns', [])
            
            for pattern in patterns:
                if pattern.lower() in content_str:
                    found_strings.append(pattern)
        
        except Exception:
            pass
        
        return found_strings
    
    def _detect_network_behavior(self, content: bytes) -> List[str]:
        """Detectar comportamiento de red/C2"""
        indicators = []
        
        try:
            content_str = content.decode('utf-8', errors='ignore')
            
            # Detectar IPs
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            ips = re.findall(ip_pattern, content_str)
            if ips:
                indicators.append(f"Hardcoded IPs found: {len(ips)}")
            
            # Detectar URLs
            url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
            urls = re.findall(url_pattern, content_str)
            if urls:
                indicators.append(f"URLs found: {len(urls)}")
            
            # Detectar puertos comunes de RAT
            common_rat_ports = ['4444', '5555', '6666', '7777', '8080', '9999']
            for port in common_rat_ports:
                if port.encode() in content:
                    indicators.append(f"Common RAT port detected: {port}")
            
            # Detectar sockets
            socket_apis = [b'socket', b'connect', b'bind', b'listen', b'recv', b'send']
            socket_count = sum(1 for api in socket_apis if api in content)
            if socket_count >= 3:
                indicators.append(f"Socket operations detected: {socket_count}")
        
        except Exception:
            pass
        
        return indicators
    
    def _detect_evasion_techniques(self, content: bytes) -> List[str]:
        """Detectar técnicas de evasión"""
        techniques = []
        
        try:
            content_str = content.decode('utf-8', errors='ignore').lower()
            
            # Anti-debugging
            anti_debug = ['isdebuggerpresent', 'checkremotedebugger', 'outputdebugstring']
            for tech in anti_debug:
                if tech in content_str:
                    techniques.append(f"Anti-debugging: {tech}")
            
            # Anti-VM
            anti_vm = ['vmware', 'virtualbox', 'vbox', 'qemu', 'sandbox']
            for tech in anti_vm:
                if tech in content_str:
                    techniques.append(f"Anti-VM: {tech}")
            
            # Obfuscación
            obfuscation = ['base64', 'xor', 'decode', 'decrypt', 'uncompress']
            for tech in obfuscation:
                if tech in content_str:
                    techniques.append(f"Obfuscation: {tech}")
        
        except Exception:
            pass
        
        return techniques
    
    def _detect_persistence(self, content: bytes) -> List[str]:
        """Detectar mecanismos de persistencia"""
        mechanisms = []
        
        try:
            content_str = content.decode('utf-8', errors='ignore').lower()
            
            # Registry Run keys
            run_keys = ['software\\microsoft\\windows\\currentversion\\run', 
                       'runonce', 'startup']
            for key in run_keys:
                if key in content_str:
                    mechanisms.append(f"Registry persistence: {key}")
            
            # Scheduled tasks
            if 'schtasks' in content_str or 'task scheduler' in content_str:
                mechanisms.append("Scheduled task persistence")
            
            # Service installation
            if 'createservice' in content_str or 'startservice' in content_str:
                mechanisms.append("Service persistence")
            
            # Startup folder
            if 'startup' in content_str or 'appdata\\roaming\\microsoft\\windows\\start menu' in content_str:
                mechanisms.append("Startup folder persistence")
        
        except Exception:
            pass
        
        return mechanisms
    
    def _detect_rat_family(self, content: bytes, file_path: str) -> str:
        """Detectar familia de RAT conocida"""
        try:
            content_str = content.decode('utf-8', errors='ignore').lower()
            file_lower = file_path.lower()
            
            families = self.enhanced_rules.get('rat_families', {}).get('families', [])
            
            for family in families:
                name = family['name']
                indicators = family['indicators']
                
                for indicator in indicators:
                    if indicator.lower() in content_str or indicator.lower() in file_lower:
                        return name
        
        except Exception:
            pass
        
        return None
    
    def _is_suspicious_filename(self, file_path: str) -> bool:
        """Verificar si el nombre de archivo es sospechoso"""
        filename = Path(file_path).name.lower()
        
        suspicious_names = [
            'stub', 'client', 'server', 'payload', 'dropper', 'injector',
            'crypter', 'builder', 'binder', 'rat', 'backdoor', 'remote',
            'keylogger', 'stealer', 'bot', 'agent', 'victim', 'target'
        ]
        
        for name in suspicious_names:
            if name in filename:
                return True
        
        # Nombres genéricos sospechosos
        if re.match(r'^(client|server|stub|bot|agent)\d*\.exe$', filename):
            return True
        
        # Nombres muy cortos (a.exe, x.exe, etc.)
        if re.match(r'^[a-z]\.exe$', filename):
            return True
        
        return False
    
    def generate_report(self, results: Dict) -> str:
        """Generar reporte de detección avanzada"""
        if not results['is_rat'] and not results['is_backdoor']:
            return "No RAT/Backdoor indicators detected"
        
        report = []
        
        report.append(f"ADVANCED DETECTION ALERT - Severity: {results['severity']}")
        report.append(f"Confidence: {results['confidence'] * 100:.1f}%")
        
        if results['is_rat']:
            report.append("IDENTIFIED AS: Remote Access Trojan (RAT)")
        if results['is_backdoor']:
            report.append("IDENTIFIED AS: Backdoor")
        
        if results['rat_indicators']:
            report.append("\nRAT Indicators:")
            for indicator in results['rat_indicators']:
                report.append(f"  • {indicator}")
        
        if results['suspicious_apis']:
            report.append(f"\nSuspicious APIs ({len(results['suspicious_apis'])}):")
            for api in results['suspicious_apis'][:10]:  # Top 10
                report.append(f"  • {api}")
        
        if results['suspicious_strings']:
            report.append(f"\nSuspicious Strings ({len(results['suspicious_strings'])}):")
            for string in results['suspicious_strings'][:10]:
                report.append(f"  • {string}")
        
        if results['network_indicators']:
            report.append("\nNetwork/C2 Indicators:")
            for indicator in results['network_indicators']:
                report.append(f"  • {indicator}")
        
        if results['evasion_techniques']:
            report.append("\nEvasion Techniques:")
            for tech in results['evasion_techniques']:
                report.append(f"  • {tech}")
        
        if results['persistence_mechanisms']:
            report.append("\nPersistence Mechanisms:")
            for mech in results['persistence_mechanisms']:
                report.append(f"  • {mech}")
        
        return "\n".join(report)