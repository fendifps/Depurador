"""
Depurador - System Scanner Module
Escaneo multihilo del sistema de archivos
"""

import os
import hashlib
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style
from datetime import datetime
import threading


class SystemScanner:
    """Motor de escaneo del sistema"""
    
    # Extensiones sospechosas
    SUSPICIOUS_EXTENSIONS = {
        '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.wsf',
        '.scr', '.pif', '.com', '.cpl', '.msi', '.sys', '.drv', '.ocx'
    }
    
    # Directorios del sistema a excluir para evitar problemas
    EXCLUDED_DIRS = {
        'Windows\\WinSxS',
        'Windows\\Installer',
        '$Recycle.Bin',
        'System Volume Information',
        'Recovery',
        'PerfLogs'
    }
    
    def __init__(self, signature_engine, logger, max_threads=8):
        self.signature_engine = signature_engine
        self.logger = logger
        self.max_threads = max_threads
        self.scan_stats = {
            'total_scanned': 0,
            'threats_found': 0,
            'suspicious_found': 0,
            'clean_files': 0,
            'errors': 0
        }
        self.threats = []
        self.lock = threading.Lock()
        
    def scan_paths(self, paths):
        """Escanear múltiples rutas"""
        print(f"{Fore.CYAN}[+] Initializing scanner...")
        print(f"{Fore.CYAN}[+] Threads: {self.max_threads}")
        print(f"{Fore.CYAN}[+] Starting scan at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        self.scan_stats = {
            'total_scanned': 0,
            'threats_found': 0,
            'suspicious_found': 0,
            'clean_files': 0,
            'errors': 0
        }
        self.threats = []
        
        files_to_scan = []
        
        # Recolectar archivos
        for path in paths:
            files_to_scan.extend(self._collect_files(path))
        
        total_files = len(files_to_scan)
        print(f"{Fore.GREEN}[+] Found {total_files} files to scan\n")
        
        if total_files == 0:
            return self._generate_results()
        
        # Escaneo multihilo
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self._scan_file, file): file for file in files_to_scan}
            
            for idx, future in enumerate(as_completed(futures), 1):
                file = futures[future]
                
                try:
                    future.result()
                except Exception as e:
                    with self.lock:
                        self.scan_stats['errors'] += 1
                
                # Progress indicator
                if idx % 100 == 0 or idx == total_files:
                    progress = (idx / total_files) * 100
                    threats = self.scan_stats['threats_found']
                    suspicious = self.scan_stats['suspicious_found']
                    
                    print(f"{Fore.YELLOW}[{progress:6.2f}%] Scanned: {idx}/{total_files} | "
                          f"{Fore.RED}Threats: {threats} | "
                          f"{Fore.YELLOW}Suspicious: {suspicious}{Style.RESET_ALL}")
        
        return self._generate_results()
    
    def _collect_files(self, root_path):
        """Recolectar archivos para escanear"""
        files = []
        root_path = Path(root_path)
        
        try:
            for item in root_path.rglob('*'):
                try:
                    # Verificar si es archivo
                    if not item.is_file():
                        continue
                    
                    # Verificar extensión sospechosa
                    if item.suffix.lower() not in self.SUSPICIOUS_EXTENSIONS:
                        continue
                    
                    # Excluir directorios del sistema
                    if any(excluded in str(item) for excluded in self.EXCLUDED_DIRS):
                        continue
                    
                    # Verificar tamaño (máximo 100MB)
                    if item.stat().st_size > 100 * 1024 * 1024:
                        continue
                    
                    files.append(str(item))
                    
                except (PermissionError, OSError):
                    continue
                    
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Warning scanning {root_path}: {e}")
        
        return files
    
    def _scan_file(self, file_path):
        """Escanear un archivo individual"""
        try:
            # Calcular hashes
            sha256_hash, md5_hash = self._calculate_hashes(file_path)
            
            if not sha256_hash:
                return
            
            # Obtener información del archivo
            file_size = os.path.getsize(file_path)
            file_ext = Path(file_path).suffix.lower()
            
            # Análisis de firma
            is_malicious, reasons = self._analyze_file(file_path, sha256_hash, md5_hash, file_ext)
            
            with self.lock:
                self.scan_stats['total_scanned'] += 1
                
                if is_malicious:
                    severity = self._determine_severity(reasons)
                    
                    threat_info = {
                        'file': file_path,
                        'sha256': sha256_hash,
                        'md5': md5_hash,
                        'size': file_size,
                        'type': file_ext,
                        'reasons': reasons,
                        'severity': severity,
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    self.threats.append(threat_info)
                    
                    if severity == 'CRITICAL':
                        self.scan_stats['threats_found'] += 1
                    else:
                        self.scan_stats['suspicious_found'] += 1
                    
                    # Log threat
                    self.logger.log_threat(threat_info)
                else:
                    self.scan_stats['clean_files'] += 1
                    
        except Exception as e:
            with self.lock:
                self.scan_stats['errors'] += 1
    
    def _calculate_hashes(self, file_path):
        """Calcular SHA256 y MD5"""
        try:
            sha256_hasher = hashlib.sha256()
            md5_hasher = hashlib.md5()
            
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    sha256_hasher.update(chunk)
                    md5_hasher.update(chunk)
            
            return sha256_hasher.hexdigest(), md5_hasher.hexdigest()
        except Exception:
            return None, None
    
    def _analyze_file(self, file_path, sha256, md5, extension):
        """Analizar archivo para detectar malware"""
        is_malicious = False
        reasons = []
        
        # 1. Check hash signatures
        if self.signature_engine.check_hash(sha256, md5):
            is_malicious = True
            reasons.append("Known malware hash signature detected")
        
        # 2. Check filename patterns
        filename = os.path.basename(file_path).lower()
        if self.signature_engine.check_filename_pattern(filename):
            is_malicious = True
            reasons.append("Suspicious filename pattern detected")
        
        # 3. Heuristic analysis
        try:
            with open(file_path, 'rb') as f:
                content = f.read(min(1024 * 1024, os.path.getsize(file_path)))  # Max 1MB
                
                heuristic_result = self.signature_engine.heuristic_analysis(content, extension)
                if heuristic_result['is_suspicious']:
                    is_malicious = True
                    reasons.extend(heuristic_result['reasons'])
        except Exception:
            pass
        
        # 4. Behavioral patterns
        if extension in ['.exe', '.dll']:
            behavioral_result = self.signature_engine.check_behavioral_patterns(file_path)
            if behavioral_result['is_suspicious']:
                is_malicious = True
                reasons.extend(behavioral_result['reasons'])
        
        return is_malicious, reasons
    
    def _determine_severity(self, reasons):
        """Determinar severidad de la amenaza"""
        critical_keywords = ['known malware', 'hash signature', 'ransomware', 'trojan']
        
        for reason in reasons:
            reason_lower = reason.lower()
            if any(keyword in reason_lower for keyword in critical_keywords):
                return 'CRITICAL'
        
        return 'SUSPICIOUS'
    
    def _generate_results(self):
        """Generar resultados del escaneo"""
        report_path = self.logger.generate_report(self.threats, self.scan_stats)
        
        return {
            'total_scanned': self.scan_stats['total_scanned'],
            'threats_found': self.scan_stats['threats_found'],
            'suspicious_found': self.scan_stats['suspicious_found'],
            'clean_files': self.scan_stats['clean_files'],
            'errors': self.scan_stats['errors'],
            'threats': self.threats,
            'report_path': report_path
        }