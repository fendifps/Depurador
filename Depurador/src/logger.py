"""
Depurador - Logging System
Sistema de registro de eventos y reportes
"""

import json
from pathlib import Path
from datetime import datetime
import threading


class ScanLogger:
    """Sistema de logging y reportes"""
    
    def __init__(self, log_dir):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        
        # Archivo de log principal
        self.main_log = self.log_dir / "depurador.log"
        
        # Inicializar log
        self._write_log(f"\n{'='*70}\n")
        self._write_log(f"Depurador initialized at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        self._write_log(f"{'='*70}\n\n")
    
    def log_threat(self, threat_info):
        """Registrar una amenaza detectada"""
        with self.lock:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            log_entry = f"[{timestamp}] THREAT DETECTED\n"
            log_entry += f"  File: {threat_info['file']}\n"
            log_entry += f"  Severity: {threat_info['severity']}\n"
            log_entry += f"  SHA256: {threat_info['sha256']}\n"
            log_entry += f"  Type: {threat_info['type']}\n"
            log_entry += f"  Reasons:\n"
            
            for reason in threat_info['reasons']:
                log_entry += f"    - {reason}\n"
            
            log_entry += "\n"
            
            self._write_log(log_entry)
    
    def generate_report(self, threats, scan_stats):
        """Generar reporte completo del escaneo"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = self.log_dir / f"scan_report_{timestamp}.txt"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            # Header
            f.write("="*70 + "\n")
            f.write("DEPURADOR - MALWARE SCAN REPORT\n")
            f.write("="*70 + "\n\n")
            
            f.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Report File: {report_file.name}\n\n")
            
            # Summary
            f.write("-"*70 + "\n")
            f.write("SCAN SUMMARY\n")
            f.write("-"*70 + "\n\n")
            
            f.write(f"Total Files Scanned:    {scan_stats['total_scanned']}\n")
            f.write(f"Threats Detected:       {scan_stats['threats_found']}\n")
            f.write(f"Suspicious Files:       {scan_stats['suspicious_found']}\n")
            f.write(f"Clean Files:            {scan_stats['clean_files']}\n")
            f.write(f"Errors Encountered:     {scan_stats['errors']}\n\n")
            
            # Threat Details
            if threats:
                f.write("-"*70 + "\n")
                f.write("DETECTED THREATS\n")
                f.write("-"*70 + "\n\n")
                
                for idx, threat in enumerate(threats, 1):
                    f.write(f"[{idx}] {threat['severity']} THREAT\n")
                    f.write(f"{'─'*70}\n")
                    f.write(f"File Path:     {threat['file']}\n")
                    f.write(f"File Type:     {threat['type']}\n")
                    f.write(f"File Size:     {threat['size']} bytes\n")
                    f.write(f"SHA256:        {threat['sha256']}\n")
                    f.write(f"MD5:           {threat['md5']}\n")
                    f.write(f"Detection Time: {threat['timestamp']}\n\n")
                    
                    f.write("Detection Reasons:\n")
                    for reason in threat['reasons']:
                        f.write(f"  • {reason}\n")
                    
                    f.write("\nRecommended Action:\n")
                    if threat['severity'] == 'CRITICAL':
                        f.write("  ⚠ CRITICAL: Quarantine or delete this file immediately.\n")
                        f.write("  ⚠ Perform a full system scan.\n")
                        f.write("  ⚠ Check for related malicious processes.\n")
                    else:
                        f.write("  ℹ Review this file manually.\n")
                        f.write("  ℹ Consider submitting to VirusTotal for additional analysis.\n")
                    
                    f.write("\n" + "="*70 + "\n\n")
            else:
                f.write("-"*70 + "\n")
                f.write("NO THREATS DETECTED\n")
                f.write("-"*70 + "\n\n")
                f.write("✓ All scanned files appear to be clean.\n\n")
            
            # Recommendations
            f.write("-"*70 + "\n")
            f.write("GENERAL RECOMMENDATIONS\n")
            f.write("-"*70 + "\n\n")
            
            f.write("1. Keep your antivirus software up to date\n")
            f.write("2. Regularly update your operating system\n")
            f.write("3. Be cautious when downloading files from the internet\n")
            f.write("4. Use strong, unique passwords for all accounts\n")
            f.write("5. Enable two-factor authentication where available\n")
            f.write("6. Perform regular system scans\n")
            f.write("7. Backup important data regularly\n\n")
            
            # Footer
            f.write("="*70 + "\n")
            f.write("END OF REPORT\n")
            f.write("="*70 + "\n")
        
        # También generar JSON para procesamiento automatizado
        json_report = self.log_dir / f"scan_report_{timestamp}.json"
        with open(json_report, 'w', encoding='utf-8') as f:
            report_data = {
                'timestamp': datetime.now().isoformat(),
                'scan_stats': scan_stats,
                'threats': threats
            }
            json.dump(report_data, f, indent=2)
        
        self._write_log(f"Report generated: {report_file}\n")
        
        return str(report_file)
    
    def _write_log(self, message):
        """Escribir en el log principal"""
        try:
            with open(self.main_log, 'a', encoding='utf-8') as f:
                f.write(message)
        except Exception as e:
            print(f"Error writing to log: {e}")