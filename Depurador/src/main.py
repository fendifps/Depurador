"""
Depurador - Malware Scanner Elite
Main Entry Point
Author: Cybersecurity Research Team
Version: 1.0.0
"""

import os
import sys
import json
from pathlib import Path
from colorama import init, Fore, Style
from datetime import datetime

# Inicializar colorama para Windows
init(autoreset=True)

# Agregar el directorio src al path
sys.path.insert(0, str(Path(__file__).parent))

from scanner import SystemScanner
from analyzer import FileAnalyzer
from signature_engine import SignatureEngine
from logger import ScanLogger


class DepuradorCore:
    """Clase principal del escáner de malware"""
    
    def __init__(self):
        self.base_path = Path(__file__).parent.parent
        self.config = self._load_config()
        self.logger = ScanLogger(self.base_path / "logs")
        self.signature_engine = SignatureEngine(self.base_path / "signatures")
        self.scanner = SystemScanner(self.signature_engine, self.logger)
        self.analyzer = FileAnalyzer(self.signature_engine, self.logger)
        
    def _load_config(self):
        """Cargar configuración del sistema"""
        config_path = self.base_path / "config.json"
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"{Fore.YELLOW}⚠ Warning: Could not load config.json, using defaults")
            return self._default_config()
    
    def _default_config(self):
        """Configuración por defecto"""
        return {
            "scan_paths": ["C:\\"],
            "max_file_size_mb": 100,
            "excluded_extensions": [".tmp", ".log"],
            "max_threads": 8,
            "deep_scan": False
        }
    
    def print_banner(self):
        """Mostrar banner de inicio"""
        banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║  {Fore.RED}██████╗ ███████╗██████╗ ██╗   ██╗██████╗  █████╗ ██████╗  {Fore.CYAN}║
║  {Fore.RED}██╔══██╗██╔════╝██╔══██╗██║   ██║██╔══██╗██╔══██╗██╔══██╗ {Fore.CYAN}║
║  {Fore.RED}██║  ██║█████╗  ██████╔╝██║   ██║██████╔╝███████║██║  ██║ {Fore.CYAN}║
║  {Fore.RED}██║  ██║██╔══╝  ██╔═══╝ ██║   ██║██╔══██╗██╔══██║██║  ██║ {Fore.CYAN}║
║  {Fore.RED}██████╔╝███████╗██║     ╚██████╔╝██║  ██║██║  ██║██████╔╝ {Fore.CYAN}║
║  {Fore.RED}╚═════╝ ╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  {Fore.CYAN}║
║                                                               ║
║          {Fore.WHITE}Malware Scanner Elite - Version 1.0.0{Fore.CYAN}             ║
║     {Fore.YELLOW}Advanced Threat Detection & Analysis System{Fore.CYAN}          ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner)
        print(f"{Fore.GREEN}[✓] Signature Engine: {Fore.WHITE}{len(self.signature_engine.malware_hashes)} signatures loaded")
        print(f"{Fore.GREEN}[✓] Heuristic Rules: {Fore.WHITE}{len(self.signature_engine.heuristic_rules)} rules active")
        print(f"{Fore.GREEN}[✓] Behavioral Patterns: {Fore.WHITE}{len(self.signature_engine.behavioral_patterns)} patterns loaded")
        print(f"{Fore.GREEN}[✓] Logs Directory: {Fore.WHITE}{self.logger.log_dir}\n")
    
    def show_menu(self):
        """Mostrar menú principal"""
        print(f"\n{Fore.CYAN}{'═' * 65}")
        print(f"{Fore.WHITE}[1] {Fore.YELLOW}Full System Scan")
        print(f"{Fore.WHITE}[2] {Fore.YELLOW}Quick Scan (User Directories)")
        print(f"{Fore.WHITE}[3] {Fore.YELLOW}Analyze Single File/Executable")
        print(f"{Fore.WHITE}[4] {Fore.YELLOW}Custom Path Scan")
        print(f"{Fore.WHITE}[5] {Fore.YELLOW}View Last Scan Report")
        print(f"{Fore.WHITE}[6] {Fore.YELLOW}Update Signatures")
        print(f"{Fore.WHITE}[0] {Fore.RED}Exit")
        print(f"{Fore.CYAN}{'═' * 65}")
        
    def run(self):
        """Ejecutar el programa principal"""
        self.print_banner()
        
        while True:
            self.show_menu()
            choice = input(f"\n{Fore.GREEN}[?] Select option: {Fore.WHITE}").strip()
            
            if choice == "1":
                self.full_system_scan()
            elif choice == "2":
                self.quick_scan()
            elif choice == "3":
                self.analyze_file()
            elif choice == "4":
                self.custom_scan()
            elif choice == "5":
                self.view_report()
            elif choice == "6":
                self.update_signatures()
            elif choice == "0":
                print(f"\n{Fore.CYAN}[!] Exiting Depurador... Stay safe!")
                break
            else:
                print(f"{Fore.RED}[✗] Invalid option. Try again.")
    
    def full_system_scan(self):
        """Escaneo completo del sistema"""
        print(f"\n{Fore.YELLOW}[!] Starting FULL SYSTEM SCAN...")
        print(f"{Fore.RED}[!] This may take a while. Press Ctrl+C to cancel.\n")
        
        try:
            results = self.scanner.scan_paths(self.config["scan_paths"])
            self._display_results(results)
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Scan cancelled by user.")
        except Exception as e:
            print(f"{Fore.RED}[✗] Error during scan: {e}")
    
    def quick_scan(self):
        """Escaneo rápido de directorios del usuario"""
        print(f"\n{Fore.YELLOW}[!] Starting QUICK SCAN...")
        user_paths = [
            str(Path.home() / "Downloads"),
            str(Path.home() / "Documents"),
            str(Path.home() / "Desktop"),
            str(Path.home() / "AppData" / "Local" / "Temp")
        ]
        
        try:
            results = self.scanner.scan_paths(user_paths)
            self._display_results(results)
        except Exception as e:
            print(f"{Fore.RED}[✗] Error during scan: {e}")
    
    def analyze_file(self):
        """Analizar un archivo específico"""
        file_path = input(f"\n{Fore.GREEN}[?] Enter file path: {Fore.WHITE}").strip('"')
        
        if not os.path.exists(file_path):
            print(f"{Fore.RED}[✗] File not found!")
            return
        
        print(f"\n{Fore.YELLOW}[!] Analyzing file: {file_path}\n")
        
        try:
            result = self.analyzer.analyze_file(file_path)
            self._display_single_result(result)
        except Exception as e:
            print(f"{Fore.RED}[✗] Error analyzing file: {e}")
    
    def custom_scan(self):
        """Escaneo de ruta personalizada"""
        path = input(f"\n{Fore.GREEN}[?] Enter path to scan: {Fore.WHITE}").strip('"')
        
        if not os.path.exists(path):
            print(f"{Fore.RED}[✗] Path not found!")
            return
        
        print(f"\n{Fore.YELLOW}[!] Scanning: {path}\n")
        
        try:
            results = self.scanner.scan_paths([path])
            self._display_results(results)
        except Exception as e:
            print(f"{Fore.RED}[✗] Error during scan: {e}")
    
    def view_report(self):
        """Ver el último reporte"""
        reports = sorted(self.logger.log_dir.glob("scan_report_*.txt"), reverse=True)
        
        if not reports:
            print(f"{Fore.YELLOW}[!] No reports found.")
            return
        
        latest = reports[0]
        print(f"\n{Fore.CYAN}[+] Latest Report: {latest.name}\n")
        
        try:
            with open(latest, 'r', encoding='utf-8') as f:
                print(f.read())
        except Exception as e:
            print(f"{Fore.RED}[✗] Error reading report: {e}")
    
    def update_signatures(self):
        """Actualizar base de datos de firmas"""
        print(f"\n{Fore.YELLOW}[!] Updating signature database...")
        try:
            self.signature_engine.reload_signatures()
            print(f"{Fore.GREEN}[✓] Signatures updated successfully!")
            print(f"{Fore.GREEN}[✓] {len(self.signature_engine.malware_hashes)} signatures loaded")
        except Exception as e:
            print(f"{Fore.RED}[✗] Error updating signatures: {e}")
    
    def _display_results(self, results):
        """Mostrar resultados del escaneo"""
        print(f"\n{Fore.CYAN}{'═' * 65}")
        print(f"{Fore.WHITE}SCAN RESULTS")
        print(f"{Fore.CYAN}{'═' * 65}\n")
        
        print(f"{Fore.GREEN}[+] Files Scanned: {Fore.WHITE}{results['total_scanned']}")
        print(f"{Fore.RED}[+] Threats Found: {Fore.WHITE}{results['threats_found']}")
        print(f"{Fore.YELLOW}[+] Suspicious Files: {Fore.WHITE}{results['suspicious_found']}")
        print(f"{Fore.BLUE}[+] Clean Files: {Fore.WHITE}{results['clean_files']}\n")
        
        if results['threats']:
            print(f"{Fore.RED}{'─' * 65}")
            print(f"{Fore.RED}DETECTED THREATS:")
            print(f"{Fore.RED}{'─' * 65}\n")
            
            for threat in results['threats'][:10]:  # Mostrar solo las primeras 10
                severity_color = Fore.RED if threat['severity'] == 'CRITICAL' else Fore.YELLOW
                print(f"{severity_color}[!] {threat['severity']}: {threat['file']}")
                print(f"    Type: {threat['type']}")
                print(f"    Reason: {threat['reason']}\n")
            
            if len(results['threats']) > 10:
                print(f"{Fore.YELLOW}... and {len(results['threats']) - 10} more threats")
        
        print(f"\n{Fore.GREEN}[✓] Full report saved to: {results['report_path']}")
    
    def _display_single_result(self, result):
        """Mostrar resultado de análisis individual"""
        print(f"{Fore.CYAN}{'═' * 65}")
        print(f"{Fore.WHITE}ANALYSIS RESULTS")
        print(f"{Fore.CYAN}{'═' * 65}\n")
        
        status_color = Fore.RED if result['is_malicious'] else Fore.GREEN
        status = "MALICIOUS" if result['is_malicious'] else "CLEAN"
        
        print(f"{status_color}[STATUS]: {status}\n")
        print(f"{Fore.WHITE}File: {result['file']}")
        print(f"SHA256: {result['sha256']}")
        print(f"MD5: {result['md5']}")
        print(f"Size: {result['size']} bytes")
        
        if result['is_malicious']:
            print(f"\n{Fore.RED}[!] THREATS DETECTED:")
            for reason in result['reasons']:
                print(f"    • {reason}")
        
        if result.get('pe_info'):
            print(f"\n{Fore.CYAN}[PE INFO]:")
            for key, value in result['pe_info'].items():
                print(f"    {key}: {value}")


def main():
    """Punto de entrada principal"""
    try:
        depurador = DepuradorCore()
        depurador.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Program interrupted by user.")
    except Exception as e:
        print(f"{Fore.RED}[✗] Fatal error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()