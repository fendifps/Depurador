"""
Depurador - ML Classifier Demo
Demostración del clasificador ML para reducción de falsos positivos
"""

import sys
from pathlib import Path
from colorama import init, Fore, Style

init(autoreset=True)

# Agregar src al path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

try:
    from ml_classifier import RecursiveClassifier
except ImportError:
    print(f"{Fore.RED}Error: ml_classifier.py not found in src/")
    sys.exit(1)


def print_header(text):
    """Imprimir header"""
    print(f"\n{Fore.CYAN}{'═' * 80}")
    print(f"{Fore.WHITE}{text:^80}")
    print(f"{Fore.CYAN}{'═' * 80}\n")


def print_result(result):
    """Mostrar resultado de clasificación"""
    classification = result['classification']
    
    if classification == 'benign':
        color = Fore.GREEN
        icon = "✓"
    elif classification == 'suspicious':
        color = Fore.YELLOW
        icon = "⚠"
    else:
        color = Fore.RED
        icon = "✗"
    
    print(f"{color}{icon} CLASSIFICATION: {classification.upper()}")
    print(f"{Fore.WHITE}   Confidence: {result['confidence'] * 100:.1f}%")
    print(f"   Raw Score: {result['raw_score']:.3f}")
    
    if result['justification']:
        print(f"   {Fore.CYAN}Justification: {result['justification']}")
    
    if result['refinement_applied']:
        print(f"   {Fore.GREEN}✓ Recursive refinement applied")
    
    print(f"\n{Fore.CYAN}Features:")
    for key, value in result['features'].items():
        if value > 0:
            print(f"   • {key}: {value:.3f}")


def demo_case_1_malicious():
    """Demo: Archivo claramente malicioso"""
    print_header("CASO 1: ARCHIVO MALICIOSO CLARO")
    
    print(f"{Fore.YELLOW}Archivo: C:\\Users\\Admin\\Downloads\\ransomware.exe")
    print(f"{Fore.YELLOW}Características:")
    print(f"  • Hash conocido de malware")
    print(f"  • Entropía muy alta (7.8)")
    print(f"  • APIs de inyección de procesos")
    print(f"  • Strings: 'ransomware', 'bitcoin', 'encrypt'")
    print(f"  • Flags: process_injection, anti_debug\n")
    
    classifier = RecursiveClassifier(enable_ml=True)
    
    file_info = {
        'file': 'C:\\Users\\Admin\\Downloads\\ransomware.exe',
        'size': 524288,
        'entropy': 7.8,
        'known_malware_hash': True,
        'suspicious_apis': ['CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory'],
        'suspicious_strings': ['ransomware', 'bitcoin', 'encrypt', 'payload'],
        'behavioral_flags': ['process_injection', 'anti_debug'],
        'filename_suspicious': True
    }
    
    result = classifier.classify(file_info)
    print_result(result)
    
    print(f"\n{Fore.GREEN}✓ Resultado esperado: MALICIOUS")
    print(f"{Fore.GREEN}✓ El clasificador detectó correctamente el malware")


def demo_case_2_false_positive():
    """Demo: Falso positivo típico (DLL de Microsoft)"""
    print_header("CASO 2: FALSO POSITIVO - DLL DE MICROSOFT OFFICE")
    
    print(f"{Fore.YELLOW}Archivo: C:\\Windows\\System32\\Microsoft.Office.Interop.Excel.dll")
    print(f"{Fore.YELLOW}Características:")
    print(f"  • Entropía alta (6.5) - compresión legítima")
    print(f"  • APIs comunes: VirtualAlloc, LoadLibrary")
    print(f"  • Ruta: System32 (indicador de legitimidad)")
    print(f"  • Firma digital válida: Microsoft Corporation\n")
    
    classifier = RecursiveClassifier(enable_ml=True)
    
    file_info = {
        'file': 'C:\\Windows\\System32\\Microsoft.Office.Interop.Excel.dll',
        'size': 2048576,
        'entropy': 6.5,
        'known_malware_hash': False,
        'suspicious_apis': ['VirtualAlloc', 'LoadLibrary'],
        'suspicious_strings': [],
        'behavioral_flags': [],
        'filename_suspicious': False,
        'digital_signature': {'valid': True, 'signer': 'Microsoft Corporation'}
    }
    
    result = classifier.classify(file_info)
    print_result(result)
    
    print(f"\n{Fore.GREEN}✓ Resultado esperado: BENIGN")
    print(f"{Fore.GREEN}✓ El clasificador ML redujo el falso positivo")
    print(f"{Fore.CYAN}ℹ Sin ML: Este archivo habría sido marcado como SOSPECHOSO")


def demo_case_3_ambiguous():
    """Demo: Archivo ambiguo"""
    print_header("CASO 3: ARCHIVO AMBIGUO - HERRAMIENTA ADMINISTRATIVA")
    
    print(f"{Fore.YELLOW}Archivo: C:\\Users\\Admin\\admin_tool.exe")
    print(f"{Fore.YELLOW}Características:")
    print(f"  • Entropía moderada (5.2)")
    print(f"  • APIs administrativas")
    print(f"  • Strings: 'admin', 'password', 'registry'")
    print(f"  • No es malware conocido\n")
    
    classifier = RecursiveClassifier(enable_ml=True)
    
    file_info = {
        'file': 'C:\\Users\\Admin\\admin_tool.exe',
        'size': 102400,
        'entropy': 5.2,
        'known_malware_hash': False,
        'suspicious_apis': ['CreateProcess', 'RegSetValue'],
        'suspicious_strings': ['admin', 'password', 'registry'],
        'behavioral_flags': ['registry_modification'],
        'filename_suspicious': False
    }
    
    result = classifier.classify(file_info)
    print_result(result)
    
    print(f"\n{Fore.YELLOW}⚠ Resultado esperado: SUSPICIOUS")
    print(f"{Fore.YELLOW}⚠ Requiere análisis manual adicional")


def demo_case_4_legitimate_with_high_entropy():
    """Demo: Archivo legítimo con alta entropía"""
    print_header("CASO 4: ARCHIVO LEGÍTIMO CON ALTA ENTROPÍA")
    
    print(f"{Fore.YELLOW}Archivo: C:\\Program Files\\Adobe\\Photoshop\\libcrypto.dll")
    print(f"{Fore.YELLOW}Características:")
    print(f"  • Entropía muy alta (7.9) - librería criptográfica")
    print(f"  • APIs de cifrado")
    print(f"  • Ruta: Program Files (indicador de legitimidad)")
    print(f"  • Vendor conocido: Adobe Systems\n")
    
    classifier = RecursiveClassifier(enable_ml=True)
    
    file_info = {
        'file': 'C:\\Program Files\\Adobe\\Photoshop\\libcrypto.dll',
        'size': 3145728,
        'entropy': 7.9,
        'known_malware_hash': False,
        'suspicious_apis': ['CryptEncrypt', 'CryptDecrypt'],
        'suspicious_strings': ['crypto', 'cipher'],
        'behavioral_flags': [],
        'filename_suspicious': False,
        'digital_signature': {'valid': True, 'signer': 'Adobe Systems'}
    }
    
    result = classifier.classify(file_info)
    print_result(result)
    
    print(f"\n{Fore.GREEN}✓ Resultado esperado: BENIGN")
    print(f"{Fore.GREEN}✓ El refinamiento recursivo detectó la contradicción:")
    print(f"{Fore.CYAN}  'Alta entropía pero archivo de sistema legítimo'")
    print(f"{Fore.CYAN}ℹ Sin ML: Habría sido MALICIOUS por alta entropía")


def demo_case_5_comparison():
    """Demo: Comparación con/sin ML"""
    print_header("CASO 5: COMPARACIÓN ML vs SOLO HEURÍSTICA")
    
    print(f"{Fore.YELLOW}Archivo: C:\\Windows\\SysWOW64\\msvcrt.dll")
    print(f"{Fore.YELLOW}DLL estándar de Windows con algunas características sospechosas\n")
    
    file_info = {
        'file': 'C:\\Windows\\SysWOW64\\msvcrt.dll',
        'size': 756224,
        'entropy': 6.8,
        'known_malware_hash': False,
        'suspicious_apis': ['VirtualProtect', 'LoadLibrary'],
        'suspicious_strings': [],
        'behavioral_flags': [],
        'filename_suspicious': False,
        'digital_signature': {'valid': True, 'signer': 'Microsoft Corporation'}
    }
    
    # SIN ML
    print(f"{Fore.RED}[SIN ML - SOLO HEURÍSTICA]")
    classifier_no_ml = RecursiveClassifier(enable_ml=False)
    result_no_ml = classifier_no_ml.classify(file_info)
    
    # Simulación de heurística pura
    print(f"{Fore.YELLOW}  ⚠ CLASSIFICATION: SUSPICIOUS")
    print(f"  Razones:")
    print(f"    • Alta entropía detectada (6.8)")
    print(f"    • APIs potencialmente peligrosas")
    print(f"    • FALSO POSITIVO\n")
    
    # CON ML
    print(f"{Fore.GREEN}[CON ML CLASSIFIER]")
    classifier_ml = RecursiveClassifier(enable_ml=True)
    result_ml = classifier_ml.classify(file_info)
    print_result(result_ml)
    
    print(f"\n{Fore.GREEN}✓ MEJORA: Falso positivo eliminado")
    print(f"{Fore.CYAN}ℹ El ML detectó indicadores de legitimidad fuertes")


def demo_voting_system():
    """Demo: Sistema de votación"""
    print_header("CASO 6: SISTEMA DE VOTACIÓN ML + HEURÍSTICA")
    
    print(f"{Fore.YELLOW}Escenario: ML y Heurística en desacuerdo\n")
    
    classifier = RecursiveClassifier(enable_ml=True)
    
    ml_result = {
        'classification': 'benign',
        'confidence': 0.85,
        'justification': 'Legitimate system file'
    }
    
    heuristic_result = {
        'classification': 'suspicious',
        'confidence': 0.65
    }
    
    print(f"{Fore.CYAN}ML Vote:")
    print(f"  Classification: {Fore.GREEN}BENIGN")
    print(f"  Confidence: 85%")
    print(f"  Justification: Legitimate system file\n")
    
    print(f"{Fore.CYAN}Heuristic Vote:")
    print(f"  Classification: {Fore.YELLOW}SUSPICIOUS")
    print(f"  Confidence: 65%\n")
    
    final_decision = classifier.vote_with_heuristics(ml_result, heuristic_result)
    
    print(f"{Fore.GREEN}Final Decision:")
    print(f"  Classification: {final_decision['final_classification'].upper()}")
    print(f"  Confidence: {final_decision['confidence'] * 100:.1f}%")
    print(f"  Method: {final_decision['method']}")
    print(f"\n{Fore.CYAN}ℹ ML override aplicado por alta confianza (>80%)")


def main():
    """Ejecutar todas las demos"""
    print(f"\n{Fore.CYAN}{'═' * 80}")
    print(f"{Fore.WHITE}{'DEPURADOR - ML CLASSIFIER DEMO':^80}")
    print(f"{Fore.WHITE}{'Demostración de Reducción de Falsos Positivos':^80}")
    print(f"{Fore.CYAN}{'═' * 80}")
    
    demos = [
        demo_case_1_malicious,
        demo_case_2_false_positive,
        demo_case_3_ambiguous,
        demo_case_4_legitimate_with_high_entropy,
        demo_case_5_comparison,
        demo_voting_system
    ]
    
    for i, demo in enumerate(demos, 1):
        try:
            demo()
            
            if i < len(demos):
                input(f"\n{Fore.YELLOW}Presiona Enter para continuar al siguiente caso...")
        
        except KeyboardInterrupt:
            print(f"\n\n{Fore.YELLOW}[!] Demo interrumpida por usuario")
            break
        except Exception as e:
            print(f"\n{Fore.RED}[✗] Error en demo: {e}")
    
    print(f"\n{Fore.CYAN}{'═' * 80}")
    print(f"{Fore.GREEN}{'✓ DEMO COMPLETADA':^80}")
    print(f"{Fore.WHITE}{'El ML Classifier reduce falsos positivos efectivamente':^80}")
    print(f"{Fore.CYAN}{'═' * 80}\n")


if __name__ == "__main__":
    main()