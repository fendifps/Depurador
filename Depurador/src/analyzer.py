"""
Depurador - File Analyzer Module
Análisis detallado de ejecutables y archivos sospechosos
INTEGRACIÓN: ML Recursive Classifier para reducir falsos positivos
"""

import os
import hashlib
from pathlib import Path
from colorama import Fore

try:
    from ml_classifier import RecursiveClassifier
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print(f"{Fore.YELLOW}[!] ML Classifier not available. Install or check ml_classifier.py")


class FileAnalyzer:
    """Analizador de archivos individuales"""
    
    def __init__(self, signature_engine, logger, enable_ml=True):
        self.signature_engine = signature_engine
        self.logger = logger
        self.ml_classifier = RecursiveClassifier(enable_ml=enable_ml) if ML_AVAILABLE else None
    
    def analyze_file(self, file_path):
        """Análisis completo de un archivo"""
        result = {
            'file': file_path,
            'sha256': None,
            'md5': None,
            'size': 0,
            'is_malicious': False,
            'reasons': [],
            'pe_info': None
        }
        
        try:
            # Calcular hashes
            result['sha256'], result['md5'] = self._calculate_hashes(file_path)
            result['size'] = os.path.getsize(file_path)
            
            file_ext = Path(file_path).suffix.lower()
            
            # 1. Check signatures
            if self.signature_engine.check_hash(result['sha256'], result['md5']):
                result['is_malicious'] = True
                result['reasons'].append("Known malware hash signature detected")
            
            # 2. Filename analysis
            filename = os.path.basename(file_path).lower()
            if self.signature_engine.check_filename_pattern(filename):
                result['is_malicious'] = True
                result['reasons'].append("Suspicious filename pattern")
            
            # 3. Heuristic analysis
            with open(file_path, 'rb') as f:
                content = f.read(min(5 * 1024 * 1024, result['size']))  # Max 5MB
                
                heuristic_result = self.signature_engine.heuristic_analysis(content, file_ext)
                if heuristic_result['is_suspicious']:
                    result['is_malicious'] = True
                    result['reasons'].extend(heuristic_result['reasons'])
            
            # 4. PE Analysis para ejecutables
            if file_ext in ['.exe', '.dll', '.sys']:
                result['pe_info'] = self._analyze_pe(file_path)
                
                behavioral_result = self.signature_engine.check_behavioral_patterns(file_path)
                if behavioral_result['is_suspicious']:
                    result['is_malicious'] = True
                    result['reasons'].extend(behavioral_result['reasons'])
            
            # 5. Script analysis
            if file_ext in ['.ps1', '.bat', '.vbs', '.js']:
                script_result = self._analyze_script(file_path, content)
                if script_result['is_suspicious']:
                    result['is_malicious'] = True
                    result['reasons'].extend(script_result['reasons'])
            
            # ========== INTEGRACIÓN ML CLASSIFIER ==========
            if self.ml_classifier and self.ml_classifier.enabled:
                # Preparar info para ML
                ml_file_info = {
                    'file': file_path,
                    'size': result['size'],
                    'entropy': self._calculate_entropy_from_content(content) if 'content' in locals() else 0,
                    'known_malware_hash': 'known malware' in ' '.join(result['reasons']).lower(),
                    'suspicious_apis': self._extract_apis(result.get('pe_info', {})),
                    'suspicious_strings': [r for r in result['reasons'] if 'string' in r.lower() or 'keyword' in r.lower()],
                    'behavioral_flags': [r for r in result['reasons'] if 'behavior' in r.lower() or 'api' in r.lower()],
                    'filename_suspicious': 'filename' in ' '.join(result['reasons']).lower(),
                    'digital_signature': self._check_digital_signature(file_path)
                }
                
                # Clasificación ML
                ml_result = self.ml_classifier.classify(ml_file_info)
                
                # Votación con heurística
                heuristic_result = {
                    'classification': 'malicious' if result['is_malicious'] else 'benign',
                    'confidence': 0.7 if result['is_malicious'] else 0.6
                }
                
                final_decision = self.ml_classifier.vote_with_heuristics(ml_result, heuristic_result)
                
                # Actualizar resultado basado en ML
                result['ml_analysis'] = ml_result
                result['final_decision'] = final_decision
                
                # Override si ML dice que es falso positivo
                if final_decision['final_classification'] == 'benign' and final_decision['confidence'] > 0.75:
                    result['is_malicious'] = False
                    result['reasons'].append(f"ML Classifier Override: {ml_result['justification']}")
                    result['ml_override'] = True
                elif final_decision['final_classification'] == 'malicious' and not result['is_malicious']:
                    result['is_malicious'] = True
                    result['reasons'].append(f"ML Escalation: {ml_result['justification']}")
                    result['ml_escalation'] = True
            
            # Log analysis
            if result['is_malicious']:
                threat_info = {
                    'file': file_path,
                    'sha256': result['sha256'],
                    'md5': result['md5'],
                    'size': result['size'],
                    'type': file_ext,
                    'reasons': result['reasons'],
                    'severity': 'CRITICAL' if 'known malware' in ' '.join(result['reasons']).lower() else 'SUSPICIOUS',
                    'ml_classification': result.get('ml_analysis', {}).get('classification', 'N/A'),
                    'ml_confidence': result.get('ml_analysis', {}).get('confidence', 0.0)
                }
                self.logger.log_threat(threat_info)
            
        except Exception as e:
            result['reasons'].append(f"Analysis error: {str(e)}")
        
        return result
    
    def _calculate_entropy_from_content(self, content):
        """Calcular entropía de Shannon para el contenido"""
        if not content or len(content) == 0:
            return 0.0
        
        # Contar frecuencia de bytes
        byte_counts = [0] * 256
        for byte_val in content:
            byte_counts[byte_val] += 1
        
        # Calcular entropía
        entropy = 0.0
        content_len = len(content)
        
        for count in byte_counts:
            if count == 0:
                continue
            probability = count / content_len
            entropy -= probability * (probability.bit_length() - 1 if probability > 0 else 0)
        
        return min(entropy, 8.0)
    
    def _extract_apis(self, pe_info):
        """Extraer APIs de la información PE"""
        apis = []
        if pe_info and 'Imports' in pe_info:
            imports = pe_info['Imports'].split(', ')
            # Filtrar solo APIs sospechosas conocidas
            suspicious_keywords = ['Virtual', 'Process', 'Thread', 'Memory', 'Inject', 'Hook']
            for imp in imports:
                if any(keyword in imp for keyword in suspicious_keywords):
                    apis.append(imp)
        return apis
    
    def _check_digital_signature(self, file_path):
        """Verificar firma digital (simplificado)"""
        # En una implementación real, usarías wincrypt o similar
        # Aquí simplificamos verificando rutas conocidas
        file_path_lower = file_path.lower()
        
        if 'windows\\system32' in file_path_lower or 'windows\\syswow64' in file_path_lower:
            return {'valid': True, 'signer': 'Microsoft Corporation'}
        elif 'program files\\microsoft' in file_path_lower or 'microsoft office' in file_path_lower:
            return {'valid': True, 'signer': 'Microsoft Corporation'}
        
        return {'valid': False, 'signer': 'Unknown'}

    
    def _calculate_hashes(self, file_path):
        """Calcular hashes SHA256 y MD5"""
        sha256_hasher = hashlib.sha256()
        md5_hasher = hashlib.md5()
        
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                sha256_hasher.update(chunk)
                md5_hasher.update(chunk)
        
        return sha256_hasher.hexdigest(), md5_hasher.hexdigest()
    
    def _analyze_pe(self, file_path):
        """Analizar estructura PE (Windows Executable)"""
        pe_info = {}
        
        try:
            import pefile
            
            pe = pefile.PE(file_path)
            
            # Información básica
            pe_info['Machine'] = hex(pe.FILE_HEADER.Machine)
            pe_info['TimeDateStamp'] = pe.FILE_HEADER.TimeDateStamp
            pe_info['NumberOfSections'] = pe.FILE_HEADER.NumberOfSections
            
            # Entry point
            if hasattr(pe, 'OPTIONAL_HEADER'):
                pe_info['EntryPoint'] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
                pe_info['ImageBase'] = hex(pe.OPTIONAL_HEADER.ImageBase)
            
            # Imports
            imports = []
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT[:5]:  # Primeras 5 DLLs
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    imports.append(dll_name)
            
            pe_info['Imports'] = ', '.join(imports) if imports else 'None'
            
            # Sections
            sections = []
            for section in pe.sections[:5]:  # Primeras 5 secciones
                name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                sections.append(f"{name} ({hex(section.VirtualAddress)})")
            
            pe_info['Sections'] = ', '.join(sections) if sections else 'None'
            
            pe.close()
            
        except ImportError:
            pe_info['Error'] = 'pefile library not available - install with: pip install pefile'
        except Exception as e:
            pe_info['Error'] = f'PE analysis failed: {str(e)}'
        
        return pe_info
    
    def _analyze_script(self, file_path, content):
        """Analizar scripts (PowerShell, Batch, VBS, JS)"""
        result = {
            'is_suspicious': False,
            'reasons': []
        }
        
        try:
            # Convertir a string
            if isinstance(content, bytes):
                content = content.decode('utf-8', errors='ignore')
            
            content_lower = content.lower()
            
            # Patrones sospechosos en scripts
            suspicious_patterns = [
                ('downloadstring', 'Remote code download detected'),
                ('downloadfile', 'File download from remote source'),
                ('invoke-expression', 'Dynamic code execution detected'),
                ('iex ', 'Obfuscated execution command'),
                ('start-process', 'Process creation detected'),
                ('bypass', 'Execution policy bypass attempt'),
                ('-encodedcommand', 'Encoded PowerShell command'),
                ('hidden', 'Hidden window execution'),
                ('webclient', 'Web client usage detected'),
                ('base64', 'Base64 encoding detected (possible obfuscation)'),
                ('frombase64string', 'Base64 decoding detected'),
                ('registry', 'Registry manipulation detected'),
                ('wscript.shell', 'Shell execution via WScript'),
                ('createobject', 'ActiveX object creation'),
                ('eval(', 'Dynamic code evaluation'),
            ]
            
            for pattern, reason in suspicious_patterns:
                if pattern in content_lower:
                    result['is_suspicious'] = True
                    result['reasons'].append(reason)
            
            # Verificar obfuscación excesiva
            if content_lower.count('^') > 20:  # Batch obfuscation
                result['is_suspicious'] = True
                result['reasons'].append('Excessive obfuscation detected (^ character abuse)')
            
            # Verificar strings muy largos (posible payload)
            lines = content.split('\n')
            for line in lines:
                if len(line) > 500:
                    result['is_suspicious'] = True
                    result['reasons'].append('Extremely long line detected (possible payload)')
                    break
            
        except Exception as e:
            result['reasons'].append(f'Script analysis error: {str(e)}')
        
        return result