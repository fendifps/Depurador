"""
Depurador - Signature Engine
Motor de detección basado en firmas, heurísticas y patrones
"""

import json
import re
from pathlib import Path


class SignatureEngine:
    """Motor de firmas y detección heurística"""
    
    def __init__(self, signatures_dir):
        self.signatures_dir = Path(signatures_dir)
        self.malware_hashes = {}
        self.heuristic_rules = []
        self.behavioral_patterns = []
        self.filename_patterns = []
        
        self._load_signatures()
    
    def _load_signatures(self):
        """Cargar todas las firmas y reglas"""
        # Cargar hashes maliciosos
        hash_file = self.signatures_dir / "malware_hashes.json"
        if hash_file.exists():
            with open(hash_file, 'r') as f:
                data = json.load(f)
                self.malware_hashes = data.get('hashes', {})
        
        # Cargar reglas heurísticas
        heuristic_file = self.signatures_dir / "heuristic_rules.json"
        if heuristic_file.exists():
            with open(heuristic_file, 'r') as f:
                data = json.load(f)
                self.heuristic_rules = data.get('rules', [])
        
        # Cargar patrones de comportamiento
        behavioral_file = self.signatures_dir / "behavioral_patterns.json"
        if behavioral_file.exists():
            with open(behavioral_file, 'r') as f:
                data = json.load(f)
                self.behavioral_patterns = data.get('patterns', [])
                self.filename_patterns = data.get('filename_patterns', [])
    
    def reload_signatures(self):
        """Recargar firmas desde disco"""
        self._load_signatures()
    
    def check_hash(self, sha256, md5):
        """Verificar si el hash coincide con malware conocido"""
        if sha256 in self.malware_hashes:
            return True
        
        if md5 in self.malware_hashes:
            return True
        
        return False
    
    def check_filename_pattern(self, filename):
        """Verificar patrones sospechosos en nombres de archivo"""
        filename_lower = filename.lower()
        
        for pattern in self.filename_patterns:
            try:
                if re.search(pattern, filename_lower):
                    return True
            except re.error:
                continue
        
        return False
    
    def heuristic_analysis(self, content, file_extension):
        """Análisis heurístico del contenido"""
        result = {
            'is_suspicious': False,
            'reasons': []
        }
        
        try:
            # Convertir a bytes si es necesario
            if isinstance(content, str):
                content = content.encode('utf-8', errors='ignore')
            
            # Aplicar reglas heurísticas
            for rule in self.heuristic_rules:
                if self._apply_heuristic_rule(rule, content, file_extension):
                    result['is_suspicious'] = True
                    result['reasons'].append(rule['description'])
            
            # Detección de strings sospechosos
            suspicious_strings = self._detect_suspicious_strings(content)
            if suspicious_strings:
                result['is_suspicious'] = True
                result['reasons'].extend(suspicious_strings)
            
            # Análisis de entropía (detectar cifrado/obfuscación)
            if self._calculate_entropy(content) > 7.5:
                result['is_suspicious'] = True
                result['reasons'].append('High entropy detected (possible encryption/packing)')
            
        except Exception as e:
            result['reasons'].append(f'Heuristic analysis error: {str(e)}')
        
        return result
    
    def check_behavioral_patterns(self, file_path):
        """Verificar patrones de comportamiento sospechoso"""
        result = {
            'is_suspicious': False,
            'reasons': []
        }
        
        try:
            # Leer contenido para análisis
            with open(file_path, 'rb') as f:
                content = f.read(min(2 * 1024 * 1024, 10 * 1024 * 1024))  # Max 2MB para análisis
            
            # Aplicar patrones de comportamiento
            for pattern in self.behavioral_patterns:
                if self._check_pattern(pattern, content):
                    result['is_suspicious'] = True
                    result['reasons'].append(pattern['description'])
        
        except Exception as e:
            result['reasons'].append(f'Behavioral analysis error: {str(e)}')
        
        return result
    
    def _apply_heuristic_rule(self, rule, content, file_extension):
        """Aplicar una regla heurística"""
        try:
            # Verificar si la regla aplica a esta extensión
            if 'extensions' in rule:
                if file_extension not in rule['extensions']:
                    return False
            
            # Verificar el tipo de regla
            if rule['type'] == 'byte_pattern':
                pattern = bytes.fromhex(rule['pattern'])
                return pattern in content
            
            elif rule['type'] == 'string_pattern':
                pattern_str = rule['pattern']
                if isinstance(content, bytes):
                    content_str = content.decode('utf-8', errors='ignore')
                else:
                    content_str = content
                return pattern_str.lower() in content_str.lower()
            
            elif rule['type'] == 'regex':
                if isinstance(content, bytes):
                    content_str = content.decode('utf-8', errors='ignore')
                else:
                    content_str = content
                return re.search(rule['pattern'], content_str, re.IGNORECASE) is not None
        
        except Exception:
            return False
        
        return False
    
    def _detect_suspicious_strings(self, content):
        """Detectar strings sospechosos en el contenido"""
        suspicious = []
        
        try:
            if isinstance(content, bytes):
                content_str = content.decode('utf-8', errors='ignore')
            else:
                content_str = content
            
            content_lower = content_str.lower()
            
            # Lista de strings sospechosos
            suspicious_keywords = {
                'ransomware': 'Ransomware-related strings detected',
                'encrypt': 'Encryption functionality detected',
                'bitcoin': 'Cryptocurrency references found',
                'keylog': 'Keylogging functionality detected',
                'rootkit': 'Rootkit indicators found',
                'inject': 'Code injection indicators',
                'privilege': 'Privilege escalation indicators',
                'mimikatz': 'Known hacking tool reference (Mimikatz)',
                'metasploit': 'Known hacking tool reference (Metasploit)',
                'shellcode': 'Shellcode indicators detected',
                'payload': 'Payload indicators detected'
            }
            
            for keyword, description in suspicious_keywords.items():
                if keyword in content_lower:
                    suspicious.append(description)
        
        except Exception:
            pass
        
        return suspicious
    
    def _calculate_entropy(self, data):
        """Calcular entropía de Shannon (detectar cifrado/compresión)"""
        if not data:
            return 0
        
        try:
            # Contar frecuencia de bytes
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            # Calcular entropía
            entropy = 0
            data_len = len(data)
            
            for count in byte_counts:
                if count == 0:
                    continue
                
                probability = count / data_len
                entropy -= probability * (probability.bit_length() - 1)
            
            return entropy
        
        except Exception:
            return 0
    
    def _check_pattern(self, pattern, content):
        """Verificar un patrón de comportamiento"""
        try:
            if pattern['type'] == 'api_call':
                # Buscar referencias a APIs sospechosas
                api_name = pattern['api_name'].encode('utf-8', errors='ignore')
                return api_name in content
            
            elif pattern['type'] == 'import':
                # Buscar imports sospechosos
                import_name = pattern['import_name'].encode('utf-8', errors='ignore')
                return import_name in content
            
            elif pattern['type'] == 'section':
                # Buscar nombres de sección sospechosos
                section_name = pattern['section_name'].encode('utf-8', errors='ignore')
                return section_name in content
        
        except Exception:
            return False
        
        return False