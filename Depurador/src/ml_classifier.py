"""
Depurador - ML Classifier Module
Sistema de clasificación ML ligero inspirado en Tiny Recursive Model
Especializado en reducción de falsos positivos
"""

import json
import hashlib
from pathlib import Path
from typing import Dict, List, Tuple
import math


class RecursiveClassifier:
    """
    Clasificador recursivo ligero para archivos
    Inspirado en TRM pero adaptado para detección de malware
    """
    
    # Pesos ajustados empíricamente
    WEIGHTS = {
        'known_hash': 1.0,          # Hash conocido = máxima confianza
        'entropy': 0.6,              # Entropía alta
        'suspicious_apis': 0.8,      # APIs peligrosas
        'suspicious_strings': 0.7,   # Strings sospechosos
        'behavioral': 0.75,          # Patrones comportamentales
        'filename': 0.5,             # Nombre de archivo
        'size': 0.3,                 # Tamaño anómalo
        'legitimate_indicators': -0.9  # Indicadores de legitimidad (reduce score)
    }
    
    # Indicadores de archivos legítimos
    LEGITIMATE_SIGNATURES = {
        'microsoft_office': [
            'Microsoft Corporation',
            'Microsoft Office',
            'MSOCACHE',
            'Office15',
            'Office16'
        ],
        'microsoft_system': [
            'Microsoft Windows',
            'Windows System32',
            'System Volume Information',
            'C:\\Windows\\System32',
            'C:\\Windows\\SysWOW64'
        ],
        'known_vendors': [
            'Adobe Systems',
            'Google LLC',
            'Mozilla Corporation',
            'Apple Inc.',
            'Intel Corporation',
            'NVIDIA Corporation'
        ]
    }
    
    def __init__(self, enable_ml=True):
        """
        Inicializar clasificador
        
        Args:
            enable_ml: Si False, desactiva el clasificador ML para pruebas A/B
        """
        self.enabled = enable_ml
        self.refinement_steps = 3  # Número de pasos de refinamiento recursivo
    
    def extract_features(self, file_info: Dict) -> Dict:
        """
        Extraer features normalizados de un archivo
        
        Args:
            file_info: Diccionario con información del archivo
        
        Returns:
            Dict con features normalizados [0-1]
        """
        features = {
            'entropy': 0.0,
            'size_score': 0.0,
            'api_score': 0.0,
            'string_score': 0.0,
            'behavioral_score': 0.0,
            'filename_score': 0.0,
            'legitimacy_score': 0.0,
            'known_hash': 0.0
        }
        
        # 1. Entropy score
        if 'entropy' in file_info:
            # Normalizar entropía (0-8 bits) a [0-1]
            features['entropy'] = min(file_info['entropy'] / 8.0, 1.0)
        
        # 2. Size score (archivos muy pequeños o muy grandes son sospechosos)
        if 'size' in file_info:
            size = file_info['size']
            # Tamaño óptimo: 10KB - 10MB
            if size < 1024:  # < 1KB
                features['size_score'] = 0.7
            elif size > 50 * 1024 * 1024:  # > 50MB
                features['size_score'] = 0.6
            else:
                features['size_score'] = 0.0
        
        # 3. API score
        if 'suspicious_apis' in file_info:
            api_count = len(file_info['suspicious_apis'])
            features['api_score'] = min(api_count / 5.0, 1.0)  # Normalizar
        
        # 4. String score
        if 'suspicious_strings' in file_info:
            string_count = len(file_info['suspicious_strings'])
            features['string_score'] = min(string_count / 5.0, 1.0)
        
        # 5. Behavioral score
        if 'behavioral_flags' in file_info:
            flag_count = len(file_info['behavioral_flags'])
            features['behavioral_score'] = min(flag_count / 4.0, 1.0)
        
        # 6. Filename score
        if 'filename_suspicious' in file_info:
            features['filename_score'] = 1.0 if file_info['filename_suspicious'] else 0.0
        
        # 7. Known hash
        if 'known_malware_hash' in file_info:
            features['known_hash'] = 1.0 if file_info['known_malware_hash'] else 0.0
        
        # 8. Legitimacy indicators (reduce false positives)
        features['legitimacy_score'] = self._calculate_legitimacy(file_info)
        
        return features
    
    def _calculate_legitimacy(self, file_info: Dict) -> float:
        """
        Calcular score de legitimidad (0 = sospechoso, 1 = claramente legítimo)
        """
        legitimacy = 0.0
        checks = 0
        
        file_path = file_info.get('file', '').lower()
        
        # Check 1: Ruta del archivo
        for category, indicators in self.LEGITIMATE_SIGNATURES.items():
            for indicator in indicators:
                if indicator.lower() in file_path:
                    legitimacy += 1.0
                    checks += 1
                    break
        
        # Check 2: Firma digital (si disponible)
        if 'digital_signature' in file_info:
            if file_info['digital_signature'].get('valid', False):
                legitimacy += 1.0
                checks += 1
        
        # Check 3: Ubicación en System32
        if 'system32' in file_path or 'syswow64' in file_path:
            legitimacy += 0.8
            checks += 1
        
        # Check 4: Microsoft DLLs
        if file_path.endswith('.dll') and ('microsoft' in file_path or 'windows' in file_path):
            legitimacy += 0.9
            checks += 1
        
        # Check 5: Archivos en Program Files
        if 'program files' in file_path:
            legitimacy += 0.5
            checks += 1
        
        return legitimacy / max(checks, 1)
    
    def recursive_refinement(self, features: Dict, initial_score: float, step: int = 0) -> Tuple[float, str]:
        """
        Refinamiento recursivo del score (inspirado en TRM)
        
        Args:
            features: Features extraídos
            initial_score: Score inicial
            step: Paso de recursión actual
        
        Returns:
            (score_refinado, justificación)
        """
        if step >= self.refinement_steps:
            return initial_score, "Max refinement steps reached"
        
        # Paso 1: Analizar contradicciones
        contradictions = self._detect_contradictions(features, initial_score)
        
        if not contradictions:
            return initial_score, "No contradictions found"
        
        # Paso 2: Ajustar score basado en contradicciones
        adjusted_score = initial_score
        justifications = []
        
        for contradiction in contradictions:
            adjusted_score *= contradiction['adjustment']
            justifications.append(contradiction['reason'])
        
        # Paso 3: Recursión si el ajuste es significativo
        if abs(adjusted_score - initial_score) > 0.1:
            return self.recursive_refinement(features, adjusted_score, step + 1)
        
        return adjusted_score, "; ".join(justifications)
    
    def _detect_contradictions(self, features: Dict, current_score: float) -> List[Dict]:
        """
        Detectar contradicciones en la clasificación
        """
        contradictions = []
        
        # Contradicción 1: Score alto pero alta legitimidad
        if current_score > 0.6 and features['legitimacy_score'] > 0.7:
            contradictions.append({
                'adjustment': 0.3,  # Reducir score 70%
                'reason': 'High legitimacy indicators detected (likely false positive)'
            })
        
        # Contradicción 2: Hash conocido pero bajo score de features
        if features['known_hash'] == 1.0 and current_score < 0.8:
            contradictions.append({
                'adjustment': 1.5,  # Aumentar score
                'reason': 'Known malware hash but low feature score'
            })
        
        # Contradicción 3: Alta entropía pero sistema legítimo
        if features['entropy'] > 0.8 and features['legitimacy_score'] > 0.6:
            contradictions.append({
                'adjustment': 0.5,
                'reason': 'High entropy but legitimate system file (possibly compressed)'
            })
        
        # Contradicción 4: Muchas APIs sospechosas pero sin otros indicadores
        if features['api_score'] > 0.7 and features['string_score'] < 0.2 and features['behavioral_score'] < 0.2:
            contradictions.append({
                'adjustment': 0.7,
                'reason': 'High API score but low other indicators (may be legitimate tool)'
            })
        
        # Contradicción 5: Nombre sospechoso pero todo lo demás limpio
        if features['filename_score'] > 0.5 and sum([
            features['entropy'],
            features['api_score'],
            features['string_score'],
            features['behavioral_score']
        ]) / 4 < 0.3:
            contradictions.append({
                'adjustment': 0.6,
                'reason': 'Suspicious filename but clean features (possibly renamed file)'
            })
        
        return contradictions
    
    def classify(self, file_info: Dict) -> Dict:
        """
        Clasificar un archivo usando ML recursivo
        
        Args:
            file_info: Información del archivo con features
        
        Returns:
            Dict con clasificación y justificación
        """
        if not self.enabled:
            return {
                'ml_enabled': False,
                'classification': 'unknown',
                'confidence': 0.0,
                'justification': 'ML classifier disabled'
            }
        
        # Paso 1: Extraer features
        features = self.extract_features(file_info)
        
        # Paso 2: Calcular score inicial
        initial_score = self._calculate_initial_score(features)
        
        # Paso 3: Refinamiento recursivo
        final_score, justification = self.recursive_refinement(features, initial_score)
        
        # Paso 4: Clasificación final
        classification, confidence = self._score_to_classification(final_score)
        
        return {
            'ml_enabled': True,
            'classification': classification,
            'confidence': round(confidence, 2),
            'raw_score': round(final_score, 3),
            'justification': justification if justification else 'Standard classification',
            'features': features,
            'refinement_applied': abs(final_score - initial_score) > 0.05
        }
    
    def _calculate_initial_score(self, features: Dict) -> float:
        """
        Calcular score inicial basado en features ponderados
        """
        score = 0.0
        
        # Aplicar pesos
        score += features['known_hash'] * self.WEIGHTS['known_hash']
        score += features['entropy'] * self.WEIGHTS['entropy']
        score += features['api_score'] * self.WEIGHTS['suspicious_apis']
        score += features['string_score'] * self.WEIGHTS['suspicious_strings']
        score += features['behavioral_score'] * self.WEIGHTS['behavioral']
        score += features['filename_score'] * self.WEIGHTS['filename']
        score += features['size_score'] * self.WEIGHTS['size']
        
        # Aplicar penalización por legitimidad
        score += features['legitimacy_score'] * self.WEIGHTS['legitimate_indicators']
        
        # Normalizar a [0-1]
        max_possible = sum([w for w in self.WEIGHTS.values() if w > 0])
        score = max(0.0, min(1.0, score / max_possible))
        
        return score
    
    def _score_to_classification(self, score: float) -> Tuple[str, float]:
        """
        Convertir score a clasificación categórica
        
        Returns:
            (clasificación, confianza)
        """
        if score >= 0.75:
            return 'malicious', score
        elif score >= 0.45:
            return 'suspicious', score
        else:
            return 'benign', 1.0 - score  # Confianza de que es benigno
    
    def vote_with_heuristics(self, ml_result: Dict, heuristic_result: Dict) -> Dict:
        """
        Sistema de votación entre ML y heurística
        
        Args:
            ml_result: Resultado del clasificador ML
            heuristic_result: Resultado del análisis heurístico
        
        Returns:
            Decisión final combinada
        """
        # Pesos de votación
        ml_weight = 0.6  # ML tiene más peso si está habilitado
        heuristic_weight = 0.4
        
        if not self.enabled:
            return {
                'final_classification': heuristic_result['classification'],
                'confidence': heuristic_result.get('confidence', 0.5),
                'method': 'heuristic_only',
                'ml_vote': None,
                'heuristic_vote': heuristic_result['classification']
            }
        
        # Mapeo de clasificaciones a scores
        classification_scores = {
            'benign': 0.0,
            'suspicious': 0.5,
            'malicious': 1.0
        }
        
        ml_score = classification_scores.get(ml_result['classification'], 0.5)
        heuristic_score = classification_scores.get(heuristic_result.get('classification', 'suspicious'), 0.5)
        
        # Votación ponderada
        final_score = (ml_score * ml_weight) + (heuristic_score * heuristic_weight)
        
        # Si ML dice "benign" con alta confianza, override heurística
        if ml_result['classification'] == 'benign' and ml_result['confidence'] > 0.8:
            final_classification = 'benign'
            confidence = ml_result['confidence']
            method = 'ml_override'
        # Si ambos coinciden
        elif ml_result['classification'] == heuristic_result.get('classification'):
            final_classification = ml_result['classification']
            confidence = (ml_result['confidence'] + heuristic_result.get('confidence', 0.5)) / 2
            method = 'consensus'
        # Votación ponderada
        else:
            if final_score >= 0.65:
                final_classification = 'malicious'
            elif final_score >= 0.35:
                final_classification = 'suspicious'
            else:
                final_classification = 'benign'
            
            confidence = abs(final_score - 0.5) * 2  # Convertir a [0-1]
            method = 'weighted_vote'
        
        return {
            'final_classification': final_classification,
            'confidence': round(confidence, 2),
            'method': method,
            'ml_vote': ml_result['classification'],
            'heuristic_vote': heuristic_result.get('classification', 'unknown'),
            'ml_justification': ml_result.get('justification', ''),
            'refinement_applied': ml_result.get('refinement_applied', False)
        }


def demo():
    """Demo de uso del clasificador"""
    classifier = RecursiveClassifier(enable_ml=True)
    
    # Ejemplo 1: Archivo claramente malicioso
    print("=== Ejemplo 1: Archivo malicioso ===")
    malicious_file = {
        'file': 'C:\\Users\\Admin\\Downloads\\malware.exe',
        'size': 524288,
        'entropy': 7.8,
        'known_malware_hash': True,
        'suspicious_apis': ['CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory'],
        'suspicious_strings': ['ransomware', 'bitcoin', 'encrypt'],
        'behavioral_flags': ['process_injection', 'anti_debug'],
        'filename_suspicious': True
    }
    
    result = classifier.classify(malicious_file)
    print(json.dumps(result, indent=2))
    
    # Ejemplo 2: DLL legítima de Microsoft (falso positivo típico)
    print("\n=== Ejemplo 2: DLL legítima de Microsoft ===")
    legitimate_dll = {
        'file': 'C:\\Windows\\System32\\Microsoft.Office.Interop.Excel.dll',
        'size': 2048576,
        'entropy': 6.5,  # Alta por compresión
        'known_malware_hash': False,
        'suspicious_apis': ['VirtualAlloc', 'LoadLibrary'],  # APIs comunes
        'suspicious_strings': [],
        'behavioral_flags': [],
        'filename_suspicious': False,
        'digital_signature': {'valid': True, 'signer': 'Microsoft Corporation'}
    }
    
    result = classifier.classify(legitimate_dll)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    demo()