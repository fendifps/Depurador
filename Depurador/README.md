🛡️ DEPURADOR - Malware Scanner 
Depurador es un escáner de malware avanzado diseñado para detectar amenazas mediante análisis de firmas, detección heurística y análisis comportamental.

📋 TABLA DE CONTENIDOS

Características
Requisitos del Sistema
Instalación
Estructura del Proyecto
Uso
Módulos
Base de Datos de Firmas
Detección Heurística
Logs y Reportes
Configuración
Pruebas
Solución de Problemas
Contribuir


✨ CARACTERÍSTICAS
🔍 Escaneo Avanzado

Escaneo completo del sistema con soporte multihilo
Escaneo rápido de directorios críticos del usuario
Análisis de archivos individuales con información detallada
Escaneo personalizado de rutas específicas

🧬 Detección Inteligente

40+ firmas de malware conocido (SHA256 y MD5)
20+ reglas heurísticas para detección de comportamiento sospechoso
20+ patrones comportamentales para análisis de ejecutables
Detección de scripts maliciosos (PowerShell, Batch, VBS, JS)
Análisis de entropía para detectar cifrado/empaquetado
Análisis de estructura PE para ejecutables Windows

🚀 Rendimiento

Escaneo multihilo (hasta 8 hilos simultáneos)
Optimización de recursos con límites de tamaño de archivo
Exclusión inteligente de directorios del sistema

📊 Reportes Detallados

Reportes en texto y JSON
Logs en tiempo real de amenazas detectadas
Clasificación de severidad (CRITICAL, SUSPICIOUS)
Recomendaciones de acción


💻 REQUISITOS DEL SISTEMA
Requisitos Mínimos

Sistema Operativo: Windows 10 o superior
Python: 3.8 o superior
RAM: 2 GB mínimo (4 GB recomendado)
Espacio en disco: 500 MB libre
Privilegios: Usuario estándar (Administrador recomendado para escaneo completo)

Dependencias Python
colorama>=0.4.6
pefile>=2023.2.7

🚀 INSTALACIÓN
Opción 1: Instalación Automática (Recomendado)

Descarga todos los archivos del proyecto en una carpeta
Organiza la estructura:

Tu_Carpeta/
├── install_and_run.bat
└── Depurador/
    ├── src/
    │   ├── main.py
    │   ├── scanner.py
    │   ├── analyzer.py
    │   ├── signature_engine.py
    │   └── logger.py
    ├── signatures/
    │   ├── malware_hashes.json
    │   ├── heuristic_rules.json
    │   └── behavioral_patterns.json
    └── config.json

Ejecuta el instalador:

Haz doble clic en install_and_run.bat
El script automáticamente:

✅ Verifica Python
✅ Crea el entorno virtual
✅ Instala dependencias
✅ Configura el proyecto
✅ Ejecuta Depurador





Opción 2: Instalación Manual
bash# 1. Crear entorno virtual
python -m venv depurador_env

# 2. Activar entorno virtual
depurador_env\Scripts\activate

# 3. Instalar dependencias
pip install colorama pefile

# 4. Ejecutar el programa
cd Depurador\src
python main.py

📁 ESTRUCTURA DEL PROYECTO
Depurador/
│
├── src/                          # Código fuente
│   ├── main.py                   # Punto de entrada principal
│   ├── scanner.py                # Motor de escaneo del sistema
│   ├── analyzer.py               # Analizador de archivos individuales
│   ├── signature_engine.py       # Motor de detección de firmas
│   └── logger.py                 # Sistema de logging
│
├── signatures/                   # Base de datos de firmas
│   ├── malware_hashes.json       # Hashes conocidos de malware
│   ├── heuristic_rules.json      # Reglas heurísticas
│   └── behavioral_patterns.json  # Patrones de comportamiento
│
├── logs/                         # Directorio de logs (auto-generado)
│   ├── depurador.log            # Log principal
│   ├── scan_report_*.txt        # Reportes de escaneo (texto)
│   └── scan_report_*.json       # Reportes de escaneo (JSON)
│
├── depurador_env/               # Entorno virtual (auto-generado)
│
├── config.json                  # Archivo de configuración
├── install_and_run.bat          # Script de instalación
└── README.md                    # Este archivo

🎮 USO
Menú Principal
Al ejecutar Depurador, verás el siguiente menú:
╔═══════════════════════════════════════════════════════════════╗
║                    DEPURADOR MENU                             ║
╚═══════════════════════════════════════════════════════════════╝

[1] Full System Scan              - Escaneo completo del sistema
[2] Quick Scan                    - Escaneo rápido de directorios críticos
[3] Analyze Single File           - Analizar un archivo específico
[4] Custom Path Scan              - Escaneo de ruta personalizada
[5] View Last Scan Report         - Ver último reporte
[6] Update Signatures             - Actualizar base de datos
[0] Exit                          - Salir del programa
Opciones Detalladas
1️⃣ Full System Scan
Escanea todo el sistema (C:) buscando archivos sospechosos.
⚠️ Advertencia: Puede tardar varias horas dependiendo del tamaño del disco.
Ejemplo de salida:
[+] Found 5,432 files to scan
[100.00%] Scanned: 5432/5432 | Threats: 3 | Suspicious: 7
2️⃣ Quick Scan
Escanea solo directorios críticos:

C:\Users\[Usuario]\Downloads
C:\Users\[Usuario]\Documents
C:\Users\[Usuario]\Desktop
C:\Users\[Usuario]\AppData\Local\Temp

Tiempo estimado: 5-15 minutos
3️⃣ Analyze Single File
Análisis profundo de un archivo específico.
Ejemplo:
[?] Enter file path: C:\Downloads\suspicious.exe

ANALYSIS RESULTS
═══════════════════════════════════════════════════════════════
[STATUS]: MALICIOUS

File: C:\Downloads\suspicious.exe
SHA256: a1b2c3d4e5f6...
MD5: 9a8b7c6d5e4f...
Size: 524288 bytes

[!] THREATS DETECTED:
    • Known malware hash signature detected
    • Process injection capability detected
    • Anti-debugging technique detected

[PE INFO]:
    Machine: 0x14c
    EntryPoint: 0x1000
    Imports: kernel32.dll, user32.dll, ws2_32.dll
4️⃣ Custom Path Scan
Escanea una ruta específica que tú elijas.
Ejemplo:
[?] Enter path to scan: D:\Proyectos
5️⃣ View Last Scan Report
Muestra el último reporte generado en formato texto.
6️⃣ Update Signatures
Recarga la base de datos de firmas desde el disco.

🧩 MÓDULOS
1. main.py - Core Principal

Interfaz de usuario
Gestión del menú
Coordinación de módulos

2. scanner.py - Motor de Escaneo
Funcionalidades:

Escaneo multihilo del sistema de archivos
Cálculo de hashes (SHA256, MD5)
Detección de extensiones sospechosas
Exclusión de directorios del sistema
Progress tracking en tiempo real

Extensiones monitoreadas:
.exe, .dll, .bat, .cmd, .ps1, .vbs, .js, .wsf, .scr, .pif, .com, .cpl, .msi, .sys, .drv, .ocx
3. analyzer.py - Analizador de Archivos
Funcionalidades:

Análisis detallado de ejecutables
Extracción de información PE
Análisis de scripts (PowerShell, Batch, VBS, JS)
Detección de obfuscación
Detección de payloads codificados

4. signature_engine.py - Motor de Detección
Funcionalidades:

Verificación de hashes conocidos
Aplicación de reglas heurísticas
Análisis de patrones comportamentales
Cálculo de entropía
Detección de strings sospechosos

5. logger.py - Sistema de Logging
Funcionalidades:

Registro de amenazas en tiempo real
Generación de reportes TXT y JSON
Logs thread-safe
Historial de escaneos


🗄️ BASE DE DATOS DE FIRMAS
malware_hashes.json
Contiene 40 hashes de malware conocido:

WannaCry
Emotet
Zeus Banking Trojan
Cryptolocker
TrickBot
Ransomware variants (Ryuk, Maze, REvil, etc.)
RATs, Keyloggers, Backdoors
Y más...

Formato:
json{
  "hashes": {
    "hash_value": "Malware Name",
    ...
  },
  "version": "1.0.0",
  "last_updated": "2025-11-22"
}
heuristic_rules.json
Contiene 20 reglas heurísticas:

Detección de APIs sospechosas
Patrones de ransomware
Indicadores de keylogging
Anti-debugging techniques
Credential theft indicators

Tipos de reglas:

byte_pattern: Patrones de bytes
string_pattern: Cadenas de texto
regex: Expresiones regulares

behavioral_patterns.json
Contiene 20 patrones comportamentales:

API calls sospechosas
Imports maliciosos
Secciones de ejecutables empaquetados
Patrones de nombres de archivo


🔍 DETECCIÓN HEURÍSTICA
Análisis de Entropía

Entropía > 7.5: Indica posible cifrado o empaquetado
Útil para detectar malware ofuscado

Strings Sospechosos
El motor busca keywords como:

ransomware, encrypt, bitcoin
keylog, credential, password
mimikatz, metasploit
inject, payload, shellcode

Análisis de Scripts
Detecta patrones peligrosos en scripts:

PowerShell: DownloadString, Invoke-Expression, -EncodedCommand
Batch: Obfuscación excesiva con ^
VBS/JS: CreateObject, WScript.Shell, eval()


📝 LOGS Y REPORTES
Formato de Reporte TXT
======================================================================
DEPURADOR - MALWARE SCAN REPORT
======================================================================

Report Generated: 2025-11-22 15:30:45
Report File: scan_report_20251122_153045.txt

----------------------------------------------------------------------
SCAN SUMMARY
----------------------------------------------------------------------

Total Files Scanned:    5,432
Threats Detected:       3
Suspicious Files:       7
Clean Files:            5,422
Errors Encountered:     0

----------------------------------------------------------------------
DETECTED THREATS
----------------------------------------------------------------------

[1] CRITICAL THREAT
──────────────────────────────────────────────────────────────────────
File Path:     C:\Users\Admin\Downloads\malware.exe
File Type:     .exe
File Size:     524288 bytes
SHA256:        a1b2c3d4e5f6...
MD5:           9a8b7c6d5e4f...
Detection Time: 2025-11-22T15:28:33

Detection Reasons:
  • Known malware hash signature detected
  • Process injection capability detected
  • Keylogging capability detected

Recommended Action:
  ⚠ CRITICAL: Quarantine or delete this file immediately.
  ⚠ Perform a full system scan.
  ⚠ Check for related malicious processes.
Formato JSON
json{
  "timestamp": "2025-11-22T15:30:45",
  "scan_stats": {
    "total_scanned": 5432,
    "threats_found": 3,
    "suspicious_found": 7,
    "clean_files": 5422,
    "errors": 0
  },
  "threats": [
    {
      "file": "C:\\Users\\Admin\\Downloads\\malware.exe",
      "sha256": "a1b2c3d4...",
      "md5": "9a8b7c6d...",
      "severity": "CRITICAL",
      "reasons": [...]
    }
  ]
}

⚙️ CONFIGURACIÓN
config.json
json{
  "scan_paths": ["C:\\"],
  "max_file_size_mb": 100,
  "excluded_extensions": [".tmp", ".log", ".bak"],
  "max_threads": 8,
  "deep_scan": false
}
Parámetros:

scan_paths: Rutas a escanear en Full System Scan
max_file_size_mb: Tamaño máximo de archivo a analizar
excluded_extensions: Extensiones a ignorar
max_threads: Número de hilos para escaneo paralelo
deep_scan: Análisis más profundo (más lento)


🧪 PRUEBAS
Archivo de Prueba EICAR
Para probar el escáner, usa el archivo de prueba EICAR:
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
Guárdalo como eicar.com y escanéalo. Depurador debería detectarlo como amenaza.
Crear Archivo de Prueba Falso
python# test_malware.py
with open('fake_malware.exe', 'wb') as f:
    f.write(b'MZ\x90\x00')  # PE header
    f.write(b'CreateRemoteThread' * 10)  # API sospechosa
    f.write(b'URLDownloadToFile' * 10)   # Descarga de archivos

🔧 SOLUCIÓN DE PROBLEMAS
Error: "Python is not installed"
Solución: Instala Python desde https://www.python.org/downloads/

✅ Marca "Add Python to PATH" durante la instalación

Error: "Failed to create virtual environment"
Solución:
bashpython -m pip install --upgrade pip
python -m pip install virtualenv
Error: "pefile module not found"
Solución:
bashpip install pefile
El escaneo es muy lento
Solución:

Reduce max_threads en config.json
Usa Quick Scan en lugar de Full System Scan
Aumenta max_file_size_mb para excluir archivos grandes

Falsos positivos
Solución:

Revisa manualmente los archivos detectados
Ajusta las reglas heurísticas en heuristic_rules.json
Reporta falsos positivos para mejorar el sistema


📊 ESTADÍSTICAS

Firmas de malware: 40
Reglas heurísticas: 20
Patrones comportamentales: 20
Extensiones monitoreadas: 16
Tipos de análisis: 5 (Hash, Filename, Heuristic, Behavioral, PE)


🛡️ LIMITACIONES

⚠️ No es un antivirus completo: Depurador es una herramienta educativa/auxiliar
⚠️ Base de datos limitada: Solo contiene firmas de malware conocido común
⚠️ Sin protección en tiempo real: Solo escanea bajo demanda
⚠️ No elimina archivos: Solo detecta y reporta
⚠️ Windows solamente: Diseñado específicamente para Windows


🤝 CONTRIBUIR
Agregar Nuevas Firmas

Edita signatures/malware_hashes.json
Agrega el hash y nombre del malware
Actualiza total_signatures

Agregar Reglas Heurísticas

Edita signatures/heuristic_rules.json
Agrega una nueva regla con:

id: Identificador único (H###)
type: byte_pattern, string_pattern, o regex
pattern: El patrón a buscar
description: Descripción de la amenaza
severity: low, medium, high, critical




📄 LICENCIA
MIT License - Uso educativo y de investigación

⚠️ DISCLAIMER
Depurador es una herramienta educativa diseñada para aprender sobre detección de malware. NO debe usarse como única medida de seguridad. Siempre usa un antivirus comercial actualizado y mantén tu sistema operativo al día.

📞 SOPORTE
Para reportar bugs o sugerir mejoras, crea un issue en el repositorio del proyecto.

🎓 RECURSOS EDUCATIVOS
Aprender más sobre:

Análisis de malware: https://www.malwaretech.com/
Estructura PE: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
Heurística de detección: https://www.virustotal.com/gui/
YARA rules: https://yara.readthedocs.io/


¡Mantente seguro! 🛡️