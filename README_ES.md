# DarkWeb Crawler v3

Una herramienta avanzada de investigación de la web oscura diseñada para análisis de amenazas cibernéticas e inteligencia de seguridad. Este programa rastrea sitios `.onion` y analiza contenido para detectar actividades ilícitas, bienes de mercado y posibles amenazas de seguridad.

## ⚠️ Aviso Legal y Ético

**Este software está diseñado únicamente para investigación de seguridad autorizada.** El usuario asume la responsabilidad total de todas las acciones realizadas con esta herramienta.

- Solo para investigación de seguridad autorizada
- Nunca acceda a contenido ilegal
- Respete las leyes locales e internacionales
- La descarga de imágenes puede constituir infracción de derechos de autor
- Asegúrese de tener autorización legal antes de usar

## Características Principales

- 🔍 **Rastreo de Profundidad Configurable**: Controle la profundidad y cantidad de páginas a rastrear
- 🖼️ **Captura de Imágenes**: Descargue y analice imágenes de sitios rastreados
- 🚨 **Detección de Amenazas**: Identifica palabras clave peligrosas y contenido sospechoso
- 📊 **Análisis de Mercado**: Categoriza bienes ilícitos detectados
- 🔐 **Anonimato Tor**: Utiliza proxy SOCKS5 para mantener anonimato
- 📈 **Reportes Múltiples**: Genera reportes en JSON, CSV y texto resumido
- 🔄 **Reinicio de Circuito Tor**: Renueva la identidad Tor periódicamente
- 📝 **Logging Detallado**: Rastreo completo de todas las actividades

## Requisitos Previos

### Software Necesario
- Python 3.7 o superior
- Tor daemon ejecutándose en el puerto 9050
- SOCKS5 proxy accesible

### Dependencias Python
```bash
pip install requests beautifulsoup4 stem lxml pillow nltk
```

### Instalación de NLTK Data
El script descargará automáticamente los datos de NLTK necesarios (punkt y stopwords) en la primera ejecución.

## Instalación

1. **Clonar el repositorio**:
```bash
git clone https://github.com/techenthusiast167/DARKWEB_CRAWLER.git
cd DARKWEB_CRAWLER
```

2. **Instalar dependencias**:
```bash
pip install -r requirements.txt
```

3. **Verificar Tor**:
```bash
# En otra terminal, asegúrese de que Tor esté ejecutándose
tor --SocksPort 9050
```

## Uso

### Sintaxis Básica
```bash
python dark_crawler.py [OPCIONES]
```

### Opciones de Línea de Comandos

| Opción | Descripción |
|--------|------------|
| `-h, --help` | Muestra este mensaje de ayuda |
| `-u URL, --url URL` | URL única .onion a rastrear |
| `-f FILE, --file FILE` | Archivo con lista de URLs .onion (una por línea) |
| `-d DEPTH, --depth DEPTH` | Profundidad máxima de rastreo (default: 3) |
| `-p PAGES, --pages PAGES` | Máximo de páginas por sitio (default: 50) |
| `-o OUTPUT, --output OUTPUT` | Directorio de salida para reportes (default: directorio actual) |
| `--images` | Descargar imágenes de páginas rastreadas |
| `--images-only` | Descargar SOLO imágenes, sin análisis de texto |
| `--image-extensions EXT1,EXT2,...` | Extensiones de imagen a descargar |
| `--max-images PER_PAGE` | Máximo de imágenes por página (default: 10) |
| `--no-tor-check` | Omitir prueba de conexión Tor |
| `--json` | Generar solo reporte JSON |
| `--csv` | Generar solo reporte CSV |
| `--all` | Generar todos los formatos de reporte |

## Ejemplos de Uso

### 1. Rastreo Simple
```bash
python dark_crawler.py -u http://3g2upl4pq6kufc4m.onion
```

### 2. Rastreo con Captura de Imágenes
```bash
python dark_crawler.py -u http://marketplace.onion --images
```

### 3. Solo Descargar Imágenes
```bash
python dark_crawler.py -u http://marketplace.onion --images-only
```

### 4. Rastreo Profundo con Limites Personalizados
```bash
python dark_crawler.py -u http://marketplace.onion --images \
    --image-extensions jpg,png \
    --max-images 5 \
    --depth 4 \
    --pages 100
```

### 5. Rastreo desde Archivo de URLs
```bash
python dark_crawler.py -f urls.txt --all -o ./reportes/
```

### 6. Análisis Comprensivo con Todos los Reportes
```bash
python dark_crawler.py -u http://marketplace.onion --images --all -o ./resultados/
```

## Formatos de Salida

### JSON
Archivo: `darkweb_crawl_results.json`

Contiene todos los datos estructurados incluyendo:
- URLs rastreadas
- Títulos y contenido
- Amenazas detectadas
- Bienes de mercado
- Información de imágenes

```json
{
  "url": "http://example.onion",
  "title": "Página de Ejemplo",
  "threats": {
    "high": ["palabras clave peligrosas"],
    "medium": [],
    "low": []
  },
  "marketplace_goods": {
    "drugs": {"cocaine": 2},
    "weapons": {}
  },
  "images_count": 5
}
```

### CSV
Archivo: `darkweb_crawl_results.csv`

Formato de hoja de cálculo con columnas:
- URL
- Título
- Contenido
- Amenazas
- Bienes de Mercado
- Número de Imágenes
- Archivos de Imagen

### Reporte Resumido
Archivo: `darkweb_analysis_summary.txt`

Resumen textual incluyendo:
- Estadísticas generales
- Desglose de amenazas
- Análisis de bienes de mercado
- Top 5 hallazgos de amenazas

### Imágenes Descargadas
Directorio: `images/`

Archivos de imagen descargados con nombres:
- `image_YYYYMMDD_HHMMSS_HASH.ext`

Manifiesto: `image_manifest.json` (con metadatos de imágenes)

## Categorías de Amenazas

### Severidad Alta
Terrorismo, tráfico de drogas, armas, tráfico de personas, pornografía infantil, fraude de tarjetas de crédito, etc.

### Severidad Media
Drogas, armas, herramientas de hacking, malware, documentos falsos, etc.

### Severidad Baja
Software pirateado, cuentas pirateadas, tutoriales de hacking, etc.

## Categorías de Bienes de Mercado

- **Drogas**: Cocaína, heroína, metanfetamina, marijuana, etc.
- **Armas**: Armas de fuego, munición, explosivos, etc.
- **Bienes Digitales**: Tarjetas de crédito, cuentas, credenciales, malware, etc.
- **Fraude**: Documentos falsos, pasaportes falsos, etc.
- **Servicios**: Hacking, DDoS, phishing, asesinato a sueldo, etc.

## Configuración Avanzada

### Personalizar Extensiones de Imagen
```bash
python dark_crawler.py -u http://example.onion \
    --images \
    --image-extensions jpg,png,gif,webp
```

### Limitar Tamaño de Imágenes
El tamaño máximo de imagen está limitado a **5 MB** (configurable en el código).

### Retraso de Rastreo
El retraso por defecto es **7 segundos** entre solicitudes (configurable).

### Renovar Circuito Tor
Se renueva cada **5 páginas rastreadas** para mayor anonimato.

## Estructura de Carpetas Generada

```
./
├── darkweb_crawl_results.json      # Datos JSON completos
├── darkweb_crawl_results.csv       # Reporte CSV
├── darkweb_analysis_summary.txt    # Resumen textual
├── image_manifest.json             # Metadatos de imágenes
└── images/
    ├── image_20241215_120000_a1b2c3d4.jpg
    ├── image_20241215_120015_e5f6g7h8.png
    └── ...
```

## Interpretación de Resultados

### Análisis de Amenazas
- **Alto**: Contenido que viola leyes graves
- **Medio**: Actividades sospechosas que merecen investigación
- **Bajo**: Contenido potencialmente ilícito pero de menor severidad

### Análisis de Mercado
Cuenta las menciones de palabras clave de bienes ilícitos por categoría.

### Metadata de Imágenes
Cada imagen descargada incluye:
- Nombre de archivo
- Tamaño en KB
- Dimensiones (ancho x alto)
- Formato
- Hash MD5 (para deduplicación)
- URL fuente
- Página de origen

## Notas de Rendimiento

- El rastreo puede ser lento debido a latencias de Tor (esperado)
- Descargar muchas imágenes aumenta el uso de ancho de banda
- Imágenes grandes ralentizan el rastreo
- Aumentar la profundidad/páginas aumenta significativamente el tiempo total

## Resolución de Problemas

### "Tor connection failed"
```bash
# Asegúrese de que Tor esté ejecutándose
tor --SocksPort 9050

# Verifique la conectividad
curl -x socks5h://127.0.0.1:9050 http://check.torproject.org/
```

### "No valid .onion URLs provided"
- Verifique que las URLs tengan el formato correcto: `http://XXXXX.onion`
- Verifique que el archivo de URLs no tenga líneas en blanco

### "Failed to download image"
- Puede ser timeout de conexión
- La imagen podría ser mayor de 5 MB (límite configurable)
- El tipo de contenido no es un tipo de imagen válido

### Importaciones Faltantes
```bash
pip install --upgrade requests beautifulsoup4 stem lxml pillow nltk
```

## Constantes Configurables

Edite estas en `dark_crawler.py`:

```python
TOR_SOCKS_PROXY = 'socks5h://127.0.0.1:9050'  # Proxy Tor
TOR_CONTROL_PORT = 9051                        # Puerto de control Tor
DEFAULT_CRAWL_DELAY = 7                        # Retraso entre solicitudes (segundos)
DEFAULT_MAX_DEPTH = 3                          # Profundidad máxima
DEFAULT_MAX_PAGES = 50                         # Páginas máximas
RETRY_COUNT = 3                                # Reintentos
BACKOFF_FACTOR = 4                             # Factor de retardo exponencial
MAX_IMAGE_SIZE_MB = 5                          # Tamaño máximo de imagen (MB)
```

## Seguridad y Privacidad

- **Anonimato Tor**: El software utiliza SOCKS5 proxy para todo el tráfico
- **Sin Historial Local**: Los datos se guardan en archivos locales
- **Sin Conexión Directa**: Nunca se conecta directamente (siempre vía Tor)
- **Deduplicación de Imágenes**: Usa hash MD5 para evitar duplicados

## Limitaciones Conocidas

- Algunos sitios bloqueadores de bots pueden no responder
- Sitios con JavaScript dinámico no se rascrean completamente
- Algunos formatos de imagen no soportados pueden omitirse
- La renovación de circuito Tor puede fallar sin puerto de control

## Contribuciones

Para reportar bugs o sugerir mejoras, abra un issue en GitHub.

## Licencia

Ver archivo LICENSE para detalles.

## Autor

**Cyber Threat Intelligence Team**
Versión: 2.4 (Enhanced with Image Capture & Market Analysis)

---

**Última actualización**: Diciembre 2025
