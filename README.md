# 🔍 bind9-audit

**Herramienta de auditoría de seguridad y configuración para servidores BIND9 DNS.**

Analiza tu servidor BIND9 en profundidad: seguridad, DNSSEC, recursión, zonas, permisos, logging, rendimiento y más. Genera reportes en texto, JSON o HTML.

---

## 📋 Características

| Módulo | Qué verifica |
|---|---|
| **system** | Versión de BIND, binarios, recursos del sistema |
| **service** | Estado del proceso, habilitación en arranque, sintaxis de named.conf |
| **zones** | Validación de zonas, SOA, NS, transferencias AXFR |
| **dnssec** | Validación, firma de zonas, claves, trust anchors |
| **recursion** | Open resolver, allow-recursion, allow-query, forwarders |
| **performance** | Caché, TCP clients, EDNS, Rate Limiting (RRL), prefetch |
| **security** | Ocultación de versión/hostname, allow-update, chroot, TSIG, RNDC, RPZ |
| **logging** | Canales, categorías, archivos, logrotate, errores recientes |
| **permissions** | Usuario del proceso, permisos de config y zonas, directorios |
| **statistics** | statistics-channels, rndc stats, archivo de estadísticas |
| **recommendations** | Recomendaciones consolidadas basadas en todos los hallazgos |

---

## 🚀 Uso rápido

```bash
# Clonar
git clone https://github.com/JeissonAlberto/bind9-audit.git
cd bind9-audit

# Dar permisos
chmod +x bind9-audit.sh

# Auditoría completa (recomendado: con sudo)
sudo ./bind9-audit.sh

# Reporte HTML
sudo ./bind9-audit.sh -f html -o reports/mi-servidor.html

# Solo módulos de seguridad y DNSSEC
sudo ./bind9-audit.sh -m security,dnssec

# Reporte JSON (para integración CI/CD)
sudo ./bind9-audit.sh -f json -o /tmp/audit.json
```

---

## 📖 Opciones

```
bind9-audit v1.0.0 — Auditoría completa de servidores BIND9

USO:
  ./bind9-audit.sh [opciones]

OPCIONES:
  -f, --format <fmt>     Formato de salida: text (default), json, html
  -o, --output <file>    Archivo de reporte (default: reports/audit_TIMESTAMP.<ext>)
  -m, --modules <list>   Módulos a ejecutar (separados por coma)
                         Módulos disponibles:
                           system, service, zones, dnssec, recursion,
                           performance, security, logging, permissions,
                           statistics, recommendations
  -v, --verbose          Salida detallada
  -h, --help             Muestra esta ayuda
```

---

## 📁 Estructura del proyecto

```
bind9-audit/
├── bind9-audit.sh          # Script principal
├── lib/
│   ├── system.sh           # Información del sistema y versión BIND
│   ├── service.sh          # Estado del servicio y sintaxis de config
│   ├── parser.sh           # Parseo de named.conf e includes
│   ├── zones.sh            # Auditoría de zonas DNS y AXFR
│   ├── dnssec.sh           # DNSSEC: validación, firma, claves
│   ├── recursion.sh        # Open resolver, allow-recursion, forwarders
│   ├── performance.sh      # Caché, EDNS, RRL, tuning
│   ├── security.sh         # Seguridad: versión, TSIG, chroot, RPZ
│   ├── logging.sh          # Configuración de logging y canales
│   ├── permissions.sh      # Permisos de archivos y directorios
│   ├── statistics.sh       # Estadísticas vía rndc y HTTP
│   ├── recommendations.sh  # Generación de recomendaciones
│   └── report.sh           # Generación de reportes (text/json/html)
├── reports/                # Directorio de reportes generados
└── README.md
```

---

## 📊 Sistema de puntuación

El script calcula una puntuación de 0 a 100 basada en los checks:

| Puntuación | Nivel |
|---|---|
| 90 – 100 | ✅ EXCELENTE |
| 75 – 89  | 🟢 BUENO |
| 60 – 74  | 🟡 ACEPTABLE |
| 40 – 59  | 🟠 DEFICIENTE |
| 0  – 39  | 🔴 CRÍTICO |

**Exit codes:**
- `0` — Sin fallos ni advertencias
- `1` — Advertencias presentes
- `2` — Fallos críticos detectados

---

## 🛡️ Checks de seguridad principales

| Check | Nivel |
|---|---|
| Open resolver (allow-recursion any) | 🔴 CRÍTICO |
| AXFR abierto (allow-transfer any) | 🔴 CRÍTICO |
| allow-update any | 🔴 CRÍTICO |
| named corriendo como root | 🔴 CRÍTICO |
| Versión BIND expuesta | 🔴 CRÍTICO |
| DNSSEC validation deshabilitado | 🔴 CRÍTICO |
| Sin Rate Limiting (RRL) | ⚠️ WARN |
| Sin TSIG keys | ⚠️ WARN |
| Sin logging configurado | ⚠️ WARN |
| Sin chroot | ⚠️ WARN |

---

## 🔧 Requisitos

- Bash 4.0+
- BIND9 instalado (`named`, `named-checkconf`, `named-checkzone`)
- `dig`, `ss` (o `netstat`)
- `rndc` (para estadísticas)
- Recomendado: ejecutar como **root** o con `sudo`

Compatible con:
- Ubuntu / Debian (bind9)
- RHEL / CentOS / Rocky Linux (named)
- Fedora, Amazon Linux

---

## 🤝 Contribuir

1. Fork del repositorio
2. Crea tu branch: `git checkout -b feature/mi-mejora`
3. Commit: `git commit -m "feat: descripción"`
4. Push: `git push origin feature/mi-mejora`
5. Abre un Pull Request

---

## 📚 Referencias

- [BIND9 ARM (Administrator Reference Manual)](https://bind9.readthedocs.io/)
- [ISC BIND Security](https://kb.isc.org/docs/aa-00674)
- [NIST SP 800-81r2 — Secure DNS Deployment Guide](https://csrc.nist.gov/publications/detail/sp/800-81/2/final)
- [CIS BIND DNS Benchmark](https://www.cisecurity.org/benchmark/dns)

---

## 📄 Licencia

MIT — ver [LICENSE](LICENSE)
