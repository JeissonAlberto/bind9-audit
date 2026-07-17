#!/usr/bin/env bash
# =============================================================================
#  bind9-audit.sh — Auditoría completa de servidores BIND9
#  Versión: 1.0.0
#  Autor  : bind9-audit contributors
#  Repo   : https://github.com/JeissonAlberto/bind9-audit
#  Licencia: MIT
# =============================================================================
set -euo pipefail

# ── Directorio base del script ─────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/lib"
REPORTS_DIR="${SCRIPT_DIR}/reports"

# ── Variables globales ─────────────────────────────────────────────────────
AUDIT_VERSION="1.0.0"
AUDIT_TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
AUDIT_LOG_FILE="${REPORTS_DIR}/audit_${AUDIT_TIMESTAMP}.log"
REPORT_FORMAT="text"   # text | json | html
REPORT_OUTPUT=""
VERBOSE=false
MODULES_TO_RUN=()      # vacío = todos

# ── Contadores de puntuación ───────────────────────────────────────────────
SCORE_PASS=0
SCORE_FAIL=0
SCORE_WARN=0
SCORE_TOTAL=0

# ── Acumuladores del reporte ───────────────────────────────────────────────
REPORT_ISSUES=()
REPORT_RECOMMENDATIONS=()
REPORT_BIND_VERSION=""
REPORT_CONF_FILE=""

# ── Colores ────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    C_RESET='\033[0m'
    C_RED='\033[0;31m'
    C_GREEN='\033[0;32m'
    C_YELLOW='\033[1;33m'
    C_BLUE='\033[0;34m'
    C_CYAN='\033[0;36m'
    C_BOLD='\033[1m'
else
    C_RESET='' C_RED='' C_GREEN='' C_YELLOW='' C_BLUE='' C_CYAN='' C_BOLD=''
fi

# =============================================================================
# Funciones de logging (usadas por todos los módulos)
# =============================================================================

log_section() {
    local msg="$1"
    local line
    line=$(printf '━%.0s' {1..60})
    echo ""
    echo -e "${C_CYAN}${C_BOLD}${line}${C_RESET}" | tee -a "$AUDIT_LOG_FILE"
    echo -e "${C_CYAN}${C_BOLD}  ▶ ${msg}${C_RESET}"       | tee -a "$AUDIT_LOG_FILE"
    echo -e "${C_CYAN}${C_BOLD}${line}${C_RESET}" | tee -a "$AUDIT_LOG_FILE"
}

log_subsection() {
    local msg="$1"
    echo -e "\n${C_BLUE}  ── ${msg} ──${C_RESET}" | tee -a "$AUDIT_LOG_FILE"
}

log_pass() {
    echo -e "${C_GREEN}  [✅ PASS]${C_RESET} $1" | tee -a "$AUDIT_LOG_FILE"
}

log_fail() {
    echo -e "${C_RED}  [❌ FAIL]${C_RESET} $1" | tee -a "$AUDIT_LOG_FILE"
}

log_warn() {
    echo -e "${C_YELLOW}  [⚠️  WARN]${C_RESET} $1" | tee -a "$AUDIT_LOG_FILE"
}

log_info() {
    echo -e "  [ℹ️  INFO] $1" | tee -a "$AUDIT_LOG_FILE"
}

# =============================================================================
# Carga de módulos
# =============================================================================

load_libs() {
    local libs=(
        system
        service
        parser
        zones
        dnssec
        recursion
        performance
        security
        logging
        permissions
        statistics
        recommendations
        report
    )

    for lib in "${libs[@]}"; do
        local lib_path="${LIB_DIR}/${lib}.sh"
        if [[ -f "$lib_path" ]]; then
            # shellcheck source=/dev/null
            source "$lib_path"
        else
            echo "ERROR: No se encontró el módulo $lib_path" >&2
            exit 1
        fi
    done
}

# =============================================================================
# Uso / Ayuda
# =============================================================================

usage() {
    cat << EOF
${C_BOLD}bind9-audit v${AUDIT_VERSION}${C_RESET} — Auditoría completa de servidores BIND9

${C_BOLD}USO:${C_RESET}
  $(basename "$0") [opciones]

${C_BOLD}OPCIONES:${C_RESET}
  -f, --format <fmt>     Formato de salida: text (default), json, html
  -o, --output <file>    Archivo de reporte (default: reports/audit_TIMESTAMP.<ext>)
  -m, --modules <list>   Módulos a ejecutar (separados por coma)
                         Módulos: system,service,zones,dnssec,recursion,
                                  performance,security,logging,permissions,
                                  statistics,recommendations
  -v, --verbose          Salida detallada
  -h, --help             Muestra esta ayuda

${C_BOLD}EJEMPLOS:${C_RESET}
  # Auditoría completa con reporte de texto (default)
  sudo ./bind9-audit.sh

  # Reporte HTML
  sudo ./bind9-audit.sh -f html -o reports/mi-servidor.html

  # Solo seguridad y DNSSEC
  sudo ./bind9-audit.sh -m security,dnssec

  # Reporte JSON
  sudo ./bind9-audit.sh -f json -o /tmp/audit.json

${C_BOLD}NOTAS:${C_RESET}
  • Requiere privilegios de root o sudo para acceso a archivos de configuración.
  • Los reportes se guardan en: ${REPORTS_DIR}/
  • El log completo siempre se guarda en: ${AUDIT_LOG_FILE}

EOF
    exit 0
}

# =============================================================================
# Parseo de argumentos
# =============================================================================

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -f|--format)
                REPORT_FORMAT="${2:-text}"
                shift 2
                ;;
            -o|--output)
                REPORT_OUTPUT="$2"
                shift 2
                ;;
            -m|--modules)
                IFS=',' read -ra MODULES_TO_RUN <<< "$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                usage
                ;;
            *)
                echo "Opción desconocida: $1" >&2
                usage
                ;;
        esac
    done
}

# =============================================================================
# Pre-flight checks
# =============================================================================

preflight() {
    # Crear directorio de reportes si no existe
    mkdir -p "$REPORTS_DIR"

    # Verificar que se ejecuta con suficientes permisos
    if [[ $EUID -ne 0 ]]; then
        echo -e "${C_YELLOW}⚠️  Advertencia: se recomienda ejecutar como root para acceso completo${C_RESET}"
        echo -e "   Algunos checks pueden fallar por permisos insuficientes."
        echo ""
    fi

    # Determinar archivo de reporte de salida
    if [[ -z "$REPORT_OUTPUT" ]]; then
        local ext
        case "$REPORT_FORMAT" in
            json) ext="json" ;;
            html) ext="html" ;;
            *)    ext="txt"  ;;
        esac
        REPORT_OUTPUT="${REPORTS_DIR}/report_${AUDIT_TIMESTAMP}.${ext}"
    fi
}

# =============================================================================
# Ejecución de módulos
# =============================================================================

should_run() {
    local module="$1"
    if [[ ${#MODULES_TO_RUN[@]} -eq 0 ]]; then
        return 0   # ejecutar todos
    fi
    for m in "${MODULES_TO_RUN[@]}"; do
        [[ "$m" == "$module" ]] && return 0
    done
    return 1
}

run_audit() {
    # Siempre inicializar el parser
    init_parser || true

    should_run "system"          && check_system_info && check_bind_binary
    should_run "service"         && check_service_status && check_named_conf_syntax
    should_run "zones"           && check_zones && check_zone_transfers
    should_run "dnssec"          && check_dnssec
    should_run "recursion"       && check_recursion
    should_run "performance"     && check_performance
    should_run "security"        && check_security
    should_run "logging"         && check_logging
    should_run "permissions"     && check_permissions
    should_run "statistics"      && check_statistics
    should_run "recommendations" && generate_recommendations
}

# =============================================================================
# Banner
# =============================================================================

print_banner() {
    echo -e "${C_CYAN}${C_BOLD}"
    cat << 'BANNER'
  ██████╗ ██╗███╗   ██╗██████╗  █████╗      █████╗ ██╗   ██╗██████╗ ██╗████████╗
  ██╔══██╗██║████╗  ██║██╔══██╗██╔══██╗    ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝
  ██████╔╝██║██╔██╗ ██║██║  ██║╚██████║    ███████║██║   ██║██║  ██║██║   ██║   
  ██╔══██╗██║██║╚██╗██║██║  ██║ ╚═══██║    ██╔══██║██║   ██║██║  ██║██║   ██║   
  ██████╔╝██║██║ ╚████║██████╔╝ █████╔╝    ██║  ██║╚██████╔╝██████╔╝██║   ██║   
  ╚═════╝ ╚═╝╚═╝  ╚═══╝╚═════╝  ╚════╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝   
BANNER
    echo -e "${C_RESET}"
    echo -e "  ${C_BOLD}bind9-audit v${AUDIT_VERSION}${C_RESET} — Herramienta de auditoría para BIND9 DNS Server"
    echo -e "  Servidor: $(hostname -f 2>/dev/null || hostname) | $(date '+%Y-%m-%d %H:%M:%S %Z')"
    echo ""
}

# =============================================================================
# Main
# =============================================================================

main() {
    parse_args "$@"
    preflight
    load_libs

    # Inicializar log
    echo "# bind9-audit log — $(date)" > "$AUDIT_LOG_FILE"

    print_banner

    echo -e "  Log: ${AUDIT_LOG_FILE}"
    echo -e "  Reporte: ${REPORT_OUTPUT}"
    echo -e "  Formato: ${REPORT_FORMAT}"
    echo ""

    run_audit

    echo ""
    echo -e "${C_BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    generate_report "$REPORT_OUTPUT" "$REPORT_FORMAT"

    # Exit code basado en issues críticos
    if [[ $SCORE_FAIL -gt 0 ]]; then
        exit 2
    elif [[ $SCORE_WARN -gt 0 ]]; then
        exit 1
    else
        exit 0
    fi
}

main "$@"
