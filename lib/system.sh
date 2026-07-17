#!/usr/bin/env bash
# lib/system.sh — Información del sistema operativo y entorno

check_system_info() {
    log_section "INFORMACIÓN DEL SISTEMA"

    log_info "Hostname: $(hostname -f 2>/dev/null || hostname)"
    log_info "Fecha/Hora: $(date '+%Y-%m-%d %H:%M:%S %Z')"
    log_info "Usuario: $(whoami)"
    log_info "Kernel: $(uname -r)"
    log_info "OS: $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || uname -s)"
    log_info "Arquitectura: $(uname -m)"
    log_info "Uptime: $(uptime -p 2>/dev/null || uptime)"

    # Versión de BIND9
    local bind_version
    bind_version=$(named -v 2>/dev/null || named --version 2>&1 | head -1)
    if [[ -n "$bind_version" ]]; then
        log_info "BIND version: $bind_version"
        REPORT_BIND_VERSION="$bind_version"
    else
        log_warn "No se pudo determinar la versión de BIND9"
        REPORT_BIND_VERSION="Desconocida"
    fi

    # Recursos del sistema
    log_info "CPU cores: $(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 'N/A')"
    log_info "Memoria total: $(free -h 2>/dev/null | awk '/^Mem:/{print $2}' || echo 'N/A')"
    log_info "Disco (root): $(df -h / 2>/dev/null | awk 'NR==2{print $4}' || echo 'N/A') disponible"
}

check_bind_binary() {
    log_section "BINARIOS DE BIND9"

    local binaries=("named" "named-checkconf" "named-checkzone" "rndc" "dig" "nsupdate")
    local missing=()

    for bin in "${binaries[@]}"; do
        local path
        path=$(command -v "$bin" 2>/dev/null)
        if [[ -n "$path" ]]; then
            log_pass "Binario encontrado: $bin → $path"
        else
            log_fail "Binario no encontrado: $bin"
            missing+=("$bin")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_warn "Binarios faltantes: ${missing[*]}"
        ((SCORE_TOTAL++)); ((SCORE_FAIL++))
    else
        ((SCORE_TOTAL++)); ((SCORE_PASS++))
    fi
}
