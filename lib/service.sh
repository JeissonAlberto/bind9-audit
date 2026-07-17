#!/usr/bin/env bash
# lib/service.sh — Estado del servicio BIND9

check_service_status() {
    log_section "ESTADO DEL SERVICIO"

    # Detectar sistema de init
    if command -v systemctl &>/dev/null; then
        _check_systemd_service
    elif command -v service &>/dev/null; then
        _check_sysv_service
    else
        log_warn "Sistema de init no reconocido"
    fi

    # Verificar proceso corriendo
    local pid
    pid=$(pgrep -x named 2>/dev/null | head -1)
    if [[ -n "$pid" ]]; then
        log_pass "Proceso named corriendo (PID: $pid)"
        ((SCORE_TOTAL++)); ((SCORE_PASS++))

        # Puertos en escucha
        local ports
        ports=$(ss -tlnup 2>/dev/null | grep named || netstat -tlnup 2>/dev/null | grep named)
        if [[ -n "$ports" ]]; then
            log_info "Puertos en escucha:"
            echo "$ports" | while read -r line; do log_info "  $line"; done
        fi
    else
        log_fail "Proceso named NO está corriendo"
        ((SCORE_TOTAL++)); ((SCORE_FAIL++))
    fi
}

_check_systemd_service() {
    local status
    status=$(systemctl is-active named 2>/dev/null || systemctl is-active bind9 2>/dev/null)

    if [[ "$status" == "active" ]]; then
        log_pass "Servicio activo (systemd)"
    else
        log_fail "Servicio inactivo: $status"
    fi

    # Habilitado en arranque
    local enabled
    enabled=$(systemctl is-enabled named 2>/dev/null || systemctl is-enabled bind9 2>/dev/null)
    if [[ "$enabled" == "enabled" ]]; then
        log_pass "Servicio habilitado en arranque"
        ((SCORE_TOTAL++)); ((SCORE_PASS++))
    else
        log_warn "Servicio NO habilitado en arranque: $enabled"
        ((SCORE_TOTAL++)); ((SCORE_WARN++))
    fi
}

_check_sysv_service() {
    local status
    status=$(service named status 2>/dev/null || service bind9 status 2>/dev/null)
    if echo "$status" | grep -qi "running\|active"; then
        log_pass "Servicio activo (SysV)"
    else
        log_fail "Servicio inactivo"
    fi
}

check_named_conf_syntax() {
    log_section "SINTAXIS DE CONFIGURACIÓN"

    local conf_files=("/etc/named.conf" "/etc/bind/named.conf" "/etc/named/named.conf")
    local conf_file=""

    for f in "${conf_files[@]}"; do
        if [[ -f "$f" ]]; then
            conf_file="$f"
            break
        fi
    done

    if [[ -z "$conf_file" ]]; then
        log_fail "No se encontró archivo de configuración principal"
        ((SCORE_TOTAL++)); ((SCORE_FAIL++))
        return
    fi

    log_info "Archivo de configuración: $conf_file"
    REPORT_CONF_FILE="$conf_file"

    if command -v named-checkconf &>/dev/null; then
        local output
        output=$(named-checkconf "$conf_file" 2>&1)
        if [[ $? -eq 0 ]]; then
            log_pass "Sintaxis de named.conf válida"
            ((SCORE_TOTAL++)); ((SCORE_PASS++))
        else
            log_fail "Errores de sintaxis en named.conf:"
            echo "$output" | while read -r line; do log_fail "  $line"; done
            ((SCORE_TOTAL++)); ((SCORE_FAIL++))
        fi
    else
        log_warn "named-checkconf no disponible, saltando validación de sintaxis"
    fi
}
