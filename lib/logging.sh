#!/usr/bin/env bash
# lib/logging.sh — Auditoría de la configuración de logging de BIND9

check_logging() {
    log_section "LOGGING"

    _check_logging_configured
    _check_log_channels
    _check_log_categories
    _check_log_files
}

_check_logging_configured() {
    log_subsection "Configuración de logging"

    if get_full_config | grep -qE '^\s*logging\s*\{'; then
        log_pass "Bloque logging configurado en named.conf"
        ((SCORE_TOTAL++)); ((SCORE_PASS++))
    else
        log_fail "Sin bloque logging configurado — usando defaults (insuficiente para auditoría)"
        ((SCORE_TOTAL++)); ((SCORE_FAIL++))
        REPORT_ISSUES+=("Logging no configurado — no hay trazabilidad de eventos DNS")
        return
    fi
}

_check_log_channels() {
    log_subsection "Canales de logging"

    local channels
    channels=$(get_full_config | awk '/^\s*logging\s*\{/,/^\s*\}/' | grep -oP 'channel\s+\K\S+' | tr -d '{')

    if [[ -z "$channels" ]]; then
        log_warn "No se encontraron canales de log definidos"
        return
    fi

    log_info "Canales definidos:"
    while IFS= read -r ch; do
        [[ -z "$ch" ]] && continue
        log_info "  → $ch"
    done <<< "$channels"

    # Verificar si hay canal a syslog
    if get_full_config | grep -qE 'syslog\s+(daemon|local[0-9])'; then
        log_pass "Canal syslog configurado (centralización de logs)"
        ((SCORE_TOTAL++)); ((SCORE_PASS++))
    else
        log_warn "Sin canal syslog — logs no centralizados"
        ((SCORE_TOTAL++)); ((SCORE_WARN++))
    fi

    # Verificar severidad
    local has_debug_all
    has_debug_all=$(get_full_config | grep -cE 'severity\s+(debug|dynamic|all)' || echo 0)
    if [[ "$has_debug_all" -gt 0 ]]; then
        log_warn "Severidad debug/all en producción — genera logs excesivos"
        ((SCORE_TOTAL++)); ((SCORE_WARN++))
    else
        log_pass "Severidad de logging adecuada para producción"
        ((SCORE_TOTAL++)); ((SCORE_PASS++))
    fi
}

_check_log_categories() {
    log_subsection "Categorías de logging"

    local important_cats=("security" "queries" "xfer-in" "xfer-out" "dnssec" "update")
    local missing_cats=()

    local logging_block
    logging_block=$(get_full_config | awk '/^\s*logging\s*\{/,/^\s*\}/')

    for cat in "${important_cats[@]}"; do
        if echo "$logging_block" | grep -qE "category\s+${cat}\s*\{"; then
            log_pass "Categoría '$cat' logueada"
        else
            log_warn "Categoría '$cat' no configurada en logging"
            missing_cats+=("$cat")
        fi
    done

    if [[ ${#missing_cats[@]} -gt 0 ]]; then
        log_warn "Categorías sin logging: ${missing_cats[*]}"
        ((SCORE_TOTAL++)); ((SCORE_WARN++))
        REPORT_ISSUES+=("Categorías de log faltantes: ${missing_cats[*]}")
    else
        ((SCORE_TOTAL++)); ((SCORE_PASS++))
    fi
}

_check_log_files() {
    log_subsection "Archivos de log"

    local log_dirs=("/var/log/named" "/var/log/bind" "/var/named/log" "/var/log")

    for dir in "${log_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            local log_files
            log_files=$(find "$dir" -name "*.log" -o -name "named*" 2>/dev/null | head -10)

            if [[ -n "$log_files" ]]; then
                log_info "Archivos de log en $dir:"
                echo "$log_files" | while read -r f; do
                    local size
                    size=$(du -sh "$f" 2>/dev/null | cut -f1)
                    local age
                    age=$(find "$f" -newer /proc/1/stat -maxdepth 0 2>/dev/null && echo "reciente" || echo "no modificado recientemente")
                    log_info "  $f ($size) — $age"
                done

                # Verificar permisos del directorio
                local dir_perms
                dir_perms=$(stat -c "%a %U" "$dir" 2>/dev/null)
                log_info "Permisos de $dir: $dir_perms"
            fi
        fi
    done

    # Verificar rotación de logs
    if [[ -f "/etc/logrotate.d/named" || -f "/etc/logrotate.d/bind9" || -f "/etc/logrotate.d/bind" ]]; then
        log_pass "Logrotate configurado para BIND9"
        ((SCORE_TOTAL++)); ((SCORE_PASS++))
    else
        log_warn "Sin configuración de logrotate para BIND9 — los logs pueden crecer indefinidamente"
        ((SCORE_TOTAL++)); ((SCORE_WARN++))
    fi

    # Verificar errores recientes en el log de sistema
    if command -v journalctl &>/dev/null; then
        local recent_errors
        recent_errors=$(journalctl -u named -u bind9 --since "24 hours ago" -p err 2>/dev/null | grep -c 'error\|critical\|fatal' || echo 0)
        if [[ "$recent_errors" -gt 0 ]]; then
            log_warn "Errores en las últimas 24h en journald: $recent_errors"
            ((SCORE_TOTAL++)); ((SCORE_WARN++))
        else
            log_pass "Sin errores críticos en las últimas 24h"
            ((SCORE_TOTAL++)); ((SCORE_PASS++))
        fi
    fi
}
