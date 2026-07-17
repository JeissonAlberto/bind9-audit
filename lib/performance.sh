#!/usr/bin/env bash
# lib/performance.sh — Auditoría de parámetros de rendimiento

check_performance() {
    log_section "RENDIMIENTO Y TUNING"

    _check_cache_size
    _check_tcp_clients
    _check_max_cache_ttl
    _check_edns
    _check_rate_limiting
    _check_prefetch
}

_check_cache_size() {
    log_subsection "Tamaño de caché"

    local max_cache_size
    max_cache_size=$(get_option_value "max-cache-size")

    if [[ -z "$max_cache_size" ]]; then
        log_warn "max-cache-size no configurado — usará 90% de la memoria disponible"
        ((SCORE_TOTAL++)); ((SCORE_WARN++))
    elif [[ "$max_cache_size" == "0" ]]; then
        log_warn "max-cache-size: 0 — sin límite de caché (puede agotar memoria)"
        ((SCORE_TOTAL++)); ((SCORE_WARN++))
    else
        log_pass "max-cache-size: $max_cache_size"
        ((SCORE_TOTAL++)); ((SCORE_PASS++))
    fi
}

_check_tcp_clients() {
    log_subsection "Clientes TCP concurrentes"

    local tcp_clients
    tcp_clients=$(get_option_value "tcp-clients")

    if [[ -z "$tcp_clients" ]]; then
        log_info "tcp-clients no configurado (default: 150)"
    elif [[ "$tcp_clients" -lt 100 ]]; then
        log_warn "tcp-clients muy bajo: $tcp_clients — puede limitar conexiones legítimas"
        ((SCORE_TOTAL++)); ((SCORE_WARN++))
    elif [[ "$tcp_clients" -gt 2000 ]]; then
        log_warn "tcp-clients muy alto: $tcp_clients — evaluar recursos del sistema"
        ((SCORE_TOTAL++)); ((SCORE_WARN++))
    else
        log_pass "tcp-clients: $tcp_clients"
        ((SCORE_TOTAL++)); ((SCORE_PASS++))
    fi

    # recursive-clients
    local rec_clients
    rec_clients=$(get_option_value "recursive-clients")
    if [[ -n "$rec_clients" ]]; then
        log_info "recursive-clients: $rec_clients"
        if [[ "$rec_clients" -gt 5000 ]]; then
            log_warn "recursive-clients muy alto: $rec_clients"
        else
            log_pass "recursive-clients dentro de rango razonable"
        fi
    fi
}

_check_max_cache_ttl() {
    log_subsection "TTL de caché"

    local max_ttl
    max_ttl=$(get_option_value "max-cache-ttl")
    if [[ -n "$max_ttl" ]]; then
        log_info "max-cache-ttl: $max_ttl segundos"
        if [[ "$max_ttl" -lt 60 ]]; then
            log_warn "max-cache-ttl muy bajo ($max_ttl s) — alta carga de consultas"
        elif [[ "$max_ttl" -gt 86400 ]]; then
            log_warn "max-cache-ttl muy alto ($max_ttl s) — datos obsoletos en caché"
        else
            log_pass "max-cache-ttl razonable: $max_ttl s"
        fi
    else
        log_info "max-cache-ttl no configurado (default: 10800)"
    fi

    local min_ttl
    min_ttl=$(get_option_value "min-cache-ttl")
    if [[ -n "$min_ttl" ]]; then
        log_info "min-cache-ttl: $min_ttl segundos"
        if [[ "$min_ttl" -gt 600 ]]; then
            log_warn "min-cache-ttl alto ($min_ttl s) — puede ignorar TTLs bajos legítimos"
        fi
    fi
}

_check_edns() {
    log_subsection "EDNS (Extension Mechanisms for DNS)"

    local edns_udp
    edns_udp=$(get_option_value "edns-udp-size")

    if [[ -z "$edns_udp" ]]; then
        log_info "edns-udp-size no configurado (default: 4096)"
    elif [[ "$edns_udp" -ge 512 && "$edns_udp" -le 4096 ]]; then
        log_pass "edns-udp-size: $edns_udp (dentro de rango recomendado)"
        ((SCORE_TOTAL++)); ((SCORE_PASS++))
    else
        log_warn "edns-udp-size fuera de rango recomendado: $edns_udp (recomendado 512-4096)"
        ((SCORE_TOTAL++)); ((SCORE_WARN++))
    fi

    # EDNS habilitado
    local disable_edns
    disable_edns=$(get_full_config | grep -c 'edns no' 2>/dev/null || echo 0)
    if [[ "$disable_edns" -gt 0 ]]; then
        log_fail "EDNS deshabilitado — puede causar problemas con DNSSEC"
        ((SCORE_TOTAL++)); ((SCORE_FAIL++))
    else
        log_pass "EDNS habilitado"
    fi
}

_check_rate_limiting() {
    log_subsection "Rate Limiting (RRL)"

    if get_full_config | grep -qE '^\s*rate-limit\s*\{'; then
        local rps
        rps=$(get_full_config | awk '/rate-limit\s*\{/,/\}/' | grep 'responses-per-second' | grep -oE '[0-9]+' | head -1)
        log_pass "Rate limiting (RRL) configurado — responses-per-second: ${rps:-N/A}"
        ((SCORE_TOTAL++)); ((SCORE_PASS++))
    else
        log_warn "Rate limiting (RRL) no configurado — vulnerable a amplification attacks"
        ((SCORE_TOTAL++)); ((SCORE_WARN++))
        REPORT_ISSUES+=("Rate limiting (RRL) no configurado — riesgo de DNS amplification")
    fi
}

_check_prefetch() {
    log_subsection "Prefetch de registros"

    local prefetch
    prefetch=$(get_option_value "prefetch")

    if [[ -n "$prefetch" ]]; then
        log_pass "prefetch configurado: $prefetch"
        ((SCORE_TOTAL++)); ((SCORE_PASS++))
    else
        log_info "prefetch no configurado (default BIND9.1+: 2 9)"
    fi
}
