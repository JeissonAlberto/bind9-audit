#!/usr/bin/env bash
# lib/statistics.sh — Estadísticas de BIND9 vía rndc y archivos de estadísticas

check_statistics() {
    log_section "ESTADÍSTICAS DEL SERVIDOR"

    _check_stats_channel
    _check_rndc_stats
    _check_named_stats_file
}

_check_stats_channel() {
    log_subsection "Canal de estadísticas HTTP"

    if get_full_config | grep -qE '^\s*statistics-channels\s*\{'; then
        local stats_port
        stats_port=$(get_full_config | awk '/statistics-channels\s*\{/,/\}/' \
            | grep -oE 'port\s+[0-9]+' | grep -oE '[0-9]+' | head -1)

        local stats_listen
        stats_listen=$(get_full_config | awk '/statistics-channels\s*\{/,/\}/' \
            | grep -oE 'inet\s+[^\s]+' | head -1)

        log_pass "statistics-channels configurado (puerto: ${stats_port:-N/A})"
        log_info "Escuchando en: ${stats_listen:-N/A}"

        # Verificar que no esté expuesto públicamente
        if echo "$stats_listen" | grep -qE 'inet\s+(0\.0\.0\.0|any|\*)'; then
            log_warn "statistics-channels accesible desde cualquier IP — restringir con allow"
            ((SCORE_TOTAL++)); ((SCORE_WARN++))
            REPORT_ISSUES+=("statistics-channels expuesto públicamente")
        else
            log_pass "statistics-channels con acceso restringido"
            ((SCORE_TOTAL++)); ((SCORE_PASS++))
        fi

        # Intentar conectar
        if [[ -n "$stats_port" ]] && command -v curl &>/dev/null; then
            local http_status
            http_status=$(curl -s -o /dev/null -w "%{http_code}" \
                "http://127.0.0.1:${stats_port}/" --connect-timeout 3 2>/dev/null)
            if [[ "$http_status" == "200" ]]; then
                log_pass "Estadísticas HTTP accesibles: http://127.0.0.1:${stats_port}/"
            else
                log_warn "statistics-channels configurado pero no responde (HTTP $http_status)"
            fi
        fi
    else
        log_info "statistics-channels no configurado — sin interfaz HTTP de estadísticas"
    fi
}

_check_rndc_stats() {
    log_subsection "Estadísticas via rndc"

    if ! command -v rndc &>/dev/null; then
        log_warn "rndc no disponible"
        return
    fi

    if ! pgrep -x named &>/dev/null; then
        log_warn "named no está corriendo — omitiendo rndc stats"
        return
    fi

    # Obtener status
    local rndc_status
    rndc_status=$(rndc status 2>&1)

    if echo "$rndc_status" | grep -qi "permission denied\|connection refused\|could not"; then
        log_warn "No se pudo conectar a rndc: $(echo "$rndc_status" | head -1)"
        ((SCORE_TOTAL++)); ((SCORE_WARN++))
        return
    fi

    log_pass "rndc conectado correctamente"
    ((SCORE_TOTAL++)); ((SCORE_PASS++))

    # Parsear datos relevantes
    echo "$rndc_status" | while IFS= read -r line; do
        case "$line" in
            *"server is up and running"*)
                log_pass "Estado: servidor activo y funcionando"
                ;;
            *"uptime:"*)
                log_info "Uptime named: $(echo "$line" | sed 's/.*uptime://' | xargs)"
                ;;
            *"queries:"*|*"queries-in:"*)
                log_info "$(echo "$line" | xargs)"
                ;;
            *"nta count:"*|*"zone count:"*)
                log_info "$(echo "$line" | xargs)"
                ;;
            *"recursive clients:"*)
                log_info "$(echo "$line" | xargs)"
                ;;
        esac
    done

    # Generar volcado de estadísticas
    local stats_file
    stats_file=$(get_option_value "statistics-file")
    stats_file="${stats_file:-/var/named/data/named_stats.txt}"

    if rndc stats 2>/dev/null; then
        if [[ -f "$stats_file" ]]; then
            log_pass "Estadísticas volcadas en: $stats_file"
            _parse_stats_file "$stats_file"
        fi
    fi
}

_parse_stats_file() {
    local stats_file="$1"

    log_info "--- Resumen de estadísticas ---"

    # Queries totales
    local total_queries
    total_queries=$(grep -A20 "Incoming Requests" "$stats_file" 2>/dev/null \
        | grep -oE '[0-9]+ QUERY' | awk '{sum+=$1} END{print sum}')
    [[ -n "$total_queries" ]] && log_info "Total QUERY recibidas: $total_queries"

    # Respuestas NXDOMAIN
    local nxdomain
    nxdomain=$(grep "NXDOMAIN" "$stats_file" 2>/dev/null | grep -oE '[0-9]+' | head -1)
    [[ -n "$nxdomain" ]] && log_info "Respuestas NXDOMAIN: $nxdomain"

    # Errores de resolución
    local servfail
    servfail=$(grep "SERVFAIL" "$stats_file" 2>/dev/null | grep -oE '[0-9]+' | head -1)
    if [[ -n "$servfail" && "$servfail" -gt 100 ]]; then
        log_warn "SERVFAIL alto: $servfail — posible problema de resolución"
    elif [[ -n "$servfail" ]]; then
        log_info "SERVFAIL: $servfail"
    fi

    # Queries recursivas
    local recursive
    recursive=$(grep -i "recursive" "$stats_file" 2>/dev/null | grep -oE '[0-9]+' | head -1)
    [[ -n "$recursive" ]] && log_info "Queries recursivas: $recursive"
}

_check_named_stats_file() {
    log_subsection "Archivo de estadísticas"

    local stats_file
    stats_file=$(get_option_value "statistics-file")

    if [[ -z "$stats_file" ]]; then
        log_info "statistics-file no configurado (default: named_stats.txt)"
        return
    fi

    if [[ -f "$stats_file" ]]; then
        local size age
        size=$(du -sh "$stats_file" 2>/dev/null | cut -f1)
        age=$(stat -c "%y" "$stats_file" 2>/dev/null | cut -d. -f1)
        log_info "Archivo de estadísticas: $stats_file (tamaño: $size, modificado: $age)"
        ((SCORE_TOTAL++)); ((SCORE_PASS++))
    else
        log_warn "statistics-file configurado pero no existe: $stats_file"
        ((SCORE_TOTAL++)); ((SCORE_WARN++))
    fi
}
