#!/usr/bin/env bash
# lib/zones.sh — Auditoría de zonas DNS

check_zones() {
    log_section "AUDITORÍA DE ZONAS DNS"

    local zones
    zones=$(list_zones)

    if [[ -z "$zones" ]]; then
        log_warn "No se encontraron zonas definidas"
        return
    fi

    local zone_count=0
    local zone_errors=0

    while IFS= read -r zone; do
        [[ -z "$zone" ]] && continue
        ((zone_count++))
        log_subsection "Zona: $zone"

        local zone_type
        zone_type=$(get_zone_type "$zone")
        log_info "Tipo: ${zone_type:-desconocido}"

        _check_zone_file "$zone" "$zone_type" || ((zone_errors++))

    done <<< "$zones"

    log_info "Total zonas analizadas: $zone_count — errores: $zone_errors"

    if [[ $zone_errors -eq 0 ]]; then
        ((SCORE_TOTAL++)); ((SCORE_PASS++))
    else
        ((SCORE_TOTAL++)); ((SCORE_FAIL++))
    fi
}

_check_zone_file() {
    local zone="$1"
    local zone_type="$2"

    # Solo validar zonas master/primary con archivo
    if [[ "$zone_type" != "master" && "$zone_type" != "primary" ]]; then
        log_info "Zona de tipo '$zone_type' — sin validación de archivo"
        return 0
    fi

    local zone_file
    zone_file=$(get_zone_file "$zone")

    if [[ -z "$zone_file" ]]; then
        log_warn "No se encontró directiva 'file' para la zona $zone"
        return 1
    fi

    if [[ ! -f "$zone_file" ]]; then
        log_fail "Archivo de zona no existe: $zone_file"
        return 1
    fi

    log_info "Archivo: $zone_file"
    _validate_zone_syntax "$zone" "$zone_file"
    _check_zone_soa "$zone" "$zone_file"
    _check_zone_ns "$zone" "$zone_file"
}

_validate_zone_syntax() {
    local zone="$1"
    local zone_file="$2"

    if ! command -v named-checkzone &>/dev/null; then
        log_warn "named-checkzone no disponible"
        return
    fi

    local output
    output=$(named-checkzone "$zone" "$zone_file" 2>&1)
    if [[ $? -eq 0 ]]; then
        log_pass "Sintaxis de zona válida"
    else
        log_fail "Errores en zona $zone:"
        echo "$output" | tail -5 | while read -r line; do log_fail "  $line"; done
        return 1
    fi
}

_check_zone_soa() {
    local zone="$1"
    local zone_file="$2"

    # Verificar registro SOA presente
    if grep -qiE '^\s*@\s+.*\s+SOA\s+' "$zone_file" 2>/dev/null; then
        log_pass "Registro SOA presente"
    else
        log_fail "Registro SOA no encontrado en $zone_file"
    fi

    # Verificar serial razonable (> 1000)
    local serial
    serial=$(grep -A5 -iE 'SOA' "$zone_file" 2>/dev/null \
        | grep -oE '[0-9]{8,10}' | head -1)
    if [[ -n "$serial" ]]; then
        log_info "Serial SOA: $serial"
        if [[ "$serial" -gt 1000 ]]; then
            log_pass "Serial SOA tiene valor razonable"
        else
            log_warn "Serial SOA parece muy bajo: $serial"
        fi
    fi
}

_check_zone_ns() {
    local zone="$1"
    local zone_file="$2"

    local ns_count
    ns_count=$(grep -ciE '\s+NS\s+' "$zone_file" 2>/dev/null || echo 0)

    if [[ "$ns_count" -ge 2 ]]; then
        log_pass "Al menos 2 registros NS presentes ($ns_count)"
    elif [[ "$ns_count" -eq 1 ]]; then
        log_warn "Solo 1 registro NS — se recomienda mínimo 2"
    else
        log_fail "No se encontraron registros NS en la zona"
    fi
}

check_zone_transfers() {
    log_section "TRANSFERENCIAS DE ZONA (AXFR)"

    local allow_transfer
    allow_transfer=$(get_option_value "allow-transfer")

    if [[ -z "$allow_transfer" || "$allow_transfer" == "none" ]]; then
        log_pass "allow-transfer: none — AXFR deshabilitado globalmente"
        ((SCORE_TOTAL++)); ((SCORE_PASS++))
    elif echo "$allow_transfer" | grep -qiE 'any|0\.0\.0\.0'; then
        log_fail "allow-transfer: any — AXFR abierto a cualquier host (CRÍTICO)"
        ((SCORE_TOTAL++)); ((SCORE_FAIL++))
        REPORT_ISSUES+=("CRÍTICO: AXFR abierto a cualquier host (allow-transfer any)")
    else
        log_warn "allow-transfer configurado: $allow_transfer — verificar que sea correcto"
        ((SCORE_TOTAL++)); ((SCORE_WARN++))
    fi
}
