#!/usr/bin/env bash
# lib/dnssec.sh — Auditoría de DNSSEC

check_dnssec() {
    log_section "DNSSEC"

    _check_dnssec_validation
    _check_dnssec_signing
    _check_dnssec_key_files
    _check_dnssec_managed_keys
}

_check_dnssec_validation() {
    log_subsection "Validación DNSSEC"

    local dnssec_val
    dnssec_val=$(get_option_value "dnssec-validation")

    case "$dnssec_val" in
        auto)
            log_pass "dnssec-validation: auto (recomendado)"
            ((SCORE_TOTAL++)); ((SCORE_PASS++))
            ;;
        yes)
            log_pass "dnssec-validation: yes"
            ((SCORE_TOTAL++)); ((SCORE_PASS++))
            ;;
        no)
            log_fail "dnssec-validation: no — validación DNSSEC deshabilitada"
            ((SCORE_TOTAL++)); ((SCORE_FAIL++))
            REPORT_ISSUES+=("CRÍTICO: dnssec-validation deshabilitado")
            ;;
        "")
            log_warn "dnssec-validation no configurado explícitamente"
            ((SCORE_TOTAL++)); ((SCORE_WARN++))
            ;;
        *)
            log_warn "dnssec-validation valor desconocido: $dnssec_val"
            ((SCORE_TOTAL++)); ((SCORE_WARN++))
            ;;
    esac
}

_check_dnssec_signing() {
    log_subsection "Firma DNSSEC (zonas)"

    local zones_signed=0
    local zones_total=0

    while IFS= read -r zone; do
        [[ -z "$zone" ]] && continue
        local zone_type
        zone_type=$(get_zone_type "$zone")
        [[ "$zone_type" != "master" && "$zone_type" != "primary" ]] && continue

        ((zones_total++))

        # Buscar dnssec-policy o auto-dnssec en la zona
        local zone_block
        zone_block=$(get_full_config | awk "/zone\s+\"${zone}\"/,/^\s*\}/")
        
        if echo "$zone_block" | grep -qE 'dnssec-policy|auto-dnssec'; then
            log_pass "Zona $zone tiene configuración DNSSEC"
            ((zones_signed++))
        else
            log_warn "Zona $zone sin DNSSEC configurado"
        fi

    done <<< "$(list_zones)"

    if [[ $zones_total -gt 0 ]]; then
        log_info "Zonas master firmadas: $zones_signed/$zones_total"
        if [[ $zones_signed -eq $zones_total ]]; then
            ((SCORE_TOTAL++)); ((SCORE_PASS++))
        elif [[ $zones_signed -gt 0 ]]; then
            ((SCORE_TOTAL++)); ((SCORE_WARN++))
        else
            ((SCORE_TOTAL++)); ((SCORE_FAIL++))
        fi
    fi
}

_check_dnssec_key_files() {
    log_subsection "Archivos de claves DNSSEC"

    local key_dirs=("/etc/bind/keys" "/var/lib/bind/keys" "/etc/named/keys" "/var/named/keys")
    local keys_found=0

    for dir in "${key_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            local ksk_count zsk_count
            ksk_count=$(find "$dir" -name "K*.key" 2>/dev/null | wc -l)
            zsk_count=$(find "$dir" -name "K*.private" 2>/dev/null | wc -l)

            if [[ $ksk_count -gt 0 ]]; then
                log_pass "Claves DNSSEC encontradas en $dir ($ksk_count archivos .key)"
                ((keys_found++))

                # Verificar permisos de claves privadas
                while IFS= read -r keyfile; do
                    local perms
                    perms=$(stat -c "%a" "$keyfile" 2>/dev/null)
                    if [[ "$perms" == "600" || "$perms" == "640" ]]; then
                        log_pass "Permisos correctos en $keyfile ($perms)"
                    else
                        log_fail "Permisos inseguros en clave privada $keyfile ($perms) — debe ser 600"
                        REPORT_ISSUES+=("Permisos inseguros en clave DNSSEC: $keyfile ($perms)")
                    fi
                done < <(find "$dir" -name "K*.private" 2>/dev/null)
            fi
        fi
    done

    if [[ $keys_found -eq 0 ]]; then
        log_info "No se encontraron directorios de claves DNSSEC"
    fi
}

_check_dnssec_managed_keys() {
    log_subsection "Claves administradas (trust anchors)"

    local managed_keys_dirs=("/var/named/dynamic" "/var/lib/bind" "/etc/bind")
    for dir in "${managed_keys_dirs[@]}"; do
        if find "$dir" -name "managed-keys.bind*" -o -name "trusted-key*" 2>/dev/null | grep -q .; then
            log_pass "Archivos de trust anchors encontrados en $dir"
        fi
    done

    # Verificar trust-anchors o managed-keys en config
    if get_full_config | grep -qE '^\s*(trust-anchors|managed-keys|trusted-keys)\s*\{'; then
        log_pass "Trust anchors configurados en named.conf"
        ((SCORE_TOTAL++)); ((SCORE_PASS++))
    else
        log_warn "No se encontraron trust anchors explícitos (puede usar auto)"
        ((SCORE_TOTAL++)); ((SCORE_WARN++))
    fi
}
