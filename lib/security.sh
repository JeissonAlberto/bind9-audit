#!/usr/bin/env bash
# lib/security.sh — Auditoría de seguridad de BIND9

check_security() {
    log_section "SEGURIDAD"

    _check_version_hiding
    _check_hostname_hiding
    _check_allow_update
    _check_chroot
    _check_tsig
    _check_blackhole
    _check_rndc_key
    _check_chaos_class
    _check_rpz
}

_check_version_hiding() {
    log_subsection "Ocultación de versión"

    local version_str
    version_str=$(get_option_value "version")

    if [[ "$version_str" == "none" || "$version_str" == "\"none\"" ]]; then
        log_pass "version: none — versión oculta"
        ((SCORE_TOTAL++)); ((SCORE_PASS++))
    elif [[ -n "$version_str" && "$version_str" != "none" ]]; then
        if echo "$version_str" | grep -qiE 'bind|[0-9]+\.[0-9]+'; then
            log_fail "version revela información real: $version_str"
            ((SCORE_TOTAL++)); ((SCORE_FAIL++))
            REPORT_ISSUES+=("version revela información de BIND: $version_str")
        else
            log_warn "version configurada como: $version_str (personalizada)"
            ((SCORE_TOTAL++)); ((SCORE_WARN++))
        fi
    else
        log_fail "version no configurado — revela versión real de BIND9"
        ((SCORE_TOTAL++)); ((SCORE_FAIL++))
        REPORT_ISSUES+=("Versión de BIND visible públicamente — configurar version none")

        # Intentar obtener la versión expuesta
        if command -v dig &>/dev/null && pgrep -x named &>/dev/null; then
            local exposed_ver
            exposed_ver=$(dig +short chaos txt version.bind @127.0.0.1 2>/dev/null | tr -d '"')
            [[ -n "$exposed_ver" ]] && log_fail "Versión expuesta: $exposed_ver"
        fi
    fi
}

_check_hostname_hiding() {
    log_subsection "Ocultación de hostname"

    local hostname_str
    hostname_str=$(get_option_value "hostname")

    if [[ "$hostname_str" == "none" || "$hostname_str" == "\"none\"" ]]; then
        log_pass "hostname: none — hostname oculto"
        ((SCORE_TOTAL++)); ((SCORE_PASS++))
    else
        log_warn "hostname no oculto — puede revelar información del servidor"
        ((SCORE_TOTAL++)); ((SCORE_WARN++))
    fi

    local server_id
    server_id=$(get_option_value "server-id")
    if [[ "$server_id" == "none" || "$server_id" == "\"none\"" ]]; then
        log_pass "server-id: none"
    elif [[ -n "$server_id" ]]; then
        log_warn "server-id configurado: $server_id"
    fi
}

_check_allow_update() {
    log_subsection "Actualizaciones dinámicas (Dynamic DNS)"

    local allow_update
    allow_update=$(get_option_value "allow-update")

    if [[ -z "$allow_update" || "$allow_update" == "none" || "$allow_update" == "{none;}" ]]; then
        log_pass "allow-update: none — Dynamic DNS deshabilitado globalmente"
        ((SCORE_TOTAL++)); ((SCORE_PASS++))
    elif echo "$allow_update" | grep -qiE '^any$'; then
        log_fail "allow-update: any — Dynamic DNS abierto a CUALQUIER host (CRÍTICO)"
        ((SCORE_TOTAL++)); ((SCORE_FAIL++))
        REPORT_ISSUES+=("CRÍTICO: allow-update any — cualquier host puede modificar zonas")
    else
        log_warn "allow-update configurado: $allow_update — verificar con TSIG"
        ((SCORE_TOTAL++)); ((SCORE_WARN++))
    fi

    # Verificar por zona también
    while IFS= read -r zone; do
        [[ -z "$zone" ]] && continue
        local zone_block
        zone_block=$(get_full_config | awk "/zone\s+\"${zone}\"/,/^\s*\}/")
        if echo "$zone_block" | grep -qE 'allow-update\s+\{?\s*any'; then
            log_fail "Zona $zone: allow-update any — CRÍTICO"
            REPORT_ISSUES+=("CRÍTICO: Zona $zone con allow-update any")
        fi
    done <<< "$(list_zones)"
}

_check_chroot() {
    log_subsection "Entorno chroot"

    # Detectar si named corre en chroot
    local pid
    pid=$(pgrep -x named 2>/dev/null | head -1)

    if [[ -n "$pid" ]]; then
        local root_link
        root_link=$(readlink /proc/"$pid"/root 2>/dev/null)
        if [[ "$root_link" != "/" && -n "$root_link" ]]; then
            log_pass "named corriendo en chroot: $root_link"
            ((SCORE_TOTAL++)); ((SCORE_PASS++))
        else
            log_warn "named NO está en chroot — considera usar chroot para mayor seguridad"
            ((SCORE_TOTAL++)); ((SCORE_WARN++))
        fi
    fi

    # Verificar usuario que corre named
    local named_user
    named_user=$(ps -eo user,comm 2>/dev/null | grep 'named' | awk '{print $1}' | head -1)
    if [[ -n "$named_user" ]]; then
        if [[ "$named_user" == "root" ]]; then
            log_fail "named corriendo como root — riesgo de seguridad"
            ((SCORE_TOTAL++)); ((SCORE_FAIL++))
            REPORT_ISSUES+=("named corriendo como root — usar usuario no privilegiado")
        else
            log_pass "named corriendo como usuario: $named_user"
            ((SCORE_TOTAL++)); ((SCORE_PASS++))
        fi
    fi
}

_check_tsig() {
    log_subsection "TSIG (Transaction Signatures)"

    if get_full_config | grep -qE '^\s*key\s+"'; then
        local key_count
        key_count=$(get_full_config | grep -cE '^\s*key\s+"' || echo 0)
        log_pass "TSIG keys configuradas: $key_count"
        ((SCORE_TOTAL++)); ((SCORE_PASS++))

        # Verificar algoritmo de las claves
        get_full_config | awk '/^\s*key\s+"/,/^\s*\}/' | grep -i 'algorithm' | while read -r line; do
            local algo
            algo=$(echo "$line" | grep -oiE 'hmac-[a-z0-9-]+')
            if echo "$algo" | grep -qiE 'hmac-md5|hmac-sha1$'; then
                log_warn "Algoritmo TSIG débil detectado: $algo — usar hmac-sha256 o superior"
                REPORT_ISSUES+=("TSIG usa algoritmo débil: $algo")
            elif [[ -n "$algo" ]]; then
                log_pass "Algoritmo TSIG: $algo"
            fi
        done
    else
        log_warn "Sin TSIG keys configuradas — comunicación DNS sin autenticar"
        ((SCORE_TOTAL++)); ((SCORE_WARN++))
    fi
}

_check_blackhole() {
    log_subsection "Lista negra (blackhole)"

    local blackhole
    blackhole=$(get_option_value "blackhole")

    if [[ -n "$blackhole" && "$blackhole" != "none" ]]; then
        log_pass "blackhole configurado: $blackhole"
        ((SCORE_TOTAL++)); ((SCORE_PASS++))
    else
        log_info "blackhole no configurado — sin bloqueo de IPs"
    fi
}

_check_rndc_key() {
    log_subsection "RNDC (Remote Name Daemon Control)"

    local rndc_conf_candidates=("/etc/rndc.conf" "/etc/bind/rndc.conf" "/etc/named/rndc.conf")
    local rndc_key_candidates=("/etc/rndc.key" "/etc/bind/rndc.key" "/etc/named/rndc.key")

    local found=false
    for f in "${rndc_conf_candidates[@]}" "${rndc_key_candidates[@]}"; do
        if [[ -f "$f" ]]; then
            log_pass "Archivo RNDC encontrado: $f"
            found=true

            local perms
            perms=$(stat -c "%a" "$f" 2>/dev/null)
            if [[ "$perms" == "600" || "$perms" == "640" ]]; then
                log_pass "Permisos de $f: $perms (correcto)"
                ((SCORE_TOTAL++)); ((SCORE_PASS++))
            else
                log_fail "Permisos inseguros en $f: $perms (debe ser 600 o 640)"
                ((SCORE_TOTAL++)); ((SCORE_FAIL++))
                REPORT_ISSUES+=("Permisos inseguros en RNDC: $f ($perms)")
            fi
        fi
    done

    if [[ "$found" == false ]]; then
        log_warn "No se encontró configuración RNDC"
    fi
}

_check_chaos_class() {
    log_subsection "Clase CHAOS (información del servidor)"

    if command -v dig &>/dev/null && pgrep -x named &>/dev/null; then
        local authors
        authors=$(dig +short chaos txt authors.bind @127.0.0.1 2>/dev/null)
        if [[ -n "$authors" ]]; then
            log_warn "Clase CHAOS responde (authors.bind): $authors"
            ((SCORE_TOTAL++)); ((SCORE_WARN++))
        else
            log_pass "Clase CHAOS no responde o está filtrada"
            ((SCORE_TOTAL++)); ((SCORE_PASS++))
        fi
    fi
}

_check_rpz() {
    log_subsection "Response Policy Zones (RPZ)"

    if get_full_config | grep -qiE 'response-policy\s*\{'; then
        log_pass "RPZ configurado — filtrado de respuestas activo"
        ((SCORE_TOTAL++)); ((SCORE_PASS++))
    else
        log_info "RPZ no configurado (opcional, para filtrado de dominios maliciosos)"
    fi
}
