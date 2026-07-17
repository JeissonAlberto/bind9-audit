#!/usr/bin/env bash
# lib/recommendations.sh — Generación de recomendaciones basadas en hallazgos

generate_recommendations() {
    log_section "RECOMENDACIONES"

    REPORT_RECOMMENDATIONS=()

    _recommend_security
    _recommend_performance
    _recommend_logging
    _recommend_dnssec
    _recommend_general

    if [[ ${#REPORT_RECOMMENDATIONS[@]} -eq 0 ]]; then
        log_pass "Sin recomendaciones adicionales — configuración en buen estado"
    else
        log_info "Total de recomendaciones: ${#REPORT_RECOMMENDATIONS[@]}"
        local i=1
        for rec in "${REPORT_RECOMMENDATIONS[@]}"; do
            log_info "  [$i] $rec"
            ((i++))
        done
    fi
}

_recommend_security() {
    # Basado en REPORT_ISSUES y hallazgos

    # Versión BIND expuesta
    local version_val
    version_val=$(get_option_value "version")
    if [[ -z "$version_val" || ("$version_val" != "none" && "$version_val" != '"none"') ]]; then
        REPORT_RECOMMENDATIONS+=("Ocultar versión BIND: agregar 'version \"none\";' en options {}")
    fi

    # Hostname expuesto
    local hostname_val
    hostname_val=$(get_option_value "hostname")
    if [[ -z "$hostname_val" || "$hostname_val" != "none" ]]; then
        REPORT_RECOMMENDATIONS+=("Ocultar hostname: agregar 'hostname none;' en options {}")
    fi

    # allow-transfer
    local allow_transfer
    allow_transfer=$(get_option_value "allow-transfer")
    if [[ -z "$allow_transfer" ]]; then
        REPORT_RECOMMENDATIONS+=("Configurar 'allow-transfer { none; };' para prevenir AXFR no autorizados")
    fi

    # TSIG
    if ! get_full_config | grep -qE '^\s*key\s+"'; then
        REPORT_RECOMMENDATIONS+=("Implementar TSIG keys (hmac-sha256+) para autenticar comunicación entre servidores DNS")
    fi

    # Chroot
    local pid
    pid=$(pgrep -x named 2>/dev/null | head -1)
    if [[ -n "$pid" ]]; then
        local root_link
        root_link=$(readlink /proc/"$pid"/root 2>/dev/null)
        if [[ "$root_link" == "/" ]]; then
            REPORT_RECOMMENDATIONS+=("Ejecutar named en entorno chroot para reducir superficie de ataque")
        fi
    fi

    # Rate limiting
    if ! get_full_config | grep -qE '^\s*rate-limit\s*\{'; then
        REPORT_RECOMMENDATIONS+=("Habilitar Rate Limiting (RRL): agregar bloque 'rate-limit { responses-per-second 10; };' en options {}")
    fi

    # RPZ
    if ! get_full_config | grep -qiE 'response-policy\s*\{'; then
        REPORT_RECOMMENDATIONS+=("Considerar Response Policy Zones (RPZ) para bloquear dominios maliciosos")
    fi

    # allow-update
    local allow_update
    allow_update=$(get_option_value "allow-update")
    if [[ -z "$allow_update" ]]; then
        REPORT_RECOMMENDATIONS+=("Configurar 'allow-update { none; };' explícitamente para deshabilitar Dynamic DNS si no es necesario")
    fi
}

_recommend_performance() {
    # max-cache-size
    local cache_size
    cache_size=$(get_option_value "max-cache-size")
    if [[ -z "$cache_size" ]]; then
        local mem_mb
        mem_mb=$(free -m 2>/dev/null | awk '/^Mem:/{print int($2*0.3)}')
        if [[ -n "$mem_mb" ]]; then
            REPORT_RECOMMENDATIONS+=("Configurar 'max-cache-size ${mem_mb}m;' (aprox. 30% RAM disponible)")
        fi
    fi

    # Rate limiting
    if ! get_full_config | grep -qE '^\s*rate-limit\s*\{'; then
        REPORT_RECOMMENDATIONS+=("Habilitar RRL para prevenir DNS amplification attacks")
    fi

    # recursive-clients
    local rec_clients
    rec_clients=$(get_option_value "recursive-clients")
    if [[ -z "$rec_clients" ]]; then
        REPORT_RECOMMENDATIONS+=("Configurar 'recursive-clients 1000;' para limitar clientes recursivos simultáneos")
    fi

    # prefetch
    local prefetch
    prefetch=$(get_option_value "prefetch")
    if [[ -z "$prefetch" ]]; then
        REPORT_RECOMMENDATIONS+=("Habilitar prefetch: 'prefetch 2 9;' para reducir latencia en registros populares")
    fi

    # edns-udp-size
    local edns
    edns=$(get_option_value "edns-udp-size")
    if [[ -z "$edns" ]]; then
        REPORT_RECOMMENDATIONS+=("Considerar ajustar 'edns-udp-size 4096;' según la red")
    fi
}

_recommend_logging() {
    # Logging completo
    if ! get_full_config | grep -qE '^\s*logging\s*\{'; then
        REPORT_RECOMMENDATIONS+=("Configurar bloque logging con categorías: security, queries, xfer-in, xfer-out, dnssec, update")
        return
    fi

    local logging_block
    logging_block=$(get_full_config | awk '/^\s*logging\s*\{/,/^\s*\}/')

    for cat in "security" "queries" "xfer-in" "xfer-out" "dnssec" "update"; do
        if ! echo "$logging_block" | grep -qE "category\s+${cat}\s*\{"; then
            REPORT_RECOMMENDATIONS+=("Agregar categoría de log '$cat' para mejor trazabilidad")
        fi
    done

    # Logrotate
    if [[ ! -f "/etc/logrotate.d/named" && ! -f "/etc/logrotate.d/bind9" ]]; then
        REPORT_RECOMMENDATIONS+=("Configurar logrotate para BIND9 en /etc/logrotate.d/named")
    fi
}

_recommend_dnssec() {
    local dnssec_val
    dnssec_val=$(get_option_value "dnssec-validation")

    if [[ "$dnssec_val" == "no" ]]; then
        REPORT_RECOMMENDATIONS+=("URGENTE: Habilitar DNSSEC validation: 'dnssec-validation auto;'")
    elif [[ -z "$dnssec_val" ]]; then
        REPORT_RECOMMENDATIONS+=("Configurar explícitamente: 'dnssec-validation auto;'")
    fi

    # Zonas sin DNSSEC
    local unsigned_zones=()
    while IFS= read -r zone; do
        [[ -z "$zone" ]] && continue
        local zone_type
        zone_type=$(get_zone_type "$zone")
        [[ "$zone_type" != "master" && "$zone_type" != "primary" ]] && continue

        local zone_block
        zone_block=$(get_full_config | awk "/zone\s+\"${zone}\"/,/^\s*\}/")
        if ! echo "$zone_block" | grep -qE 'dnssec-policy|auto-dnssec'; then
            unsigned_zones+=("$zone")
        fi
    done <<< "$(list_zones)"

    if [[ ${#unsigned_zones[@]} -gt 0 ]]; then
        REPORT_RECOMMENDATIONS+=("Firmar con DNSSEC las zonas: ${unsigned_zones[*]} (usar dnssec-policy default;)")
    fi
}

_recommend_general() {
    # Actualizaciones
    local bind_version
    bind_version=$(named -v 2>/dev/null | grep -oP 'BIND\s+\K[\d.]+' | head -1)
    if [[ -n "$bind_version" ]]; then
        REPORT_RECOMMENDATIONS+=("Verificar que BIND $bind_version esté actualizado: https://www.isc.org/bind/")
    fi

    # AppArmor / SELinux
    if command -v apparmor_status &>/dev/null; then
        if ! apparmor_status 2>/dev/null | grep -q "named"; then
            REPORT_RECOMMENDATIONS+=("Habilitar perfil AppArmor para named")
        fi
    elif command -v getenforce &>/dev/null; then
        local selinux
        selinux=$(getenforce 2>/dev/null)
        if [[ "$selinux" == "Disabled" ]]; then
            REPORT_RECOMMENDATIONS+=("Considerar habilitar SELinux en modo Enforcing para mayor seguridad")
        fi
    fi

    # Firewall
    if command -v ufw &>/dev/null; then
        if ufw status 2>/dev/null | grep -qi "inactive"; then
            REPORT_RECOMMENDATIONS+=("Habilitar firewall (ufw) y restringir acceso al puerto 53")
        fi
    elif command -v firewall-cmd &>/dev/null; then
        if ! firewall-cmd --state 2>/dev/null | grep -qi "running"; then
            REPORT_RECOMMENDATIONS+=("Habilitar firewalld y configurar zona para DNS")
        fi
    fi

    # Zona inversa
    local has_reverse=false
    while IFS= read -r zone; do
        if echo "$zone" | grep -qE 'in-addr\.arpa|ip6\.arpa'; then
            has_reverse=true
            break
        fi
    done <<< "$(list_zones)"

    if [[ "$has_reverse" == false ]]; then
        REPORT_RECOMMENDATIONS+=("Considerar configurar zonas de resolución inversa (in-addr.arpa)")
    fi
}
