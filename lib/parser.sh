#!/usr/bin/env bash
# lib/parser.sh — Parseo y extracción de directivas del named.conf

NAMED_CONF=""
NAMED_CONF_DIR=""

init_parser() {
    local conf_candidates=("/etc/named.conf" "/etc/bind/named.conf" "/etc/named/named.conf")

    for f in "${conf_candidates[@]}"; do
        if [[ -f "$f" ]]; then
            NAMED_CONF="$f"
            NAMED_CONF_DIR=$(dirname "$f")
            break
        fi
    done

    if [[ -z "$NAMED_CONF" ]]; then
        log_warn "Parser: archivo named.conf no encontrado"
        return 1
    fi

    log_info "Parser inicializado con: $NAMED_CONF"
}

# Obtiene el valor de una directiva simple en named.conf
# Uso: get_option "allow-query"
get_option() {
    local key="$1"
    grep -E "^\s*${key}\s+" "$NAMED_CONF" 2>/dev/null \
        | head -1 \
        | sed -E "s/^\s*${key}\s+//" \
        | tr -d '";' \
        | xargs
}

# Obtiene un bloque completo entre llaves
# Uso: get_block "options"
get_block() {
    local block="$1"
    awk "/^\s*${block}\s*\{/,/^\s*\}/" "$NAMED_CONF" 2>/dev/null
}

# Verifica si una directiva existe en options {}
option_exists() {
    local key="$1"
    get_block "options" | grep -qE "^\s*${key}\s+"
}

# Retorna el valor de una opción dentro del bloque options {}
get_option_value() {
    local key="$1"
    get_block "options" \
        | grep -E "^\s*${key}\s+" \
        | head -1 \
        | sed -E "s/^\s*${key}\s+//" \
        | tr -d '";' \
        | xargs
}

# Lista todos los archivos include del named.conf
get_includes() {
    grep -E '^\s*include\s+' "$NAMED_CONF" 2>/dev/null \
        | sed -E 's/^\s*include\s+//' \
        | tr -d '";' \
        | xargs
}

# Combina named.conf con todos sus includes en un solo stream
get_full_config() {
    cat "$NAMED_CONF"
    for inc in $(get_includes); do
        if [[ -f "$inc" ]]; then
            cat "$inc"
        elif [[ -f "${NAMED_CONF_DIR}/${inc}" ]]; then
            cat "${NAMED_CONF_DIR}/${inc}"
        fi
    done
}

# Extrae IPs de una ACL definida en named.conf
# Uso: get_acl_ips "trusted"
get_acl_ips() {
    local acl_name="$1"
    get_full_config \
        | awk "/^\s*acl\s+\"?${acl_name}\"?\s*\{/,/^\s*\}/" \
        | grep -v "^[[:space:]]*acl" \
        | tr -d '{}; ' \
        | grep -v '^$'
}

# Lista todas las zonas definidas
list_zones() {
    get_full_config \
        | grep -E '^\s*zone\s+"' \
        | sed -E 's/^\s*zone\s+"//' \
        | cut -d'"' -f1
}

# Tipo de una zona específica
get_zone_type() {
    local zone="$1"
    get_full_config \
        | awk "/^\s*zone\s+\"${zone}\"/,/^\s*\}/" \
        | grep -E '^\s*type\s+' \
        | head -1 \
        | sed -E 's/^\s*type\s+//' \
        | tr -d '";' \
        | xargs
}

# Archivo de zona de una zona específica
get_zone_file() {
    local zone="$1"
    local zone_file
    zone_file=$(get_full_config \
        | awk "/^\s*zone\s+\"${zone}\"/,/^\s*\}/" \
        | grep -E '^\s*file\s+' \
        | head -1 \
        | sed -E 's/^\s*file\s+//' \
        | tr -d '";' \
        | xargs)

    # Resolver ruta relativa
    if [[ -n "$zone_file" && ! "$zone_file" = /* ]]; then
        echo "${NAMED_CONF_DIR}/${zone_file}"
    else
        echo "$zone_file"
    fi
}
