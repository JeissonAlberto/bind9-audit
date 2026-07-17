#!/usr/bin/env bash
# lib/recursion.sh — Auditoría de recursión y open resolver

check_recursion() {
    log_section "RECURSIÓN DNS"

    _check_recursion_config
    _check_allow_recursion
    _check_allow_query
    _check_open_resolver
    _check_forwarders
}

_check_recursion_config() {
    log_subsection "Configuración de recursión"

    local recursion
    recursion=$(get_option_value "recursion")

    case "$recursion" in
        yes|"")
            # Recursión habilitada — verificar que esté restringida
            log_warn "recursion: yes (o por defecto) — verificar allow-recursion"
            ;;
        no)
            log_pass "recursion: no — servidor autoritativo puro"
            ((SCORE_TOTAL++)); ((SCORE_PASS++))
            return
            ;;
    esac
}

_check_allow_recursion() {
    log_subsection "Control de allow-recursion"

    local allow_recursion
    allow_recursion=$(get_option_value "allow-recursion")

    if [[ -z "$allow_recursion" ]]; then
        log_fail "allow-recursion no configurado — puede ser open resolver"
        ((SCORE_TOTAL++)); ((SCORE_FAIL++))
        REPORT_ISSUES+=("CRÍTICO: allow-recursion no configurado — posible open resolver")
        return
    fi

    if echo "$allow_recursion" | grep -qiE '^any$|^0\.0\.0\.0'; then
        log_fail "allow-recursion: any — servidor es un OPEN RESOLVER (CRÍTICO)"
        ((SCORE_TOTAL++)); ((SCORE_FAIL++))
        REPORT_ISSUES+=("CRÍTICO: Servidor es un open resolver (allow-recursion any)")
    elif echo "$allow_recursion" | grep -qiE 'localhost|127\.0\.0\.1|::1'; then
        log_pass "allow-recursion restringido a localhost"
        ((SCORE_TOTAL++)); ((SCORE_PASS++))
    else
        log_warn "allow-recursion: $allow_recursion — verificar que el rango sea correcto"
        ((SCORE_TOTAL++)); ((SCORE_WARN++))
    fi
}

_check_allow_query() {
    log_subsection "Control de allow-query"

    local allow_query
    allow_query=$(get_option_value "allow-query")

    if [[ -z "$allow_query" || "$allow_query" == "any" ]]; then
        log_warn "allow-query: any (o no configurado) — acepta queries de cualquier origen"
        ((SCORE_TOTAL++)); ((SCORE_WARN++))
    else
        log_pass "allow-query restringido: $allow_query"
        ((SCORE_TOTAL++)); ((SCORE_PASS++))
    fi

    # allow-query-cache
    local allow_query_cache
    allow_query_cache=$(get_option_value "allow-query-cache")
    if [[ -n "$allow_query_cache" ]]; then
        if echo "$allow_query_cache" | grep -qiE '^any$'; then
            log_warn "allow-query-cache: any — cache accesible a todos"
        else
            log_pass "allow-query-cache: $allow_query_cache"
        fi
    fi
}

_check_open_resolver() {
    log_subsection "Test de open resolver (local)"

    # Solo testear si dig está disponible y named corre localmente
    if ! command -v dig &>/dev/null; then
        log_warn "dig no disponible — test de open resolver omitido"
        return
    fi

    if ! pgrep -x named &>/dev/null; then
        log_warn "named no está corriendo — test de open resolver omitido"
        return
    fi

    local test_domain="google.com"
    local result
    result=$(dig +short +time=3 +tries=1 "@127.0.0.1" "$test_domain" A 2>/dev/null)

    if [[ -n "$result" ]]; then
        log_fail "Open resolver confirmado: resuelve $test_domain desde 127.0.0.1 → $result"
        # Nota: esto es esperado si la recursión está limitada a localhost, no es necesariamente un problema
        log_warn "(Si allow-recursion localhost, esto es correcto y esperado)"
        ((SCORE_TOTAL++)); ((SCORE_WARN++))
    else
        log_pass "No responde a queries recursivas desde 127.0.0.1 (puede ser autoritativo puro)"
        ((SCORE_TOTAL++)); ((SCORE_PASS++))
    fi
}

_check_forwarders() {
    log_subsection "Forwarders"

    local forwarders_block
    forwarders_block=$(get_block "options" | awk '/forwarders\s*\{/,/\}/')

    if [[ -z "$forwarders_block" ]]; then
        log_info "Sin forwarders configurados"
        return
    fi

    log_info "Forwarders configurados:"
    echo "$forwarders_block" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | while read -r ip; do
        log_info "  → $ip"
    done

    local forward_only
    forward_only=$(get_option_value "forward")
    if [[ "$forward_only" == "only" ]]; then
        log_warn "forward: only — depende completamente de los forwarders"
        ((SCORE_TOTAL++)); ((SCORE_WARN++))
    else
        log_pass "forward: first (intentará resolver directamente si forwarder falla)"
        ((SCORE_TOTAL++)); ((SCORE_PASS++))
    fi
}
