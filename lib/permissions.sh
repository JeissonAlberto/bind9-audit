#!/usr/bin/env bash
# lib/permissions.sh — Auditoría de permisos de archivos y directorios de BIND9

check_permissions() {
    log_section "PERMISOS DE ARCHIVOS Y DIRECTORIOS"

    _check_named_user_group
    _check_config_permissions
    _check_zone_file_permissions
    _check_working_dirs
}

_check_named_user_group() {
    log_subsection "Usuario y grupo de named"

    # Usuario configurado
    local run_as
    run_as=$(get_option_value "user")

    if [[ -n "$run_as" ]]; then
        log_info "Directiva user en named.conf: $run_as"
    fi

    # Usuario real del proceso
    local proc_user
    proc_user=$(ps -eo user,comm 2>/dev/null | awk '/named/{print $1}' | head -1)

    if [[ -n "$proc_user" ]]; then
        if [[ "$proc_user" == "root" ]]; then
            log_fail "named corre como root — reducir privilegios"
            ((SCORE_TOTAL++)); ((SCORE_FAIL++))
            REPORT_ISSUES+=("named corriendo como root — usar usuario bind/named")
        elif [[ "$proc_user" == "named" || "$proc_user" == "bind" ]]; then
            log_pass "named corre como usuario sin privilegios: $proc_user"
            ((SCORE_TOTAL++)); ((SCORE_PASS++))
        else
            log_warn "named corre como: $proc_user — verificar si es adecuado"
            ((SCORE_TOTAL++)); ((SCORE_WARN++))
        fi
    fi

    # Verificar existencia del usuario named/bind en el sistema
    for u in named bind; do
        if id "$u" &>/dev/null; then
            local uid
            uid=$(id -u "$u")
            local shell
            shell=$(getent passwd "$u" 2>/dev/null | cut -d: -f7)
            log_info "Usuario $u: UID=$uid, shell=$shell"
            if [[ "$shell" == "/bin/bash" || "$shell" == "/bin/sh" ]]; then
                log_warn "Usuario $u tiene shell interactivo: $shell — usar /sbin/nologin"
                ((SCORE_TOTAL++)); ((SCORE_WARN++))
                REPORT_ISSUES+=("Usuario $u tiene shell interactivo: $shell")
            else
                log_pass "Usuario $u sin shell interactivo: $shell"
                ((SCORE_TOTAL++)); ((SCORE_PASS++))
            fi
        fi
    done
}

_check_config_permissions() {
    log_subsection "Permisos de archivos de configuración"

    local config_files=(
        "/etc/named.conf"
        "/etc/bind/named.conf"
        "/etc/named/named.conf"
        "/etc/bind/named.conf.options"
        "/etc/bind/named.conf.local"
        "/etc/named.conf.options"
    )

    for f in "${config_files[@]}"; do
        [[ -f "$f" ]] || continue

        local perms owner group
        perms=$(stat -c "%a" "$f" 2>/dev/null)
        owner=$(stat -c "%U" "$f" 2>/dev/null)
        group=$(stat -c "%G" "$f" 2>/dev/null)

        log_info "$(basename "$f"): perms=$perms owner=$owner group=$group"

        # Los archivos de config deben ser legibles por named pero no por todos
        if [[ "$perms" == "640" || "$perms" == "644" || "$perms" == "600" ]]; then
            log_pass "Permisos adecuados en $f: $perms"
        elif [[ "${perms: -1}" != "0" ]]; then
            log_warn "Otros usuarios tienen acceso a $f (perms: $perms)"
            ((SCORE_TOTAL++)); ((SCORE_WARN++))
        else
            log_pass "Permisos correctos: $f ($perms)"
            ((SCORE_TOTAL++)); ((SCORE_PASS++))
        fi

        # El dueño no debe ser root sin grupo correcto
        if [[ "$owner" == "root" && "$group" == "root" ]]; then
            log_warn "$f: owner=root:root — grupo debería ser bind/named"
        fi
    done
}

_check_zone_file_permissions() {
    log_subsection "Permisos de archivos de zona"

    local zone_dirs=("/etc/bind/zones" "/var/named" "/var/lib/bind" "/etc/named/zones")
    local issues=0

    for dir in "${zone_dirs[@]}"; do
        [[ -d "$dir" ]] || continue
        log_info "Directorio de zonas: $dir"

        while IFS= read -r zfile; do
            local perms owner
            perms=$(stat -c "%a" "$zfile" 2>/dev/null)
            owner=$(stat -c "%U" "$zfile" 2>/dev/null)

            # World-writable es crítico
            if [[ "${perms: -1}" -ge 2 ]]; then
                log_fail "Archivo de zona world-writable: $zfile ($perms)"
                ((issues++))
                REPORT_ISSUES+=("Zona world-writable: $zfile ($perms)")
            elif [[ "${perms: -1}" -ge 4 ]]; then
                log_warn "Archivo de zona legible por otros: $zfile ($perms)"
            else
                log_pass "Permisos OK: $(basename "$zfile") ($perms, $owner)"
            fi

        done < <(find "$dir" -maxdepth 2 -name "*.zone" -o -name "db.*" 2>/dev/null)
    done

    if [[ $issues -eq 0 ]]; then
        ((SCORE_TOTAL++)); ((SCORE_PASS++))
    else
        ((SCORE_TOTAL++)); ((SCORE_FAIL++))
    fi
}

_check_working_dirs() {
    log_subsection "Directorios de trabajo"

    local work_dir
    work_dir=$(get_option_value "directory")

    if [[ -z "$work_dir" ]]; then
        work_dir="/var/named"
        log_info "Directorio de trabajo (default): $work_dir"
    else
        log_info "Directorio de trabajo configurado: $work_dir"
    fi

    if [[ -d "$work_dir" ]]; then
        local perms owner
        perms=$(stat -c "%a" "$work_dir" 2>/dev/null)
        owner=$(stat -c "%U" "$work_dir" 2>/dev/null)
        log_info "Permisos $work_dir: $perms (owner: $owner)"

        # No debe ser world-writable
        if [[ "${perms: -1}" -ge 2 ]]; then
            log_fail "Directorio de trabajo world-writable: $work_dir ($perms)"
            ((SCORE_TOTAL++)); ((SCORE_FAIL++))
            REPORT_ISSUES+=("Directorio de trabajo world-writable: $work_dir")
        else
            log_pass "Directorio de trabajo con permisos correctos"
            ((SCORE_TOTAL++)); ((SCORE_PASS++))
        fi
    fi

    # Verificar directorio de dump y statistics
    for opt in "dump-file" "statistics-file" "memstatistics-file"; do
        local opt_val
        opt_val=$(get_option_value "$opt")
        if [[ -n "$opt_val" ]]; then
            log_info "$opt: $opt_val"
            local opt_dir
            opt_dir=$(dirname "$opt_val")
            if [[ -d "$opt_dir" ]]; then
                local dp
                dp=$(stat -c "%a" "$opt_dir" 2>/dev/null)
                log_info "  → directorio $opt_dir perms: $dp"
            fi
        fi
    done
}
