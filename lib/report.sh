#!/usr/bin/env bash
# lib/report.sh — Generación del reporte final de auditoría

generate_report() {
    local report_file="$1"
    local format="${2:-text}"   # text | json | html

    case "$format" in
        json) _generate_json_report "$report_file" ;;
        html) _generate_html_report "$report_file" ;;
        *)    _generate_text_report "$report_file" ;;
    esac
}

_calculate_score() {
    local score=0
    if [[ $SCORE_TOTAL -gt 0 ]]; then
        score=$(( (SCORE_PASS * 100) / SCORE_TOTAL ))
    fi
    echo "$score"
}

_score_label() {
    local score="$1"
    if   [[ $score -ge 90 ]]; then echo "EXCELENTE"
    elif [[ $score -ge 75 ]]; then echo "BUENO"
    elif [[ $score -ge 60 ]]; then echo "ACEPTABLE"
    elif [[ $score -ge 40 ]]; then echo "DEFICIENTE"
    else                           echo "CRÍTICO"
    fi
}

_generate_text_report() {
    local report_file="$1"
    local score
    score=$(_calculate_score)
    local label
    label=$(_score_label "$score")
    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')

    {
        echo "╔══════════════════════════════════════════════════════════════════╗"
        echo "║           BIND9 AUDIT REPORT — REPORTE DE AUDITORÍA             ║"
        echo "╚══════════════════════════════════════════════════════════════════╝"
        echo ""
        echo "  Servidor    : $(hostname -f 2>/dev/null || hostname)"
        echo "  Fecha       : $ts"
        echo "  BIND versión: ${REPORT_BIND_VERSION:-Desconocida}"
        echo "  Config      : ${REPORT_CONF_FILE:-No encontrada}"
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "  PUNTUACIÓN GLOBAL: $score/100 — $label"
        echo "  ✅ Pasaron   : $SCORE_PASS"
        echo "  ❌ Fallaron  : $SCORE_FAIL"
        echo "  ⚠️  Advertencias: $SCORE_WARN"
        echo "  📋 Total checks : $SCORE_TOTAL"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""

        if [[ ${#REPORT_ISSUES[@]} -gt 0 ]]; then
            echo "🚨 PROBLEMAS CRÍTICOS / ADVERTENCIAS IMPORTANTES:"
            echo ""
            local i=1
            for issue in "${REPORT_ISSUES[@]}"; do
                echo "  [$i] $issue"
                ((i++))
            done
            echo ""
        fi

        if [[ ${#REPORT_RECOMMENDATIONS[@]} -gt 0 ]]; then
            echo "💡 RECOMENDACIONES:"
            echo ""
            local i=1
            for rec in "${REPORT_RECOMMENDATIONS[@]}"; do
                echo "  [$i] $rec"
                ((i++))
            done
            echo ""
        fi

        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "  Log completo disponible en: $AUDIT_LOG_FILE"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        echo "  Referencias:"
        echo "  • ISC BIND9 ARM   : https://bind9.readthedocs.io/"
        echo "  • NIST DNS Guide  : https://csrc.nist.gov/publications/detail/sp/800-81/2/final"
        echo "  • CIS BIND Bench  : https://www.cisecurity.org/benchmark/dns"
        echo ""

    } | tee "$report_file"

    log_info "Reporte guardado en: $report_file"
}

_generate_json_report() {
    local report_file="$1"
    local score
    score=$(_calculate_score)
    local label
    label=$(_score_label "$score")
    local ts
    ts=$(date '+%Y-%m-%dT%H:%M:%S')

    # Construir JSON con printf para evitar dependencia de jq
    {
        printf '{\n'
        printf '  "audit": {\n'
        printf '    "timestamp": "%s",\n' "$ts"
        printf '    "hostname": "%s",\n' "$(hostname -f 2>/dev/null || hostname)"
        printf '    "bind_version": "%s",\n' "${REPORT_BIND_VERSION:-unknown}"
        printf '    "config_file": "%s"\n' "${REPORT_CONF_FILE:-unknown}"
        printf '  },\n'
        printf '  "score": {\n'
        printf '    "total": %d,\n' "$score"
        printf '    "label": "%s",\n' "$label"
        printf '    "checks_total": %d,\n' "$SCORE_TOTAL"
        printf '    "checks_pass": %d,\n' "$SCORE_PASS"
        printf '    "checks_fail": %d,\n' "$SCORE_FAIL"
        printf '    "checks_warn": %d\n' "$SCORE_WARN"
        printf '  },\n'

        # Issues
        printf '  "issues": [\n'
        local first=true
        for issue in "${REPORT_ISSUES[@]}"; do
            [[ "$first" == true ]] && first=false || printf ',\n'
            printf '    "%s"' "${issue//\"/\\\"}"
        done
        printf '\n  ],\n'

        # Recommendations
        printf '  "recommendations": [\n'
        first=true
        for rec in "${REPORT_RECOMMENDATIONS[@]}"; do
            [[ "$first" == true ]] && first=false || printf ',\n'
            printf '    "%s"' "${rec//\"/\\\"}"
        done
        printf '\n  ]\n'
        printf '}\n'
    } > "$report_file"

    log_pass "Reporte JSON guardado en: $report_file"
}

_generate_html_report() {
    local report_file="$1"
    local score
    score=$(_calculate_score)
    local label
    label=$(_score_label "$score")
    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')

    # Color según puntuación
    local score_color
    if   [[ $score -ge 90 ]]; then score_color="#27ae60"
    elif [[ $score -ge 75 ]]; then score_color="#2ecc71"
    elif [[ $score -ge 60 ]]; then score_color="#f39c12"
    elif [[ $score -ge 40 ]]; then score_color="#e67e22"
    else                           score_color="#e74c3c"
    fi

    cat > "$report_file" << HTML
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BIND9 Audit Report — $(hostname)</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: #1a1a2e; color: #e0e0e0; margin: 0; padding: 20px; }
        .container { max-width: 900px; margin: 0 auto; }
        h1 { color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: 10px; }
        h2 { color: #7ec8e3; margin-top: 30px; }
        .score-box { background: ${score_color}22; border: 2px solid ${score_color}; border-radius: 12px; padding: 20px; text-align: center; margin: 20px 0; }
        .score-num { font-size: 4em; font-weight: bold; color: ${score_color}; }
        .score-label { font-size: 1.5em; color: ${score_color}; }
        .stats { display: flex; gap: 15px; margin: 20px 0; flex-wrap: wrap; }
        .stat { background: #16213e; border-radius: 8px; padding: 15px; flex: 1; min-width: 120px; text-align: center; }
        .stat-num { font-size: 2em; font-weight: bold; }
        .pass { color: #27ae60; }
        .fail { color: #e74c3c; }
        .warn { color: #f39c12; }
        .issues, .recommendations { background: #16213e; border-radius: 8px; padding: 20px; margin: 15px 0; }
        .issue-item { background: #e74c3c22; border-left: 4px solid #e74c3c; padding: 8px 12px; margin: 8px 0; border-radius: 0 6px 6px 0; }
        .rec-item { background: #3498db22; border-left: 4px solid #3498db; padding: 8px 12px; margin: 8px 0; border-radius: 0 6px 6px 0; }
        .meta { background: #0f3460; border-radius: 8px; padding: 15px; margin: 15px 0; font-family: monospace; }
        .meta p { margin: 5px 0; }
        footer { text-align: center; margin-top: 40px; color: #666; font-size: 0.85em; }
    </style>
</head>
<body>
<div class="container">
    <h1>🔍 BIND9 Audit Report</h1>

    <div class="meta">
        <p><strong>Servidor:</strong> $(hostname -f 2>/dev/null || hostname)</p>
        <p><strong>Fecha:</strong> $ts</p>
        <p><strong>BIND versión:</strong> ${REPORT_BIND_VERSION:-Desconocida}</p>
        <p><strong>Configuración:</strong> ${REPORT_CONF_FILE:-No encontrada}</p>
    </div>

    <div class="score-box">
        <div class="score-num">${score}</div>
        <div>/100</div>
        <div class="score-label">$label</div>
    </div>

    <div class="stats">
        <div class="stat"><div class="stat-num pass">${SCORE_PASS}</div><div>✅ Pasaron</div></div>
        <div class="stat"><div class="stat-num fail">${SCORE_FAIL}</div><div>❌ Fallaron</div></div>
        <div class="stat"><div class="stat-num warn">${SCORE_WARN}</div><div>⚠️ Warnings</div></div>
        <div class="stat"><div class="stat-num">${SCORE_TOTAL}</div><div>📋 Total</div></div>
    </div>
HTML

    # Issues
    if [[ ${#REPORT_ISSUES[@]} -gt 0 ]]; then
        echo '<h2>🚨 Problemas Detectados</h2><div class="issues">' >> "$report_file"
        for issue in "${REPORT_ISSUES[@]}"; do
            echo "<div class='issue-item'>$issue</div>" >> "$report_file"
        done
        echo '</div>' >> "$report_file"
    fi

    # Recommendations
    if [[ ${#REPORT_RECOMMENDATIONS[@]} -gt 0 ]]; then
        echo '<h2>💡 Recomendaciones</h2><div class="recommendations">' >> "$report_file"
        for rec in "${REPORT_RECOMMENDATIONS[@]}"; do
            echo "<div class='rec-item'>$rec</div>" >> "$report_file"
        done
        echo '</div>' >> "$report_file"
    fi

    cat >> "$report_file" << HTML
    <footer>
        <p>Generado por bind9-audit | <a href="https://bind9.readthedocs.io/" style="color:#00d4ff">BIND9 Docs</a></p>
    </footer>
</div>
</body>
</html>
HTML

    log_pass "Reporte HTML guardado en: $report_file"
}
