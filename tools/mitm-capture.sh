#!/bin/bash
# mitmproxy 抓包启动器
# 用法: ./mitm-capture.sh [output-dir] [listen-port]
#
# 注意: 需要 root 权限设置端口转发（Android USB调试时）
#   adb forward tcp:8080 tcp:8080

set -e

TOOLS="/opt/data/home/reverse-tools"
OUTPUT_DIR="${1:-$TOOLS/capture}"
PORT="${2:-8080}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$OUTPUT_DIR"

SCRIPT="$TOOLS/mitm-script.py"
HAR_FILE="$OUTPUT_DIR/capture_$TIMESTAMP.har"
LOG_FILE="$OUTPUT_DIR/mitm_$TIMESTAMP.log"

echo "▶ mitmproxy 抓包启动"
echo "  Proxy   : http://127.0.0.1:$PORT"
echo "  HAR     : $HAR_FILE"
echo "  Log     : $LOG_FILE"
echo ""
echo "  按 Ctrl+C 停止抓包"
echo ""

mitmproxy \
    --listen-port "$PORT" \
    --web-interface-host 127.0.0.1 \
    -s "$SCRIPT" \
    --set output_tcp_file="$HAR_FILE" \
    2>&1 | tee "$LOG_FILE"
