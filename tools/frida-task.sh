#!/bin/bash
# Frida Hook 任务执行器
# 用法: ./frida-task.sh <package-name> <frida-script.js> [output-dir]

set -e

TOOLS="/opt/data/home/reverse-tools"
JAVA="$TOOLS/jdk-17.0.18+8"
FRIDA_SERVER="$TOOLS/frida/frida-server"
export PATH="$JAVA/bin:$PATH"

PACKAGE="$1"
SCRIPT="$2"
OUTPUT_DIR="${3:-$TOOLS/output}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

if [ -z "$PACKAGE" ] || [ -z "$SCRIPT" ]; then
    echo "用法: $0 <package-name> <frida-script.js> [output-dir]"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "▶ Frida Hook 启动"
echo "  Package : $PACKAGE"
echo "  Script  : $SCRIPT"
echo "  Output  : $OUTPUT_DIR/frida_$TIMESTAMP.log"

# 等待 frida-server（假设已手动启动）
# frida -U -f "$PACKAGE" -l "$SCRIPT" \
#     -o "$OUTPUT_DIR/frida_$TIMESTAMP.log" \
#     --no-pause

# 无设备模式（本地 inject）
frida -n "$PACKAGE" -l "$SCRIPT" \
    -o "$OUTPUT_DIR/frida_$TIMESTAMP.log" \
    2>&1

echo "✅ 完成: $OUTPUT_DIR/frida_$TIMESTAMP.log"
