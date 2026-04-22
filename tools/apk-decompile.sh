#!/bin/bash
# APKTool 反编译 launcher
# 用法: ./apk-decompile.sh <apk-file> [output-dir]

set -e

TOOLS="/opt/data/home/reverse-tools"
JAVA="$TOOLS/jdk-17.0.18+8"
APKTOOL_JAR="$TOOLS/apktool/apktool.jar"
export PATH="$JAVA/bin:$PATH"

APK="$1"
OUTPUT_DIR="${2:-$TOOLS/decompiled}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

if [ -z "$APK" ]; then
    echo "用法: $0 <apk-file> [output-dir]"
    exit 1
fi

APK_NAME=$(basename "$APK" .apk)
WORK_DIR="$OUTPUT_DIR/$APK_NAME"
mkdir -p "$WORK_DIR"

echo "▶ APK 反编译: $APK"
echo "  输出目录: $WORK_DIR"
echo ""

java -jar "$APKTOOL_JAR" d "$APK" -o "$WORK_DIR" -f

echo ""
echo "✅ 反编译完成: $WORK_DIR"
echo "   使用 jadx 打开: $TOOLS/bin/jadx $WORK_DIR"
