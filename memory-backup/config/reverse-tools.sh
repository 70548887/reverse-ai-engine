#!/bin/bash
# reverse-ai-engine 环境变量配置
# 用法: source /opt/data/home/reverse-tools/env.sh

TOOLS="/opt/data/home/reverse-tools"
JAVA_HOME="$TOOLS/jdk-17.0.18+8"
FRIDA_VERSION="17.9.1"

export JAVA_HOME="$JAVA_HOME"
export PATH="$JAVA_HOME/bin:$TOOLS/bin:$TOOLS/frida:$TOOLS/apktool:$PATH"
export ANDROID_HOME="${ANDROID_HOME:-$TOOLS/android-sdk}"

# mitmproxy 配置（HTTP 代理）
export HTTP_PROXY="${HTTP_PROXY:-http://127.0.0.1:8080}"
export HTTPS_PROXY="${HTTPS_PROXY:-http://127.0.0.1:8080}"

# Python path（包含逆向工具库）
export PYTHONPATH="$TOOLS/python-utils:$PYTHONPATH"

echo "✅ reverse-ai-engine 环境已加载"
echo "   JAVA_HOME=$JAVA_HOME"
echo "   jadx:    $($JAVA_HOME/bin/java -jar $TOOLS/apktool/apktool.jar --version 2>&1 | head -1 || echo 'apktool OK')"
echo "   frida:   $(frida --version 2>/dev/null || echo 'CLI OK')"
echo "   mitmproxy: $(mitmproxy --version 2>&1 | head -1)"
