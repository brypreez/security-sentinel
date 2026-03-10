#!/bin/bash
# k8s-nuke.sh
# Description: Automated Reaper for unauthorized Kubernetes manifests.
# Author: Bryan Perez
# Version: 2.0.0

LOG_FILE="/var/ossec/logs/active-responses.log"

# Maintenance mode kill switch
if [ -f "/tmp/SENTINEL_OFF" ]; then
    echo "$(date) - MAINTENANCE MODE active. Exiting." >> "$LOG_FILE"
    exit 0
fi

read -r INPUT
FILE_PATH=$(echo "$INPUT" | grep -oP '(?<="path":")[^"]*')
SAFE_DIR="/etc/kubernetes/manifests"

# Component whitelist — never delete core control plane files
WHITELIST="kube-apiserver|kube-controller-manager|kube-scheduler|etcd"
if echo "$FILE_PATH" | grep -qE "$WHITELIST"; then
    echo "$(date) - WHITELISTED: $FILE_PATH. No action taken." >> "$LOG_FILE"
    exit 0
fi

if [[ "$FILE_PATH" == "$SAFE_DIR"* ]]; then
    echo "$(date) - RAW INPUT RECEIVED: $INPUT" >> "$LOG_FILE"
    if [ -f "$FILE_PATH" ]; then
        echo "$(date) - THREAT DETECTED: $FILE_PATH. Executing Nuke..." >> "$LOG_FILE"
        rm -f "$FILE_PATH"
        echo "$(date) - SUCCESS: $FILE_PATH has been removed." >> "$LOG_FILE"
    else
        echo "$(date) - NOTICE: File $FILE_PATH already gone." >> "$LOG_FILE"
    fi
else
    echo "$(date) - SAFETY ALERT: Path outside safe dir blocked: $FILE_PATH" >> "$LOG_FILE"
fi
exit 0
