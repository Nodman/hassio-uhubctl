#!/bin/bash
# Setup udev rules for USB hub control
# This script configures proper permissions for uhubctl to control USB ports

set -e

echo "[$(date)] Setting up USB udev rules for uhubctl..."

# Create udev rules directory if it doesn't exist
mkdir -p /etc/udev/rules.d/

# Create udev rules for uhubctl USB hub control
cat > /etc/udev/rules.d/52-uhubctl.rules << 'EOF'
# uhubctl - USB hub per-port power control
# https://github.com/mvp/uhubctl

# For Linux 6.0+ (Home Assistant OS 16.x uses Linux 6.x kernel)
# This rule sets proper permissions for sysfs disable files
SUBSYSTEM=="usb", DRIVER=="hub|usb", \
 RUN+="/bin/sh -c \"chown -f root:dialout $sys$devpath/*/disable || true\"" \
 RUN+="/bin/sh -c \"chmod -f 660 $sys$devpath/*/disable || true\""

# For older kernels and general USB device access
SUBSYSTEM=="usb", DRIVER=="hub|usb", MODE="0664", GROUP="dialout"

# Raspberry Pi 4B specific hub IDs (from CLAUDE.md telemetry)
# USB 2.0 Hub: Vid=1d6b (Linux Foundation), Vid=2109 (VIA Labs)
# USB 3.0 Hub: Vid=1d6b (Linux Foundation)
SUBSYSTEM=="usb", ATTR{idVendor}=="1d6b", MODE="0664", GROUP="dialout"
SUBSYSTEM=="usb", ATTR{idVendor}=="2109", MODE="0664", GROUP="dialout"
EOF

echo "[$(date)] Created udev rules at /etc/udev/rules.d/52-uhubctl.rules"

# Reload udev rules if udevadm is available
if command -v udevadm >/dev/null 2>&1; then
    echo "[$(date)] Reloading udev rules..."
    udevadm control --reload-rules 2>/dev/null || echo "[$(date)] Warning: Could not reload udev rules"
    udevadm trigger --attr-match=subsystem=usb 2>/dev/null || echo "[$(date)] Warning: Could not trigger udev events"
    echo "[$(date)] udev rules reloaded"
else
    echo "[$(date)] Warning: udevadm not available - udev rules will take effect on next reboot"
fi

# Check if current user/process has access to dialout group
if groups | grep -q dialout 2>/dev/null; then
    echo "[$(date)] Current process has dialout group access"
else
    echo "[$(date)] Warning: Current process may not have dialout group access"
fi

echo "[$(date)] USB udev setup completed"