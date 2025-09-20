#!/usr/bin/with-contenv bashio
set +eu

# Check if the log level configuration option exists
declare LOG_LEVEL="INFO"
if bashio::config.has_value 'LOG_LEVEL'; then
    LOG_LEVEL="$(bashio::string.lower "$(bashio::config 'LOG_LEVEL')")"
fi
bashio::log.blue "Log level is set to ${LOG_LEVEL}"

# Setup USB permissions once at startup
bashio::log.blue "Setting up USB device permissions..."
if /app/setup-udev.sh; then
    bashio::log.green "USB setup completed successfully"
else
    bashio::log.yellow "USB setup completed with warnings"
fi

while true
do
    bashio::log.blue "Starting MQTT - uhubctl bridge..."

    if ! bashio::services.available "mqtt"; then
        bashio::log.red "No MQTT service running! Retry after 30 seconds..."
    else
        export MQTT_HOST=$(bashio::services "mqtt" "host")
        export MQTT_PORT=$(bashio::services "mqtt" "port")
        export MQTT_USERNAME=$(bashio::services "mqtt" "username")
        export MQTT_PASSWORD=$(bashio::services "mqtt" "password")
        python3 main.py --log ${LOG_LEVEL}
    fi
    sleep 30
done
