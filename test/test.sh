#!/bin/bash

set -e

SCRIPT_DIR=$(dirname "$0")
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
KEYSTORE="$SCRIPT_DIR/cas/thekeystore"
TRUSTSTORE="$SCRIPT_DIR/jenkins/cacerts"
PLUGIN_SRC="$SCRIPT_DIR/../target/cas-plugin.hpi"
PLUGIN_DST="$SCRIPT_DIR/jenkins/plugins/cas-plugin.jpi"

if [ ! -e "$KEYSTORE" ]; then
    echo "Generating key store"
    keytool -genkeypair -alias localhost -keystore "$KEYSTORE" -storepass changeit -keyalg RSA -keysize 2048 -sigalg SHA256withRSA -validity 365 -dname "CN=localhost" -ext "san=dns:localhost" 
else
    echo "Skipping key store generation (already done)"
fi

if [ ! -e "$TRUSTSTORE" ]; then
    echo "Generating trust store"
    CERTFILE=$(mktemp)
    docker compose -f "$COMPOSE_FILE" run --rm jenkins bash -c 'cat $JAVA_HOME/lib/security/cacerts' > "$TRUSTSTORE"
    keytool -exportcert -alias localhost -keystore "$KEYSTORE" -storepass changeit -rfc -file "$CERTFILE"
    keytool -importcert -noprompt -keystore "$TRUSTSTORE" -storepass changeit -file "$CERTFILE" -alias localhost
    rm "$CERTFILE"
else
    echo "Skipping trust store generation (already done)"
fi

echo "Downloading required plugins"
docker compose -f "$COMPOSE_FILE" run --rm jenkins jenkins-plugin-cli -p bouncycastle-api jackson2-api mailer script-security

echo "Copying CAS plugin to Jenkins plugins directory"
if [ -e "$PLUGIN_SRC" ]; then
    cp "$PLUGIN_SRC" "$PLUGIN_DST.override"
else
    echo "Cannot find '$PLUGIN_SRC', please build it before running this script."
    exit 1
fi

echo "Starting containers"
docker compose -f "$COMPOSE_FILE" up -d

echo
echo "Please wait for the containers to start, then connect to http://localhost:8080 and start testing"
echo "Default CAS user is 'casuser' with password 'Mellon'"
echo "Use 'docker compose logs -f' to watch logs"
echo "Use 'docker compose down -v' to destroy containers and volumes"
