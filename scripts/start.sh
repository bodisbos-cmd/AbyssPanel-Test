#!/bin/sh
set -eu
mkdir -p /data /tmp/nginx-client-body /tmp/nginx-proxy /tmp/nginx-fastcgi /tmp/nginx-uwsgi /tmp/nginx-scgi
nginx -t
nginx -g 'daemon off;' &
NGINX_PID=$!
uvicorn app.main:app --host 127.0.0.1 --port 8000 --proxy-headers --forwarded-allow-ips='127.0.0.1' &
APP_PID=$!
shutdown() {
  kill -TERM "$APP_PID" "$NGINX_PID" 2>/dev/null || true
  wait "$APP_PID" 2>/dev/null || true
  wait "$NGINX_PID" 2>/dev/null || true
}
trap shutdown INT TERM EXIT
while kill -0 "$APP_PID" 2>/dev/null && kill -0 "$NGINX_PID" 2>/dev/null; do sleep 2; done
exit 1
