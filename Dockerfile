FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATA_DIR=/data XRAY_BIN=/usr/local/bin/xray COOKIE_SECURE=1

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl unzip nginx && rm -rf /var/lib/apt/lists/* && rm -f /etc/nginx/sites-enabled/default

# Fetch the official Xray Linux x64 release and verify its published SHA-256.
RUN set -eu; \
    tag="$(curl -fsSL --retry 3 --retry-delay 2 https://api.github.com/repos/XTLS/Xray-core/releases/latest | python -c 'import json,sys; print(json.load(sys.stdin)["tag_name"])')"; \
    url="https://github.com/XTLS/Xray-core/releases/download/${tag}"; \
    curl -fsSL --retry 3 --retry-delay 2 "${url}/Xray-linux-64.zip" -o /tmp/xray.zip; \
    curl -fsSL --retry 3 --retry-delay 2 "${url}/Xray-linux-64.zip.dgst" -o /tmp/xray.dgst; \
    expected="$(grep -i "SHA256" /tmp/xray.dgst | grep -oE "[0-9a-fA-F]{64}" | head -n 1)"; \
    test -n "$expected"; printf '%s  %s\n' "$expected" /tmp/xray.zip | sha256sum -c -; \
    unzip -q /tmp/xray.zip xray -d /usr/local/bin; chmod 0755 /usr/local/bin/xray; \
    rm -f /tmp/xray.zip /tmp/xray.dgst; /usr/local/bin/xray version

WORKDIR /app
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY nginx/nginx.conf /etc/nginx/nginx.conf
COPY nginx/default.conf /etc/nginx/conf.d/default.conf
COPY scripts/start.sh /usr/local/bin/abyss-start
RUN chmod 0755 /usr/local/bin/abyss-start && useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin abyss && mkdir -p /data /tmp/nginx-client-body /tmp/nginx-proxy /tmp/nginx-fastcgi /tmp/nginx-uwsgi /tmp/nginx-scgi && chown -R abyss:abyss /data /tmp/nginx-client-body /tmp/nginx-proxy /tmp/nginx-fastcgi /tmp/nginx-uwsgi /tmp/nginx-scgi
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=45s --retries=3 CMD curl -fsS http://127.0.0.1:8080/health || exit 1
CMD ["/usr/local/bin/abyss-start"]
