# Caddy: сайт-прикрытие + автоматический сертификат (запускается панелью)
ARG CADDY_VERSION=2
FROM caddy:${CADDY_VERSION} AS caddy-bin

FROM python:3.12-slim

# telemt: "latest" или конкретная версия, например --build-arg TELEMT_VERSION=3.5.14
ARG TELEMT_VERSION=latest
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates wget tar iptables openssh-client \
 && rm -rf /var/lib/apt/lists/* \
 && ARCH="$(uname -m)" \
 && if [ "$TELEMT_VERSION" = "latest" ]; then URL="https://github.com/telemt/telemt/releases/latest/download/telemt-${ARCH}-linux-gnu.tar.gz"; \
    else URL="https://github.com/telemt/telemt/releases/download/${TELEMT_VERSION}/telemt-${ARCH}-linux-gnu.tar.gz"; fi \
 && wget -qO- "$URL" | tar -xz -C /usr/local/bin telemt \
 && chmod +x /usr/local/bin/telemt && telemt --version

COPY --from=caddy-bin /usr/bin/caddy /usr/local/bin/caddy
RUN caddy version

RUN pip install --no-cache-dir fastapi==0.115.6 uvicorn==0.32.1 python-multipart==0.0.17
WORKDIR /app
COPY app/ /app/
COPY exit-setup.sh /app/exit-setup.sh
ENV DATA_DIR=/data PYTHONUNBUFFERED=1
VOLUME /data
CMD ["python", "/app/main.py"]
