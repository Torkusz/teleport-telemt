FROM python:3.12-slim

# telemt: "latest" или конкретная версия, например --build-arg TELEMT_VERSION=3.5.14
ARG TELEMT_VERSION=latest
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates wget tar iptables \
 && rm -rf /var/lib/apt/lists/* \
 && ARCH="$(uname -m)" \
 && if [ "$TELEMT_VERSION" = "latest" ]; then URL="https://github.com/telemt/telemt/releases/latest/download/telemt-${ARCH}-linux-gnu.tar.gz"; \
    else URL="https://github.com/telemt/telemt/releases/download/${TELEMT_VERSION}/telemt-${ARCH}-linux-gnu.tar.gz"; fi \
 && wget -qO- "$URL" | tar -xz -C /usr/local/bin telemt \
 && chmod +x /usr/local/bin/telemt && telemt --version

RUN pip install --no-cache-dir fastapi==0.115.6 uvicorn==0.32.1
WORKDIR /app
COPY app/ /app/
ENV DATA_DIR=/data PYTHONUNBUFFERED=1
VOLUME /data
CMD ["python", "/app/main.py"]
