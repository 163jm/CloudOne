FROM debian:bookworm-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tzdata sqlite3 openssl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /app/data

ARG TARGETARCH
COPY cloudone-linux-${TARGETARCH} /app/cloudone
RUN chmod +x /app/cloudone

EXPOSE 6677
CMD ["/app/cloudone"]
