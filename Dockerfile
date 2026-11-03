# Build the C components and run the unit tests, then ship a small runtime image.
FROM gcc:13-bookworm AS build
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      libssl-dev default-libmysqlclient-dev pkg-config \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Makefile .
COPY src src
COPY tests tests
RUN make -s all && ./bin/test_common > /dev/null

FROM debian:bookworm-slim
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      libssl3 libmariadb3 nftables openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/bin/pg-gateway /src/bin/van-sim /usr/local/bin/
COPY scripts/gen_certs.sh scripts/gateway-entrypoint.sh /usr/local/bin/
RUN sed -i 's/\r$//' /usr/local/bin/*.sh && chmod +x /usr/local/bin/*.sh
