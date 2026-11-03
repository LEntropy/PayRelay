# Build image for the C components, also used to run the unit tests.
FROM gcc:13-bookworm
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      libssl-dev default-libmysqlclient-dev pkg-config \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
