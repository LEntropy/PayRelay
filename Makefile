CC      ?= gcc
CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 -D_GNU_SOURCE -Wall -Wextra -Wpedantic -Wshadow -Wformat=2 -Wno-format-y2k -Isrc/common
LDLIBS  += -lssl -lcrypto -lpthread
MYSQL_CFLAGS := $(shell mysql_config --cflags 2>/dev/null || pkg-config --cflags mysqlclient 2>/dev/null)
MYSQL_LIBS   := $(shell mysql_config --libs 2>/dev/null || pkg-config --libs mysqlclient 2>/dev/null)

ifeq ($(SANITIZE),1)
CFLAGS  += -O1 -fsanitize=address,undefined -fno-omit-frame-pointer
LDFLAGS += -fsanitize=address,undefined
endif

COMMON := src/common/telegram.c src/common/card.c src/common/util.c src/common/tlsio.c
GATEWAY_SRC := src/gateway/main.c src/gateway/conn.c src/gateway/worker.c src/gateway/store.c \
               src/gateway/guard.c src/gateway/control.c

all: bin/pg-gateway bin/van-sim bin/test_common

bin:
	mkdir -p bin

bin/pg-gateway: $(GATEWAY_SRC) $(COMMON) src/gateway/*.h src/common/*.h | bin
	$(CC) $(CFLAGS) $(MYSQL_CFLAGS) -o $@ $(GATEWAY_SRC) $(COMMON) $(LDFLAGS) $(LDLIBS) $(MYSQL_LIBS)

bin/van-sim: src/vansim/van_sim.c $(COMMON) src/common/*.h | bin
	$(CC) $(CFLAGS) -o $@ src/vansim/van_sim.c $(COMMON) $(LDFLAGS) $(LDLIBS)

bin/test_common: tests/test_common.c $(COMMON) src/common/*.h | bin
	$(CC) $(CFLAGS) -o $@ tests/test_common.c $(COMMON) $(LDFLAGS) $(LDLIBS)

test: bin/test_common
	./bin/test_common

clean:
	rm -rf bin

.PHONY: all test clean
