# SPDX-License-Identifier: PostgreSQL
# PGXS build: `make USE_PGXS=1`, against the pg_config on PATH (or PG_CONFIG=...).
MODULE_big = pg_gcm
OBJS = src/pg_gcm.o src/fn_encrypt.o src/gcm.o src/envelope.o src/nonce.o
EXTENSION = pg_gcm
DATA = sql/pg_gcm--0.1.0.sql
REGRESS = $(patsubst test/sql/%.sql,%,$(wildcard test/sql/*.sql))
REGRESS_OPTS = --inputdir=test --load-extension=pg_gcm

# The server's own libcrypto and nothing else: no static linking, no bundled copy.
SHLIB_LINK += -lcrypto

PG_CONFIG ?= pg_config

# C11. CI and scripts/build-in-docker.sh set PG_GCM_WERROR=1: -Wall -Wextra -Werror on this
# project's code, with the server's headers taken as system headers so that their own
# -Wextra noise (unused parameters in static inlines) does not fail the build.
PG_CFLAGS += -std=gnu11
ifdef PG_GCM_WERROR
PG_CFLAGS += -Wall -Wextra -Werror
PG_CPPFLAGS += -isystem $(shell $(PG_CONFIG) --includedir-server)
endif
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
