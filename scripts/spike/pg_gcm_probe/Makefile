# SPDX-License-Identifier: PostgreSQL
# Measurement-only module for Phase S; built by scripts/spike/measure.sh, never installed by users.
MODULE_big = pg_gcm_probe
OBJS = pg_gcm_probe.o
EXTENSION = pg_gcm_probe
DATA = pg_gcm_probe--1.0.sql
SHLIB_LINK += -lcrypto

PG_CONFIG ?= pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
