#
# Copyright (c) 2020-2023 SECOM CO., LTD. All Rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
#

THIS_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
ROOT_DIR := $(abspath $(THIS_DIR)/../..)

CFLAGS = -Wall -g
LDFLAGS = $(CMD_LD) -lt_cose -lqcbor -lm
INC = $(CMD_INC) -I $(ROOT_DIR)/inc -I $(ROOT_DIR)/examples/common -I $(ROOT_DIR)/examples/inc
TAM = $(ROOT_DIR)/bin/teep_cose_tam
AGENT = $(ROOT_DIR)/bin/teep_cose_agent
SRCS = \
	$(ROOT_DIR)/examples/common/teep_examples_common.c \
	$(ROOT_DIR)/src/teep_common.c \
	$(ROOT_DIR)/src/cose_print_common.c \
	$(ROOT_DIR)/src/teep_message_decode.c \
	$(ROOT_DIR)/src/teep_message_print.c \
	$(ROOT_DIR)/src/teep_cose.c
OBJDIR = $(THIS_DIR)/obj
REL_SRCS = $(patsubst $(ROOT_DIR)/%,%,$(SRCS))
OBJS = $(addprefix $(OBJDIR)/,$(patsubst %.c,%.o,$(REL_SRCS)))
TAM_OBJ = $(OBJDIR)/teep_cose_tam.o
AGENT_OBJ = $(OBJDIR)/teep_cose_agent.o

ifeq ($(MBEDTLS),1)
    # use MbedTLS
    CFLAGS += -DLIBTEEP_PSA_CRYPTO_C=1
    LDFLAGS += -lmbedcrypto
else
    # use OpenSSL
    MBEDTLS=0
    LDFLAGS += -lcrypto
endif

.PHONY: all
all: $(TAM) $(AGENT)

include $(ROOT_DIR)/Makefile.common

$(OBJDIR)/%.o: $(ROOT_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INC) -o $@ -c $<

$(TAM_OBJ): $(ROOT_DIR)/examples/cose/teep_cose_test_main.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INC) -DTEEP_ACTOR_TAM=1 -o $@ -c $<

$(AGENT_OBJ): $(ROOT_DIR)/examples/cose/teep_cose_test_main.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INC) -DTEEP_ACTOR_AGENT=1 -o $@ -c $<

$(TAM): $(OBJS) $(TAM_OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

$(AGENT): $(OBJS) $(AGENT_OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

.PHONY: clean
clean:
	$(RM) $(OBJS) $(TAM_OBJ) $(AGENT_OBJ) $(TAM) $(AGENT)


SOURCES := \
	query_request.cbor \
	query_response.cbor \
	update.cbor \
	teep_success.cbor \
	teep_error.cbor

$(SOURCES):
	$(MAKE) -C $(ROOT_DIR)/testfiles $@

run: $(TAM) $(AGENT) $(SOURCES)
	$(TAM)   $(ROOT_DIR)/testfiles/query_request.cbor  $(ROOT_DIR)/testfiles/query_request_cose.cbor  || exit 1
	$(AGENT) $(ROOT_DIR)/testfiles/query_response.cbor $(ROOT_DIR)/testfiles/query_response_cose.cbor || exit 1
	$(TAM)   $(ROOT_DIR)/testfiles/update.cbor         $(ROOT_DIR)/testfiles/update_cose.cbor         || exit 1
	$(AGENT) $(ROOT_DIR)/testfiles/teep_success.cbor   $(ROOT_DIR)/testfiles/teep_success_cose.cbor   || exit 1
	$(AGENT) $(ROOT_DIR)/testfiles/teep_error.cbor     $(ROOT_DIR)/testfiles/teep_error_cose.cbor     || exit 1
