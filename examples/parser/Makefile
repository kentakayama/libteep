#
# Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
#

THIS_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
ROOT_DIR := $(abspath $(THIS_DIR)/../..)

CFLAGS = -Wall -g
LDFLAGS = $(CMD_LD) -lt_cose -lqcbor -lm
INC = $(CMD_INC) -I $(ROOT_DIR)/inc -I $(ROOT_DIR)/examples/common -I $(ROOT_DIR)/examples/inc
TAM = $(ROOT_DIR)/bin/teep_message_parser_tam
AGENT = $(ROOT_DIR)/bin/teep_message_parser_agent
SRCS = $(ROOT_DIR)/examples/common/teep_examples_common.c $(ROOT_DIR)/src/teep_common.c $(ROOT_DIR)/src/cose_print_common.c $(ROOT_DIR)/src/teep_message_decode.c $(ROOT_DIR)/src/teep_message_print.c $(ROOT_DIR)/src/teep_cose.c
TAM_OBJ = $(THIS_DIR)/obj/teep_message_parser_tam.o
AGENT_OBJ = $(THIS_DIR)/obj/teep_message_parser_agent.o
OBJDIR = $(THIS_DIR)/obj
REL_SRCS = $(patsubst $(ROOT_DIR)/%,%,$(SRCS))
OBJS = $(addprefix $(OBJDIR)/,$(patsubst %.c,%.o,$(REL_SRCS)))
COSE_FLAG_TAM = .tam.cose
COSE_FLAG_AGENT = .agent.cose

ifeq ($(suit),1)
    CFLAGS += -DPARSE_SUIT
    LDFLAGS := $(ROOT_DIR)/../libcsuit/bin/libcsuit.a $(LDFLAGS)
    INC += -I $(ROOT_DIR)/../libcsuit/inc -I $(ROOT_DIR)/../libcsuit/examples/inc
endif

ifeq ($(debug),1)
    CFLAGS += -DALLOW_CBOR_WITHOUT_SIGN1
    COSE_FLAG_TAM = .cbor
	COSE_FLAG_AGENT = .cbor
endif

ifeq ($(MBEDTLS),1)
    # use MbedTLS
    CFLAGS += -DLIBTEEP_PSA_CRYPTO_C=1
    LDFLAGS += -lmbedcrypto
else
    # use OpenSSL
    MBEDTLS=0
    LDFLAGS += -lcrypto
endif

.PHONY: all run clean debug_test

all: $(TAM) $(AGENT) $(VERIFIER)

include $(ROOT_DIR)/Makefile.common

$(OBJDIR)/%.o: $(ROOT_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INC) -o $@ -c $<

$(TAM_OBJ): $(ROOT_DIR)/examples/parser/teep_message_parser_main.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INC) -DTEEP_ACTOR_TAM=1 -o $@ -c $<

$(AGENT_OBJ): $(ROOT_DIR)/examples/parser/teep_message_parser_main.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INC) -DTEEP_ACTOR_AGENT=1 -o $@ -c $<

$(TAM): $(OBJS) $(TAM_OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

$(AGENT): $(OBJS) $(AGENT_OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

run: $(TAM) $(AGENT) $(VERIFIER)
	$(AGENT) $(ROOT_DIR)/testfiles/query_request$(COSE_FLAG_TAM) || exit 1
	$(TAM) $(ROOT_DIR)/testfiles/query_response$(COSE_FLAG_AGENT) || exit 1
	$(AGENT) $(ROOT_DIR)/testfiles/update$(COSE_FLAG_TAM) || exit 1
	$(TAM) $(ROOT_DIR)/testfiles/teep_success$(COSE_FLAG_AGENT) || exit 1
	$(TAM) $(ROOT_DIR)/testfiles/teep_error$(COSE_FLAG_AGENT) || exit 1

clean:
	$(RM) $(OBJS) $(TAM_OBJ) $(AGENT_OBJ) $(TAM) $(AGENT)
