#
# Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
#

THIS_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
ROOT_DIR := $(abspath $(THIS_DIR)/../..)

CFLAGS = -Wall -g
LDFLAGS = $(CMD_LD) -lt_cose -lqcbor -lcurl -lm
INC = $(CMD_INC) -I $(ROOT_DIR)/inc -I $(ROOT_DIR)/examples/common -I $(ROOT_DIR)/examples/inc
TARGET = $(ROOT_DIR)/bin/teep_http_client
SRCS := $(ROOT_DIR)/examples/client/teep_http_client_main.c
SRCS += $(ROOT_DIR)/examples/common/teep_examples_common.c
SRCS += $(ROOT_DIR)/src/teep_common.c
SRCS += $(ROOT_DIR)/src/teep_cose.c
SRCS += $(ROOT_DIR)/src/teep_message_print.c
SRCS += $(ROOT_DIR)/src/teep_message_decode.c
SRCS += $(ROOT_DIR)/src/teep_message_encode.c
SRCS += $(ROOT_DIR)/examples/client/teep_http_client.c

OBJDIR = $(THIS_DIR)/obj
REL_SRCS = $(patsubst $(ROOT_DIR)/%,%,$(SRCS))
OBJS = $(addprefix $(OBJDIR)/,$(patsubst %.c,%.o,$(REL_SRCS)))

ifeq ($(MBEDTLS),1)
    # use MbedTLS
    CFLAGS += -DLIBTEEP_PSA_CRYPTO_C=1
    LDFLAGS +=-lmbedcrypto
else
    # use OpenSSL
    MBEDTLS=0
    LDFLAGS += -lcrypto
endif

ifdef debug
    CFLAGS += -DALLOW_CBOR_WITHOUT_SIGN1 -DSEND_CBOR_WITHOUT_SIGN1
endif

.PHONY: all debug clean

all: $(TARGET)

include $(ROOT_DIR)/Makefile.common

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

$(OBJDIR)/%.o: $(ROOT_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INC) -o $@ -c $<


run: $(TARGET)
	sh -c "$(ROOT_DIR)/testfiles/tam_server.sh > $(ROOT_DIR)/tam_stdout.txt &"
	sleep 1
	sh -c "$(TARGET) > $(ROOT_DIR)/agent_stdout.txt"

clean:
	$(RM) $(OBJS) $(TARGET)
