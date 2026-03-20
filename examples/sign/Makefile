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
TARGET = $(ROOT_DIR)/bin/teep_sign_test
SRCS = \
	$(ROOT_DIR)/examples/sign/teep_sign_test_main.c \
	$(ROOT_DIR)/examples/common/teep_examples_common.c \
	$(ROOT_DIR)/src/teep_common.c $(ROOT_DIR)/src/cose_print_common.c $(ROOT_DIR)/src/teep_message_encode.c \
	$(ROOT_DIR)/src/teep_message_decode.c \
	$(ROOT_DIR)/src/teep_message_print.c \
	$(ROOT_DIR)/src/teep_cose.c
OBJDIR = $(THIS_DIR)/obj
REL_SRCS = $(patsubst $(ROOT_DIR)/%,%,$(SRCS))
OBJS = $(addprefix $(OBJDIR)/,$(patsubst %.c,%.o,$(REL_SRCS)))

ifeq ($(MBEDTLS),1)
    # use MbedTLS
    CFLAGS += -DLIBTEEP_PSA_CRYPTO_C=1
    #LDFLAGS += -lmbedtls -lmbedx509
    LDFLAGS += -lmbedcrypto
else
    # use OpenSSL
    MBEDTLS=0
    LDFLAGS += -lcrypto
endif

.PHONY: all clean run

all: $(TARGET)

$(OBJDIR)/%.o: $(ROOT_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INC) -o $@ -c $<

$(TARGET): $(OBJS)
	$(CC) -o $@ $(CFLAGS) $(INC) $^ $(LDFLAGS)

clean:
	$(RM) -f $(OBJS) $(TAM_OBJ) $(AGENT_OBJ) $(TAM) $(AGENT)


run: $(TARGET)
	$<
