#
# Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
#

THIS_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
ROOT_DIR := $(abspath $(THIS_DIR)/../..)

CFLAGS = -Wall -g
LDFLAGS = $(CMD_LD) -lt_cose -lqcbor -lm
INC = $(CMD_INC) -I $(ROOT_DIR)/inc -I $(ROOT_DIR)/src -I $(ROOT_DIR)/examples/common
TARGET = $(ROOT_DIR)/bin/eat_parser
SRCS = \
	$(ROOT_DIR)/examples/eat_tool/eat_parser.c \
	$(ROOT_DIR)/examples/common/teep_examples_common.c \
	$(ROOT_DIR)/src/cose_print_common.c
OBJDIR = $(THIS_DIR)/obj
REL_SRCS = $(patsubst $(ROOT_DIR)/%,%,$(SRCS))
OBJS = $(addprefix $(OBJDIR)/,$(patsubst %.c,%.o,$(REL_SRCS)))

.PHONY: all clean run

all: $(TARGET)

$(OBJDIR)/%.o: $(ROOT_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INC) -o $@ -c $<

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	$(RM) $(OBJS) $(TARGET)

run: $(TARGET)
	$<
