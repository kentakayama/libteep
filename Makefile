#
# Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
#

NAME = libteep
CFLAGS = -Wall -g -fPIC
INC = $(CMD_INC) -I ./inc
SRCS = \
	src/teep_common.c \
	src/teep_cose.c \
	src/teep_message_decode.c \
	src/teep_message_encode.c \
	src/teep_message_print.c
PUBLIC_INTERFACE = \
	inc/teep/teep.h \
	inc/teep/teep_common.h \
	inc/teep/teep_message_data.h \
	inc/teep/teep_cose.h \
	inc/teep/teep_message_print.h
OBJDIR = ./obj
OBJS = $(addprefix $(OBJDIR)/,$(patsubst %.c,%.o,$(SRCS)))

ifeq ($(MBEDTLS),1)
    # use MbedTLS
    CFLAGS += -DLIBTEEP_PSA_CRYPTO_C=1
else
    # use OpenSSL
    MBEDTLS=0
endif

ifdef suit
    CFLAGS += -DPARSE_SUIT
    INC += -I ../libcsuit/inc -I ../libcsuit/examples/inc
endif

.PHONY: all so install uninstall build_test test clean

all: $(NAME).a

so: $(NAME).so

include Makefile.common

$(NAME).a: $(OBJS)
	$(AR) -r $@ $^

$(NAME).so: $(OBJS)
	$(CC) -shared $^ $(CFLAGS) $(INC) -o $@

$(OBJDIR)/%.o: %.c | $(OBJDIR) $(OBJDIR)/src
	$(CC) $(CFLAGS) $(INC) -o $@ -c $<

ifeq ($(PREFIX),)
    PREFIX := /usr/local
endif

define install-header
	install -m 644 $1 $2/$(nodir $1)

endef

install: $(NAME).a $(PUBLIC_INTERFACE)
	install -d $(DESTDIR)$(PREFIX)/lib/
	install -m 644 $(NAME).a $(DESTDIR)$(PREFIX)/lib/
	install -d $(DESTDIR)$(PREFIX)/include/teep
	$(foreach header,$(PUBLIC_INTERFACE),$(call install-header,$(header),$(DESTDIR)$(PREFIX)/include/teep))

install_so: $(NAME).so
	install -m 755 $(NAME).so $(DESTDIR)$(PREFIX)/lib/$(NAME).so.1.0.0
	ln -sf $(NAME).so.1 $(DESTDIR)$(PREFIX)/lib/$(NAME).so
	ln -sf $(NAME).so.1.0.0 $(DESTDIR)$(PREFIX)/lib/$(NAME).so.1

uninstall: $(NAME).a $(PUBLIC_INTERFACE)
	$(RM) -d $(DESTDIR)$(PREFIX)/include/teep/*
	$(RM) -d $(DESTDIR)$(PREFIX)/include/teep/
	$(RM) $(addprefix $(DESTDIR)$(PREFIX)/lib/, \
		$(NAME).a $(NAME).so $(NAME).so.1 $(NAME).so.1.0.0)

build_test:
	$(MAKE) -C test MBEDTLS=$(MBEDTLS)

test: build_test
	$(MAKE) -C test MBEDTLS=$(MBEDTLS) run

generate:
	$(MAKE) -C testfiles

clean:
	$(RM) $(OBJS) $(NAME).a $(NAME).so
	$(MAKE) -C test clean


