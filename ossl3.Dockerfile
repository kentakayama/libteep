# Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update
RUN apt-get -y install curl git gcc make libcunit1-dev ruby
RUN gem install cbor-diag

RUN git clone --depth 1 https://github.com/openssl/openssl.git /root/openssl
WORKDIR /root/openssl
RUN ./Configure && make -j`nproc` && make install

RUN git clone --depth 1 https://github.com/laurencelundblade/QCBOR.git /root/QCBOR
WORKDIR /root/QCBOR
RUN make libqcbor.a install

RUN git clone --branch dev --depth 1 https://github.com/kentakayama/t_cose.git /root/t_cose
WORKDIR /root/t_cose
RUN make -f Makefile.ossl libt_cose.a install

WORKDIR /root
COPY . ./libteep
WORKDIR /root/libteep
RUN make
RUN make -f Makefile.cose
RUN make -f Makefile.parser
RUN make -f Makefile.sign

CMD make test && \
    make -f Makefile.cose run && \
    make -f Makefile.parser run && \
    make -f Makefile.sign run
