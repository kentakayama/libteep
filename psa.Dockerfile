# Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
FROM debian:latest

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update
RUN apt-get -y install curl git gcc make libcunit1-dev python3 ruby
RUN gem install cbor-diag

RUN git clone -b v3.1.0 --depth 1 https://github.com/Mbed-TLS/mbedtls.git /root/mbedtls
WORKDIR /root/mbedtls
RUN make -j`nproc` install

RUN git clone --depth 1 https://github.com/laurencelundblade/QCBOR.git /root/QCBOR
WORKDIR /root/QCBOR
RUN make libqcbor.a install

RUN git clone --branch dev-deterministic-ecdsa --depth 1 https://github.com/kentakayama/t_cose.git /root/t_cose
WORKDIR /root/t_cose
RUN make -f Makefile.psa libt_cose.a install

COPY . /root/libteep
WORKDIR /root/libteep
RUN make MBEDTLS=1
RUN make -f Makefile.cose MBEDTLS=1
RUN make -f Makefile.parser MBEDTLS=1
RUN make -f Makefile.sign MBEDTLS=1

CMD make MBEDTLS=1 test && \
    make -f Makefile.cose MBEDTLS=1 run && \
    make -f Makefile.parser MBEDTLS=1 run && \
    make -f Makefile.sign MBEDTLS=1 run
