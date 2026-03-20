# Copyright (c) 2020 SECOM CO., LTD. All Rights reserved.
# SPDX-License-Identifier: BSD-2-Clause

# Latest-check CI image.
# Intentionally tracks latest upstream dependencies to detect breakages early.
FROM debian:latest

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      curl \
      git \
      gcc \
      libc6-dev \
      make \
      libcunit1-dev \
      libssl-dev \
      ruby && \
    rm -rf /var/lib/apt/lists/*

RUN gem install --no-document cbor-diag

RUN git clone --depth 1 https://github.com/laurencelundblade/QCBOR.git /root/QCBOR
WORKDIR /root/QCBOR
RUN make libqcbor.a install

RUN git clone --branch dev-deterministic-ecdsa --depth 1 https://github.com/kentakayama/t_cose.git /root/t_cose
WORKDIR /root/t_cose
RUN make -f Makefile.ossl libt_cose.a install

WORKDIR /root
COPY . ./libteep
WORKDIR /root/libteep
RUN make
RUN make -f examples/cose/Makefile
RUN make -f examples/parser/Makefile
RUN make -f examples/sign/Makefile

CMD make test && \
    make -f examples/cose/Makefile run && \
    make -f examples/parser/Makefile run && \
    make -f examples/sign/Makefile run
