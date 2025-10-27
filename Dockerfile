# **************** BUILD STAGE ********************#
FROM ubuntu:22.04 AS builder

ARG SDK_VERSION=2.25
ARG SGX_VERSION=2.25.100.3

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gpg \
    ca-certificates \
    build-essential \
    make \
    pkg-config

RUN curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | gpg --dearmor -o /usr/share/keyrings/intel-sgx-deb.gpg \
    && echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx-deb.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main' | tee /etc/apt/sources.list.d/intel-sgx.list \
    && apt-get update

RUN apt-get install -y --no-install-recommends libsgx-dcap-ql-dev libsgx-dcap-quote-verify-dev

ADD https://download.01.org/intel-sgx/sgx-linux/${SDK_VERSION}/distro/ubuntu22.04-server/sgx_linux_x64_sdk_${SGX_VERSION}.bin ./sgx/

RUN chmod +x ./sgx/sgx_linux_x64_sdk_${SGX_VERSION}.bin

RUN echo -e 'no\n/opt' | ./sgx/sgx_linux_x64_sdk_${SGX_VERSION}.bin && \
    rm -rf ./sgx/*

ENV LD_LIBRARY_PATH=/opt/sgxsdk/libsgx-enclave-common/

WORKDIR /app
COPY . .
RUN . /opt/sgxsdk/environment && make

# **************** FINAL STAGE ********************#
FROM ubuntu:22.04 AS attester

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gpg \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | gpg --dearmor -o /usr/share/keyrings/intel-sgx-deb.gpg \
    && echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx-deb.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main' | tee /etc/apt/sources.list.d/intel-sgx.list \
    && apt-get update

RUN apt-get install -y --no-install-recommends \
    libsgx-dcap-ql \
    libsgx-dcap-quote-verify \
    libsgx-uae-service \
    libsgx-dcap-default-qpl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/app attester
COPY --from=builder /app/enclave.signed.so enclave.signed.so

ENTRYPOINT ["./attester"]
