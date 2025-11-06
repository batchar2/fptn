# --- Stage 1: Building ---
FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y gcc g++ python3 python3-pip \
      openssh-client \
      git \
      cmake \
      ca-certificates wget gpg lsb-release && \
    pip install conan==2.15.1 numpy --break-system-packages

RUN conan profile detect --force

RUN mkdir -p /code
WORKDIR /code

COPY ./.conan /code/.conan
COPY ./conanfile.py /code/

RUN mkdir -p build && \
    conan install . --output-folder=build --build=missing -s compiler.cppstd=17 --settings build_type=Release

COPY ./src/ /code/src/
COPY ./tests /code/tests
COPY ./depends /code/depends
COPY ./CMakeLists.txt /code/

RUN cd build && \
    cmake .. -DCMAKE_TOOLCHAIN_FILE=conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Release && \
    cmake --build . --config Release



# --- Stage 2: Runtime image ---
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

COPY --from=builder /code/build/src/fptn-server/fptn-server /usr/bin/
COPY --from=builder /code/build/src/fptn-passwd/fptn-passwd /usr/bin/
RUN chmod +x /usr/bin/fptn-server && \
    chmod +x /usr/bin/fptn-passwd

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y dnsmasq iproute2 iptables && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN echo "server=8.8.8.8" > /etc/dnsmasq.conf && \
    echo "server=8.8.4.4" >> /etc/dnsmasq.conf && \
    echo "server=2001:4860:4860::8888" >> /etc/dnsmasq.conf && \
    echo "server=2001:4860:4860::8844" >> /etc/dnsmasq.conf
