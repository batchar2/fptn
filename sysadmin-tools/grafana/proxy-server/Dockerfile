# --- Stage 1: Building ---
FROM ubuntu:24.04 AS build

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y cmake gcc g++ python3 python3-pip git \
    && pip install conan==2.9.2 numpy --break-system-packages

RUN conan profile detect --force

RUN mkdir -p /code
WORKDIR /code

RUN git clone https://github.com/batchar2/fptn fptn-project \
    && cp -rv fptn-project/.conan .conan \
    && echo 2

COPY ./conanfile.py /code/
RUN conan install . --output-folder=build --build=missing -s compiler.cppstd=17 --settings build_type=Release

COPY ./CMakeLists.txt /code/
COPY ./src/ /code/src/

RUN cd build \
    && cmake .. -DCMAKE_TOOLCHAIN_FILE=conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Release \
    && cmake --build . --config Release


# --- Stage 2: Runtime image ---
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

COPY --from=build /code/build//fptn-proxy /usr/bin/
RUN chmod +x /usr/bin/fptn-proxy
