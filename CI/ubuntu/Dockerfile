FROM ubuntu:24.04 AS build

ARG PLATFORM_ARCH=linux/amd64
# FROM --platform=${PLATFORM_ARCH} node:${NODE_TAG} as devBuild

# install build depends
RUN apt-get update -y >/dev/null 2>/dev/null \
    && apt-get -y install \
        gcc \
        g++ \
        git \
        cmake \
        python3-pip \
    && pip install --break-system-packages conan==2.3.2
# install c++ depends
RUN conan profile detect --force
RUN mkdir -p /app
WORKDIR /app
COPY conanfile.py /app
RUN conan install . --output-folder=build --build=missing
# build
COPY . /app
RUN conan build . --output-folder=build
