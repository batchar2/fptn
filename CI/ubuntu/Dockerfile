ARG PLATFORM_ARCH=amd64

#################### stage 1
FROM --platform=linux/$PLATFORM_ARCH ubuntu:22.04 AS build-fptn

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -y >/dev/null 2>/dev/null \
    && apt-get -y install gcc g++ git cmake python3-pip \
    && pip install conan==2.3.2
RUN conan profile detect --force

RUN mkdir -p /app
WORKDIR /app
COPY conanfile.py /app
RUN conan install . --output-folder=build --build=missing

COPY . /app
RUN conan build . --output-folder=build


#################### stage 2
FROM --platform=linux/$PLATFORM_ARCH ubuntu:22.04 AS make-deb-fptn

RUN apt-get update -y >/dev/null 2>/dev/null \
    && apt-get install -y dpkg-dev build-essential fakeroot

## build client
RUN mkdir -p /fptn-client-cli/DEBIAN \
    && mkdir -p /fptn-client-cli/usr/bin/ \
    && mkdir -p /fptn-client-cli/DEBIAN/ \
    && mkdir -p /fptn-client-cli/usr/ \
    && mkdir -p /fptn-client-cli/usr/bin/
WORKDIR /
COPY --from=build-fptn /app/build/build/Release/code/fptn-client/fptn-client-cli  /fptn-client-cli/usr/bin/
RUN chmod 755 /fptn-client-cli/usr/bin/fptn-client-cli
ARG VERSION=0.0.1
ARG MAINTAINER=Stas Skokov
RUN INSTALLED_SIZE=$(du -s /fptn-client-cli/usr | cut -f1) \
    echo "Package: fptn-client-cli" > /fptn-client-cli/DEBIAN/control \
    && echo "Version: ${VERSION}" >> /fptn-client-cli/DEBIAN/control \
    && echo "Architecture: $(dpkg --print-architecture)" >> /fptn-client-cli/DEBIAN/control \
    && echo "Maintainer: ${MAINTAINER}" >> /fptn-client-cli/DEBIAN/control \
    && echo "Installed-Size: ${INSTALLED_SIZE}" >> /fptn-client-cli/DEBIAN/control \
    && echo "Depends: iptables, iproute2" >> /fptn-client-cli/DEBIAN/control \
    && echo "Section: admin" >> /fptn-client-cli/DEBIAN/control \
    && echo "Priority: optional" >> /fptn-client-cli/DEBIAN/control \
    && echo "Description: fptn client" >> /fptn-client-cli/DEBIAN/control

RUN dpkg-deb --build /fptn-client-cli /fptn-client-cli-${VERSION}-$(dpkg --print-architecture).deb \
    && mkdir -p /result \
    && cp /fptn-client-cli-${VERSION}-$(dpkg --print-architecture).deb /result \
    && chmod 644 /result/fptn-client-cli-${VERSION}-$(dpkg --print-architecture).deb

### build server
RUN mkdir -p /fptn-server/DEBIAN \
    && mkdir -p /fptn-server/usr/bin/ \
    && mkdir -p /fptn-server/DEBIAN/ \
    && mkdir -p /fptn-server/usr/ \
    && mkdir -p /fptn-server/usr/bin/
WORKDIR /
COPY --from=build-fptn /app/build/build/Release/code/fptn-server/fptn-server  /fptn-server/usr/bin/
COPY --from=build-fptn /app/build/build/Release/code/fptn-passwd/fptn-passwd  /fptn-server/usr/bin/
RUN chmod 755 /fptn-server/usr/bin/fptn-server \
    && chmod 755 /fptn-server/usr/bin/fptn-passwd 
RUN INSTALLED_SIZE=$(du -s /fptn-server/usr | cut -f1) \
    echo "Package: fptn-server" > /fptn-server/DEBIAN/control \
    && echo "Version: ${VERSION}" >> /fptn-server/DEBIAN/control \
    && echo "Architecture: $(dpkg --print-architecture)" >> /fptn-server/DEBIAN/control \
    && echo "Maintainer: ${MAINTAINER}" >> /fptn-server/DEBIAN/control \
    && echo "Installed-Size: ${INSTALLED_SIZE}" >> /fptn-server/DEBIAN/control \
    && echo "Depends: iptables, iproute2" >> /fptn-server/DEBIAN/control \
    && echo "Section: admin" >> /fptn-server/DEBIAN/control \
    && echo "Priority: optional" >> /fptn-server/DEBIAN/control \
    && echo "Description: fptn server" >> /fptn-server/DEBIAN/control
RUN dpkg-deb --build /fptn-server /fptn-server-${VERSION}-$(dpkg --print-architecture).deb \
    && mkdir -p /result \
    && cp /fptn-server-${VERSION}-$(dpkg --print-architecture).deb /result \
    && chmod 644 /result/fptn-server-cli-${VERSION}-$(dpkg --print-architecture).deb
