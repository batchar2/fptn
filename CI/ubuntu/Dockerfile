ARG PLATFORM_ARCH=linux/amd64

#################### stage 1
FROM --platform=$PLATFORM_ARCH ubuntu:22.04 AS build-fptn

RUN apt-get update -y >/dev/null 2>/dev/null \
    && apt-get -y install gcc g++ git cmake python3-pip \
    && pip install --break-system-packages conan==2.3.2
RUN conan profile detect --force

RUN mkdir -p /app
WORKDIR /app
COPY conanfile.py /app
RUN conan install . --output-folder=build --build=missing

COPY . /app
RUN conan build . --output-folder=build




#################### stage 2
FROM --platform=$PLATFORM_ARCH ubuntu:22.04 AS make-deb-fptn

RUN apt-get update -y >/dev/null 2>/dev/null \
    && apt-get install -y dpkg-dev build-essential fakeroot

## build client
RUN mkdir -p /fptn-client/DEBIAN \
    && mkdir -p /fptn-client/usr/bin/ \
    && mkdir -p /fptn-client/DEBIAN/ \
    && mkdir -p /fptn-client/usr/ \
    && mkdir -p /fptn-client/usr/bin/
WORKDIR /
COPY --from=build-fptn /app/build/build/Release/code/fptn-client/fptn-client  /fptn-client/usr/bin/
RUN chmod 755 /fptn-client/usr/bin/fptn-client
ARG VERSION=0.0.1
ARG MAINTAINER=Stas Skokov
RUN INSTALLED_SIZE=$(du -s /fptn-client/usr | cut -f1) \
    echo "Package: logon" > /fptn-client/DEBIAN/control \
    && echo "Version: ${VERSION}" >> /fptn-client/DEBIAN/control \
    && echo "Architecture: amd64" >> /fptn-client/DEBIAN/control \
    && echo "Maintainer: ${MAINTAINER}" >> /fptn-client/DEBIAN/control \
    && echo "Installed-Size: ${INSTALLED_SIZE}" >> /fptn-client/DEBIAN/control \
    && echo "Depends: iptables, iproute2" >> /fptn-client/DEBIAN/control \
    && echo "Section: admin" >> /fptn-client/DEBIAN/control \
    && echo "Priority: optional" >> /fptn-client/DEBIAN/control \
    && echo "Description: fptn client" >> /fptn-client/DEBIAN/control
RUN dpkg-deb --build /fptn-client /fptn-client-${VERSION}.deb \
    && mkdir -p /result \
    && cp /fptn-client-${VERSION}.deb /result

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
    && /fptn-server/usr/bin/fptn-passwd 
RUN INSTALLED_SIZE=$(du -s /fptn-server/usr | cut -f1) \
    echo "Package: logon" > /fptn-server/DEBIAN/control \
    && echo "Version: ${VERSION}" >> /fptn-server/DEBIAN/control \
    && echo "Architecture: amd64" >> /fptn-server/DEBIAN/control \
    && echo "Maintainer: ${MAINTAINER}" >> /fptn-server/DEBIAN/control \
    && echo "Installed-Size: ${INSTALLED_SIZE}" >> /fptn-server/DEBIAN/control \
    && echo "Depends: iptables, iproute2" >> /fptn-server/DEBIAN/control \
    && echo "Section: admin" >> /fptn-server/DEBIAN/control \
    && echo "Priority: optional" >> /fptn-server/DEBIAN/control \
    && echo "Description: fptn server" >> /fptn-server/DEBIAN/control
RUN dpkg-deb --build /fptn-server /fptn-server-${VERSION}.deb \
    && mkdir -p /result \
    && cp /fptn-server-${VERSION}.deb /result