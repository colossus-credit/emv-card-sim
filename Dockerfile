FROM alpine:3.20

WORKDIR /tmp

RUN apk add --no-cache bash gcc make pkgconfig openssl-dev rust cargo gradle openjdk8

# JDK8 is best supported by different JavaCard versions (<=3.0.4)
ENV JAVA_HOME=/usr/lib/jvm/java-1.8-openjdk/
ENV PATH=$PATH:/usr/lib/jvm/java-1.8-openjdk/bin
ENV JAVA_VERSION=8u392
ENV JAVA_ALPINE_VERSION=8.392.08-r1

COPY oracle_javacard_sdks ./oracle_javacard_sdks
COPY build.gradle gradle.properties ./
COPY config ./config
COPY gradle ./gradle
COPY src ./src

# build and test the application
RUN gradle build \
# build dev JavaCard caps (JC 3.0.5)
    && gradle -Pjc_version=3.0.5 --console=verbose clean cap --info \
    && mkdir --parents /tmp/javacard_build/dev/3_0_5 \
    && mv /tmp/build/card/*.cap /tmp/javacard_build/dev/3_0_5/ \
# build production JavaCard caps (admin commands stripped)
    && gradle -Pbuild_type=production -Pjc_version=3.0.5 --console=verbose clean cap --info \
    && mkdir --parents /tmp/javacard_build/production/3_0_5 \
    && mv /tmp/build/card/*.cap /tmp/javacard_build/production/3_0_5/ \
    && tar cvzf javacard_build.tar.gz javacard_build

CMD ["exit"]
