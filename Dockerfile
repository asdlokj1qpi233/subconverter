FROM alpine:3.16 AS builder
LABEL maintainer="subconverter"
ARG THREADS="4"

# Install build tools and dependencies
RUN apk add --no-cache --virtual .build-tools \
        git g++ build-base linux-headers cmake python3 && \
    apk add --no-cache --virtual .build-deps \
        curl-dev rapidjson-dev pcre2-dev yaml-cpp-dev

# Build QuickJS
RUN git clone --no-checkout https://github.com/ftk/quickjspp.git && \
    cd quickjspp && \
    git fetch origin 0c00c48895919fc02da3f191a2da06addeb07f09 && \
    git checkout 0c00c48895919fc02da3f191a2da06addeb07f09 && \
    git submodule update --init && \
    cmake -DCMAKE_BUILD_TYPE=Release . && \
    make quickjs -j $THREADS && \
    install -d /usr/lib/quickjs/ && \
    install -m644 quickjs/libquickjs.a /usr/lib/quickjs/ && \
    install -d /usr/include/quickjs/ && \
    install -m644 quickjs/quickjs.h quickjs/quickjs-libc.h /usr/include/quickjs/ && \
    install -m644 quickjspp.hpp /usr/include

# Build LibCron
RUN git clone https://github.com/PerMalmberg/libcron --depth=1 && \
    cd libcron && \
    git submodule update --init && \
    cmake -DCMAKE_BUILD_TYPE=Release . && \
    make libcron -j $THREADS && \
    install -m644 libcron/out/Release/liblibcron.a /usr/lib/ && \
    install -d /usr/include/libcron/ && \
    install -m644 libcron/include/libcron/* /usr/include/libcron/ && \
    install -d /usr/include/date/ && \
    install -m644 libcron/externals/date/include/date/* /usr/include/date/

# Build toml11
RUN git clone https://github.com/ToruNiina/toml11 --branch="v4.3.0" --depth=1 && \
    cd toml11 && \
    cmake -DCMAKE_CXX_STANDARD=11 . && \
    make install -j $THREADS

# Copy local source and build
WORKDIR /subconverter_src
COPY . .
RUN cmake -DCMAKE_BUILD_TYPE=Release . && \
    make -j $THREADS

# --- Final image ---
FROM alpine:3.16
LABEL maintainer="subconverter"

RUN apk add --no-cache pcre2 libcurl yaml-cpp

COPY --from=builder /subconverter_src/subconverter /usr/bin/
COPY --from=builder /subconverter_src/base /base/

ENV TZ=UTC
RUN ln -sf /usr/share/zoneinfo/$TZ /etc/localtime && \
    echo $TZ > /etc/timezone

WORKDIR /base
EXPOSE 25500/tcp
CMD ["subconverter"]
