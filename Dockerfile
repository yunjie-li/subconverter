FROM alpine:3.21 AS builder
ARG THREADS=1
RUN apk add --no-cache git g++ make linux-headers cmake python3 curl-dev rapidjson-dev pcre2-dev yaml-cpp-dev
WORKDIR /deps
RUN git clone https://github.com/ftk/quickjspp.git && cd quickjspp && \
    git checkout 0c00c48895919fc02da3f191a2da06addeb07f09 && git submodule update --init && \
    cmake -DCMAKE_BUILD_TYPE=Release . && make quickjs -j${THREADS} && \
    install -d /usr/lib/quickjs /usr/include/quickjs && \
    install -m644 quickjs/libquickjs.a /usr/lib/quickjs/ && \
    install -m644 quickjs/quickjs.h quickjs/quickjs-libc.h /usr/include/quickjs/ && \
    install -m644 quickjspp.hpp /usr/include/
RUN git clone --depth=1 https://github.com/PerMalmberg/libcron && cd libcron && \
    git checkout ee34810b11bd23c8be637345532f91059b68b2d7 && \
    git submodule update --init && cmake -DCMAKE_BUILD_TYPE=Release . && make libcron -j${THREADS} && \
    install -m644 libcron/out/Release/liblibcron.a /usr/lib/ && install -d /usr/include/libcron /usr/include/date && \
    install -m644 libcron/include/libcron/* /usr/include/libcron/ && install -m644 libcron/externals/date/include/date/* /usr/include/date/
RUN git clone --depth=1 --branch=v4.3.0 https://github.com/ToruNiina/toml11 && cd toml11 && \
    cmake -DCMAKE_CXX_STANDARD=11 . && make install
WORKDIR /src
COPY . .
RUN cmake -DCMAKE_BUILD_TYPE=Release -DLOW_MEMORY_BUILD=ON -DCMAKE_CXX_FLAGS_RELEASE="-O1 -DNDEBUG" . && make -j${THREADS}

FROM alpine:3.21
RUN apk add --no-cache pcre2 libcurl yaml-cpp ca-certificates && adduser -D -u 10001 converter
COPY --from=builder /src/subconverter /usr/bin/subconverter
COPY --from=builder --chown=converter:converter /src/base /base
WORKDIR /base
USER converter
EXPOSE 25500
CMD ["subconverter"]
