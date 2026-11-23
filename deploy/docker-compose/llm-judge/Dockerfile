FROM docker.1ms.run/library/ubuntu:26.04@sha256:678c6550cc43645e08669028bc177f50be4e7c5b8cca677067b1914d4afc7a03 AS build

ARG LLAMA_CPP_REVISION
ARG LLAMA_CPP_COMMIT_COUNT
ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential cmake ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY llama.cpp/ ./
RUN set -eu; \
    set -- \
      -DCMAKE_BUILD_TYPE=Release \
      -DGGML_NATIVE=OFF \
      -DGGML_BACKEND_DL=ON \
      -DGGML_OPENMP=ON \
      -DGGML_BLAS=OFF \
      -DGGML_LTO=OFF \
      -DGGML_CPU_KLEIDIAI=OFF \
      -DLLAMA_CURL=OFF \
      -DLLAMA_OPENSSL=OFF \
      -DLLAMA_BUILD_TESTS=OFF \
      -DLLAMA_BUILD_EXAMPLES=OFF \
      -DLLAMA_BUILD_SERVER=ON \
      -DLLAMA_BUILD_UI=OFF \
      -DLLAMA_USE_PREBUILT_UI=OFF \
      -DBUILD_SHARED_LIBS=ON \
      -DLLAMA_BUILD_COMMIT="$LLAMA_CPP_REVISION" \
      -DLLAMA_BUILD_NUMBER="$LLAMA_CPP_COMMIT_COUNT"; \
    if [ "$TARGETARCH" = amd64 ]; then \
      set -- "$@" -DGGML_CPU_ALL_VARIANTS=ON; \
    elif [ "$TARGETARCH" = arm64 ]; then \
      set -- "$@" -DGGML_CPU_ALL_VARIANTS=OFF -DGGML_AVX512=OFF -DGGML_AVX=OFF -DGGML_AVX2=OFF -DGGML_FMA=OFF \
        -DGGML_F16C=OFF -DGGML_BMI2=OFF -DGGML_SSE42=OFF \
        -DGGML_CPU_ARM_ARCH=armv8-a; \
    else \
      echo "unsupported llama.cpp target architecture: $TARGETARCH" >&2; exit 1; \
    fi; \
    cmake -S . -B build "$@" \
    && cmake --build build --target llama-server -j2

FROM docker.1ms.run/library/ubuntu:26.04@sha256:678c6550cc43645e08669028bc177f50be4e7c5b8cca677067b1914d4afc7a03
RUN apt-get update && apt-get install -y --no-install-recommends \
      libgomp1 ca-certificates wget \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 judge

COPY --from=build /src/build/bin/ /opt/llama/
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh && chmod +x /opt/llama/llama-server

ENV LD_LIBRARY_PATH=/opt/llama
USER judge
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
