# syntax=docker.1ms.run/docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
# The amd64 digests are pinned so tomorrow's customer artifact cannot drift.
ARG CUDA_DEVEL_IMAGE=nvidia/cuda:12.8.1-devel-ubuntu24.04@sha256:520292dbb4f755fd360766059e62956e9379485d9e073bbd2f6e3c20c270ed66
ARG CUDA_RUNTIME_IMAGE=nvidia/cuda:12.8.1-runtime-ubuntu24.04@sha256:ebef3c171eeef0298e4eb2e4be843105edf3b8b0ac45e0b43acee358e8046867

FROM ${CUDA_DEVEL_IMAGE} AS build
ARG CUDA_ARCHITECTURES=80-real;90-real
ARG LLAMA_CPP_REVISION
ARG LLAMA_CPP_COMMIT_COUNT

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential ca-certificates cmake libssl-dev ninja-build \
    && ln -sf libcuda.so /usr/local/cuda/lib64/stubs/libcuda.so.1 \
    && rm -rf /var/lib/apt/lists/*
ENV LIBRARY_PATH=/usr/local/cuda/lib64/stubs
WORKDIR /src
COPY --from=llama-src . ./
RUN test -n "$LLAMA_CPP_REVISION" && test -n "$LLAMA_CPP_COMMIT_COUNT" \
    && cmake -S . -B /build -G Ninja \
      -DGGML_CUDA=ON \
      -DGGML_CUDA_FA=ON \
      -DGGML_CUDA_NCCL=OFF \
      -DCMAKE_CUDA_ARCHITECTURES="$CUDA_ARCHITECTURES" \
      -DCMAKE_EXE_LINKER_FLAGS="-Wl,-rpath-link,/usr/local/cuda/lib64/stubs" \
      -DGGML_NATIVE=OFF \
      -DGGML_AVX=ON \
      -DGGML_AVX2=ON \
      -DGGML_FMA=ON \
      -DGGML_F16C=ON \
      -DGGML_BMI2=ON \
      -DGGML_AVX512=OFF \
      -DLLAMA_CURL=OFF \
      -DLLAMA_BUILD_TESTS=OFF \
      -DLLAMA_BUILD_EXAMPLES=OFF \
      -DLLAMA_BUILD_SERVER=ON \
      -DLLAMA_BUILD_UI=OFF \
      -DLLAMA_USE_PREBUILT_UI=OFF \
      -DBUILD_SHARED_LIBS=ON \
      -DLLAMA_BUILD_COMMIT="$LLAMA_CPP_REVISION" \
      -DLLAMA_BUILD_NUMBER="$LLAMA_CPP_COMMIT_COUNT" \
    && cmake --build /build --target llama-server -j8

FROM ${CUDA_RUNTIME_IMAGE}
ARG LLAMA_CPP_REVISION
ARG RELEASE_REVISION
ARG CUDA_ARCHITECTURES_LABEL=80,90
LABEL org.opencontainers.image.title="JJDGuard GPU Judge" \
      org.opencontainers.image.description="CUDA inference runtime for the JJDGuard bundled 4B semantic judge (multi-instance)" \
      org.opencontainers.image.revision="$RELEASE_REVISION" \
      com.jjdguard.llama_cpp_revision="$LLAMA_CPP_REVISION" \
      com.jjdguard.cuda_architectures="$CUDA_ARCHITECTURES_LABEL" \
      com.jjdguard.model_origin="derived"

COPY --from=build /build/bin/ /opt/llama/
COPY --from=build /usr/lib/x86_64-linux-gnu/libgomp.so.1.0.0 /opt/llama/libgomp.so.1
COPY --chmod=755 entrypoint.sh /usr/local/bin/jjdguard-gpu-judge
COPY --chmod=755 healthcheck.sh /usr/local/bin/jjdguard-gpu-judge-health
RUN mkdir -p /models /tmp/jjdguard \
    && chown -R 10001:10001 /models /tmp/jjdguard \
    && chmod 0755 /opt/llama/llama-server /usr/local/bin/jjdguard-gpu-judge /usr/local/bin/jjdguard-gpu-judge-health

ENV LD_LIBRARY_PATH=/opt/llama \
    NVIDIA_VISIBLE_DEVICES=all \
    NVIDIA_DRIVER_CAPABILITIES=compute,utility
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/jjdguard-gpu-judge"]
