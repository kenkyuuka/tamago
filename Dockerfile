# Stage shape: base -> build -> dev-deps -> dev / wheel -> final.
#   build:    compiler + packaging tools; needed to compile the C accelerators.
#   dev-deps: toolchain only (no app code), so editing code never invalidates
#             it or anything built on it (Dockerfile.local).
#   dev:      dev-deps + app code, self-contained.
#   wheel:    builds the accelerated tamago wheel.
#   final:    production image: slim base + the wheel, no toolchain.

FROM python:3.14-slim AS base

FROM base AS build
# gcc/libc6-dev: the slim image ships no C compiler, and without one the
# accelerators silently fall back to (much slower) pure Python.
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
RUN python3 -m venv /pyenv
ENV PATH="/pyenv/bin:$PATH"
RUN --mount=type=cache,target=/root/.cache python3 -m pip install -U pip wheel hatch uv
# Fail the build rather than ship an image without the accelerators.
ENV TAMAGO_REQUIRE_ACCEL=1

FROM build AS dev-deps

FROM dev-deps AS dev
COPY . /workspace
WORKDIR /workspace
RUN hatch env create

FROM build AS wheel
COPY . /src
RUN --mount=type=cache,target=/root/.cache python3 -m pip wheel --no-deps -w /wheels /src

FROM base AS final
RUN --mount=type=cache,target=/root/.cache --mount=type=bind,from=wheel,source=/wheels,target=/wheels \
    python3 -m pip install /wheels/*.whl
WORKDIR /data
ENTRYPOINT ["tamago"]
