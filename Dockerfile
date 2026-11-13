# Stage shape: base -> build -> dev-deps -> dev / final.
#   dev-deps: toolchain only (no app code), so editing code never invalidates
#             it or anything built on it (Dockerfile.local).
#   dev:      dev-deps + app code, self-contained.
#   final:    production image.

FROM python:3.14-slim AS base

FROM base AS build
RUN python3 -m venv /pyenv
ENV PATH="/pyenv/bin:$PATH"
RUN --mount=type=cache,target=/root/.cache python3 -m pip install -U pip wheel hatch uv

FROM build AS dev-deps

FROM dev-deps AS dev
COPY . /workspace
WORKDIR /workspace
RUN hatch env create

FROM build AS final
COPY . /src
RUN --mount=type=cache,target=/root/.cache python3 -m pip install /src
WORKDIR /data
ENTRYPOINT ["tamago"]
