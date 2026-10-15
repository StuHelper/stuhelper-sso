FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

ARG SOURCE_DATE_EPOCH
ARG SSO_SOURCE_COMMIT
ARG CASDOOR_UPSTREAM_COMMIT
ARG CASDOOR_UPSTREAM_VERSION
ARG CASDOOR_COMPONENT_VERSION
ARG CASDOOR_RELEASE_INPUT_SHA256
LABEL org.opencontainers.image.title="StuHelper SSO" \
      org.opencontainers.image.source="https://github.com/StuHelper/stuhelper-sso" \
      org.opencontainers.image.revision="${SSO_SOURCE_COMMIT}" \
      org.opencontainers.image.version="${CASDOOR_COMPONENT_VERSION}" \
      io.stuhelper.sso.source-commit="${SSO_SOURCE_COMMIT}" \
      io.stuhelper.sso.database-major="4" \
      io.stuhelper.sso.rollback-policy="restore-pre-upgrade-database-for-major-downgrade" \
      io.stuhelper.casdoor.upstream-commit="${CASDOOR_UPSTREAM_COMMIT}" \
      io.stuhelper.casdoor.upstream-version="${CASDOOR_UPSTREAM_VERSION}" \
      io.stuhelper.casdoor.component-version="${CASDOOR_COMPONENT_VERSION}" \
      io.stuhelper.casdoor.release-input-sha256="${CASDOOR_RELEASE_INPUT_SHA256}"

RUN apk add --no-cache \
      ca-certificates=20260611-r0 \
      tzdata=2026c-r0 \
      libcrypto3=3.5.8-r0 \
      libssl3=3.5.8-r0 \
    && adduser -D -u 1000 casdoor \
    && mkdir -p /logs /conf /web/build /files \
    && chown -R casdoor:casdoor /logs /conf /web /files

USER 1000:1000
WORKDIR /

COPY --chown=casdoor:casdoor server /server
COPY --chown=casdoor:casdoor swagger /swagger
COPY --chown=casdoor:casdoor conf/app.conf /conf/app.conf
COPY --chown=casdoor:casdoor web/build /web/build

HEALTHCHECK --interval=10s --timeout=5s --start-period=20s --retries=6 \
  CMD wget -q -T 5 --spider \
    http://127.0.0.1:8000/.well-known/openid-configuration || exit 1

ENTRYPOINT ["/server"]
