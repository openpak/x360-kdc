# Multi-stage, cross-compiled: the build stage runs on the runner's native arch and Go
# emits the target arch, so linux/arm64 builds need no QEMU.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/x360-kdc ./cmd/x360-kdc

FROM alpine:3.22
# The firmware dials UDP 88, a privileged port: give the binary the bind
# capability so the container still runs as an unprivileged user.
RUN addgroup -S app && adduser -S -G app app && apk add --no-cache libcap-utils
COPY --from=build /out/x360-kdc /usr/local/bin/x360-kdc
RUN setcap cap_net_bind_service=+ep /usr/local/bin/x360-kdc && apk del libcap-utils
USER app
EXPOSE 88/udp
ENTRYPOINT ["/usr/local/bin/x360-kdc"]
