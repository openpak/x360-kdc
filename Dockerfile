# Multi-stage, cross-compiled: the build stage runs on the runner's native arch and Go
# emits the target arch, so linux/arm64 builds need no QEMU.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/x360-kdc ./cmd/x360-kdc \
 && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/x360-gateway ./cmd/x360-gateway \
 && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/x360-liveinfo ./cmd/x360-liveinfo

FROM alpine:3.22
# The firmware dials UDP 88, a privileged port: give the binary the bind
# capability so the container still runs as an unprivileged user.
RUN addgroup -S app && adduser -S -G app app && apk add --no-cache libcap-utils
COPY --from=build /out/x360-kdc /usr/local/bin/x360-kdc
# Same image, second entrypoint: the security gateway (quadlet sets Entrypoint=/usr/local/bin/x360-gateway).
COPY --from=build /out/x360-gateway /usr/local/bin/x360-gateway
# Third entrypoint: the LiveHive HTTP endpoint on TCP 25 (also privileged).
COPY --from=build /out/x360-liveinfo /usr/local/bin/x360-liveinfo
RUN setcap cap_net_bind_service=+ep /usr/local/bin/x360-kdc && setcap cap_net_bind_service=+ep /usr/local/bin/x360-liveinfo && apk del libcap-utils
USER app
EXPOSE 88/udp 3074/udp 25/tcp
ENTRYPOINT ["/usr/local/bin/x360-kdc"]
