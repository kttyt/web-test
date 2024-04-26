ARG TARGETOS=linux
ARG TARGETARCH=arm64

FROM golang:1.21-rc-alpine as builder
ENV GOCACHE=/go_cache \
    CGO_ENABLED=0 \
    GOOS=${TARGETOS} \
    GOARCH=${TARGETARCH}
RUN apk --no-cache add ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

#No cache after this action
COPY . .
RUN go build -ldflags="-w -s" -o app .


FROM scratch
WORKDIR /data
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /src/app /usr/bin/app
ENTRYPOINT ["/usr/bin/app"]
