# syntax=docker/dockerfile:1.7
FROM golang:1.25-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/mcp-gateway ./cmd/mcp-gateway

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/mcp-gateway /usr/local/bin/mcp-gateway
EXPOSE 9000
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/mcp-gateway"]
CMD ["--config", "/etc/mcp-gateway/config.yaml"]
