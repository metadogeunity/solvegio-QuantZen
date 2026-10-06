FROM golang:1.25-alpine AS build
WORKDIR /src
RUN apk add --no-cache ca-certificates
COPY go.mod go.sum ./
COPY . .
RUN go mod tidy
RUN go mod download
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/quantzen-gateway ./cmd/gateway

FROM alpine:3.22
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=build /out/quantzen-gateway /app/quantzen-gateway
COPY web /app/web
EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/app/quantzen-gateway"]
