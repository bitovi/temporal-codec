# syntax=docker/dockerfile:1.7

FROM golang:1.26.5-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/temporal-codec ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=build /out/temporal-codec /temporal-codec
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/temporal-codec"]
