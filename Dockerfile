FROM golang:1.23-alpine

WORKDIR /app

# Install Air for hot reloading (using a version compatible with Go 1.21)
RUN go install github.com/cosmtrek/air@v1.49.0

COPY go.mod ./
COPY go.sum ./
COPY *.go ./
COPY pkg/ ./pkg/
COPY .air.toml ./

RUN go mod tidy

# Build the application
RUN go build -o codec-server

EXPOSE 8080

# Use Air for development
CMD ["air"] 