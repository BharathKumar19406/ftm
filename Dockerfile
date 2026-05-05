# Build Stage
FROM golang:1.21-bullseye AS builder
RUN apt-get update && apt-get install -y clang llvm libbpf-dev linux-headers-generic
WORKDIR /app
COPY . .
# Generate the eBPF Go bindings and compile the agent
RUN go generate ./...
RUN go build -o ftm-agent

# Run Stage
FROM debian:bullseye-slim
WORKDIR /app
COPY --from=builder /app/ftm-agent .
CMD ["./ftm-agent"]
