# Use an official Rust runtime as a parent image
FROM rust:1.72

# Copy the rest of your source code into the container
COPY . .

# Install Protocol Buffers compiler (required for CLN dep).
RUN apt-get update && apt-get install -y protobuf-compiler

# Build your Rust project
RUN cargo build --release

# Copy the configuration file from the host into the container using an ARG
ARG CONFIG_PATH

# Conditionally copy the configuration file from the host into the container if CONFIG_PATH is set
RUN if [ -n "$CONFIG_PATH" ]; then \
    COPY $CONFIG_PATH config.json; \
fi

# Define the command to run your CLI tool when the container starts
CMD ["./target/release/sim-cli", "--config", "config.json"]
