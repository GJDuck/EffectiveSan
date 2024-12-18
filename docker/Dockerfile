# Use Ubuntu 16.04 as the base image
FROM ubuntu:16.04

# Set environment variables to avoid interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

# Update and install required packages
RUN apt-get update && \
    apt-get install -y \
        git \
        vim \
        wget \
        unzip \
        build-essential \
        cmake \
        python3 \
        zlib1g-dev \
        llvm-4.0 \
        clang-4.0 && \
    # Clean up apt cache to reduce image size
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Clone the EffectiveSan repository
RUN cd /home && \
    git clone https://github.com/GJDuck/EffectiveSan.git

# Build the EffectiveSan project
RUN cd /home/EffectiveSan && \
    ./build.sh

# Set default working directory
WORKDIR /home/EffectiveSan

