# Variables
IMAGE_NAME=effective-san
TAG=latest

# Default target (run when `make` is invoked)
all: build

# Rule to build the Docker image
build:
	docker build -t $(IMAGE_NAME):$(TAG) .

# Rule to clean up (optional)
clean:
	docker rmi $(IMAGE_NAME):$(TAG)

# Rule to push the Docker image to a registry (optional)
push:
	docker push $(IMAGE_NAME):$(TAG)

