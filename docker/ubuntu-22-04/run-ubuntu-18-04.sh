#!/bin/bash

# enable debugging and also exit immediately if a command exits with error.
set -ex

# some constants
TAG_VERSION=1.0.33
CURRENT_DIR=$(pwd)
DOCKER_IMAGE=ubuntu-22.04:${TAG_VERSION}

# NOTE: when upgrading to different version tag make sure update this script
# to remove the previous version image

# some debug logs
echo "Running the linux build for ${DOCKER_IMAGE}..."
echo "Current dir - ${CURRENT_DIR}..."
pwd

# check if docker image exists if not build one
if [[ "$(docker images -q ${DOCKER_IMAGE} 2> /dev/null)" == "" ]]; then
	echo "Info: building docker image  ${DOCKER_IMAGE}..."
	docker build -t ${DOCKER_IMAGE} ./docker/ubuntu-22-04/src/.
else
	echo "Info: Reusing existing docker image ${DOCKER_IMAGE}..."
fi

BUILDKITE_DOCKER=${BUILDKITE:-false}

# run the image
docker run --rm -ti \
	-v ${CURRENT_DIR}:/app \
	-v ~/.ssh:/root/.ssh \
	-w /app \
	-e PATH=/root/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin \
	${DOCKER_IMAGE} \
	/bin/bash
