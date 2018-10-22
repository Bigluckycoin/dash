#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR/..

DOCKER_IMAGE=${DOCKER_IMAGE:-hatchpay/hatchd-develop}
DOCKER_TAG=${DOCKER_TAG:-latest}

BUILD_DIR=${BUILD_DIR:-.}

rm docker/bin/*
mkdir docker/bin
cp $BUILD_DIR/src/hatchd docker/bin/
cp $BUILD_DIR/src/hatch-cli docker/bin/
cp $BUILD_DIR/src/hatch-tx docker/bin/
strip docker/bin/hatchd
strip docker/bin/hatch-cli
strip docker/bin/hatch-tx

docker build --pull -t $DOCKER_IMAGE:$DOCKER_TAG -f docker/Dockerfile docker
