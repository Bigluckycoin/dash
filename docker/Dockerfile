FROM debian:stretch
LABEL maintainer="Hatch Developers <dev@hatch.org>"
LABEL description="Dockerised HatchCore, built from Travis"

RUN apt-get update && apt-get -y upgrade && apt-get clean && rm -fr /var/cache/apt/*

COPY bin/* /usr/bin/
