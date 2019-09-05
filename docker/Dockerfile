FROM debian:stretch
LABEL maintainer="Hatch Developers <support@hatch.ga>"
LABEL description="Dockerised HatchCore, built from Travis"

RUN apt-get update && apt-get -y upgrade && apt-get clean && rm -fr /var/cache/apt/*

COPY bin/* /usr/bin/
