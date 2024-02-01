FROM ubuntu:22.04

RUN apt-get update && \
  apt-get install -y nsd iputils-ping tshark vim
