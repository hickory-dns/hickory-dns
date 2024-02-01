FROM ubuntu:22.04

RUN apt-get update && \
  apt-get install -y unbound iputils-ping tshark vim

COPY ./files/etc/unbound/unbound.conf /etc/unbound/unbound.conf
COPY ./files/etc/unbound/root.hints /etc/unbound/root.hints
