FROM ubuntu:22.04

USER root

# RUN apt-get update && apt-get install -y wget
RUN apt update
RUN apt install openssl -y

RUN mkdir -p /key
RUN chown -R 1000:1000 /key
RUN chmod -R 770 /key

WORKDIR /key

USER 1000

CMD ["tail", "-f", "/dev/null"]