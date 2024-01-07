FROM ubuntu:latest
LABEL authors="roman"

ENTRYPOINT ["top", "-b"]