#FROM python:3.12
# ERROR: failed to solve: python:3.12: docker.io/library/python:3.12: not found
FROM ubuntu:latest
WORKDIR /PKI

# COPY test.py /PKI/
# COPY pki.py /PKI/
COPY /PKI/requirement.txt /PKI/

RUN apt-get update
RUN apt-get install python3 -y
RUN apt-get install python3-pip -y
RUN apt install iproute2 -y
RUN pip3 install -r requirement.txt

# RUN python3 test.py
# RUN python3 pki.py