#FROM python:3.12
# ERROR: failed to solve: python:3.12: docker.io/library/python:3.12: not found
FROM ubuntu:latest
WORKDIR /PKI

# COPY site_A.py /PKI/
COPY /PKI/requirement.txt /PKI/

# ENTRYPOINT mkdir /usr/share/PKI && echo "PKI/root_cert.crt" >> /etc/ca-certificates.conf

RUN apt-get update
RUN apt install python3 -y
RUN apt-get install python3-pip -y
RUN apt install iproute2 -y
RUN pip install -r requirement.txt

# CMD tail -f /dev/null

# RUN python3 site_B.py