#FROM python:3.12
# ERROR: failed to solve: python:3.12: docker.io/library/python:3.12: not found
FROM python:latest
WORKDIR /PKI

COPY site_B.py /PKI/
COPY requirement.txt /PKI/
RUN pip install -r requirement.txt

RUN python3 site_B.py