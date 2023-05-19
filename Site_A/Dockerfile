# Définition d'une image ubuntu avec comme dossier courant /PKI
FROM ubuntu:latest
WORKDIR /PKI

# Installation des paquets nécessaires
COPY /PKI/requirement.txt /PKI/
RUN apt-get update
RUN apt install python3 -y
RUN apt-get install python3-pip -y
RUN apt install iproute2 -y
RUN pip install -r requirement.txt