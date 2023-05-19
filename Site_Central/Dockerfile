# Définition d'une image ubuntu avec comme dossier courant /PKI
FROM ubuntu:latest
WORKDIR /PKI

# Installation des paquets nécessaires
COPY /PKI/requirement.txt /PKI/
RUN apt-get update
RUN apt-get install python3 -y
RUN apt-get install python3-pip -y
RUN apt install iproute2 -y
RUN pip3 install -r requirement.txt
