#!/bin/bash

# HE Private Key
openssl genrsa -out he_private_key.pem 2048

# HE Public Key
openssl rsa -in he_private_key.pem -pubout -out he_public_key.pem

# OAM Private Key
openssl genrsa -out oam_private_key.pem 2048

# OAM Public Key
openssl rsa -in oam_private_key.pem -pubout -out oam_public_key.pem
