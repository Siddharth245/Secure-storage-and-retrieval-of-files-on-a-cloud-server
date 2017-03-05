#!/bin/bash
#Generating an RSA Key Pair  for server
openssl genrsa  -out server_privkey.pem 2048
#Exporting the public key from the key pair - 
openssl rsa -in server_privkey.pem -outform PEM -pubout -out server_pubkey.pem

