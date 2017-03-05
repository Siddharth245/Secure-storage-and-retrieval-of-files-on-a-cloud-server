#!/bin/bash
#Generating an RSA Key Pair  for client
openssl genrsa  -out client_privkey.pem 2048
#Exporting the public key from the key pair - 
openssl rsa -in client_privkey.pem -outform PEM -pubout -out client_pubkey.pem
