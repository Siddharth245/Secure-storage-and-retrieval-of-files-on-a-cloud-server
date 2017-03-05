import socket                   
import os
import sys

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from exchange_keys import send, receive
from random import choice
from string import ascii_uppercase

#Generate RSA public-private key pair for client
os.system('chmod +x keygen.sh')
os.system('./keygen.sh')

delimiter = '=='
option = 0
while option < 3 :
		#Establish secure socket connection with server
		sock = socket.socket()             # Create a socket object
		host = socket.gethostname()     # Get local machine name
		port = 63945                    # Reserve a port for your service.
		sock.connect((host, port))
		print("Connection established")
		send(sock,"initial message")


		#Send client's public key
		fobj = open('client_pubkey.pem','rb')
		c_pubkey = fobj.read(1024)
		send(sock,c_pubkey)
		fobj.close()

		#Get server's public key
		s_pubkey = receive(sock)
		f2 = open('server_pubkey.pem','wb')
		f2.write(s_pubkey)
		f2.close()
		print("Public key exchange successful!!!")

		print("what do you want to do?")
		print("1. download")
		print("2. Upload")
		print("3.Exit")

		option = input("Enter 1 or 2 or 3:")


		if option == 1:	
			send(sock,option)
			file_name=raw_input("Enter the file name:")
			send(sock,file_name)	
			f = open('received_file','wb')
			try:

		    		while True:
					data = receive(sock)
					if data == "nill" : 
						print "No such file exists on the server" 
						sock.close()
					else :
						print 'file opened'
			       			print('receiving data')
			       			
			       			split_msg =data.split(delimiter)
			       			enc_message = split_msg[0]
			       			enc_session_key = split_msg[1]
	
			       			#Decrypt one-time session key with client's private key
			       			r_private_key = RSA.importKey(open('client_privkey.pem').read())
			       			rsa_cipher = PKCS1_OAEP.new(r_private_key)
			       			dec_session_key = rsa_cipher.decrypt(enc_session_key)

			       			#Decrypt encrypted signed message
			       			iv = Random.new().read(AES.block_size)
			       			aes_cipher = AES.new(dec_session_key, AES.MODE_CFB, iv)
			       			dec_signed_msg =aes_cipher.decrypt(enc_message)
			       			ret = str(dec_signed_msg)
			       			dec_signed_msg = ret[AES.block_size:]

			       			# Verify Signature
			       			message = dec_signed_msg.split(delimiter)[0]
			       			signature = dec_signed_msg.split(delimiter)[1]

			       			s_public_key = RSA.importKey(open('server_pubkey.pem').read())
						message_hash = SHA256.new(message)
						verifier = PKCS1_v1_5.new(s_public_key)
						if verifier.verify(message_hash, signature):
						   		print "The signature is authentic."
					 	  		print("Data Received:")
						   		print(message)
						else:
					 	   		print "The signature is not authentic."
						f.write(data)

			except:
		       		pass
			f.close()
			if data != "nill" :
				print('Successfully got the file')
				sock.close()
				print('connection closed')
		elif option == 2:
			send(sock,option)
			filename = raw_input("Enter file name to upload :")
			if os.path.exists(filename) :
				send(sock,filename)
				f = open(filename, 'rb')
				l = f.read(1024)
				print(l)

				# Hash and digitally sign the plaintext message
				message_hash = SHA256.new(l)
				s_private_key = RSA.importKey(open('client_privkey.pem').read())
				signer = PKCS1_v1_5.new(s_private_key)
				signature = signer.sign(message_hash)

				# Append signature to message
				signed_message = l + delimiter + signature

				# Generate a one-time session key
				session_key_gen = (''.join(choice(ascii_uppercase) for i in range(32)))
				session_key = bytes(session_key_gen)

				# Encrypt the data with one-time session key
				iv = Random.new().read(AES.block_size)
				aes_cipher = AES.new(session_key, AES.MODE_CFB, iv)
				b_signed = bytes(signed_message)
				aes_enc_msg = iv + aes_cipher.encrypt(b_signed)

				# Encrypt one-time session key with server's public key
				r_public_key = RSA.importKey(open('server_pubkey.pem').read())
				rsa_cipher = PKCS1_OAEP.new(r_public_key)
				encrypted_session_key = rsa_cipher.encrypt(session_key)

				# Send the encrypted message to the client
				final_msg = aes_enc_msg + delimiter + encrypted_session_key
				while (final_msg):
					send(sock, final_msg)
					print('Sent ', repr(final_msg))
					final_msg = f.read(1024)
				f.close()

				print('Done sending')
				sock.close()
			else :
				print "No such file Exists !! "
				send (s,"nill")
				sock.close()
		elif option ==3 :
			print "Client Terminating: "
			sock.close()	
		else:
			sock.close()

