import socket			
import hashlib
import hmac
import base64
import os
import sys
import os.path

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto import Random
from exchange_keys import send, receive
from random import choice
from string import ascii_uppercase


#Generate RSA public-private key pair for server
os.system('chmod +x keygen.sh')
os.system('./keygen.sh')

delimiter = '=='

#Establish secure socket connection with client
port =  63945                  # Reserve a port for your service.
s = socket.socket()             # Create a socket object
host = socket.gethostname()     # Get local machine name
s.bind((host, port))            # Bind to the port
s.listen(5)                     # Now wait for client connection.

print 'Server listening:'
banned_lists = ["server_privkey.pem","server_pubkey.pem","client_pubkey.pem"]

while True:
    conn, addr = s.accept()     
    data = receive(conn)
    print(repr(data), " recieved")

    #Get client's public key 
    c_pubkey = receive(conn)
    f2 = open('client_pubkey.pem','wb')
    f2.write(c_pubkey)
    f2.close()

    #Send server's public key
    fobj = open('server_pubkey.pem','rb')
    s_pubkey = fobj.read(1024)
    send(conn,s_pubkey)
    fobj.close()
    print("Public key exchange successful!!!")
    
    option = 0	
    option = receive(conn)
    print(option)
    if option==1:		
        filename=receive(conn)
	if os.path.exists(filename) :
		if filename in banned_lists :
		    print "You do not have permission to open that file"
		    conn.close()
		else :
		    f = open(filename,'rb')
		    line = f.read(1024)
		    print(line)

		    #Hash and digitally sign the plaintext message
		    message_hash = SHA256.new(line)
		    s_private_key = RSA.importKey(open('server_privkey.pem').read())
		    signer = PKCS1_v1_5.new(s_private_key)
		    signature = signer.sign(message_hash)


		    #Append signature to message
		    signed_message = line +delimiter+ signature


		    #Generate a one-time session key
		    session_key_gen = (''.join(choice(ascii_uppercase) for i in range(32)))
		    session_key= bytes(session_key_gen)

		    #Encrypt the data with one-time session key
		    iv = Random.new().read(AES.block_size)
		    aes_cipher = AES.new(session_key, AES.MODE_CFB, iv)
		    b_signed = bytes(signed_message)
		    aes_enc_msg = iv + aes_cipher.encrypt(b_signed)

		    #Encrypt one-time session key with client's public key
		    r_public_key = RSA.importKey(open('client_pubkey.pem').read())
		    rsa_cipher = PKCS1_OAEP.new(r_public_key)
		    encrypted_session_key = rsa_cipher.encrypt(session_key)


		    #Send the encrypted message to the client
		    final_msg = aes_enc_msg +delimiter+ encrypted_session_key
		    while (final_msg):
		    	send(conn,final_msg)
		    	print('Sent ',repr(final_msg))
		    	final_msg = f.read(1024)
		    	f.close()

		    print('Done sending')
		    conn.close()
	else:
		print "No such file exists" 
		send(conn,"nill")
		conn.close();
    elif option == 2:
        filename=receive(conn)
        print(filename)
	if filename == "nill" :
		conn.close;
	else :
		f = open(filename, 'wb')
		try:
		    print 'file opened'
		    while True:
		        print('receiving data...')
		        data = receive(conn)
		        split_msg = data.split(delimiter)
		        enc_message = split_msg[0]
		        enc_session_key = split_msg[1]

		        # Decrypt one-time session key with server's private key
		        r_private_key = RSA.importKey(open('server_privkey.pem').read())
		        rsa_cipher = PKCS1_OAEP.new(r_private_key)
		        dec_session_key = rsa_cipher.decrypt(enc_session_key)

		        # Decrypt encrypted signed message
		        iv = Random.new().read(AES.block_size)
		        aes_cipher = AES.new(dec_session_key, AES.MODE_CFB, iv)
		        dec_smsg = aes_cipher.decrypt(enc_message)
		        ret = str(dec_smsg)
		        dec_smsg = ret[AES.block_size:]

		        # Verify Signature
		        message = dec_smsg.split(delimiter)[0]
		        print(message)
		        signature = dec_smsg.split(delimiter)[1]
		        #print(signature)
		        f.write(message)

		        s_public_key = RSA.importKey(open('client_pubkey.pem').read())
		    message_hash = SHA256.new(message)
		    print(message_hash)

		    verifier = PKCS1_v1_5.new(s_public_key)
		    if verifier.verify(message_hash, signature):
		        print ("The signature is authentic.")
		        print("Data Received:")
		        print(message)
		    else:
		        print ("The signature is not authentic.")
		    f.write(message)

		except:
		    pass
		f.close()
		print('Successfully got the file')
		conn.close()
		print('connection closed')


