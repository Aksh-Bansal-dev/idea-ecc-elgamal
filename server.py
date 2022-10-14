#
# Aksh Bansal
# 20BCS021
#

import socket			

from idea import IDEA
from ecc.curve import (P256,Point)
from ecc.cipher import ElGamal
from ecc.key import gen_keypair

s = socket.socket()		
port = 5000			

# Empty string to make it listen to all networks
s.bind(('', port))		
print ("socket binded to %s" %(port))

# put the socket into listening mode
s.listen(5)	
print ("socket is listening")		
 

# Generate keypair
privateKey, publicKey= gen_keypair(P256)

# Ask user for public and private keys
print("Server's public key parameter: ",end="")
sPublicKey = int(input())
print("Server's private key parameter: ",end="")
sPrivateKey = int(input())

print("Public key: ",publicKey)
print("Private key: ",privateKey)

# a forever loop until we interrupt it or
# an error occurs
while True:
    # Establish connection with client.
    c, addr = s.accept()	
    print ('Got connection from', addr )

    req = c.recv(1024).decode()
    if req=="publickey":
        # send public key to client
        c.send((str(publicKey.x)+" "+str(publicKey.y)+" "+str(publicKey.curve)).encode())

        # recv encrypted message & secret key
        payload = c.recv(1048).decode().split()
        encMsg = payload[0]
        # payload = c.recv(2048).decode().split()
        encSK1 = Point(int(payload[1]), int(payload[2]), P256)
        # payload = c.recv(2048).decode().split()
        encSK2 = Point(int(payload[4]), int(payload[5]), P256)

        # decrypt secret key using private key (ECC elgamal)
        ecc_elgamal = ElGamal(P256)
        secretKey = ecc_elgamal.decrypt(privateKey, encSK1, encSK2).decode()
        print("Secret key: ",secretKey)
        print("Encrypted message: ",int(encMsg))

        # decrypt message using secret key (Simplified IDEA)
        idea = IDEA(int(secretKey))
        msg = idea.decrypt(int(encMsg))
        print("Message:",msg)


        # Close the connection with the client
        c.close()
        break

print("Aksh Bansal\n20bcs021")
