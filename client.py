#
# Aksh Bansal
# 20BCS021
#

from idea import IDEA
from ecc.cipher import ElGamal
from ecc.curve import (P256,Point)
import socket			

s = socket.socket()		
port = 5000			
	

print("Message: ",end="")
msg = int(input())

print("Secret key: ",end="")
secretKey = input()

print("Client's public key: ",end="")
cPublicKey = int(input())

print("Client's private key: ",end="")
cPrivateKey = int(input())

# connect to the server on local computer
s.connect(('127.0.0.1', port))

# receive data from the server and decoding to get the string.
s.send("publickey".encode())
payload = s.recv(2048).decode().split()
publicKey = Point(int(payload[0]), int(payload[1]), P256)
print("Server's public key:",publicKey)

# encrypted secret key
ecc_elgamal = ElGamal(P256)
encSK1,encSK2 = ecc_elgamal.encrypt(secretKey.encode(),publicKey)
print("Encrypted secret key:",encSK1, encSK2)

# encrypt message
idea = IDEA(int(secretKey))
encMsg = idea.encrypt(msg)
print("Encrypted message:",encMsg)

# Send ciphertext & encrypted key
s.send((str(encMsg)+" "+(str(encSK1.x)+" "+str(encSK1.y)+" "+str(encSK1.curve))+" "+(str(encSK2.x)+" "+str(encSK2.y)+" "+str(encSK2.curve))).encode())
# s.send((str(encSK1.x)+" "+str(encSK1.y)+" "+str(encSK1.curve)).encode())
# s.send((str(encSK2.x)+" "+str(encSK2.y)+" "+str(encSK2.curve)).encode())
# close the connection
s.close()	

