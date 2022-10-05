# Simplified IDEA + ECC ElGamal
Secure client-server communication using Simplified International Data Encryption Algorithm(IDEA) and ElGamal with elliptic curves.

## How it works?
The message is first encrypted using a secret key provided by client using
Simplified IDEA (symmetric). The private and public keys are generated on the
server using ECC Elgamal (asymmetric) and the public key is sent to the client. The secret
key is encrypted using the server's public key on client-side. The encrypted secret key
and encrypted message is then sent server. The server uses it's private key to decrypt 
the encrypted secret key and then uses this secret key to decrypt the encrypted message.

Simplified IDEA: [link](https://www.nku.edu/~christensen/simplified%20IDEA%20algorithm.pdf)
