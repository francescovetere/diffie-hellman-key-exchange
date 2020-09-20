# diffie-hellman-key-exchange

## Introduction
The source code contained in this project implements an authenticated Diffie-Hellman key exchange between a client and a server, according to the message exchange protocol described [here](https://github.com/francescovetere/diffie-hellman-key-exchange/edit/master/project-specs.txt).

Binary messaging protocol has been chosen.
The sources require at least Java 9.

## Java Classes
The source code is organized in 5 Java classes:

- ClientNetSec: Implements the client side of the protocol, assuming that server is located at netsec.unipr.it 

- ClientLocalhost: Implements the client side of the protocol, assuming that server is located at localhost 

- Server: Implements, on the local machine, the server side of the protocol

- Utils: Contains utility methods for hex/bytes's conversions, communication of messages, generation and storage of public and private keys, signing/verification of messages and encryption/decryption of messages 

- KeyGenerator: Implements a main program in which, using Utils' methods, a public-private key pair is generated, and then each key is stored in a .bin file. Finally, a simple correctness test is performed. 


## Usage
This exchange protocol can be executed either using the server located at netsec.unipr.it, or, in alternative, completely on localhost.

First approach only requires one process to be run, ClientNetSec.
This process will establish a connection with netsec.unipr.it, which already provides a running server's process.

Second approach requires a few extra steps.
First, KeyGenerator must be executed, in order to obtain two files "private-key.bin" and "public-key.bin".
Private key will be used by local server for signing, public key will be used by local client for verifying.
Once these two files are generated, Server's process must be run. It will wait until a client performs a connection request.
Finally, ClientLocalhost's process must be run. It will establish a connection with local server, and protocol's execution will begin.

## Contributor(s)
Francesco Vetere <<francescovetere1997@gmail.com>>
Andrea Fois <<https://github.com/andreaf96/>>
Giulia Magnani
