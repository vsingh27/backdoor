# backdoor

Introduction
This document is a guide to our back door program. It requires the user some intermediate to advanced computer knowledge in order to use the back door program fully. The program is divided in 2 components the client and the backdoor. More details are discussed in the following parts
What does the backdoor program do?
The backdoor program sniffs for TCP and UDP packets at the card level and performs task based on what the client is sending covertly.
Our back door program is stealthy because it sniffs for packets at the card level and not at the application level. This bypass the security provided by the firewalls installed on the attacked machine. The backdoor can identify using a password when a legitimate client wants to perform some tasks using the backdoor application.
What type of tasks can I do using the backdoor program?
The attacker/client can perform root level commands like changing the password of the root user. Getting the list of the processors running on the victim machine, reading files that are stored on the attacked machine.
All of this is done without getting in the eyes of the IDS or other security systems. The backdoor program transmits data through TCP or UDP depending on the client.

# Starting the Back Door
Flags
-s: Source_PORT   is the port which the backdoor listens for incoming packets

-d: Destination PORT  is the port which the backdoor sends the encrypted data to the client

-p: Password  is the mechanism we use to authenticate the connection. It is an implementation of the port knocking mechanism

-n: Password Number  is the number used to decode the password received -k: Key  is the key used to decrypt the connection

A call to initiate the backdoor would look like following
*sudo python required.py -s 8080 -d 9090 -p hello12345 -n 10 -k 1234567890123456* 
Once the server/backdoor is running the client is can start sending commands to the back door to execute and send them back

# Starting the Client
Flags
Upon running client.py typing “-h” will display the usage information as below
-s: Source IP  is the IP you want the backdoor to know as the originating IP address

-g: Source Port  is the port of the source machine where the client listens for packets coming from back door

-i: Destination IP  is the ip address of the back door machine 4

-d:Destination Port  is the port on which the Backdoor listens for connections -t: TCP  is a flag to transmit data over TCP

-u:UDP  is the flag to transmit data over UDP

-p:Password  is to authenticate the connection to the backdoor

-n:Password Number  is used to encode the password -k:Key  is used to encrypt the connection

To start the client a command would look like
*sudo python client.py -s localhost -g 9090 -i localhost -d 8080 -t -p hello12345 -n 10 -k 1234567890123456*

After this command the server will authenticate the connection and send a confirmation back telling the client to start sending the commands to execute


The client can now send commands as he/she would execute in their host machines
shell. Sending a  ls -l command will produce a result like following figure

# Closing The Connection

 There are 2 ways to close the connection
1. By just closing the client session. This will not affect the server and will end the connection from the client side or the attacker's machine. To achieve this simply type exit
  
2. By killing the server and the client connection. To do this type “timetogo” and the server will be killed along with the client
  
