from socket import *
import math
import os
import sys
import struct
import time
import select
import binascii
# Should use stdev

ICMP_ECHO_REQUEST = 8


def checksum(packet_string):
    # In this function we make the checksum of our packet 
    packet_string = bytearray(packet_string)
    csum = 0
    countTo = (len(packet_string) // 2) * 2

    for count in range(0, countTo, 2):
        thisVal = packet_string[count+1] * 256 + packet_string[count]
        csum = csum + thisVal
        csum = csum & 0xffffffff

    if countTo < len(packet_string):
        csum += (string[len(packet_string) - 1])
        csum &= 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer



def receiveOnePing(mySocket, ID, timeout, destAddr):
    timeLeft = timeout

    while 1:
        startedSelect = time.time()
        whatReady = select.select([mySocket], [], [], timeLeft)
        howLongInSelect = (time.time() - startedSelect)
        if whatReady[0] == []:  # Timeout
            return "Request timed out."

        timeReceived = time.time()
        recPacket, addr = mySocket.recvfrom(1024)

        # Fill in start
        
        ICMP_header=recPacket[20:28]
        icmptype, code, mychecksum, packetID, sequence = struct.unpack("bbHHh",ICMP_header)
        if icmptype != 8 and packetID == ID:
            doubledata= struct.calcsize("d")
            timesent=struct.unpack("d", recPacket[28:28+doubledata])[0]
            return (timeReceived-timesent) * 1000
        # Fetch the ICMP header from the IP packet

        # Fill in end
        timeLeft = timeLeft - howLongInSelect
        if timeLeft <= 0:
            return "Request timed out."


def sendOnePing(mySocket, destAddr, ID):
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)

    myChecksum = 0
    # Make a dummy header with a 0 checksum
    # struct -- Interpret strings as packed binary data
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    data = struct.pack("d", time.time())
    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(header + data)

    # Get the right checksum, and put in the header

    if sys.platform == 'darwin':
        # Convert 16-bit integers from host to network  byte order
        myChecksum = htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)


    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    packet = header + data
    mySocket.sendto(packet, (destAddr, 1))  # AF_INET address must be tuple, not str
    # Both LISTS and TUPLES consist of a number of objects
    # which can be referenced by their position number within the object.

def doOnePing(destAddr, timeout):
    icmp = getprotobyname("icmp")


    # SOCK_RAW is a powerful socket type. For more details:   http://sockraw.org/papers/sock_raw
    mySocket = socket(AF_INET, SOCK_RAW, icmp)

    myID = os.getpid() & 0xFFFF  # Return the current process i
    sendOnePing(mySocket, destAddr, myID)
    delay = receiveOnePing(mySocket, myID, timeout, destAddr)
    mySocket.close()
    return delay

def packet_avg(delaylist):
    return (sum(delaylist)/len(delaylist))
def stdev_var(delaylist):
    variation = sum(pow(i- (sum(delaylist)/len(delaylist)),2) for i in delaylist)/len(delaylist)
    return math.sqrt(variation)
def packet_min(delaylist):
    return min(delaylist)
def packet_max(delaylist):
    return max(delaylist)

def ping(host, timeout=1):
    # timeout=1 means: If one second goes by without a reply from the server,  	# the client assumes that either the client's ping or the server's pong is lost
    dest = gethostbyname(host)
    print("Pinging "+  dest)
    print("")
    delaylist=[]
    # Calculate vars values and return them
    # Send ping requests to a server separated by approximately one second
    for i in range(0,4):
        delay = doOnePing(dest, timeout)
        print(delay)
        time.sleep(1)  # one second
        delaylist.append(delay)
    vars = [str(round(packet_min(delaylist), 2)), str(round(packet_avg(delaylist), 2)), str(round(packet_max(delaylist), 2)),str(round(stdev_var(delaylist), 2))]
    return vars

if __name__ == '__main__':
    ping("google.co.il")
