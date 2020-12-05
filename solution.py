from socket import *
import socket
import os
import sys
import struct
import time
import select
import binascii

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 1
# The packet that we shall send to each router along the path is the ICMP echo
# request packet, which is exactly what we had used in the ICMP ping exercise.
# We shall use the same packet that we built in the Ping exercise

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

def build_packet():
    #Fill in start
    myChecksum=0
    myID=os.getpid() & 0xFFFF
    # In the sendOnePing() method of the ICMP Ping exercise ,firstly the header of our
    # packet to be sent was made, secondly the checksum was appended to the header and
    # then finally the complete packet was sent to the destination.
    header=struct.pack("bbHHh",ICMP_ECHO_REQUEST, 0, myChecksum, myID, 1)
    data= struct.pack("d", time.time())
    
    # Make the header in a similar way to the ping exercise.
    # Append checksum to the header.
    myChecksum = checksum(header + data)
    if sys.platform == "darwin":
        myChecksum=socket.htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)
    

    # Don’t send the packet yet , just return the final packet in this function.
    #Fill in end
    # So the function ending should look like this
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, myID, 1)
    packet = header + data
    return packet
def ip_to_host(addr):

    try:
        fqdn = socket.gethostbyaddr(addr)[0]
        shortname = fqdn.split('.')[0]
        if fqdn == shortname:
            fqdn = ""

    except:
        # can't resolve it, so default to the address given
        shortname = addr
        fqdn = "hostname not returnable"

    return fqdn

def get_route(hostname):
    timeLeft = TIMEOUT
    tracelist2 = [] #This is your list to contain all traces
    for ttl in range(1,MAX_HOPS):
        for tries in range(TRIES):
            tracelist1=[]
            destAddr=socket.gethostbyname(hostname)

            #Fill in start
            icmp=socket.getprotobyname("icmp")
            # Make a raw socket named mySocket
            mySocket=socket.socket(socket.AF_INET,socket.SOCK_DGRAM, icmp)
            #Fill in end
            mySocket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)
            try:
                d = build_packet()
                mySocket.sendto(d, (hostname, 0))
                t= time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                howLongInSelect = (time.time() - startedSelect)
                if whatReady[0] == []: # Timeout
                    tracelist1.append("* * * Request timed out.")
                    #Fill in start
                    tracelist2.append(tracelist1)
                    #Fill in end
                recvPacket, addr = mySocket.recvfrom(1024)
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    tracelist1.append("* * * Request timed out.")
                    #Fill in start
                    tracelist2.append(tracelist1)
                    #Fill in end
            except socket.timeout:
                continue

            else:
                #Fill in start
                icmpHeader = recvPacket[20:28]
                types, code, checksum, packetID, sequence = struct.unpack("bbHHh", icmpHeader)
                #Fetch the icmp type from the IP packet
                #Fill in end
                if types == 11:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 +bytes])[0]
                    #Fill in start
                    tracelist1.append(str(ttl))
                    tracelist1.append("%.0fms"%((timeReceived -t)*1000))
                    tracelist1.append(str(addr[0]))
                    tracelist1.append(ip_to_host(addr[0]))
                    tracelist2.append(tracelist1)
                    print(" %d   %.0fms %s" % (ttl,(timeReceived -t)*1000, addr[0]))
                    #Fill in end
                elif types == 3:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    #Fill in start
                    tracelist1.append(str(ttl))
                    tracelist1.append("%.0fms"%((timeReceived -t)*1000))
                    tracelist1.append(str(addr[0]))
                    tracelist1.append(ip_to_host(addr[0]))
                    tracelist2.append(tracelist1)
                    print(" %d   %.0fms %s" % (ttl,(timeReceived -t)*1000, addr[0]))
                    #Fill in end
                elif types == 0:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    #Fill in start
                    tracelist1.append(str(ttl))
                    tracelist1.append("%0fms"%((timeReceived -t)*1000))
                    tracelist1.append(str(addr[0]))
                    tracelist1.append(ip_to_host(addr[0]))
                    tracelist2.append(tracelist1)
                    print(" %d   %.0fms %s" % (ttl,(timeReceived -t)*1000, addr[0]))
                    print (tracelist2)
                    return tracelist2
                    #Fill in end
                else:
                    tracelist1.append("error")
                    tracelist2.append(tracelist1)
                    #Fill in end
                break
            finally:
                mySocket.close()




        
