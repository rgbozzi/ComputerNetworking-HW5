from socket import *
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


def checksum(string):
# In this function we make the checksum of our packet
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0
    while count < countTo:
        thisVal = (string[count + 1]) * 256 + (string[count])
        csum += thisVal
        csum &= 0xffffffff
        count += 2
    if countTo < len(string):
        csum += (string[len(string) - 1])
        csum &= 0xffffffff
    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def build_packet():
    #Fill in start
    # In the sendOnePing() method of the ICMP Ping exercise ,firstly the header of our
    # packet to be sent was made, secondly the checksum was appended to the header and
    # then finally the complete packet was sent to the destination.
    myID = os.getpid() & 0xFFFF  # Return the current process i
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, myID, 1)
    data = struct.pack("d", time.time())
    myChecksum = checksum(header + data)

    # Make the header in a similar way to the ping exercise.
    # Append checksum to the header.
    if sys.platform == 'darwin':

        myChecksum = htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)

    # Don’t send the packet yet , just return the final packet in this function.
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, myID, 1)

    #Fill in end


    # So the function ending should look like this


    packet = header + data
    return packet

def get_route(hostname):
    destAddr = gethostbyname(hostname)
    print("Checking the Traceroute for {} ({}): {} Max Hops, {} Max Retries".format(hostname, destAddr, MAX_HOPS, TRIES))
    timeLeft = TIMEOUT
    tracelist1 = [] #This is your list to use when iterating through each trace
    tracelist2 = [] #This is your list to contain all traces
    for ttl in range(1, MAX_HOPS):
        for tries in range(TRIES):
            destAddr = gethostbyname(hostname)
            #Fill in start
            # Socket creation from Pinger
            icmp = getprotobyname("icmp")
            mySocket = socket(AF_INET, SOCK_RAW, icmp)
            mySocket.bind(("", 0))
            #Fill in end
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)
            try:
                d = build_packet()
                mySocket.sendto(d, (hostname, 0))
                t = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                howLongInSelect = (time.time() - startedSelect)
                if whatReady[0] == []: # Timeout
                    tracelist1.append("* * * Request timed out.")
                    #Fill in start
                    tracelist2.append([str(ttl), "*", "Request timed out"])
                    #Fill in end
                recvPacket, addr = mySocket.recvfrom(1024)
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    tracelist1.append("* * * Request timed out.")
                    tracelist2.append([str(ttl), "*", "Request timed out"])
            except timeout:
                continue
            else:

                icmpType, icmpCode, icmpChecksum, icmpID, icmpSequence \
                    = struct.unpack('bbHHh', recvPacket[20:28])
                try:

                    host_hop_domain = gethostbyaddr(addr[0])
                except herror as e:   #if the host does not provide a hostname
                    host_hop_domain = 'hostname not returnable'
                if isinstance(host_hop_domain, tuple):
                    host_hop_domain = host_hop_domain[0]

                if icmpType == 11:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    delay = timeReceived - t
                    delay = round(delay * 1000)
                    delay_str = str(delay) + 'ms'
                    tracelist2.append([str(ttl), delay_str, addr[0], host_hop_domain])
                    print('{}\t{}\t{}\t{}'.format(str(ttl), delay_str, addr[0], host_hop_domain))
                elif icmpType == 3:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    delay = timeReceived - t
                    delay = round(delay * 1000)
                    delay_str = str(delay) + 'ms'
                    tracelist2.append([str(ttl), delay_str, addr[0], host_hop_domain])
                    print('{}\t{}\t{}\t{}'.format(str(ttl), delay_str, addr[0], host_hop_domain))
                elif icmpType == 0:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    delay = timeReceived - timeSent
                    delay = round(delay * 1000)
                    delay_str = str(delay) + 'ms'
                    tracelist2.append([str(ttl), delay_str, addr[0], host_hop_domain])
                    print('{}\t{}\t{}\t{}'.format(str(ttl), delay_str, addr[0], host_hop_domain))
                    return tracelist2
                else:
                    tracelist2.append([str(ttl), "*", "Request timed out"])
                    print('{}\t{}\t{}'.format(str(ttl), '*', 'Request timed out'))
                break
            finally:
                mySocket.close()
if __name__ == '__main__':


    get_route("www.google.com")
