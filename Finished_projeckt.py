import os
import socket
import sys
from struct import *
import struct
import daemon
import pcap

pcap_file = pcap.pcap('/home/heimdall/PycharmProjects/BGP2BMP_Converter/nyiix.pcap')


class BMPWriter():
    """ BMP Writer
        Transmits messages to remote bmp collector.
    """

    def __init__(self, port, host, adr,  init_mes, term_mes, socket):

        self.init_message = init_mes
        self.term_message = term_mes

        self.socket = socket

        self.host = host
        self.port = port

        self.Router_adr = adr

        self._isConnected = False
        self._sock = None
        self._stop = False

    def run(self):

        self.connect()
        #cnt = 0

        try:
            while not self.stopped():

                #if cnt == 3:
                    #break
                #cnt += 1

                if self.isConnected:

                    try:
                        message = packet_loop(self.socket, self.Router_adr)
                        if message == 0:
                            self.stop()
                            pass
                        if message != "":
                            print("\nSENT\n")
                            sen = self.send(message)
                            print sen
                            #cnt +=1
                    except KeyboardInterrupt:
                        pass
                        #self._isConnected = False


                else:
                    self.connect()

        except (KeyboardInterrupt, IOError, EOFError):
            pass

    def connect(self):
        """ Connect to remote collector
        :return: True if connected, False otherwise/error
        """
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.connect((self.host, self.port))

            self._isConnected = True
            print("Connected")

            print self._isConnected

            # Send INIT message.
            sent = False
            while not sent:
                sent = self.send(self.init_message)

        except socket.error as msg:
            self._isConnected = False
            print("Not connected")

        except KeyboardInterrupt:
            pass

    def send(self, msg):
        """ Send BMP message to socket.
            :param msg:     Message to send/write
            :return: True if sent, False if not sent
        """
        sent = False

        try:
            print("SENDING")
            self._sock.sendall(msg)
            sent = True
            print sent

        except socket.error as msg:
            print(msg)
            self.disconnect()
            self.connect()

        finally:
            return sent

    def disconnect(self):
        """ Disconnect from remote collector
        """

        # Send TERM message to the collector.
        self.send(self.term_message)

        if self._sock:
            self._sock.close()
            self._sock = None

        self._isConnected = False

    def isConnected(self):
        return self._isConnected

    def stop(self):
        self._stop = True


    def stopped(self):
        return self._stop != True




class BMP_Helper:

    @staticmethod
    def createBmpCommonHeader(version, data_length, msg_type):

        """
        BMP Common Header:
          0                   1                   2                   3
          0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         +-+-+-+-+-+-+-+-+
         |    Version    |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                        Message Length                         |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |   Msg. Type   |
         +---------------+
        Message Types:
          *  Type = 0: Route Monitoring
          *  Type = 1: Statistics Report
          *  Type = 2: Peer Down Notification
          *  Type = 3: Peer Up Notification
          *  Type = 4: Initiation Message
          *  Type = 5: Termination Message
          *  Type = 6: Route Mirroring Message
        """

        addrinfo = [
            'Common header version: {}'.format(version),
            'Common header length: {}'.format(data_length),
            'Common header type: {}'.format(msg_type)
        ]
        print(' '.join(addrinfo))

        return struct.pack("!B I B", version, data_length, msg_type)

    @staticmethod
    def createBmpPerPeerHeader(s_addr, asn, bgp_id, hold_time):

        """
        BMP Peer Header:
          0                   1                   2                   3
          0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |   Peer Type   |  Peer Flags   |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |         Peer Distinguisher (present based on peer type)       |
         |                                                               |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                 Peer Address (16 bytes)                       |
         ~                                                               ~
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                           Peer AS                             |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                         Peer BGP ID                           |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                    Timestamp (seconds)                        |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                  Timestamp (microseconds)                     |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          *  Peer Type = 0: Global Instance Peer
          *  Peer Type = 1: RD Instance Peer
          *  Peer Type = 2: Local Instance Peer
          Peer Flags:
         0 1 2 3 4 5 6 7
         +-+-+-+-+-+-+-+-+
         |V|L|A| Reserved|
         +-+-+-+-+-+-+-+-+
        """

        peer_type = 0x00
        peer_flags = 0x00
        peer_dist = 0x00

        peer_address = struct.pack('!12x') + socket.inet_pton(socket.AF_INET, s_addr)

        #bgp_id = socket.inet_pton(socket.AF_INET, bgp_id)

        addrinfo = [
            'Peer header flags: {}'.format(peer_flags),
            'Peer header type: {}'.format(peer_type),
            'Peer header Distinguisher: {}'.format(peer_dist),
            'Peer header Address: {}'.format(s_addr),
            'Peer header AS: {}'.format(asn),
            'Peer header BGP iD: {}'.format(bgp_id)
        ]
        print(' '.join(addrinfo))

        return struct.pack("!B B Q", peer_type, peer_flags, peer_dist) + peer_address + struct.pack("!I", asn) \
            + struct.pack("!I", bgp_id) + struct.pack("!I I", hold_time, hold_time)

    @staticmethod
    def createInitiationMessage():

        type_mes= struct.pack("!H", 0)

        inf = struct.pack("!7s",  "UNKNOWN")

        init =type_mes + struct.pack("!H",  len(inf)) + inf

        common = BMP_Helper.createBmpCommonHeader(3, len(init) + 6, 4)

        return common + init

    @staticmethod
    def createTermMessage():


        term = struct.pack("!H H H", 1, 2, 0)

        common = BMP_Helper.createBmpCommonHeader(3, len(term) + 6, 5)

        return common + term

    @staticmethod
    def createPeerUpNotification(adress, s_port, d_port, message_s, message_r):

        """
          Peer Up Notification:
          0                   1                   2                   3
          0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                 Local Address (16 bytes)                      |
         ~                                                               ~
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |         Local Port            |        Remote Port            |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                    Sent OPEN Message                          |
         ~                                                               ~
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                  Received OPEN Message                        |
         ~                                                               ~
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                 Information (variable)                        |
         ~                                                               ~
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        """

        # Local Address
        local_address = struct.pack('!12x') + socket.inet_pton(socket.AF_INET, adress)

        # Local Port
        local_port = struct.pack('!H', s_port)

        # Remote Port
        remote_port = struct.pack('!H', d_port)

        return local_address + local_port + remote_port + message_s + message_r

    @staticmethod
    def createPeerDownNotification():

        """
        Peer Down Notification:
          0                   1                   2                   3
          0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         +-+-+-+-+-+-+-+-+
         |    Reason     |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |            Data (present if Reason = 1, 2 or 3)               |
         ~                                                               ~
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        """

        REASON = 1

        return struct.pack("!B", REASON)



def BGP2BMP(bgp, s_addr, d_addr, s_port, d_port, router):
    header_len = 19

    if len(bgp) < 19:
        return ""

    mes_header = bgp[:header_len]

    mes = unpack('!16sHB', mes_header)

    mes_type = mes[2]

    addrinfo = [
        'Message Type: {}'.format(mes_type),
    ]
    print(' '.join(addrinfo))

    if (mes_type == 1):
        open_header = bgp[header_len:header_len+10]

        open_mes = unpack('!BHHIB', open_header)

        open_version = open_mes[0]
        open_AS_sender = open_mes[1]
        open_hold_time = open_mes[2]
        open_BGP_id = open_mes[3]
        open_opt_len = open_mes[4]

        message_s = ''
        message_r = ''

        if router == s_addr:
            message_s = bgp
        else:
            message_r = bgp

        PeerUp = BMP_Helper.createPeerUpNotification(s_addr, s_port, d_port, message_s, message_r)

        per_peer = BMP_Helper.createBmpPerPeerHeader(s_addr, open_AS_sender, open_BGP_id, open_hold_time)

        common = BMP_Helper.createBmpCommonHeader(3, len(PeerUp) + len(per_peer) + 6 ,3)

        return common + per_peer + PeerUp

    elif (mes_type == 3):

        PeerDown = BMP_Helper.createPeerDownNotification()

        PeerDown += bgp

        per_peer = BMP_Helper.createBmpPerPeerHeader(s_addr, 0, 0, 0)

        common = BMP_Helper.createBmpCommonHeader(3, len(PeerDown) + len(per_peer) + 6, 2)

        return common + per_peer + PeerDown

    elif (mes_type == 2):

        per_peer = BMP_Helper.createBmpPerPeerHeader(s_addr, 0, 0, 0)

        common = BMP_Helper.createBmpCommonHeader(3, len(bgp) + len(per_peer) + 6, 0)

        return common + per_peer + bgp

    return ""



def packet_loop(s, Router_adr):

    for ts, pkt in pcap_file:

        #packet = s.recvfrom(65565)

        #packet = packet[0]
        packet = pkt


        # parse ethernet header
        eth_length = 14

        eth_header = packet[:eth_length]
        eth = unpack('!6s6sH', eth_header)
        eth_protocol = socket.ntohs(eth[2])
        addrinfo = [
            'Destination MAC: {}'.format(eth_addr2(packet[0:6])),
            'Source MAC: {}'.format(eth_addr2(packet[6:12])),
            'Protocol: {}'.format(eth_protocol)
        ]
        print(' '.join(addrinfo))

        # Parse IP packets, IP Protocol number = 8
        if eth_protocol == 8:
            # Parse IP header
            # take first 20 characters for the ip header
            ip_header = packet[eth_length:20 + eth_length]

            # now unpack them :)
            iph = unpack('!BBHHHBBH4s4s', ip_header)

            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF

            iph_length = ihl * 4

            ttl = iph[5]
            protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8])
            d_addr = socket.inet_ntoa(iph[9])
            if not((s_addr != Router_adr) and (d_addr != Router_adr)):
                print('\nWrong Adress\n')
            else:
                headerinfo = [
                    'Version: {}'.format(version),
                    'IP Header Length: {}'.format(ihl),
                    'TTL: {}'.format(ttl),
                    'Protocol: {}'.format(protocol),
                    'Source Addr: {}'.format(s_addr),
                    'Desr.Addr: {}'.format(d_addr)]
                print(' '.join(headerinfo))

                # TCP protocol
                if protocol == 6:
                    t = iph_length + eth_length
                    tcp_header = packet[t:t + 20]

                    # now unpack them :)
                    tcph = unpack('!HHLLBBHHH', tcp_header)

                    source_port = tcph[0]
                    dest_port = tcph[1]
                    if (source_port != 179) and (dest_port != 179) :
                        print('\nFalse port\n')
                    else:
                        sequence = tcph[2]
                        acknowledgement = tcph[3]
                        doff_reserved = tcph[4]
                        tcph_length = doff_reserved >> 4

                        tcpinfo = [
                            'Source Port: {}'.format(source_port),
                            'Dest. Port: {}'.format(dest_port),
                            'Sequence Num: {}'.format(sequence),
                            'Acknowledgement: {}'.format(acknowledgement),
                            'TCP Header Len.: {}'.format(tcph_length),
                        ]
                        print(' '.join(tcpinfo))

                        h_size = eth_length + iph_length + tcph_length * 4
                        data_size = len(packet) - h_size

                        # get data from the packet
                        data = packet[h_size:]

                        print('Data: {}'.format(data_decode(data)))

                        mes = BGP2BMP(data, s_addr, d_addr, source_port, dest_port, Router_adr)

                        print('Message: {}'.format(data_decode(mes)))

                        return mes

                else:
                    print('Protocol other than TCP')

            print('')
    return 0



def data_decode(b):
    if sys.version_info.major == 2:
        return b
    return b.decode('ascii', errors='replace')

"""def eth_addr(a):
     Convert a string of 6 characters of ethernet address into a
        dash separated hex string
    pieces = (a[i] for i in range(6))
    return '{:2x}:{:2x}:{:2x}:{:2x}:{:2x}:{:2x}'.format(*pieces)"""

def eth_addr2(a):
    """ Same as eth_addr, for Python 2 """
    pieces = tuple(ord(a[i]) for i in range(6))
    return '%.2x:%.2x:%.2x:%.2x:%.2x:%.2x' % pieces






def main():

    print '\nEnter router adress:\n'
    Router_adr = sys.stdin.readline()
    #print '\nEnter port:\n'
    #Router_port = int(sys.stdin.readline())
    #print '\nEnter host:\n'
    #Router_host = sys.stdin.readline()
    Router_host = "62.76.121.12"
    Router_port = 5000

    try:
        s = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.ntohs(0x0003))
    except socket.error as exmsg:
        print('Socket could not be created.')
        print('    Error Code : {}'.format(getattr(exmsg, 'errno', '?')))
        print('       Message : {}'.format(exmsg))
        sys.exit()

    process = BMPWriter(Router_port, Router_host, Router_adr,  BMP_Helper.createInitiationMessage(), BMP_Helper.createTermMessage(), s)

    with daemon.DaemonContext():
        process.run()
        process.stop()

main()