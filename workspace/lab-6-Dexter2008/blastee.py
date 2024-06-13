#!/usr/bin/env python3

import time
import threading
from struct import pack
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *

blaster_mac='10:00:00:00:00:01'
blastee_mac='20:00:00:00:00:01'
intf0_mac='40:00:00:00:00:01'
intf1_mac='40:00:00:00:00:02'

class Blastee:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasterIp,
            num
    ):
        self.net = net
        # TODO: store the parameters
        ...
        self.recv_pac=[]
        self.count=0
        self.blasterIp=blasterIp
        self.num=int(num)

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        log_debug(f"I got a packet from {fromIface}")
        log_debug(f"Pkt: {packet}")
        if packet.has_header(Ethernet) == False or packet.has_header(IPv4) == False or packet.has_header(UDP) == False:
            return

        ack=Packet()
        ether=Ethernet()
        ether.ethertype=EtherType.IP
        ether.src=blastee_mac
        ether.dst=intf1_mac
        
        ip=IPv4()
        ip.src=self.net.interfaces()[0].ipaddr
        ip.dst=self.blasterIp
        ip.protocol=IPProtocol.UDP
        ip.ttl=32

        udp=UDP()
        udp.src=4444
        udp.dst=514
        ack=ether+ip+udp

        seq=packet[3].to_bytes()[:4]
        ack+=RawPacketContents(seq)
        seq_num=int.from_bytes(packet[3].to_bytes()[:4],'big')
        if seq_num not in self.recv_pac:
            self.recv_pac.append(seq_num)
            self.count+=1
        pl_len=int.from_bytes(packet[3].to_bytes()[4:6],'big')
        if pl_len>=8:
            pl=packet[3].to_bytes()[6:14]
        else:
            pl=packet[3].to_bytes()[6:]+(0).to_bytes(8-pl_len,'big')
        assert(len(seq+pl)==12)
        
        ack+=RawPacketContents(pl)
        
        self.net.send_packet(fromIface,ack)
        if self.count==self.num:
            self.shutdown()

    def start(self):
        '''A running daemon of the blastee.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    blastee = Blastee(net, **kwargs)
    blastee.start()
