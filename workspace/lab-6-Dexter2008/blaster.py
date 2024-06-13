#!/usr/bin/env python3

import time
from random import randint
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *

blaster_mac='10:00:00:00:00:01'
blastee_mac='20:00:00:00:00:01'
intf0_mac='40:00:00:00:00:01'
intf1_mac='40:00:00:00:00:02'

class Blaster:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasteeIp,
            num,
            length="100",
            senderWindow="5",
            timeout="300",
            recvTimeout="100"
    ):
        self.net = net
        # TODO: store the parameters
        ...
        self.blasteeIp=blasteeIp
        self.num=int(num)
        self.senderWindow=int(senderWindow)
        self.LHS=1
        #self.RHS=self.LHS+self.senderWindow-1
        self.RHS=0
        self.recv_ack=[]
        self.wait_pktseq=[]
        self.ackcount=0
        self.sended_pkt=[]
        self.length=int(length)
        self.timeout=float(timeout)/1000
        self.recvTimeout=float(recvTimeout)/1000
        self.sended_bytes=0
        self.start_time=0
        self.end_time=0
        self.timeout_count=0
        self.resend_count=0
        self.timer=time.time()

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        log_debug("I got a packet")
        if packet.has_header(Ethernet) == False or packet.has_header(IPv4) == False or packet.has_header(UDP) == False:
            return
        ack_seq_num=int.from_bytes(packet[3].to_bytes()[:4],'big')
        if ack_seq_num not in self.recv_ack:
            self.recv_ack.append(ack_seq_num)
            self.ackcount+=1
        if self.ackcount==self.num:
            self.print_info()
            self.shutdown()

        for i in self.wait_pktseq[:]:
            if i==ack_seq_num:
                self.wait_pktseq.remove(i)

        

    def handle_no_packet(self):
        log_debug("Didn't receive anything")
        
        while(self.LHS in self.recv_ack and self.LHS<=self.RHS):
            self.LHS+=1
            self.timer=time.time()

        tmp=self.RHS
        self.RHS=min(self.LHS+self.senderWindow-1,self.num)
        for i in range(tmp+1,self.RHS+1):
            assert i not in self.recv_ack
            self.wait_pktseq.append(i)
        
        if(time.time()-self.timer>self.timeout):
            self.timeout_count+=1
            self.timer=time.time()
            for i in range(self.LHS,self.RHS+1):
                if i in self.recv_ack:
                    continue
                else:
                    self.wait_pktseq.append(i)
       
        if len(self.wait_pktseq)==0:
            return
            # if self.RHS==self.LHS-1:
            #     self.timer=time.time()
            #     self.RHS=min(self.LHS+self.senderWindow-1,self.num)
            #     for i in range(self.LHS,self.RHS+1):
            #         assert i not in self.recv_ack
            #         self.wait_pktseq.append(i)
            # else:
            #     return

        self.timer=time.time()

        # Creating the headers for the packet
        pkt = Ethernet() + IPv4() + UDP()
        pkt[1].protocol = IPProtocol.UDP
        pkt[0].src=blaster_mac
        pkt[0].dst=intf0_mac
        pkt[0].ethertype=EtherType.IPv4
        pkt[1].src=self.net.interfaces()[0].ipaddr
        pkt[1].dst=self.blasteeIp
        pkt[1].ttl=32
        pkt[2].src=514
        pkt[2].dst=4444
        # Do other things here and send packet
        ...
        new_seqnum=self.wait_pktseq.pop(0)
        if new_seqnum in self.sended_pkt:
            self.resend_count+=1
        else:
            self.sended_pkt.append(new_seqnum)
        seq=RawPacketContents(new_seqnum.to_bytes(4,'big'))
        pl=RawPacketContents(self.length.to_bytes(2,'big')+(0).to_bytes(self.length,'big'))
        self.sended_bytes+=self.length
        pkt=pkt+seq+pl
        self.net.send_packet(self.net.interfaces()[0],pkt)
        
    def print_info(self):
        self.end_time=time.time()
        transmit_time=self.end_time-self.start_time
        log_info(f'Total TX time: {transmit_time}')
        log_info(f'Number of reTX: {self.resend_count}')
        log_info(f'Number of coarse TOs: {self.timeout_count}')
        log_info(f'Throughput (Bps): {float(self.sended_bytes) / transmit_time}')
        log_info(f'Goodput (Bps): {float(self.num * self.length) / transmit_time}')

    def start(self):
        '''A running daemon of the blaster.
        Receive packets until the end of time.
        '''
        self.start_time=time.time()
        while True:
            try:
                recv = self.net.recv_packet(timeout=self.recvTimeout)
            except NoPackets:
                self.handle_no_packet()
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    blaster = Blaster(net, **kwargs)
    blaster.start()
