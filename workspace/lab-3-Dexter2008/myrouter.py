#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *


class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.arptable={}
        # other initialization stuff here

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        # TODO: your logic here
        my_interfaces=self.net.interfaces()
        arp=packet.get_header(Arp)
        if arp is not None:
            if(self.arptable.get(arp.senderprotoaddr)==None):
                self.arptable[arp.senderprotoaddr]=arp.senderhwaddr
                for key,value in self.arptable.items():
                    log_info("{}  \t{}".format(key,value))
                print()
            for intf in my_interfaces:
                if intf.ipaddr== arp.targetprotoaddr:
                    response=create_ip_arp_reply(intf.ethaddr,arp.senderhwaddr,intf.ipaddr,arp.senderprotoaddr)
                    self.net.send_packet(intf.name,response)
        #intf=my_interfaces.ipaddr(arp.targetprotoaddr)
        ...

    def start(self):
        '''A running daemon of the router.
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

        self.stop()

    def stop(self):
        self.net.shutdown()


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()
