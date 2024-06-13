#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
import _thread
from switchyard.lib.userlib import *

class ForwardTable(object):
    def __init__(self,interfaces):
        self.data=[]
        # debugger()
        for intf in interfaces:
            # debugger()
            key=IPv4Network(str(IPv4Address(int(intf.ipaddr)&int(intf.netmask)))+'/'+str(intf.netmask))
            self.data.append([key,IPv4Address('0.0.0.0'),intf.name])
        with open('forwarding_table.txt','r') as fp:
            for line in fp.readlines():
                line=line.strip()
                line=line.split(' ')
                key=IPv4Network(line[0]+'/'+line[1])
                self.data.append([key,IPv4Address(line[2]),line[3]])
        self.data.sort(key=lambda key:key[0].prefixlen,reverse=True)
    
    def Query(self,address:IPv4Address):
        # debugger()
        for key in self.data:
            if address in key[0]:
                return key[1:]
        return None


class WaitPacket(object):
    def __init__(self,net,packet,intf,next_ip):
        self.net=net
        self.packet=packet
        self.intf=intf
        self.next_ip=next_ip
        self.timestamp=0
        self.count=0
    
    def send_arp_request(self):
        ether=Ethernet()
        # debugger()
        ether.src=self.intf.ethaddr
        ether.dst='ff:ff:ff:ff:ff:ff'
        ether.ethertype = EtherType.ARP
        arp = Arp(operation=ArpOperation.Request,
                senderhwaddr=self.intf.ethaddr,
                senderprotoaddr=self.intf.ipaddr,
                targethwaddr='ff:ff:ff:ff:ff:ff',
                targetprotoaddr=self.next_ip)
        arppacket = ether + arp
        self.net.send_packet(self.intf,arppacket)
        self.timestamp=time.time()
        self.count+=1
        return self.count

class ArpQueue(object):
    def __init__(self,net):
        self.data=[]
        self.sendedarp=[]
        self.sendedip=[]
     #  self.forbidip=[]
        self.net=net
    
    def put(self,waitpkt):
        self.data.append(waitpkt)
    
    def handle_reply(self,reply):
        # debugger()
        dstip=reply.senderprotoaddr
        dstmac=reply.senderhwaddr
        if dstip not in self.sendedip: return
        self.sendedip.remove(dstip)
        for waitpkt in self.data[:]:
            if waitpkt.next_ip==dstip:
                ether_idx=waitpkt.packet.get_header_index(Ethernet)
                waitpkt.packet[ether_idx].src=waitpkt.intf.ethaddr
                waitpkt.packet[ether_idx].dst=dstmac
                self.net.send_packet(waitpkt.intf,waitpkt.packet)
                if waitpkt in self.sendedarp:self.sendedarp.remove(waitpkt)
                self.data.remove(waitpkt)
                
    def clearpkts(self,ip):
        for waitpkt in self.data[:]:
            if waitpkt.next_ip==ip:
                self.data.remove(waitpkt)
        #self.forbidip.append(ip)
        
    def timeout(self):
        for waitpkt in self.data:
            if(time.time()-waitpkt.timestamp>1):
                # debugger()
                # waitpkt.send_arp_request()
                if waitpkt in self.sendedarp:
                    if waitpkt.count>=5:
                        self.clearpkts(waitpkt.next_ip)
                        self.sendedarp.remove(waitpkt)
                        self.sendedip.remove(waitpkt.next_ip)
                    else:
                        waitpkt.send_arp_request()
                else:
                    if waitpkt.next_ip  in self.sendedip:
                        pass
                    else:
                        self.sendedarp.append(waitpkt)
                        self.sendedip.append(waitpkt.next_ip)
                        tries=waitpkt.send_arp_request()
                        assert(tries==1)


class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.arptable={}
        self.forwardtable=ForwardTable(net.interfaces())
        self.arpqueue=ArpQueue(net)
        # other initialization stuff here
        # debugger()
    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        # TODO: your logic here
        my_interfaces=self.net.interfaces()
        mymacs = [intf.ethaddr for intf in my_interfaces]
        myips = [intf.ipaddr for intf in my_interfaces]
        arp=packet.get_header(Arp)
        ipv4=packet.get_header(IPv4)
        eth=packet.get_header(Ethernet)
        
        if (eth.dst!=self.net.interface_by_name(ifaceName).ethaddr) and (eth.dst!='ff:ff:ff:ff:ff:ff'):
            return
        if packet[Ethernet].ethertype==EtherType.VLAN:return
        if arp is not None:
                # for key,value in self.arptable.items():
                # log_info("{}  \t{}".format(key,value))
                # print()
            assert(arp.senderhwaddr==eth.src)    
            if arp.targetprotoaddr not in myips: return 
            # if(self.arptable.get(arp.senderprotoaddr)==None):
            #self.arptable[arp.senderprotoaddr]=arp.senderhwaddr
            # if arp.senderprotoaddr==IPv4Address('10.10.128.20'): 
                # debugger()
            # if arp.senderprotoaddr==IPv4Address('31.0.1.1'): 
            #     if arp.senderhwaddr=='34:00:00:00:01:20':pass
            # if arp.targetprotoaddr in self.arpqueue.sendedip:
            #     self.arpqueue.handle_reply(arp)
            #     return
            if arp.operation==1:
                self.arptable[arp.senderprotoaddr]=arp.senderhwaddr
                for intf in my_interfaces:
                    if intf.ipaddr== arp.targetprotoaddr:
                        response=create_ip_arp_reply(intf.ethaddr,arp.senderhwaddr,intf.ipaddr,arp.senderprotoaddr)
                        self.net.send_packet(ifaceName,response)
            elif arp.operation==2:
                if eth.src != 'ff:ff:ff:ff:ff:ff' and eth.dst!='ff:ff:ff:ff:ff:ff' and arp.senderhwaddr!='ff:ff:ff:ff:ff:ff' and arp.targethwaddr !='ff:ff:ff:ff:ff:ff':
                    # if arp.senderprotoaddr==IPv4Address('10.10.128.20')and arp.senderhwaddr=='33:00:00:00:01:20': 
                    # if arp.senderhwaddr=='34:00:00:00:01:20':pass
                    self.arptable[arp.senderprotoaddr]=arp.senderhwaddr
                    self.arpqueue.handle_reply(arp)
        # debugger()
        elif ipv4 is not None:
            # debugger()
            if ipv4.dst in myips: return
            info=self.forwardtable.Query(ipv4.dst)
            # debugger()
            if info==None: pass
            else:
                ipv4_idx=packet.get_header_index(IPv4)
                # debugger()
                assert(ipv4_idx!=-1)
                packet[ipv4_idx].ttl-=1
                # debugger()
                next_ip=ipv4.dst if info[0]==IPv4Address('0.0.0.0') else info[0]
                next_intf=self.net.interface_by_name(info[1])
                next_mac=self.arptable.get(next_ip)
                # debugger()
                if(next_mac!=None):
                    # debugger()
                    ether_idx=packet.get_header_index(Ethernet)
                    packet[ether_idx].src=next_intf.ethaddr
                    packet[ether_idx].dst=next_mac
                    self.net.send_packet(next_intf,packet)
                    # debugger()
                else:
                    self.arpqueue.put(WaitPacket(self.net,packet,next_intf,next_ip))
        ...

    # def thread_timeout(self):
    #     while True:
    #         # debugger()
    #         self.arpqueue.timeout()


    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        # _thread.start_new_thread(self.thread_timeout,())
        
        while True:
            self.arpqueue.timeout()
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
