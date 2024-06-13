'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
import switchyard
import collections
from switchyard.lib.userlib import *

TableMAXNUM=5
def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    table=collections.OrderedDict()
    table_num=0
    while True:
        try:
            _, fromIface, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            break

        log_debug (f"In {net.name} received packet {packet} on {fromIface}")
        eth = packet.get_header(Ethernet)
        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            return
        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
        else:
            if table.get(eth.src) !=None:
                table[eth.src]=fromIface
                table.move_to_end(eth.src,last=True)
            else:
                if table_num<TableMAXNUM:
                    table[eth.src]=fromIface
                    table_num+=1
                else:
                    table.popitem(last=False)
                    table[eth.src]=fromIface
            if table.get(eth.dst)!=None:
                table.move_to_end(eth.dst,last=True)
                net.send_packet(table[eth.dst],packet)
            else:
                for intf in my_interfaces:
                    if fromIface!= intf.name:
                        log_info (f"Flooding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)

    net.shutdown()
