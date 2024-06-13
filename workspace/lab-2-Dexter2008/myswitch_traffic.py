'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
import switchyard
from switchyard.lib.userlib import *
TableMaxNUM=5

def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    table={}
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
            if table.get(eth.src)!= None:
                table[eth.src][0]=fromIface
            else:
                if table_num<TableMaxNUM:
                    table[eth.src]=[fromIface,0]
                    table_num+=1
                else:
                    small_traffic=float("inf")
                    mykey=None
                    for key in table.keys():
                        if small_traffic > table[key][1]:
                            small_traffic=table[key][1]
                            mykey=key
                    del table[mykey]
                    table[eth.src]=[fromIface,0]
            if table.get(eth.dst)!=None:
                table[eth.dst][1]+=1
                net.send_packet(table[eth.dst][0],packet)
            else:
                for intf in my_interfaces:
                    if fromIface!= intf.name:
                        log_info (f"Flooding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)

    net.shutdown()
