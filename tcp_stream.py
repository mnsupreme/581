from os import listdir
import sys
from scapy.all import *

os.chdir('lab/split')
files =  os.listdir()
streams = []

def run(file):
	scap = sniff(offline=file,filter='tcp and ip src net 192.168 and not ip dst net 192.168')

	cap = sorted(cap, key=lambda pkt:int(pkt.tcp.stream))

	global streams


		scapy_packet =None
		for scp in scap:
			if scp['IP'].src == match['src_ip'] and scp['IP'].dst == match['dst_ip'] and scp['IP'].id == match['id'] and scp['TCP'].sport == match['src_port'] and scp['TCP'].dport == match['dst_port'] and scp['TCP'].seq == match['seq'] and scp['TCP'].ack == match['ack'] and scp['TCP'].chksum == match['checksum']:
				scapy_packet = scp
		if scapy_packet == None:
			print("error: No matching packet")
			sys.exit(0)
		else:
			file = "../streams/" + pkt.tcp.stream + '.pcap'
			if int(pkt.tcp.stream) not in streams:
				streams.append(int(pkt.tcp.stream))
				wrpcap(file,scapy_packet)
			else:
				wrpcap(file,scapy_packet,append=True)

		
for file in files:
	run(file)
			


