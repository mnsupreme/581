import pyshark
import sys
import pprint
import collections
from scapy.all import *



scap = sniff(offline='test_capture.pcap',filter='tcp and ip src net 192.168 and not ip dst net 192.168')
cap = pyshark.FileCapture('test_capture.pcap',display_filter='ip.src == 192.168.0.0/16 and ip.dst != 192.168.0.0/16 and tcp',override_prefs={'tcp.relative_sequence_numbers':False},disable_protocol='UDP',keep_packets=True)

max_number = 0

for pkt in cap:
	if pkt.tcp.stream > max_number:
		max_number = pkt.tcp.stream


for strm in range(0,max_number):
	if pkt.tcp.stream == stream:
		match = {
			'dst_ip': pkt.ip.dst,
			'src_ip': pkt.ip.src,
			'dst_port': pkt.tcp.dstport,
			'src_port': pkt.tcp.srcport,
			'id':int(pkt.ip.id,16),
			'checksum':int(pkt.tcp.checksum,16),
			'seq':int(pkt.tcp.seq)
			'ack':int(pkt.tcp.ack)
		}

		

			


