from os import listdir
import pyshark
from scapy.all import *



scap = sniff(offline='test_capture.pcap',filter='tcp and ip src net 192.168 and not ip dst net 192.168')
cap = pyshark.FileCapture('test_capture.pcap',display_filter='ip.src == 192.168.0.0/16 and ip.dst != 192.168.0.0/16 and tcp',override_prefs={'tcp.relative_sequence_numbers':False},disable_protocol='UDP',keep_packets=True)

max_number = 0

streams[]
cap = sorted(cap, key=lambda pkt:int(pkt.tcp.stream))



for pkt in a:
	match = {
		'dst_ip': pkt.ip.dst,
		'src_ip': pkt.ip.src,
		'dst_port': int(pkt.tcp.dstport),
		'src_port': int(pkt.tcp.srcport),
		'id':int(pkt.ip.id,16),
		'checksum':int(pkt.tcp.checksum,16),
		'seq':int(pkt.tcp.seq)
		'ack':int(pkt.tcp.ack)
	}
	scapy_packet =None
	for scp in scap:
		if scp['IP'].src = match['src_ip'] and scp['IP'].dst = match['dst_ip'] and src['IP'].id = match['id'] and src['TCP'].sport = match['src_port'] and src['TCP'].dport = match['dst_port'] and src['TCP'].seq = match['seq'] and src['TCP'].ack = match['ack'] and src['TCP'].chksum = match['checksum']:
			scapy_packet = scp
	if scapy_packet == None:
		print("error: No matching packet")
		break
	else:
		file = pkt.tcp.stream + '.pcap'
		if int(pkt.tcp.stream) not in streams:
			wrpcap(file,scapy_packet)
		else:
			wrpcap(file,scapy_packet,append=True)

		

			


