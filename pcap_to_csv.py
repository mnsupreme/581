import gc
import csv
import pprint
import os
from scapy.all import *

directory = sys.argv[1]
csv_name= sys.argv[2]
files = os.listdir()

def process(file):
	file=directory + file
	scap = rdpcap(file)
	arr=[]
	for packet in range(0,len(scap)):
		pkt = scap[packet]
		if packet==0:
			time_delta = 0
			seq_delta = 0
			ack_delta = 0
		else
			lst_pkt = scap[packet-1]
			time_delta = pkt.time - lst_pkt.time
			seq_delta = pkt['TCP'].seq - lst_pkt['TCP'].seq
			ack_delta = pkt['TCP'].ack - lst_pkt['TCP'].ack
		arr.append({
			'time_delta':time_delta,
			'frag':pkt['IP'].frag
			'ttl':pkt['IP'].ttl, 
			'ihl':pkt['IP'].ihl, 
			'len':pkt['IP'].len, 
			'dataofs':pkt['TCP'].dataofs, 
			'window_length':pkt['TCP'].window,
			'seq_delta':seq_delta,
			'ack_delta':cack_delta})
	return arr




with open(csv_name,'w+') as csvFile:
	#[time_delta,fragmentation_offset, ttl, header_length, datagram_length, data_offset, window_length, sequence_delta, ack_delta]
	fieldnames = ['time_delta','frag','ttl','ihl','len','dataofs','window_length','sequence_delta','ack_delta']
	writer=csv.DictWriter(csvFile,fieldnames)
	writer.writeheader()

	