from multiprocessing import Pool
import os
import _pickle as cPickle
import pyshark
import sys
import pprint
import collections

files = ['test_capture']

def udp(file):
	capture = file + '.pcap'
	output = collections.OrderedDict()
	cap = pyshark.FileCapture(capture,display_filter='ip.src == 192.168.0.0/16 and ip.dst != 192.168.0.0/16 and udp',keep_packets=True)
	for pkt in cap:
		try:
			key = str(pkt.udp.stream)
			if key in output.keys():
				output[key]['packets'].append(pkt)
			else:
				output[key] = {
					'packets': [pkt]
				} 
		except:
			pass

	if bool(output):
		output_file = 'dill_pickles/' + file + '_udp.p'
		test_binary = open(output_file,'wb')
		cPickle.dump(output,test_binary)
		test_binary.close()
	else:
		print('object empty')

def tcp(file):
	capture = file + '.pcap'
	output = collections.OrderedDict()
	cap = pyshark.FileCapture(capture,display_filter='ip.src == 192.168.0.0/16 and ip.dst != 192.168.0.0/16 and tcp',keep_packets=True)
	for pkt in cap:
		try:
			key = str(pkt.tcp.stream)
			if key in output.keys():
				output[key]['packets'].append(pkt)
			else:
				output[key] = {
					'packets': [pkt]
				} 
		except:
			pass

	if bool(output):
		output_file = 'dill_pickles/' + file + '_tcp.p'
		test_binary = open(output_file,'wb')
		cPickle.dump(output,test_binary)
		test_binary.close()
	else:
		print('object empty')

tcp_pool = Pool(processes=2)
udp_pool = Pool(processes=2)

tcp_pool.map(tcp,files)
udp_pool.map(udp,files)

tcp_pool.close()
udp_pool.close()


