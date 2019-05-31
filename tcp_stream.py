from os import listdir
import gc
import sys
from scapy.all import *




def run(file):
	global streams
	global write
	global src
	file = src + '/' + file
	scap = sniff(offline=file,filter='tcp',lfilter=lambda x:(x['IP'].src != x['IP'].dst))

	


	for pkt in scap:
		socket = str(pkt['TCP'].sport) +'-'+ str(pkt['TCP'].dport) +'-'+ pkt['IP'].src + '-' + pkt['IP'].dst
		dumpfile = write + '/' + socket + '.pcap'
		if os.path.isfile(dumpfile):
			wrpcap(dumpfile,pkt,append=True)
		else:
			wrpcap(dumpfile,pkt)

	print("freeing memory")
	del scap
	gc.collect()
		

		
if __name__ == '__main__':
	src = sys.argv[1]
	write = sys.argv[2]
	files =  os.listdir(src)

	for file in files:
		run(file)

	



