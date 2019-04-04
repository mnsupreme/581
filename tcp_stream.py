from os import listdir
import sys
from scapy.all import *
from multiprocessing.pool import ThreadPool



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



		

		
if __name__ == '__main__':
	src = sys.argv[1]
	write = sys.argv[2]
	files =  os.listdir(src)

	# for file in files:
	# 	run(file)

	
	pool = ThreadPool(6)
	pool.map(run,files)


