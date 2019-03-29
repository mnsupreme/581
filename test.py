#!/usr/bin/env python

import os, subprocess, sys, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

# Add some colouring for printing packets later
YELLOW = '\033[93m'
GREEN = '\033[92m'
END = '\033[0m'

if len(sys.argv) != 3:
	print('Usage: ./pcap-streams.py pcapfile outputfolder')
	print('Example: ./pcap-streams.py /tmp/test.pcap /tmp/output')
	sys.exit(1)

pcap = sys.argv[1]
folder = sys.argv[2]


tcp_stream_index = []
tcp_stream_file = []

devnull = open('/dev/null', 'w')

# Check to see if the folder exists already
if not os.path.exists(folder):
	print(YELLOW + '[c!] Folder doesnt exist so creating ' + folder + END)
	os.makedirs(folder)

def sort_packets(file):
	scap = sniff(offline=file)
	sort = sorted(scap, key= lambda pkt:pkt['TCP'].seq)
	wrpcap(file,sort)

# Function to extract TCP streams
def tcp_stream(pcap):

	print(GREEN + '[+] Extracting TCP streams' + END)
	# Create a list of the tcp streams in the pcap file and save them as an index
	cmd = 'tshark -r ' + pcap+ ' -T fields -e tcp.stream'
	p = os.popen(cmd).readlines()
	for x in p:
		if x not in tcp_stream_index:
			tcp_stream_index.append(x)
	# Now we are going to write out all the streams as a pcap file
	try:
		for y in tcp_stream_index:
			y = y.strip('\n')
			dumpfile = folder + '/tcp-stream' + y + '.pcap'
			if 'tcp-stream.pcap' in dumpfile:
				pass
			else:
				cmd = 'tshark -r ' + pcap + ' -Y "tcp.stream eq ' + y + '" -w ' + dumpfile 
				if dumpfile not in tcp_stream_file:
					tcp_stream_file.append(dumpfile)
				#subprocess.run(cmd, shell=True, stdout=devnull, stderr=devnull)
				os.system(cmd)
				#print(cmd)
	except:
		pass

	print(YELLOW + '[!] There are ' + str(len(tcp_stream_file)) + ' TCP streams saved in: ' + folder + END)



tcp_stream(pcap)

