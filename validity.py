from scapy.all import *
import os

os.chdir('lab/streams')
files = os.listdir()
files = sorted(files, key=lambda file:file)
print(files)

def seq_check(file):
	#a=pyshark.FileCapture(input_file=file,display_filter='ip.src == 192.168.0.0/16 and ip.dst != 192.168.0.0/16 and tcp',override_prefs={'tcp.relative_sequence_numbers':False},disable_protocol='UDP',keep_packets=True)
	a = sniff(offline=file,filter='tcp and ip src net 192.168 and not ip dst net 192.168')


	current_greatest = 0

	for pkt in a:
		if current_greatest <= pkt['TCP'].seq:
			current_greatest = pkt['TCP'].seq
			print(pkt['TCP'].seq)
		elif current_greatest > pkt['TCP'].seq:
			raise Exception("packets out of order " + str(current_greatest) + " " + str(pkt['TCP'].seq))
		else:
			print(pkt['TCP'].seq)


for file in files:
	seq_check(file)

# for pkt in a:
# 	if int(pkt.tcp.stream) > max_number:
# 		max_number = int(pkt.tcp.stream)

