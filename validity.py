from scapy.all import *
import os
import sys
import gc

directory = sys.argv[1]
os.chdir(directory)
files = sorted(os.listdir())
files = sorted(files, key=lambda file:file)
print(files)
bad_files=[]

def seq_check(file):
	#a=pyshark.FileCapture(input_file=file,display_filter='ip.src == 192.168.0.0/16 and ip.dst != 192.168.0.0/16 and tcp',override_prefs={'tcp.relative_sequence_numbers':False},disable_protocol='UDP',keep_packets=True)
	a = sniff(offline=file,filter='tcp and ip')


	current_greatest = 0

	for pkt in a:
		if current_greatest <= pkt['TCP'].seq:
			current_greatest = pkt['TCP'].seq
			#print(pkt['TCP'].seq)
		elif current_greatest > pkt['TCP'].seq:
			raise Exception("packets out of order " + str(current_greatest) + " " + str(pkt['TCP'].seq))
			bad_files.append(file)
		else:
			pass
			#print(pkt['TCP'].seq)

	gc.collect()


def seq_check_split_files():

	current_greatest = 0

	for file in files:
		
		a = sniff(offline=file,filter='tcp and ip')
		for pkt in a:
			if current_greatest <= pkt['TCP'].seq:
				current_greatest = pkt['TCP'].seq
				#print(pkt['TCP'].seq)
			elif current_greatest > pkt['TCP'].seq:
				raise Exception("packets out of order " + str(current_greatest) + " " + str(pkt['TCP'].seq))
				bad_files.append(file)
			else:
				pass

		gc.collect()

# for file in files:
# 	seq_check(file)

seq_check_split_files()

print(bad_files)

# for pkt in a:
# 	if int(pkt.tcp.stream) > max_number:
# 		max_number = int(pkt.tcp.stream)

