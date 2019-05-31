from os import listdir
import gc
import sys
from scapy.all import *



def sort(file):
	global streams
	global src
	global counter
	global files
	global unsorted
	counter += 1
	print('file ' + str(counter) + ' out of ' + str(len(files)))
	file = src + '/' + file
	print(file)
	try:
		scap = sniff(offline=file)

	
		scap =sorted(scap,key=lambda x:x['TCP'].seq)
		wrpcap(file,scap)
		print("freeing memory")
		del scap
		gc.collect()
	except:
		unsorted.append(file)
		print('problem sorting file ' + file)

		
if __name__ == '__main__':
	src = sys.argv[1]
	files =  os.listdir(src)
	unsorted = []
	counter = 0
	for file in files:
		sort(file)
	

	
	print(unsorted)

	#['botnet/streams/62516-428-10_0_2_22-178_63_42_65.pcap', 'botnet/streams/42254-428-10_0_2_22-69_50_192_33.pcap', 'botnet/streams/55408-428-10_0_2_22-178_63_42_65.pcap', 'botnet/streams/34323-80-10_0_2_22-193_28_86_55.pcap', 'botnet/streams/38555-80-10_0_2_22-210_172_144_61.pcap', 'botnet/streams/25794-428-10_0_2_22-69_50_192_29.pcap', 'botnet/streams/53397-25-10_0_2_22-173_194_70_27.pcap', 'botnet/streams/31567-443-10_0_2_22-144_76_28_61.pcap', 'botnet/streams/62879-428-10_0_2_22-69_50_192_240.pcap', 'botnet/streams/35285-25-10_0_2_22-94_100_176_20.pcap', 'botnet/streams/7384-25-10_0_2_22-74_125_142_27.pcap', 'botnet/streams/2095-428-10_0_2_22-69_50_192_137.pcap', 'botnet/streams/57850-428-10_0_2_22-69_50_192_29.pcap', 'botnet/streams/24561-25-10_0_2_22-94_100_176_20.pcap', 'botnet/streams/3103-428-10_0_2_22-46_4_98_62.pcap', 'botnet/streams/22295-428-10_0_2_22-69_50_192_46.pcap', 'botnet/streams/51052-428-10_0_2_22-69_50_192_240.pcap', 'botnet/streams/40023-80-10_0_2_22-192_254_235_39.pcap', 'botnet/streams/64316-428-10_0_2_22-204_12_192_7.pcap', 'botnet/streams/7959-25-10_0_2_22-74_125_142_26.pcap', 'botnet/streams/40211-25-10_0_2_22-74_125_136_26.pcap', 'botnet/streams/41596-443-10_0_2_22-69_50_208_16.pcap', 'botnet/streams/51308-428-10_0_2_22-204_12_192_47.pcap', 'botnet/streams/43759-428-10_0_2_22-204_12_192_7.pcap']
