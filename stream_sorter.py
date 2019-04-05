from os import listdir
import gc
import sys
from scapy.all import *
from multiprocessing.pool import ThreadPool


def sort(file):
	global streams
	global src
	file = src + '/' + file
	print(file)
	scap = sniff(offline=file)

	
	scap =sorted(scap,key=lambda x:x['TCP'].seq)
	wrpcap(file,scap)
	print("freeing memory")
	del scap
	gc.collect()
		

		
if __name__ == '__main__':
	src = sys.argv[1]
	files =  os.listdir(src)

	# for file in files:
	# 	run(file)

	
	pool = ThreadPool(6)
	pool.map(sort,files)
	pool.close()
	pool.join()