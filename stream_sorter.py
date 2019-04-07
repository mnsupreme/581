from os import listdir
import gc
import sys
from scapy.all import *
from multiprocessing.pool import ThreadPool


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
	# for file in files:
	# 	run(file)
	counter = 0

	
	pool = ThreadPool(6)
	pool.map(sort,files)
	pool.close()
	pool.join()
	print(unsorted)