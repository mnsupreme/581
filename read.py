from scapy.all import *
import time
import gc
from concurrent.futures import ThreadPoolExecutor,ProcessPoolExecutor
from multiprocessing.pool import ThreadPool
from multiprocessing import Pool
import asyncio
import pprint
import os

def read(file):
	global files
	global t
	index = files.index(file)
	file = 'dev/' + file
	print(t + ' '+ str(index) + ' out of 801')
	rdpcap(file)
	gc.collect()


async def read_async(file):
	global files
	global t
	index = files.index(file)
	file = 'dev/' + file
	print(t + ' '+ str(index) + ' out of 801')
	rdpcap(file)
	gc.collect()

async def main(file_list):
	await asyncio.gather(*(read_async(file) for file in file_list))


if __name__ == '__main__':
	files = os.listdir('dev')
	t = 'regular'
	run_times = {}
	start = time.perf_counter()
	for file in files:
		read(file)
	run_times['regular']=time.perf_counter() - start
	t='asyncio'
	start = time.perf_counter()
	asyncio.run(main(files))
	run_times['asyncio']=time.perf_counter() - start
	t = 'threadpool'
	start = time.perf_counter()
	pool = ThreadPool(2)
	pool.map(read,files)
	pool.close()
	pool.join()
	run_times['threadpool']=time.perf_counter() - start
	t = 'threadpoolexecutor'
	start = time.perf_counter()
	with ThreadPoolExecutor(max_workers=2) as apool:
		apool.map(read,files)
	run_times['threadpoolexecutor']=time.perf_counter() - start
	t = 'pools'
	start = time.perf_counter()
	with Pool(processes=2) as p:
		p.map(read,files)
	run_times['processes'] =time.perf_counter() - start
	with ProcessPoolExecutor(max_workers=2) as ap:
		ap.map(read,files)
	run_times['processespoolexecutor'] =time.perf_counter() - start
	pprint.pprint(run_times)
