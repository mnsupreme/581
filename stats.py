import numpy as np
import gc
import pprint
import traceback
from scapy.all import *
#from multiprocessing.pool import ThreadPool
import time
from multiprocessing import Pool, Lock, Queue, JoinableQueue, Value
pq = Queue()
sq= Queue()
q=JoinableQueue()

def initialize(file):
    global count
    global super_stream
    global stats
    count += 1
    scap  = rdpcap(file)
    pkt = scap[0]
    last_time = pkt.time
    last_seq = pkt.seq
    last_ack = pkt.ack
    stats['frag']= [pkt['IP'].frag, pkt['IP'].frag]
    stats['ttl']= [pkt['IP'].ttl,pkt['IP'].ttl]
    stats['header_len'] = [pkt['IP'].ihl,pkt['IP'].ihl]
    stats['datagram_size'] =  [pkt['IP'].len,pkt['IP'].len]
    stats['dataofs'] = [pkt['TCP'].dataofs,pkt['TCP'].dataofs]
    stats['window_size'] = [pkt['TCP'].window,pkt['TCP'].window]
    stats['flags'][pkt['IP'].flags] = 1
    #[time_delta, fragmentation_offset, ttl, header_length, datagram_length, data_offset, window_length, sequence_delta, ack_delta]
    super_stream = np.array([0,pkt['IP'].frag, pkt['IP'].ttl, pkt['IP'].ihl, pkt['IP'].len,pkt['TCP'].dataofs, pkt['TCP'].window,0,0])
    print('initial array shape ' + str(super_stream.shape))
    scap.remove(scap[0])
    for packet in range(0,len(scap)):
        count += 1
        pkt = scap[packet]
        flag = pkt['TCP'].flags
        print(str(pkt['TCP'].seq), str(pkt['TCP'].ack))
        if pkt['IP'].frag < stats['frag'][0]:
            stats['frag'][0] = pkt['IP'].frag
        if pkt['IP'].frag > stats['frag'][1]:
            stats['frag'][1] = pkt['IP'].frag
        if pkt['IP'].ttl < stats['ttl'][0]:
            stats['ttl'][0] = pkt['IP'].ttl
        if pkt['IP'].ttl > stats['ttl'][1]:
            stats['ttl'][1] = pkt['IP'].ttl
        if pkt['IP'].ihl < stats['header_len'][0]:
            stats['header_len'][0] = pkt['IP'].ihl
        if pkt['IP'].ihl > stats['header_len'][1]:
            stat['header_len'][1] = pkt['IP'].ihl
        if pkt['IP'].len < stats['datagram_size'][0]:
            stats['datagram_size'][0] = pkt['IP'].len
        if pkt['IP'].len > stats['datagram_size'][1]:
            stats['datagram_size'][1] = pkt['IP'].len
        if pkt['TCP'].dataofs < stats['dataofs'][0]:
            stats['datagram_size'][0] = pkt['TCP'].dataofs
        if pkt['TCP'].dataofs > stats['dataofs'][1]:
            stats['datagram_size'][1] = pkt['TCP'].dataofs
        if pkt['TCP'].window < stats['window_size'][0]:
            stats['window_size'][0] = pkt['TCP'].window
        if pkt['TCP'].window > stats['window_size'][1]:
            stats['window_size'][1] = pkt['TCP'].window
        try:
            stats['flags'][flag][0] += 1
        except:
            stats['flags'][flag] = [1]
        if packet == 0:
            super_stream = np.vstack([super_stream,np.array([pkt.time-last_time,pkt['IP'].frag, pkt['IP'].ttl, pkt['IP'].ihl, pkt['IP'].len, pkt['TCP'].dataofs, pkt['TCP'].window,pkt['TCP'].seq-last_seq,pkt['TCP'].ack-last_ack])])
        else:
            lst_pkt = scap[packet-1]
            if pkt.time - lst_pkt.time < stats['time_delta'][0]:
                stats['time_delta'][0] = pkt.time-lst_pkt.time
            if pkt.time - lst_pkt.time > stats['time_delta'][1]:
                stats['time_delta'][1]=pkt.time-lst_pkt.time
            if pkt['TCP'].seq-lst_pkt['TCP'].seq < stats['seq_delta'][0]:
                stats['seq_delta'][0] = pkt['TCP'].seq-lst_pkt['TCP'].seq
            if pkt['TCP'].seq-lst_pkt['TCP'].seq > stats['seq_delta'][1]:
                stats['seq_delta'][1] = pkt['TCP'].seq-lst_pkt['TCP'].seq
            if pkt['TCP'].ack-lst_pkt['TCP'].ack < stats['ack_delta'][0]:
                stats['seq_delta'][0] = pkt['TCP'].ack-lst_pkt['TCP'].ack
            if pkt['TCP'].ack-lst_pkt['TCP'].ack > stats['seq_delta'][1]:
                stats['ack_delta'][1] = pkt['TCP'].ack-lst_pkt['TCP'].ack
            super_stream = np.vstack([super_stream,np.array([pkt.time - lst_pkt.time,pkt['IP'].frag, pkt['IP'].ttl, pkt['IP'].ihl, pkt['IP'].len, pkt['TCP'].dataofs, pkt['TCP'].window,pkt['TCP'].seq - lst_pkt['TCP'].seq,pkt['TCP'].ack - lst_pkt['TCP'].ack])])
        
        
    del pkt
    del lst_pkt
    del scap
    gc.collect()
    
    super_stream = super_stream.sum(0)
    print(super_stream)

def read(file,q=q):
    scap = rdpcap(file)
    q.put_nowait(scap)

def describe(scap,sq=sq):
    stats = sq.get(True)
    for packet in range(0,len(scap)):
        with process_counter.get_lock():
            process_counter.value+=1
        pkt = scap[packet]
        flag = pkt['TCP'].flags
        if pkt['IP'].frag < stats['frag'][0]:
            stats['frag'][0] = pkt['IP'].frag
        if pkt['IP'].frag > stats['frag'][1]:
            stats['frag'][1] = pkt['IP'].frag
        if pkt['IP'].ttl < stats['ttl'][0]:
            stats['ttl'][0] = pkt['IP'].ttl
        if pkt['IP'].ttl > stats['ttl'][1]:
            stats['ttl'][1] = pkt['IP'].ttl
        if pkt['IP'].ihl < stats['header_len'][0]:
            stats['header_len'][0] = pkt['IP'].ihl
        if pkt['IP'].ihl > stats['header_len'][1]:
            stat['header_len'][1] = pkt['IP'].ihl
        if pkt['IP'].len < stats['datagram_size'][0]:
            stats['datagram_size'][0] = pkt['IP'].len
        if pkt['IP'].len > stats['datagram_size'][1]:
            stats['datagram_size'][1] = pkt['IP'].len
        if pkt['TCP'].dataofs < stats['dataofs'][0]:
            stats['datagram_size'][0] = pkt['TCP'].dataofs
        if pkt['TCP'].dataofs > stats['dataofs'][1]:
            stats['datagram_size'][1] = pkt['TCP'].dataofs
        if pkt['TCP'].window < stats['window_size'][0]:
            stats['window_size'][0] = pkt['TCP'].window
        if pkt['TCP'].window < stats['window_size'][0]:
            stats['window_size'][0] = pkt['TCP'].window
        try:
            stats['flags'][flag][0] += 1
        except:
            stats['flags'][flag] = [1]
        if packet == 0:
            
            stream = np.array([0,pkt['IP'].frag, pkt['IP'].ttl, pkt['IP'].ihl, pkt['IP'].len, pkt['TCP'].dataofs, pkt['TCP'].window,0,0])
            
        else:
            lst_pkt = scap[packet-1]
            if pkt.time - lst_pkt.time < stats['time_delta'][0]:
                stats['time_delta'][0] = pkt.time-lst_pkt.time
            if pkt.time - lst_pkt.time > stats['time_delta'][1]:
                stats['time_delta'][1]=pkt.time-lst_pkt.time
            if pkt['TCP'].seq-lst_pkt['TCP'].seq < stats['seq_delta'][0]:
                stats['seq_delta'][0] = pkt['TCP'].seq-lst_pkt['TCP'].seq
            if pkt['TCP'].seq-lst_pkt['TCP'].seq > stats['seq_delta'][1]:
                stats['seq_delta'][1] = pkt['TCP'].seq-lst_pkt['TCP'].seq
            if pkt['TCP'].ack-lst_pkt['TCP'].ack < stats['ack_delta'][0]:
                stats['seq_delta'][0] = pkt['TCP'].ack-lst_pkt['TCP'].ack
            if pkt['TCP'].ack-lst_pkt['TCP'].ack > stats['seq_delta'][1]:
                stats['ack_delta'][1] = pkt['TCP'].ack-lst_pkt['TCP'].ack
            stream = np.vstack([stream,np.array([pkt.time - lst_pkt.time,pkt['IP'].frag, pkt['IP'].ttl, pkt['IP'].ihl, pkt['IP'].len, pkt['TCP'].dataofs, pkt['TCP'].window,pkt['TCP'].seq - lst_pkt['TCP'].seq,pkt['TCP'].ack - lst_pkt['TCP'].ack])])
        
#     if np.size(stream,0) >= 2:
#         stream=stream.sum(0)
#     super_stream=np.vstack([super_stream,stream])
    
    sq.put(stats)

    
    del scap
    del pkt
    gc.collect()

    try:
        concat_add(stream)
    except Exception as e: 
        traceback.print_exc()
        raise e
        print()

def consume(q=q):
	while True:
		while not q:
			print('waiting')
			pass

		try:
			scap = q.get()
			describe(scap)
			q.task_done()
		except Exception as e: 
			traceback.print_exc()
			raise e
			print()

def concat_add(stream,pq=pq):
    strm = pq.get(True)
    pprint.pprint(strm)
    strm = np.vstack([strm,stream])
    strm =  strm.sum(0)
    pq.put_nowait(strm)


def calculate_mean():
    global stats
    global count
    global super_stream
    means = np.divide(super_stream,count)
    keys = list(stats)
    keys.pop()
    for index in range(0,len(keys)):
        key = keys[index]
        print(stats[key])
        stats[key].append(means[index])
    for flag in stats['flags']:
        stats['flags'][flag].append(stats['flags'][flag][0]/count)

        

if __name__ == '__main__':
    start = time.perf_counter()
    stats = {'time_delta':[0,0], #[min,max,mean,normalized_mean]
         'frag':[],       
         'ttl':[],
         'header_len':[],
         'datagram_size':[],
         'dataofs':[],
         'window_size':[],
         'seq_delta':[0,0],
         'ack_delta':[0,0],
         'flags':{}
        } #flags[count,mean,normalized_mean]
    
    count = 0
    
    super_stream = np.zeros([1,9])
#     files = os.listdir(sys.argv[1])
    files = os.listdir('dev')
    for x in range(0,len(files)):
        files[x] = 'dev/' + files[x]
    initialize(files[0])
    pprint.pprint(stats)
    
    
    files.remove(files[0])
    pq.put(super_stream)
    sq.put(stats)
    process_counter = Value('i',count)
#     for file in files:
#         describe(file)
    with Pool(processes=2) as producers:
        producers.map(read,files)
    with Pool(processes=2) as consumers:
        proc1 = consumers.apply(consume)
        proc2 = consumers.apply(consume)
#     q.join()
    producers.close()
    consumers.close()
    producers.join()
    consumers.join()
    print(str(q.qsize()))
#     super_stream = pq.get(True)
#     stats=sq.get(True)
#     pprint.pprint(stats)
#     count = process_counter.value
#     super_stream = super_stream.sum(0)
#     print("final result...")
#     pprint.pprint(super_stream)
#     calculate_mean()
#     pprint.pprint(stats)
#     end = time.perf_counter()
#     print('run time... ' + str(end-start))