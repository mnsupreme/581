#!/usr/bin/env python
# coding: utf-8

# In[1]:


import numpy as np
import gc
import pprint
import traceback
from scapy.all import *
import time
from multiprocessing import JoinableQueue, Queue, Process
pq = Queue()
sq= Queue()
q= Queue() 
buff=Queue()
adder_res=Queue()
agg_res=Queue()
reader_res=Queue()
super_stream = np.zeros([1,9])


# In[2]:


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
    #[time_delta,fragmentation_offset, ttl, header_length, datagram_length, data_offset, window_length, sequence_delta, ack_delta]
    super_stream = np.array([0,pkt['IP'].frag, pkt['IP'].ttl, pkt['IP'].ihl, pkt['IP'].len,pkt['TCP'].dataofs, pkt['TCP'].window,0,0])
    print('initial array shape ' + str(super_stream.shape))
    scap.remove(scap[0])
    count += int(len(scap))
    for packet in range(0,len(scap)):
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
                stats['ack_delta'][0] = pkt['TCP'].ack-lst_pkt['TCP'].ack
            if pkt['TCP'].ack-lst_pkt['TCP'].ack > stats['ack_delta'][1]:
                stats['ack_delta'][1] = pkt['TCP'].ack-lst_pkt['TCP'].ack
            super_stream = np.vstack([super_stream,np.array([pkt.time - lst_pkt.time,pkt['IP'].frag, pkt['IP'].ttl, pkt['IP'].ihl, pkt['IP'].len, pkt['TCP'].dataofs, pkt['TCP'].window,pkt['TCP'].seq - lst_pkt['TCP'].seq,pkt['TCP'].ack - lst_pkt['TCP'].ack])])
        
        
    del pkt
    del lst_pkt
    del scap
    gc.collect()
    
    super_stream = super_stream.sum(0)
    print(super_stream)
    


# In[3]:


def describe(scap): 
    stats = sq.get(True)

    for packet in range(0,len(scap)):

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
        if pkt['TCP'].window > stats['window_size'][1]:
            stats['window_size'][1] = pkt['TCP'].window
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
                stats['ack_delta'][0] = pkt['TCP'].ack-lst_pkt['TCP'].ack
            if pkt['TCP'].ack-lst_pkt['TCP'].ack > stats['ack_delta'][1]:
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
    
#     return count
  


# In[4]:


def describe_reg(file): 
    global count
    global stats
    scap = rdpcap(file)
    count+=len(scap)
    for packet in range(0,len(scap)):
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
        if pkt['TCP'].window > stats['window_size'][1]:
            stats['window_size'][1] = pkt['TCP'].window
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
                stats['ack_delta'][0] = pkt['TCP'].ack-lst_pkt['TCP'].ack
            if pkt['TCP'].ack-lst_pkt['TCP'].ack > stats['ack_delta'][1]:
                stats['ack_delta'][1] = pkt['TCP'].ack-lst_pkt['TCP'].ack
            stream = np.vstack([stream,np.array([pkt.time - lst_pkt.time,pkt['IP'].frag, pkt['IP'].ttl, pkt['IP'].ihl, pkt['IP'].len, pkt['TCP'].dataofs, pkt['TCP'].window,pkt['TCP'].seq - lst_pkt['TCP'].seq,pkt['TCP'].ack - lst_pkt['TCP'].ack])])
        
#     if np.size(stream,0) >= 2:
#         stream=stream.sum(0)
#     super_stream=np.vstack([super_stream,stream])
    
    try:
        concat_add_reg(stream)
    except Exception as e: 
        traceback.print_exc()
        raise e
        print()

    
    del scap
    del pkt
    gc.collect()


# In[5]:


# more memory efficient 

def concat_add(stream):
    strm = pq.get(True)
#     pprint.pprint(strm)
    strm = np.vstack([strm,stream])
    strm =  strm.sum(0)
    pq.put_nowait(strm)


# In[6]:


def concat_add_reg(stream):
    global super_stream
    super_stream = np.vstack([super_stream,stream])
    super_stream =  super_stream.sum(0)


# In[7]:


def read():
    for file in iter(q.get,None):
#         print(file)
        scap =  rdpcap(file)
        pq.put_nowait(scap)
        sq.put_nowait(scap)
#         print(scap[0].time)
        reader_res.put_nowait(len(scap))
#         del scap
        gc.collect()
    q.put(None)
        


# In[8]:


def adder(stream):
    for scap in iter(sq.get,None):
        for packet in range(0,len(scap)):
            pkt = scap[packet]
            if packet == 0:
                stream = np.vstack([stream,np.array([0,pkt['IP'].frag, pkt['IP'].ttl, pkt['IP'].ihl, pkt['IP'].len, pkt['TCP'].dataofs, pkt['TCP'].window,0,0])])
            else:
                lst_pkt=scap[packet-1]
                stream = np.vstack([stream,np.array([pkt.time-lst_pkt.time,pkt['IP'].frag, pkt['IP'].ttl, pkt['IP'].ihl, pkt['IP'].len, pkt['TCP'].dataofs, pkt['TCP'].window,pkt['TCP'].seq - lst_pkt['TCP'].seq,pkt['TCP'].ack - lst_pkt['TCP'].ack])])
        stream = stream.sum(0)
        del scap
        del pkt
        del lst_pkt
        gc.collect()
    adder_res.put_nowait(stream)


# In[9]:


def comparer(stats):
    stats['flags']={}
    for scap in iter(pq.get,None):
        for packet in range(0,len(scap)):

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
            if pkt['TCP'].window > stats['window_size'][1]:
                stats['window_size'][1] = pkt['TCP'].window
            try:
                stats['flags'][flag][0] += 1
            except:
                stats['flags'][flag] = [1]
            
            if packet != 0:
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
                    stats['ack_delta'][0] = pkt['TCP'].ack-lst_pkt['TCP'].ack
                if pkt['TCP'].ack-lst_pkt['TCP'].ack > stats['ack_delta'][1]:
                    stats['ack_delta'][1] = pkt['TCP'].ack-lst_pkt['TCP'].ack
        
        del scap
        gc.collect()
    pq.put(None)
    buff.put_nowait(stats)
    


# In[10]:


def stat_to_arr(obj):
    keys = list(obj)
    keys.pop()
    mins=[]
    maxes=[]
    for key in keys:
        mins.append(obj[key][0])
        maxes.append(obj[key][1])
    return [np.array(mins),np.array(maxes)]


# In[11]:


def aggregator(stats):
    flags=stats['flags']
    mins,maxes=stat_to_arr(stats)
    for local in iter(buff.get,None):
        lmins,lmaxes = stat_to_arr(local)
        mins=np.vstack([mins,lmins])
        maxes=np.vstack([maxes,lmaxes])
        maxes=maxes.max(axis=0)
        mins=mins.min(axis=0)
        fl = local['flags']
        for flag in fl:
            try:
                flags[flag][0]+=fl[flag][0]
            except:
                flags[flag]=fl[flag]
            
    keys = list(stats)
    keys.pop()
    for index in range(0,len(keys)):
        key=keys[index]
        stats[key][0]=mins[index]
        stats[key][1]=maxes[index]
    stats['flags']=flags
    agg_res.put_nowait(stats)
    


# In[12]:


def calculate_mean():
    global stats
    global count
    global super_stream
    means = np.divide(super_stream,count)
    keys = list(stats)
    keys.pop()
    for index in range(0,len(keys)):
        key = keys[index]
        stats[key].append(means[index])
    for flag in stats['flags']:
        stats['flags'][flag].append(stats['flags'][flag][0]/count)
        


# In[13]:


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
#     files = os.listdir(sys.argv[1])
    files = os.listdir('dev')
    for x in range(0,len(files)):
        files[x] = 'dev/' + files[x]
    initialize(files[0])
    pprint.pprint(stats)
    files.remove(files[0])
    for file in files:
        q.put(file)
    q.put(None)
    
    reader1=Process(target=read)
    reader1.start()
    
    
    add_process=Process(target=adder, args=(super_stream,))
    add_process.start()
    compare1=Process(target=comparer, args=(stats,))
    compare2=Process(target=comparer, args=(stats,))
    compare1.start()
    compare2.start()
    agg=Process(target=aggregator, args=(stats,))
    agg.start()
    
    
    reader1.join()
    reader1.close()
    print('reading complete')

    
    print('sq put none')
    sq.put(None)
    print('pq put none')
    pq.put(None)
    add_process.join()
    add_process.close()
    print('adding complete')
    compare1.join()
    compare2.join()
    compare1.close()
    compare2.close()
    print('scalable comparing complete')
    print(pq.qsize())
    
    print('buff put none')
    buff.put(None)

    agg.join()
    agg.close()
    print('comparing complete')
    
    count_arr=[]
    while reader_res.qsize() != 0:
        count_arr.append(reader_res.get_nowait())
    count =  count + np.sum(np.array(count_arr))
    stats=agg_res.get_nowait()
    super_stream=adder_res.get_nowait()
    
        


    
    
#     for file in files:
#         describe_reg(file)
    
    
    
    
    

    print(count)
    print("final result...")
    pprint.pprint(super_stream)
    calculate_mean()
    pprint.pprint(stats)
    end = time.perf_counter()
    print('run time... ' + str(end-start))


# In[14]:


# array([-6.73444361e+06,  0.00000000e+00,  5.97376000e+05,  2.33350000e+04,
#         3.35720000e+05,  2.92170000e+04,  1.31505852e+08,  5.29164557e+11,
#         6.73957074e+11])

# {'ack_delta': [-4279434806, 4294315522, 144409058.11356333],
#  'datagram_size': [5, 1064, 71.93486179558603],
#  'dataofs': [7, 7, 6.260338547246625],
#  'flags': {<Flag 2 (DF)>: [2940, 0.6299550032140562],
#            <Flag 4 (R)>: [1, 0.00021427040925648167],
#            <Flag 16 (A)>: [1122, 0.24041139918577245],
#            <Flag 17 (FA)>: [382, 0.081851296335976],
#            <Flag 20 (RA)>: [50, 0.010713520462824084],
#            <Flag 24 (PA)>: [171, 0.03664023998285837]},
#  'frag': [0, 0, 0.0],
#  'header_len': [5, 5, 5.0],
#  'seq_delta': [0, 4055567438, 113384306.26976645],
#  'time_delta': [-2139911.731453, 2057643.5035180002, -1442.9919886076661],
#  'ttl': [128, 128, 128.0],
#  'window_size': [0, 64240, 28177.81272766231]}

# 1106632.891896
# 1104029.332798
# 210917.779953
# 145601.002458
# 1871501.177152


# In[ ]:





# In[ ]:




