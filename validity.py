import pyshark

a=pyshark.FileCapture('test_capture.pcap',display_filter='ip.src == 192.168.0.0/16 and ip.dst != 192.168.0.0/16 and tcp',override_prefs={'tcp.relative_sequence_numbers':False},disable_protocol='UDP',keep_packets=True)

max_number = int(a[0].tcp.stream)

for pkt in a:
	if int(pkt.tcp.stream) > max_number:
		max_number = int(pkt.tcp.stream)

prevseq = {'seq':0}
stream = []

for pkt in a:
	if pkt.tcp.stream not in stream:
		print("new stream	",pkt.tcp.stream)
		stream.append(pkt.tcp.stream)
	elif prevseq['seq'] > int(pkt.tcp.seq) and prevseq['strm'] == pkt.tcp.stream:
		print("packets out of order " + prevseq[0] + " " + pkt.tcp.seq)
	else:
		print(pkt.tcp.seq)
	prevseq['seq']=int(pkt.tcp.seq)
	prevseq['strm']=pkt.tcp.stream