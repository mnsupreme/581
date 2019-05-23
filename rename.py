import os
import sys


directory =  sys.argv[1]
os.chdir(directory)

for file in os.listdir():
	new_file = file.split('.')
	new_file.pop()
	new_file = '_'.join(new_file) + '.pcap'
	os.popen('mv ' + file + ' ' + new_file)
