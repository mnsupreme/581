import sys
import os
import random
from multiprocessing.pool import ThreadPool




def sample()
	global files
	x = random.randint(0,len(files))
	os.popen('cp ' + files[x] + ' ' + test + '/' + files[x])
	file.remove(files[x])



if __name__ == '__main__':
	directory = sys.argv[1]
	test = sys.argv[2]
	n = sys.argv[3]
	files = os.listdir(directory)
	if not os.path.isdir(test):
		os.mkdirs(test)
	for i in range(0,n):
		sample()
