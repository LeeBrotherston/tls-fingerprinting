#!/usr/bin/env python2

import time, os, json, sys

inputfile = sys.argv[1]
print "Tailing: "+inputfile
# Set the filename and open the file
filename = inputfile
file = open(filename,'r')

#Find the size of the file and move to the end
st_results = os.stat(filename)
st_size = st_results[6]
file.seek(st_size)

while 1:
    where = file.tell()
    line = file.readline()
    if not line:
        time.sleep(1)
        file.seek(where)
    else:
		jline = json.loads(line)

		# Actually outputting things here....
		if(jline["event"] == 'fingerprint_match'):
			print jline["timestamp"]+" \""+jline["fingerprint_desc"]+"\" "+jline["tls_version"]+" connection to \""\
			+jline["server_name"]+"\" "+jline["ipv4_src"]+":"+str(jline["src_port"])+" -> "+jline["ipv4_dst"]+":"\
			+str(jline["dst_port"])+" "



#print '\033[1;30mGray like Ghost\033[1;m'
#print '\033[1;31mRed like Radish\033[1;m'
#print '\033[1;32mGreen like Grass\033[1;m'
#print '\033[1;33mYellow like Yolk\033[1;m'
#print '\033[1;34mBlue like Blood\033[1;m'
#print '\033[1;35mMagenta like Mimosa\033[1;m'
#print '\033[1;36mCyan like Caribbean\033[1;m'
#print '\033[1;37mWhite like Whipped Cream\033[1;m'
#print '\033[1;38mCrimson like Chianti\033[1;m'
#print '\033[1;41mHighlighted Red like Radish\033[1;m'
#print '\033[1;42mHighlighted Green like Grass\033[1;m'
#print '\033[1;43mHighlighted Brown like Bear\033[1;m'
#print '\033[1;44mHighlighted Blue like Blood\033[1;m'
#print '\033[1;45mHighlighted Magenta like Mimosa\033[1;m'
#print '\033[1;46mHighlighted Cyan like Caribbean\033[1;m'
#print '\033[1;47mHighlighted Gray like Ghost\033[1;m'
#print '\033[1;48mHighlighted Crimson like Chianti\033[1;m'
