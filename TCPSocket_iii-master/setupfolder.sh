#!/bin/sh
mkdir -p clientfile
mkdir -p proxyfile
mkdir -p serverfile
touch blacklist.txt
echo '1.txt'>>blacklist.txt
cd proxyfile/
for  i in `seq 1 6`
do
	mkdir -p P${i}
done
cd ..
cd serverfile
touch 1.txt
touch 2.txt
