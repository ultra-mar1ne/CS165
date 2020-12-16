src code:
	Server.c
	Client.c
	Proxy.c
Application：
	server
	client
	proxy
	The files needed to run the program：CA root certificate, Public and private key，Libtls，blacklist.txt file
Steps：
1. Create serverfile, clientfile, proxyfile folder under build/src.
	a. create P1,P2,P3,P4,P5,P6 folder in under proxyfile folder.


2. Create blacklist.txt file under build/src to store the blacklist. 
	a. Each line in the blacklist.txt represents a file which is in the blacklist. 

Hint: you can run setupfolder.sh under build/src/ to setup all folder and file. 

3. Copy all files in TCPSocket_iii-master/extern/libressl_install/lib to /usr/lib

4. Run the following commands to start server, proxy and client
	a.   ./server –p 1234
	b.   ./proxy –p 1212 localhost:1234
	c.   ./client –p 1212 [filename]


Result：
1. The client selects the cache of the proxy based on the hash and sends the file request.
2. The proxy receives the request from client and queires Bloom filter in the corresponding Cache. Determines if the file is on a blacklist. If so, proxy rejects the file. If not on the blacklist, proxy check in the cache for the existence of the file. Proxy returns the file if it exists, or requests it from the server if it does not.
3. The Server receives the proxy request. Server detects the existence of the file. If the file exists, it returns the file directly. If not, server tells the proxy that the file does not exist.
4. The proxy receives the return value from server and determine what kind of reture value it is. If it is a file, fetch it into Cache and return it to client. 
5. Client receives the file and close the connect. 

TLS connection is used throughout file communication, more detiles and result in contribution_report.pdf
