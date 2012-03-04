import SocketServer, socket, re

#tosend = []
#for f in [ 'r1.txt', 'r2.txt', 'r3.txt']:
	#tosend.append(open(f).read())

class MyTCPHandler(SocketServer.BaseRequestHandler):
	#global tosend

	def handle(self):
		#d = tosend.pop()
		# self.request is the TCP socket connected to the client
		data = self.request.recv(1794).strip()
		resp = re.sub(' i([0-9]) ', ' r\\1 ', data)+'\x0a' # response is same as request with all ' i1 ' replaced with ' r1 ' and a '\x0a' appended
		self.request.send(resp)


class V6Server(SocketServer.TCPServer):
	address_family = socket.AF_INET6

if __name__ == "__main__":
	HOST, PORT = "", 9999
	server = V6Server((HOST, PORT), MyTCPHandler)
	print "running"
	server.serve_forever()
