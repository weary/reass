import socket, thread, time

def threadfunc(f):
	print "in func for %s" % f
	d = open(f).read()
	a = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
	a.connect(('2002:5375:b0f1:0:248:54ff:fe66:21c1',9999))
	a.send(d)
	a.recv(1794)
	print "got the stuff"
	a.close()

i1 = thread.start_new_thread(threadfunc, ("i1.txt",))
i2 = thread.start_new_thread(threadfunc, ("i2.txt",))
i3 = thread.start_new_thread(threadfunc, ("i3.txt",))

time.sleep(5)
