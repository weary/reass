
for fn in ['i1','i2','i3','r1','r2','r3']:
	f = open(fn+".txt", "w")
	for n in xrange(0,26):
		print >>f, "[%02d %s %s]" % (n, fn, chr(ord('a') + n) * 60)
