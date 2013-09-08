#include "misc.h"
#include <boost/scoped_array.hpp>
#include <stdarg.h>
#include <stdexcept>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>


std::string sformat(const char *fmt, ...)
{
	va_list ap;
	char buf[256];

	va_start(ap, fmt);
	int n = vsnprintf(buf, 256, fmt, ap);
	va_end(ap);

	if (n < 256)
		return std::string(buf, buf+n);
	else {
		boost::scoped_array<char> dbuf(new char[n+1]);
		va_start(ap, fmt);
#ifndef NDEBUG
		int n2 = 
#endif
			vsnprintf(dbuf.get(), n+1, fmt, ap);
		va_end(ap);
		assert(n == n2);

		return std::string(dbuf.get(), dbuf.get()+n);
	}
}

std::string only_printable(const std::string &src_)
{
	std::string::size_type s = src_.size();
	boost::scoped_array<char> buf(new char[s]);
	for (std::string::size_type i=0; i<s; ++i) {
		char c = src_[i];
		buf[i] = (c>=0 && c<' ' ? '.' : c);
	}
	return std::string(buf.get(), buf.get() + s);
}

format_exception_t::format_exception_t(const char *fmt, ...) throw()
{
	va_list ap;
	char buf[256];

	va_start(ap, fmt);
	int n = vsnprintf(buf, 256, fmt, ap);
	va_end(ap);

	if (n < 256)
		d_what.assign(buf, buf+n);
	else {
		boost::scoped_array<char> dbuf(new char[n+1]);
		va_start(ap, fmt);
#ifndef NDEBUG
		int n2 = 
#endif
			vsnprintf(dbuf.get(), n+1, fmt, ap);
		va_end(ap);
		assert(n == n2);

		d_what.assign(dbuf.get(), dbuf.get()+n);
	}
}

std::string stringerror(int e)
{
	return strerror(e);
}

void unix_die(const std::string &during)
{
	int e = errno;
	throw format_exception_t("exception during %s, %s", during.c_str(), stringerror(e).c_str());
}

int open_file(const std::string &name_, int flags)
{
	int h = ::open(name_.c_str(), flags);
	if (h<0)
		unix_die("opening file '"+name_+"'");
	return h;
}
void close_file(int h_)
{
	int e = ::close(h_);
	if (e != 0) unix_die("close");
}

void writen(int handle, const void *buf, size_t size)
{
	while (size) {
		ssize_t r = ::write(handle, buf, size);
		if (r<0) unix_die("writen");
		buf = reinterpret_cast<const char *>(buf) + r;
		size -= r;
	}
}

void readn(int handle, void *buf, size_t size)
{
	while (size) {
		ssize_t r = ::read(handle, buf, size);
		if (r<0)
		 	unix_die("readn");
		else if (r==0)
		 	throw std::runtime_error("eof");
		buf = reinterpret_cast<char *>(buf) + r;
		size -= r;
	}
}

std::string make_hexdump(const char *buf_, int size)
{
	std::string result;
	result.reserve(size*3);
	char buf[3];
	for (int n=0; n<size; ++n)
	{
		if (n) result += ' ';
		snprintf(buf, 3, "%02x", (int)buf_[n]);
		result.append(buf, 2);
	}
	return result;
}

off_t filesize(int handle)
{
	struct stat st;
	int r = fstat(handle, &st);
	if (r != 0)
		unix_die("stat");
	return st.st_size;
}
