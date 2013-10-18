#ifndef __SHARED_MISC_H__
#define __SHARED_MISC_H__

#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <string>
#include <boost/lexical_cast.hpp>
#include <boost/static_assert.hpp>

#ifndef BOOST_STATIC_ASSERT_MSG
#  define BOOST_STATIC_ASSERT_MSG(a, m) BOOST_STATIC_ASSERT(a)
#endif


namespace {
template<typename T, typename S>
struct convert_t {
	convert_t(const S&item_) : d_item(item_) {}
	T get() const { return boost::lexical_cast<T,S>(d_item); }
protected:
	const S&d_item;
};

template<typename S>
struct convert_t<S,S> {
	convert_t(const S&item_) : d_item(item_) {}
	S get() const { return d_item; }
protected:
	const S&d_item;
};
}

template<typename T, typename S>
T convert(const S&item_) { return convert_t<T,S>(item_).get(); }

template<typename T>
std::string to_str(const T&t_) { return convert<std::string,T>(t_); }



template<typename T=uint8_t>
struct range_t // part of a buffer
{
	typedef T value_type;
	typedef unsigned size_type;
	range_t() : d_begin(NULL), d_end(NULL) {}
	range_t(const range_t<T> &rhs_) : d_begin(rhs_.d_begin), d_end(rhs_.d_end) {}
	range_t(T *begin_, T *end_) : d_begin(begin_), d_end(end_) {}
	~range_t() {}

	T* begin() { return d_begin; }
	T* end() { return d_end; }
	const T* begin() const { return d_begin; }
	const T* end() const { return d_end; }
	size_type size() const { return d_end - d_begin; }
	bool empty() const { return d_end == d_begin; }
	std::string as_str() const { return std::string(d_begin, d_end); }

	template<typename Q> Q& cast(unsigned offset_=0)
 	{ assert(sizeof(Q)<size()); return *reinterpret_cast<Q *>(d_begin+offset_); }
protected:
	T *d_begin;
	T *d_end;
};

template<typename T=uint8_t>
struct const_range_t // part of a buffer
{
	typedef T value_type;
	typedef unsigned size_type;
	const_range_t() : d_begin(NULL), d_end(NULL) {}
	const_range_t(const range_t<T> &rhs_) : d_begin(rhs_.d_begin), d_end(rhs_.d_end) {}
	const_range_t(const const_range_t<T> &rhs_) : d_begin(rhs_.d_begin), d_end(rhs_.d_end) {}
	const_range_t(const T *begin_, const T *end_) : d_begin(begin_), d_end(end_) {}
	~const_range_t() {}

	const T* begin() const { return d_begin; }
	const T* end() const { return d_end; }
	size_type size() const { return d_end - d_begin; }
	bool empty() const { return d_end == d_begin; }

	template<typename Q> const T& cast(unsigned offset_=0)
 	{ assert(sizeof(Q)<size()); return *reinterpret_cast<Q *>(d_begin+offset_); }
protected:
	const T *d_begin;
	const T *d_end;
};


std::string sformat(const char *fmt, ...);

std::string only_printable(const std::string &src_);

struct format_exception_t : public std::exception
{
	format_exception_t(const char *fmt, ...) throw();
	virtual ~format_exception_t() throw() {}

	virtual const char* what() const throw() { return d_what.c_str(); }

protected:
	std::string d_what;
};
typedef format_exception_t format_exception;

std::string stringerror(int e);
void unix_die(const std::string &during);

int open_file(const std::string &name_, int flags);
void close_file(int h_);

void writen(int handle, const void *buf, size_t size);
template<typename T> inline void writen(int handle, const T&t_) { writen(handle, &t_, sizeof(T)); }

void readn(int handle, void *buf, size_t size);
template<typename T> inline void readn(int handle, T&t_) { readn(handle, &t_, sizeof(T)); }
template<typename T> inline T readn(int handle) { T t; readn(handle, &t, sizeof(T)); return t; }
inline std::string readstring(int handle, size_t size)
{
	char *buf = new char[size];
	try {
		readn(handle, buf, size);
	}
 	catch(...) {
		delete[] buf;
		throw;
	}
	std::string r(buf, size);
	delete[] buf;
	return r;
}

template<typename LIST>
std::string join(const LIST &l_, const std::string &sep_)
{
	if (l_.empty()) return std::string();
	typename LIST::const_iterator i = l_.begin();
	std::string r = to_str(*i);
	++i;
	for (; i!=l_.end(); ++i)
		r += sep_ + to_str(*i);
	return r;
}

std::string make_hexdump(const char *buf_, int size);
inline std::string make_hexdump(const std::string &s_) { return make_hexdump(s_.data(), s_.size()); }


off_t filesize(int handle);

#endif // __SHARED_MISC_H__
