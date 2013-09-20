
#include <sys/time.h>

inline
double as_double(const struct timeval &tv)
{
	return \
		static_cast<double>(tv.tv_sec) + \
		static_cast<double>(tv.tv_usec) * 0.000001;
}

struct gettime : public timeval
{
	gettime() { ::gettimeofday(this, NULL); }
	operator double() const { return as_double(*this); }
};

inline
bool operator ==(const timeval &l, const timeval &r)
{
	return l.tv_sec == r.tv_sec && l.tv_usec == r.tv_usec;
}

inline
timeval operator +(const timeval &l, const timeval &r)
{
	timeval out = l;
	out.tv_sec += r.tv_sec;
	out.tv_usec += r.tv_usec;
	if (out.tv_usec > 1000000)
	{
		out.tv_sec += 1;
		out.tv_usec -= 1000000;
	}
	return out;
}


inline
timeval operator -(const timeval &l, const timeval &r)
{
	timeval out = l;
	out.tv_sec -= r.tv_sec;
	while (r.tv_usec > out.tv_usec)
	{
		out.tv_sec--;
		out.tv_usec += 1000000;
	}
	out.tv_usec -= r.tv_usec;
	return out;
}

inline
std::string to_str(const timeval&t_)
{
	char buf[32];
	snprintf(buf, 32, "%d.%06u", (int)t_.tv_sec, (int)t_.tv_usec);
	buf[31] = 0;
	return buf;
}
