/*
 * Copyright 2011 Hylke Vellinga
 */


#ifndef __REASS_FREELIST_H__
#define __REASS_FREELIST_H__

#include <boost/noncopyable.hpp>

template<typename T>
struct free_list_member_t : public boost::noncopyable
{
	free_list_member_t(T *&free_head) :
	 	d_free_head(free_head) // d_free_next does not need to be initialised
 	{}

	~free_list_member_t()
	{
		if (d_free_next)
		{
			delete d_free_next;
			d_free_next = NULL;
		}
	}

	void release()
	{
		d_free_next = d_free_head;
		d_free_head = static_cast<T *>(this);
	}

private:

	void claim()
	{
		if (d_free_head == this) // race condition if items got deleted and we are in-place -> never delete
		{ // we are in the free list, remove ourselves
			d_free_head = d_free_next;
			d_free_next = NULL;
		}
	}

	template<typename Q>
	friend struct free_list_container_t;

	T *&d_free_head;
	T *d_free_next; // NULL if we are the last in the chain, undefined if not free
};

template<typename T>
struct free_list_container_t : public boost::noncopyable
{
	free_list_container_t() : d_free_head(NULL)
	{
	}

	~free_list_container_t()
	{
		if (d_free_head)
		{
			delete d_free_head;
			d_free_head = NULL;
		}
	}


	T *claim()
	{
		T *r = NULL;
		if (d_free_head)
			r = d_free_head;
		else
			r = new T(d_free_head);
		r->claim();
		return r;
	}

protected:
	T *d_free_head;
};

template<typename T>
struct auto_release_t
{
	auto_release_t(T *t) : d_t(t) {}
	~auto_release_t() { if (d_t) d_t->release(); }

	void do_not_release() { d_t = NULL; }
protected:
	T *d_t;
};

#endif // __REASS_FREELIST_H__
