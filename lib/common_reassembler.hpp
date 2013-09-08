#include "reass/common_reassembler.h"

template<typename CRTP>
FORCE_INLINE common_stream_t<CRTP>::common_stream_t(CRTP *&free_head) :
	free_list_member_t<CRTP>(free_head)
{
}

template<typename CRTP>
FORCE_INLINE void common_stream_t<CRTP>::release()
{
	if (have_partner())
		d_partner->d_partner = partner_destroyed();
#ifdef DEBUG
	d_partner = partner_destroyed();
	::memset(&d_src, 'X', sizeof(d_src));
	::memset(&d_dst, 'X', sizeof(d_dst));
#endif

	free_list_member_t<CRTP>::release();
}

template<typename CRTP>
FORCE_INLINE void common_stream_t<CRTP>::set_src_dst4(
		u_int32_t from, u_int16_t fromport,
		u_int32_t to, u_int16_t toport,
		bool swap)
{
	ip_address_t &src = (swap ? d_dst : d_src);
	ip_address_t &dst = (swap ? d_src : d_dst);
#ifdef DEBUG
	::memset(&src, 'Z', sizeof(d_src));
	::memset(&dst, 'Z', sizeof(d_dst));
#endif

	d_src.v4.sin_family = AF_INET;
	d_dst.v4.sin_family = AF_INET;

	src.v4.sin_addr.s_addr = from;
	src.v4.sin_port = fromport;

	dst.v4.sin_addr.s_addr = to;
	dst.v4.sin_port = toport;

	d_partner = nullptr; // so ->release can check the partner
}

template<typename CRTP>
FORCE_INLINE void common_stream_t<CRTP>::set_src_dst6(
		const in6_addr &from, u_int16_t fromport,
		const in6_addr &to, u_int16_t toport,
		bool swap)
{
	ip_address_t &src = (swap ? d_dst : d_src);
	ip_address_t &dst = (swap ? d_src : d_dst);
#ifdef DEBUG
	::memset(&src, 'Z', sizeof(d_src));
	::memset(&dst, 'Z', sizeof(d_dst));
#endif

	d_src.v6.sin6_family = AF_INET6;
	d_dst.v6.sin6_family = AF_INET6;
	d_src.v6.sin6_flowinfo = 0;
	d_dst.v6.sin6_flowinfo = 0;
	d_src.v6.sin6_scope_id = 0;
	d_dst.v6.sin6_scope_id = 0;

	src.v6.sin6_addr = from;
	src.v6.sin6_port = fromport;
	dst.v6.sin6_addr = to;
	dst.v6.sin6_port = toport;

	d_partner = nullptr; // so ->release can check the partner
}

template<typename CRTP>
FORCE_INLINE void common_stream_t<CRTP>::init(packet_listener_t *listener)
{
	d_listener = listener;
	d_userdata = nullptr;
	d_partner = nullptr;
}

template<typename CRTP>
inline void common_stream_t<CRTP>::print(std::ostream &os) const
{
	os << d_src << " -> " << d_dst;
}

