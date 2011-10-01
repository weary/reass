/*
 * Copyright 2011 Hylke Vellinga
 */


#ifndef __REASS_CONFIG_H__
#define __REASS_CONFIG_H__

// maximum number of layers supported for a packet
// increasing this costs some memory per packet
#define MAX_LAYERS 8

// undefine this to save one function call per packet, but violate c++ specs
#define NO_MEMBER_CALLBACK

// if NO_REUSE is defined, we will not re-use memory internally, but rely
// on new/delete. Define it if you are going to use valgrind, otherwise
// leave undefined.
//#define NO_REUSE

// if defined call accept_error on listener if we cannot parse a packet's
// layers, otherwise throw away packet
#define UNKNOWN_LAYER_AS_ERROR

// if defined print per-pcap statistics
//#define PRINT_STATS

// number of packets to wait in a stream before accepting we missed something
#define MAX_DELAYED_PACKETS 16

#endif // __REASS_CONFIG_H__
