// Cuckoo Cycle, a memory-hard proof-of-work
// Copyright (c) 2013-2017 John Tromp
#ifndef CUCKOO_H
#define CUCKOO_H

#include <stdint.h> // for types uint32_t,uint64_t
#include <string.h> // for functions strlen, memset
#include "blake2.h"
#include "siphash.h"

#ifdef SIPHASH_COMPAT
#include <stdio.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

// proof-of-work parameters
#ifndef EDGEBITS
// the main parameter is the 2-log of the graph size,
// which is the size in bits of the node identifiers
#define EDGEBITS 29
#endif
#ifndef PROOFSIZE
// the next most important parameter is the (even) length
// of the cycle to be found. a minimum of 12 is recommended
#define PROOFSIZE 42
#endif

// save some keystrokes since i'm a lazy typer
typedef uint32_t u32;

#if EDGEBITS > 30
typedef uint64_t word_t;
#elif EDGEBITS > 14
typedef u32 word_t;
#else // if EDGEBITS <= 14
typedef uint16_t word_t;
#endif

// number of edges
#define NEDGES ((word_t)1 << EDGEBITS)
// used to mask siphash output
#define EDGEMASK ((word_t)NEDGES - 1)

void cuckoo_hash(const char* input, const char *nonces, uint32_t len, char* output);

#ifdef __cplusplus
}
#endif
#endif //CUCKOO_H
