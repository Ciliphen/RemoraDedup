/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2017 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Derived from FreeBSD's bufring.h
 *
 **************************************************************************
 *
 * Copyright (c) 2007-2009 Kip Macy kmacy@freebsd.org
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. The name of Kip Macy nor the names of other
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 ***************************************************************************/

#ifndef _RTE_RING_H_
#define _RTE_RING_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdint.h>
#include <sys/queue.h>
#include <errno.h>
#include <xmmintrin.h>
#include "rte_atomic_x86.h"
#include "rte_branch_prediction.h"
#define __rte_always_inline inline

#define RTE_RING_MZ_PREFIX "RG_"

enum rte_ring_queue_behavior {
	RTE_RING_QUEUE_FIXED = 0,
	RTE_RING_QUEUE_VARIABLE
};

struct rte_ring_headtail {
	volatile uint32_t head;
	volatile uint32_t tail;
	uint32_t single;
};
#define RTE_NAMESIZE 256

struct rte_ring {
	char name[RTE_NAMESIZE];
	int flags;

	uint32_t size;
	uint32_t mask;
	uint32_t capacity;

	struct rte_ring_headtail prod;

	struct rte_ring_headtail cons;
};

#define RING_F_SP_ENQ 0x0001
#define RING_F_SC_DEQ 0x0002

#define RING_F_EXACT_SZ	 0x0004
#define RTE_RING_SZ_MASK (unsigned)(0x0fffffff)

#define __IS_SP 1
#define __IS_MP 0
#define __IS_SC 1
#define __IS_MC 0

static inline uint32_t rte_align32pow2(uint32_t x)
{
	x--;
	x |= x >> 1;
	x |= x >> 2;
	x |= x >> 4;
	x |= x >> 8;
	x |= x >> 16;

	return x + 1;
}

ssize_t rte_ring_get_memsize(unsigned count);

int rte_ring_init(struct rte_ring *r, const char *name, unsigned count,
		  unsigned flags);

struct rte_ring *rte_ring_create(const char *name, unsigned count,
				 unsigned flags);

void rte_ring_free(struct rte_ring *r);

void rte_ring_dump(FILE *f, const struct rte_ring *r);

#define ENQUEUE_PTRS(r, ring_start, prod_head, obj_table, n, obj_type)         \
	do {                                                                   \
		unsigned int i;                                                \
		const uint32_t size = (r)->size;                               \
		uint32_t idx	    = prod_head & (r)->mask;                   \
		obj_type *ring	    = (obj_type *)ring_start;                  \
		if (idx + n < size) {                                          \
			for (i = 0; i < (n & ((~(unsigned)0x3)));              \
			     i += 4, idx += 4) {                               \
				ring[idx]     = obj_table[i];                  \
				ring[idx + 1] = obj_table[i + 1];              \
				ring[idx + 2] = obj_table[i + 2];              \
				ring[idx + 3] = obj_table[i + 3];              \
			}                                                      \
			switch (n & 0x3) {                                     \
			case 3:                                                \
				ring[idx++] = obj_table[i++];                  \
			case 2:                                                \
				ring[idx++] = obj_table[i++];                  \
			case 1:                                                \
				ring[idx++] = obj_table[i++];                  \
			}                                                      \
		} else {                                                       \
			for (i = 0; idx < size; i++, idx++)                    \
				ring[idx] = obj_table[i];                      \
			for (idx = 0; i < n; i++, idx++)                       \
				ring[idx] = obj_table[i];                      \
		}                                                              \
	} while (0)

#define DEQUEUE_PTRS(r, ring_start, cons_head, obj_table, n, obj_type)         \
	do {                                                                   \
		unsigned int i;                                                \
		uint32_t idx	    = cons_head & (r)->mask;                   \
		const uint32_t size = (r)->size;                               \
		obj_type *ring	    = (obj_type *)ring_start;                  \
		if (idx + n < size) {                                          \
			for (i = 0; i < (n & (~(unsigned)0x3));                \
			     i += 4, idx += 4) {                               \
				obj_table[i]	 = ring[idx];                  \
				obj_table[i + 1] = ring[idx + 1];              \
				obj_table[i + 2] = ring[idx + 2];              \
				obj_table[i + 3] = ring[idx + 3];              \
			}                                                      \
			switch (n & 0x3) {                                     \
			case 3:                                                \
				obj_table[i++] = ring[idx++];                  \
			case 2:                                                \
				obj_table[i++] = ring[idx++];                  \
			case 1:                                                \
				obj_table[i++] = ring[idx++];                  \
			}                                                      \
		} else {                                                       \
			for (i = 0; idx < size; i++, idx++)                    \
				obj_table[i] = ring[idx];                      \
			for (idx = 0; i < n; i++, idx++)                       \
				obj_table[i] = ring[idx];                      \
		}                                                              \
	} while (0)

static __rte_always_inline void update_tail(struct rte_ring_headtail *ht,
					    uint32_t old_val, uint32_t new_val,
					    uint32_t single)
{
	if (!single)
		while (unlikely(ht->tail != old_val))
			_mm_pause();

	ht->tail = new_val;
}

static __rte_always_inline unsigned int
__rte_ring_move_prod_head(struct rte_ring *r, int is_sp, unsigned int n,
			  enum rte_ring_queue_behavior behavior,
			  uint32_t *old_head, uint32_t *new_head,
			  uint32_t *free_entries)
{
	const uint32_t capacity = r->capacity;
	unsigned int max	= n;
	int success;

	do {
		n = max;

		*old_head		 = r->prod.head;
		const uint32_t cons_tail = r->cons.tail;

		*free_entries = (capacity + cons_tail - *old_head);

		if (unlikely(n > *free_entries))
			n = (behavior == RTE_RING_QUEUE_FIXED) ? 0 :
								 *free_entries;

		if (n == 0)
			return 0;

		*new_head = *old_head + n;
		if (is_sp)
			r->prod.head = *new_head, success = 1;
		else
			success = rte_atomic32_cmpset(&r->prod.head, *old_head,
						      *new_head);
	} while (unlikely(success == 0));
	return n;
}

static __rte_always_inline unsigned int
__rte_ring_do_enqueue(struct rte_ring *r, void *const *obj_table,
		      unsigned int n, enum rte_ring_queue_behavior behavior,
		      int is_sp, unsigned int *free_space)
{
	uint32_t prod_head, prod_next;
	uint32_t free_entries;

	n = __rte_ring_move_prod_head(r, is_sp, n, behavior, &prod_head,
				      &prod_next, &free_entries);
	if (n == 0)
		goto end;

	ENQUEUE_PTRS(r, &r[1], prod_head, obj_table, n, void *);
	rte_smp_wmb();

	update_tail(&r->prod, prod_head, prod_next, is_sp);
end:
	if (free_space != NULL)
		*free_space = free_entries - n;
	return n;
}

static __rte_always_inline unsigned int
__rte_ring_move_cons_head(struct rte_ring *r, int is_sc, unsigned int n,
			  enum rte_ring_queue_behavior behavior,
			  uint32_t *old_head, uint32_t *new_head,
			  uint32_t *entries)
{
	unsigned int max = n;
	int success;

	do {
		n = max;

		*old_head		 = r->cons.head;
		const uint32_t prod_tail = r->prod.tail;

		*entries = (prod_tail - *old_head);

		if (n > *entries)
			n = (behavior == RTE_RING_QUEUE_FIXED) ? 0 : *entries;

		if (n == 0)
			return 0;

		*new_head = *old_head + n;
		if (is_sc)
			r->cons.head = *new_head, success = 1;
		else
			success = rte_atomic32_cmpset(&r->cons.head, *old_head,
						      *new_head);
	} while (success == 0);
	return n;
}

static __rte_always_inline unsigned int
__rte_ring_do_dequeue(struct rte_ring *r, void **obj_table, unsigned int n,
		      enum rte_ring_queue_behavior behavior, int is_sc,
		      unsigned int *available)
{
	uint32_t cons_head, cons_next;
	uint32_t entries;

	n = __rte_ring_move_cons_head(r, is_sc, n, behavior, &cons_head,
				      &cons_next, &entries);
	if (n == 0)
		goto end;

	DEQUEUE_PTRS(r, &r[1], cons_head, obj_table, n, void *);
	rte_smp_rmb();

	update_tail(&r->cons, cons_head, cons_next, is_sc);

end:
	if (available != NULL)
		*available = entries - n;
	return n;
}

static __rte_always_inline unsigned int
rte_ring_mp_enqueue_bulk(struct rte_ring *r, void *const *obj_table,
			 unsigned int n, unsigned int *free_space)
{
	return __rte_ring_do_enqueue(r, obj_table, n, RTE_RING_QUEUE_FIXED,
				     __IS_MP, free_space);
}

static __rte_always_inline unsigned int
rte_ring_sp_enqueue_bulk(struct rte_ring *r, void *const *obj_table,
			 unsigned int n, unsigned int *free_space)
{
	return __rte_ring_do_enqueue(r, obj_table, n, RTE_RING_QUEUE_FIXED,
				     __IS_SP, free_space);
}

static __rte_always_inline unsigned int
rte_ring_enqueue_bulk(struct rte_ring *r, void *const *obj_table,
		      unsigned int n, unsigned int *free_space)
{
	return __rte_ring_do_enqueue(r, obj_table, n, RTE_RING_QUEUE_FIXED,
				     r->prod.single, free_space);
}

static __rte_always_inline int rte_ring_mp_enqueue(struct rte_ring *r,
						   void *obj)
{
	return rte_ring_mp_enqueue_bulk(r, &obj, 1, NULL) ? 0 : -ENOBUFS;
}

static __rte_always_inline int rte_ring_sp_enqueue(struct rte_ring *r,
						   void *obj)
{
	return rte_ring_sp_enqueue_bulk(r, &obj, 1, NULL) ? 0 : -ENOBUFS;
}

static __rte_always_inline int rte_ring_enqueue(struct rte_ring *r, void *obj)
{
	return rte_ring_enqueue_bulk(r, &obj, 1, NULL) ? 0 : -ENOBUFS;
}

static __rte_always_inline unsigned int
rte_ring_mc_dequeue_bulk(struct rte_ring *r, void **obj_table, unsigned int n,
			 unsigned int *available)
{
	return __rte_ring_do_dequeue(r, obj_table, n, RTE_RING_QUEUE_FIXED,
				     __IS_MC, available);
}

static __rte_always_inline unsigned int
rte_ring_sc_dequeue_bulk(struct rte_ring *r, void **obj_table, unsigned int n,
			 unsigned int *available)
{
	return __rte_ring_do_dequeue(r, obj_table, n, RTE_RING_QUEUE_FIXED,
				     __IS_SC, available);
}

static __rte_always_inline unsigned int
rte_ring_dequeue_bulk(struct rte_ring *r, void **obj_table, unsigned int n,
		      unsigned int *available)
{
	return __rte_ring_do_dequeue(r, obj_table, n, RTE_RING_QUEUE_FIXED,
				     r->cons.single, available);
}

static __rte_always_inline int rte_ring_mc_dequeue(struct rte_ring *r,
						   void **obj_p)
{
	return rte_ring_mc_dequeue_bulk(r, obj_p, 1, NULL) ? 0 : -ENOENT;
}

static __rte_always_inline int rte_ring_sc_dequeue(struct rte_ring *r,
						   void **obj_p)
{
	return rte_ring_sc_dequeue_bulk(r, obj_p, 1, NULL) ? 0 : -ENOENT;
}

static __rte_always_inline int rte_ring_dequeue(struct rte_ring *r,
						void **obj_p)
{
	return rte_ring_dequeue_bulk(r, obj_p, 1, NULL) ? 0 : -ENOENT;
}

static inline unsigned rte_ring_count(const struct rte_ring *r)
{
	uint32_t prod_tail = r->prod.tail;
	uint32_t cons_tail = r->cons.tail;
	uint32_t count	   = (prod_tail - cons_tail) & r->mask;
	return (count > r->capacity) ? r->capacity : count;
}

static inline unsigned rte_ring_free_count(const struct rte_ring *r)
{
	return r->capacity - rte_ring_count(r);
}

static inline int rte_ring_full(const struct rte_ring *r)
{
	return rte_ring_free_count(r) == 0;
}

static inline int rte_ring_empty(const struct rte_ring *r)
{
	return rte_ring_count(r) == 0;
}

static inline unsigned int rte_ring_get_size(const struct rte_ring *r)
{
	return r->size;
}

static inline unsigned int rte_ring_get_capacity(const struct rte_ring *r)
{
	return r->capacity;
}

void rte_ring_list_dump(FILE *f);

struct rte_ring *rte_ring_lookup(const char *name);

static __rte_always_inline unsigned
rte_ring_mp_enqueue_burst(struct rte_ring *r, void *const *obj_table,
			  unsigned int n, unsigned int *free_space)
{
	return __rte_ring_do_enqueue(r, obj_table, n, RTE_RING_QUEUE_VARIABLE,
				     __IS_MP, free_space);
}

static __rte_always_inline unsigned
rte_ring_sp_enqueue_burst(struct rte_ring *r, void *const *obj_table,
			  unsigned int n, unsigned int *free_space)
{
	return __rte_ring_do_enqueue(r, obj_table, n, RTE_RING_QUEUE_VARIABLE,
				     __IS_SP, free_space);
}

static __rte_always_inline unsigned
rte_ring_enqueue_burst(struct rte_ring *r, void *const *obj_table,
		       unsigned int n, unsigned int *free_space)
{
	return __rte_ring_do_enqueue(r, obj_table, n, RTE_RING_QUEUE_VARIABLE,
				     r->prod.single, free_space);
}

static __rte_always_inline unsigned
rte_ring_mc_dequeue_burst(struct rte_ring *r, void **obj_table, unsigned int n,
			  unsigned int *available)
{
	return __rte_ring_do_dequeue(r, obj_table, n, RTE_RING_QUEUE_VARIABLE,
				     __IS_MC, available);
}

static __rte_always_inline unsigned
rte_ring_sc_dequeue_burst(struct rte_ring *r, void **obj_table, unsigned int n,
			  unsigned int *available)
{
	return __rte_ring_do_dequeue(r, obj_table, n, RTE_RING_QUEUE_VARIABLE,
				     __IS_SC, available);
}

static __rte_always_inline unsigned
rte_ring_dequeue_burst(struct rte_ring *r, void **obj_table, unsigned int n,
		       unsigned int *available)
{
	return __rte_ring_do_dequeue(r, obj_table, n, RTE_RING_QUEUE_VARIABLE,
				     r->cons.single, available);
}

enum femu_ring_type {
	FEMU_RING_TYPE_SP_SC,
	FEMU_RING_TYPE_MP_SC,
	FEMU_RING_TYPE_MP_MC,
};

struct rte_ring *femu_ring_create(enum femu_ring_type type, size_t count);

void femu_ring_free(struct rte_ring *ring);

size_t femu_ring_count(struct rte_ring *ring);

size_t femu_ring_enqueue(struct rte_ring *ring, void **objs, size_t count);

size_t femu_ring_dequeue(struct rte_ring *ring, void **objs, size_t count);

#ifdef __cplusplus
}
#endif

#endif
