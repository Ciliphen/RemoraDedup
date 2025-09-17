/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2010-2017 Intel Corporation
 * Copyright (c) 2007-2009 Kip Macy kmacy@freebsd.org
 * All rights reserved.
 * Derived from FreeBSD's bufring.h
 * Used as BSD-3 Licensed with permission from Kip Macy.
 */

#ifndef _RTE_RING_GENERIC_H_
#define _RTE_RING_GENERIC_H_

static __rte_always_inline void
update_tail(struct rte_ring_headtail *ht, uint32_t old_val, uint32_t new_val,
		uint32_t single, uint32_t enqueue)
{
	if (enqueue)
		rte_smp_wmb();
	else
		rte_smp_rmb();
	
	if (!single)
		while (unlikely(ht->tail != old_val))
			rte_pause();

	ht->tail = new_val;
}


static __rte_always_inline unsigned int
__rte_ring_move_prod_head(struct rte_ring *r, unsigned int is_sp,
		unsigned int n, enum rte_ring_queue_behavior behavior,
		uint32_t *old_head, uint32_t *new_head,
		uint32_t *free_entries)
{
	const uint32_t capacity = r->capacity;
	unsigned int max = n;
	int success;

	do {
		
		n = max;

		*old_head = r->prod.head;

		
		rte_smp_rmb();

		
		*free_entries = (capacity + r->cons.tail - *old_head);

		
		if (unlikely(n > *free_entries))
			n = (behavior == RTE_RING_QUEUE_FIXED) ?
					0 : *free_entries;

		if (n == 0)
			return 0;

		*new_head = *old_head + n;
		if (is_sp)
			r->prod.head = *new_head, success = 1;
		else
			success = rte_atomic32_cmpset(&r->prod.head,
					*old_head, *new_head);
	} while (unlikely(success == 0));
	return n;
}


static __rte_always_inline unsigned int
__rte_ring_move_cons_head(struct rte_ring *r, unsigned int is_sc,
		unsigned int n, enum rte_ring_queue_behavior behavior,
		uint32_t *old_head, uint32_t *new_head,
		uint32_t *entries)
{
	unsigned int max = n;
	int success;

	
	do {
		
		n = max;

		*old_head = r->cons.head;

		
		rte_smp_rmb();

		
		*entries = (r->prod.tail - *old_head);

		
		if (n > *entries)
			n = (behavior == RTE_RING_QUEUE_FIXED) ? 0 : *entries;

		if (unlikely(n == 0))
			return 0;

		*new_head = *old_head + n;
		if (is_sc)
			r->cons.head = *new_head, success = 1;
		else
			success = rte_atomic32_cmpset(&r->cons.head, *old_head,
					*new_head);
	} while (unlikely(success == 0));
	return n;
}

#endif 
