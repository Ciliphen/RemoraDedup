#ifndef RTE_ATOMIC_H
#define RTE_ATOMIC_H

#define rte_compiler_barrier()                                                 \
	do {                                                                   \
		asm volatile("" : : : "memory");                               \
	} while (0)

#define MPLOCKED "lock ; "

static inline int rte_atomic32_cmpset(volatile uint32_t *dst, uint32_t exp,
				      uint32_t src)
{
	uint8_t res;

	asm volatile(MPLOCKED "cmpxchgl %[src], %[dst];"
			      "sete %[res];"
		     : [res] "=a"(res), [dst] "=m"(*dst)
		     : [src] "r"(src), "a"(exp), "m"(*dst)
		     : "memory");
	return res;
}

#define rte_smp_wmb() rte_compiler_barrier()

#define rte_smp_rmb() rte_compiler_barrier()

#endif
