/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LKL_PGALLOC_H
#define _LKL_PGALLOC_H

#include <linux/mm.h>
#include <linux/mmzone.h>

#include <asm-generic/pgalloc.h> /* for pte_{alloc,free}_one */

#ifdef CONFIG_MMU

#define pmd_populate_kernel(mm, pmd, pte) \
	set_pmd(pmd, __pmd(_PAGE_TABLE + (unsigned long) __pa(pte)))

#define pmd_populate(mm, pmd, pte) 				\
	set_pmd(pmd, __pmd(_PAGE_TABLE +			\
		((unsigned long long)page_to_pfn(pte) <<	\
			(unsigned long long) PAGE_SHIFT)))
#define pmd_pgtable(pmd) pmd_page(pmd)

/*
 * Allocate and free page tables.
 */
extern pgd_t *pgd_alloc(struct mm_struct *);

#define __pte_free_tlb(tlb,pte, address)		\
do {							\
	tlb_remove_page((tlb),(pte));			\
} while (0)
#endif // CONFIG_MMU

#endif /* _LKL_PGALLOC_H */
