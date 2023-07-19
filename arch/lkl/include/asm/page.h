#ifndef _ASM_LKL_PAGE_H
#define _ASM_LKL_PAGE_H

#ifndef CONFIG_MMU

#define ARCH_PFN_OFFSET	(memory_start >> PAGE_SHIFT)

#ifndef __ASSEMBLY__
void free_mem(void);
void bootmem_init(unsigned long mem_size);
#endif

#include <asm-generic/page.h>

#undef PAGE_OFFSET
#define PAGE_OFFSET memory_start

#else // CONFIG_MMU

#include <linux/const.h>

/* PAGE_SHIFT determines the page size */
#define PAGE_SHIFT	12
#define PAGE_SIZE	(_AC(1,UL) << PAGE_SHIFT)
#define PAGE_MASK	(~(PAGE_SIZE-1))
#define PFN_PTE_SHIFT PAGE_SHIFT

#ifndef __ASSEMBLY__

struct page;
#define clear_page(page)	memset((void *)(page), 0, PAGE_SIZE)
#define copy_page(to,from)	memcpy((void *)(to), (void *)(from), PAGE_SIZE)
#define clear_user_page(page, vaddr, pg)	clear_page(page)
#define copy_user_page(to, from, vaddr, pg)	copy_page(to, from)

/*
 * These are used to make use of C type-checking..
 */
typedef struct {unsigned long pte;} pte_t;
typedef struct {unsigned long pgd;} pgd_t;
typedef struct {unsigned long pgprot;} pgprot_t;
typedef struct page *pgtable_t;
#define pte_val(p) ((p).pte)
#define pgd_val(x)	((x).pgd)
#define pgprot_val(x)	((x).pgprot)

#define __pte(x)	((pte_t) { (x) } )
#define __pgd(x)	((pgd_t) { (x) } )
#define __pgprot(x)	((pgprot_t) { (x) } )

#define PAGE_OFFSET		(memory_start)

extern unsigned long memory_start;
extern unsigned long memory_end;

#define pte_get_bits(p, bits) ((p).pte & (bits))
#define pte_set_bits(p, bits) ((p).pte |= (bits))
#define pte_clear_bits(p, bits) ((p).pte &= ~(bits))
#define pte_copy(to, from) ({ (to).pte = (from).pte; })
#define pte_is_zero(p) (!((p).pte & ~_PAGE_NEWPAGE))
#define pte_set_val(p, phys, prot) ({ (p).pte = (phys) | pgprot_val(prot); })

#define virt_to_pfn(kaddr)	(__pa(kaddr) >> PAGE_SHIFT)
typedef unsigned long long phys_t;


#define __va_space (8*1024*1024)

#include <asm/mem.h>

/* Cast to unsigned long before casting to void * to avoid a warning from
 * mmap_kmem about cutting a long long down to a void *.  Not sure that
 * casting is the right thing, but 32-bit UML can't have 64-bit virtual
 * addresses
 */
#define __pa(virt) to_phys((void *) (unsigned long) (virt))
#define __va(phys) to_virt((unsigned long) (phys))

#define phys_to_pfn(p) ((p) >> PAGE_SHIFT)
#define pfn_to_phys(pfn) PFN_PHYS(pfn)

#define pfn_valid(pfn) ((pfn) < max_mapnr)
#define virt_addr_valid(v) pfn_valid(phys_to_pfn(__pa(v)))

void free_mem(void);
void bootmem_init(unsigned long mem_size);

#endif // __ASSEMBLY__
#include <asm-generic/memory_model.h>
#include <asm-generic/getorder.h>

#endif // CONFIG_MMU

#endif /* _ASM_LKL_PAGE_H */
