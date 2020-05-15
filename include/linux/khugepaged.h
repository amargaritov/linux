/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_KHUGEPAGED_H
#define _LINUX_KHUGEPAGED_H

#include <linux/hashtable.h>
#include <linux/sched/coredump.h> /* MMF_VM_HUGEPAGE */

#define MY_HASH_TABLE_LOG_SIZE 25

#define RESERV_ORDER           3 
#define RESERV_SHIFT           (RESERV_ORDER + PAGE_SHIFT) // 3 + 12 = 15
#define RESERV_SIZE            ((1UL) << RESERV_SHIFT)     // 00000000000000001000000000000000 //32768 
#define RESERV_MASK            (~( RESERV_SIZE - 1))       // 11111111111111111000000000000000 //-32768
#define RESERV_NR              ((1UL) << RESERV_ORDER)     // 00000000000000000000000000001000 //8
#define RESERV_GROUP_NR_IN_PMD (HPAGE_PMD_NR / RESERV_NR)  // 512 / 8 = 64
#define RESERV_OFFSET_MASK     ((1UL << RESERV_ORDER) - 1) // 00000000000000000000000000000111 //7

#define CHECK_BIT(var,pos) ((var) & (1<<(pos)))
#define SET_BIT(var,pos)   ((var) &= (1<<(pos)))


#ifdef CONFIG_TRANSPARENT_HUGEPAGE
extern struct attribute_group khugepaged_attr_group;

extern int khugepaged_init(void);
extern void khugepaged_destroy(void);
extern int start_stop_khugepaged(void);
extern int __khugepaged_enter(struct mm_struct *mm);
extern void __khugepaged_exit(struct mm_struct *mm);
extern int khugepaged_enter_vma_merge(struct vm_area_struct *vma,
				      unsigned long vm_flags);

#define khugepaged_enabled()					       \
	(transparent_hugepage_flags &				       \
	 ((1<<TRANSPARENT_HUGEPAGE_FLAG) |		       \
	  (1<<TRANSPARENT_HUGEPAGE_REQ_MADV_FLAG)))
#define khugepaged_always()				\
	(transparent_hugepage_flags &			\
	 (1<<TRANSPARENT_HUGEPAGE_FLAG))
#define khugepaged_req_madv()					\
	(transparent_hugepage_flags &				\
	 (1<<TRANSPARENT_HUGEPAGE_REQ_MADV_FLAG))
#define khugepaged_defrag()					\
	(transparent_hugepage_flags &				\
	 (1<<TRANSPARENT_HUGEPAGE_DEFRAG_KHUGEPAGED_FLAG))

struct thp_reservation {
	spinlock_t *lock;
	unsigned long haddr;
	struct page *page;
	struct vm_area_struct *vma;
	struct hlist_node node;
	struct list_head lru;
	int nr_unused;
  unsigned char used_mask; //Artemiy added to indicate which pages are used (others are reserved)
};

struct thp_resvs {
	atomic_t refcnt;
	spinlock_t res_hash_lock;
  bool initialized;
	DECLARE_HASHTABLE(res_hash, MY_HASH_TABLE_LOG_SIZE);
};

#define	vma_thp_reservations(vma)	((vma)->thp_reservations)

static inline void thp_resvs_fork(struct vm_area_struct *vma,
				  struct vm_area_struct *pvma)
{
	// XXX Do not share THP reservations for now
	vma->thp_reservations = NULL;
}

void thp_resvs_new(struct vm_area_struct *vma);


extern void khugepaged_free_reservation(struct thp_reservation *res);

extern void __thp_resvs_put(struct thp_resvs *r);
static inline void thp_resvs_put(struct thp_resvs *r)
{
	struct hlist_node *tmp;
	int i;
	struct thp_reservation *res = NULL;

	if (r) {
    //Artemiy release on dealocation
    /**
     *  * hash_for_each - iterate over a hashtable
     *  * @name: hashtable to iterate
     *  * @bkt: integer to use as bucket loop cursor
     *  * @obj: the type * to use as a loop cursor for each entry
     *  * @member: the name of the hlist_node within the struct
     *  */

//    int bkt = 0;
//    hash_for_each(r->res_hash, bkt, res, node) {
//      khugepaged_free_reservation(res);
//    }
    if (r->initialized) {
      hash_for_each_safe(r->res_hash, i, tmp, res, node) {
        khugepaged_free_reservation(res);
      }
    }
    __thp_resvs_put(r);
  }
}

void khugepaged_mod_resv_unused(struct vm_area_struct *vma,
				  unsigned long address, int delta);

struct page *khugepaged_get_reserved_page(
	struct vm_area_struct *vma,
	unsigned long address);

void khugepaged_reserve(struct vm_area_struct *vma,
			unsigned long address);

void khugepaged_release_reservation(struct vm_area_struct *vma,
				    unsigned long address);

void _khugepaged_reservations_fixup(struct vm_area_struct *src,
				   struct vm_area_struct *dst);

void _khugepaged_move_reservations_adj(struct vm_area_struct *prev,
				      struct vm_area_struct *next, long adjust);

void thp_reservations_mremap(struct vm_area_struct *vma,
		unsigned long old_addr, struct vm_area_struct *new_vma,
		unsigned long new_addr, unsigned long len,
		bool need_rmap_locks);

static inline int khugepaged_fork(struct mm_struct *mm, struct mm_struct *oldmm)
{
	if (test_bit(MMF_VM_HUGEPAGE, &oldmm->flags))
		return __khugepaged_enter(mm);
	return 0;
}

static inline void khugepaged_exit(struct mm_struct *mm)
{
	if (test_bit(MMF_VM_HUGEPAGE, &mm->flags))
		__khugepaged_exit(mm);
}

static inline int khugepaged_enter(struct vm_area_struct *vma,
				   unsigned long vm_flags)
{
	if (!test_bit(MMF_VM_HUGEPAGE, &vma->vm_mm->flags))
		if ((khugepaged_always() ||
		     (khugepaged_req_madv() && (vm_flags & VM_HUGEPAGE))) &&
		    !(vm_flags & VM_NOHUGEPAGE) &&
		    !test_bit(MMF_DISABLE_THP, &vma->vm_mm->flags))
			if (__khugepaged_enter(vma->vm_mm))
				return -ENOMEM;
	return 0;
}
#else /* CONFIG_TRANSPARENT_HUGEPAGE */

#define	vma_thp_reservations(vma)	NULL

static inline void thp_resvs_fork(struct vm_area_struct *vma,
				  struct vm_area_struct *pvma)
{
}

static inline void thp_resvs_new(struct vm_area_struct *vma)
{
}

static inline void __thp_resvs_put(struct thp_resvs *r)
{
}

static inline void thp_resvs_put(struct thp_resvs *r)
{
}

static inline void khugepaged_mod_resv_unused(struct vm_area_struct *vma,
					      unsigned long address, int delta)
{
}

static inline struct page *khugepaged_get_reserved_page(
	struct vm_area_struct *vma,
	unsigned long address)
{
	return NULL;
}

static inline void khugepaged_reserve(struct vm_area_struct *vma,
			       unsigned long address)
{
}

static inline void khugepaged_release_reservation(struct vm_area_struct *vma,
				    unsigned long address)
{
}

static inline void _khugepaged_reservations_fixup(struct vm_area_struct *src,
				   struct vm_area_struct *dst)
{
}

static inline void _khugepaged_move_reservations_adj(
				struct vm_area_struct *prev,
				struct vm_area_struct *next, long adjust)
{
}

static inline void thp_reservations_mremap(struct vm_area_struct *vma,
		unsigned long old_addr, struct vm_area_struct *new_vma,
		unsigned long new_addr, unsigned long len,
		bool need_rmap_locks)
{
}

static inline int khugepaged_fork(struct mm_struct *mm, struct mm_struct *oldmm)
{
	return 0;
}
static inline void khugepaged_exit(struct mm_struct *mm)
{
}
static inline int khugepaged_enter(struct vm_area_struct *vma,
				   unsigned long vm_flags)
{
	return 0;
}
static inline int khugepaged_enter_vma_merge(struct vm_area_struct *vma,
					     unsigned long vm_flags)
{
	return 0;
}
#endif /* CONFIG_TRANSPARENT_HUGEPAGE */

#endif /* _LINUX_KHUGEPAGED_H */
