// SPDX-License-Identifier: GPL-2.0

#include <linux/mm.h>
#include <linux/slab.h> 
#include <linux/highmem.h>
#include <linux/vmstat.h>
#include <linux/mem_reservations.h>

struct rm_node* rm_node_create() {
  struct rm_node* new = NULL;
  unsigned int i;
  new = kmalloc(sizeof(struct rm_node), GFP_KERNEL & ~__GFP_DIRECT_RECLAIM);
  if (new) {
    for (i = 0; i < RT_NODE_RANGE_SIZE; i++) {
      spin_lock_init(&new->items[i].lock);
      new->items[i].next_node = NULL;
    }
  }
  return new;
}

struct page *rm_alloc_from_reservation(struct vm_area_struct *vma, unsigned long address) {
  unsigned char level;
  unsigned int i;
  unsigned int index;

  struct rm_node *cur_node = GET_RM_ROOT(vma);
  struct rm_node *next_node;
  
  unsigned long leaf_value;
  unsigned char mask;

  struct page *page;
  spinlock_t  *next_lock;

  gfp_t gfp           = ((GFP_HIGHUSER | __GFP_NOMEMALLOC | __GFP_NOWARN) & ~__GFP_RECLAIM);
	unsigned long haddr = address & RESERV_MASK; 
  int region_offset   = (address & (~RESERV_MASK)) >> PAGE_SHIFT;
  bool my_app         = (vma->vm_mm->owner->pid == 5555);

  if (!my_app) 
    return NULL;
  if (!vma_is_anonymous(vma))
    return NULL;
  if ((haddr < vma->vm_start) || (haddr + RESERV_SIZE > vma->vm_end)) 
    return NULL;

  // travers the radix tree
  // firstly, all levels but not the leaf node
  for (level = 1; level < NUM_RT_LEVELS; level++) {
    index = get_node_index(level, address);
    next_lock = &cur_node->items[index].lock;
    next_node = cur_node->items[index].next_node;

    if (unlikely(next_node == NULL)) {
      spin_lock(next_lock);
      if (next_node == NULL) {
        cur_node->items[index].next_node = rm_node_create();
      }
      spin_unlock(next_lock);
    }

    cur_node = cur_node->items[index].next_node;
  }

  //secondly, the leaf node
  level = NUM_RT_LEVELS;
  index = get_node_index(level, address); 
  next_lock = &cur_node->items[index].lock;

  spin_lock(next_lock);
  leaf_value = (unsigned long)(cur_node->items[index].next_node);
  page = get_page_from_rm(leaf_value);
  if (leaf_value == 0) { //create a new reservation if not present 
    // allocate pages 
    page = alloc_pages_vma(gfp, RESERV_ORDER, vma, haddr, numa_node_id(), false); 
    for (i = 0; i < RESERV_NR; i++) {
      set_page_count(page + i, 1);
    }
    //create leaf node
    leaf_value = create_value(page, 0);
    mod_node_page_state(page_pgdat(page), NR_MEM_RESERVATIONS_RESERVED, RESERV_NR - 1);
    count_vm_event(MEM_RESERVATIONS_ALLOC);
  } else {
    dec_node_page_state(page, NR_MEM_RESERVATIONS_RESERVED);
  }
  page = page + region_offset;

  // mark that a page is used
  mask = get_mask_from_rm(leaf_value);
  SET_BIT(mask, region_offset); 
  leaf_value = update_mask(leaf_value, mask);
  cur_node->items[index].next_node = (void*)(leaf_value);

  get_page(page);
  clear_user_highpage(page, address);

  spin_unlock(next_lock);

  return page;
}

//  if (CHECK_BIT(leaf_node->used_mask, region_offset) > 0) {
//    spin_unlock(next_lock);
//    return NULL;
//  }


//int rm_set_unused(struct vm_area_struct *vma, unsigned long address) {
//  int level;
//  unsigned int index;
//  struct rm_node* root = GET_RM_ROOT(vma);
//  struct rm_node* cur_node = root;
//  struct rm_leaf_node* leaf_node;
//
//
//  unsigned char region_offset = (address & (~RESERV_MASK)) >> PAGE_SHIFT;
//
//  // traver the radix tree
//  for (level = 1; level <= (NUM_RT_LEVELS - 1); level++) {
//    index = get_node_index(level, address);
//    if (cur_node->nodes[index] == NULL) {
//      return 0;
//    }
//    cur_node = cur_node->nodes[index];
//  }
//  //last level
//  index = get_node_index(RT_LEVEL_INDEX_LENGTH, address); 
//  leaf_node = (struct rm_leaf_node*)(cur_node->nodes[index]);
//
//  spin_lock(&cur_node->locks[index]);
//  if (leaf_node == NULL) { //allocate if not present 
//    spin_unlock(&cur_node->locks[index]);
//    return 0;
//  }
//  UNSET_BIT(leaf_node->used_mask, region_offset); //set used bit
//  put_page(leaf_node->page + region_offset);
//
////  if (leaf_node->used_mask == 0) {
////    __free_pages(leaf_node->page, RESERV_ORDER);
////    kfree(leaf_node);
////    cur_node->nodes[index] = NULL;
////  }
//  spin_unlock(&cur_node->locks[index]);
//  return 0;
//}

void rm_destroy(struct rm_node *node, unsigned char level) { //not thread-safe 
  unsigned int index;
  int i;
  struct rm_node *cur_node = node;
  unsigned char mask;
  unsigned char unused;
  struct page *page;
  unsigned long leaf_value;

  // traver the radix tree
  for (index = 0; index < RT_NODE_RANGE_SIZE; index++) {
    if (cur_node->items[index].next_node != NULL) {
      if (level != 4) {
        rm_destroy(cur_node->items[index].next_node, level + 1);
      } else {
        leaf_value = (unsigned long)(cur_node->items[index].next_node);
        page = get_page_from_rm(leaf_value);
        mask = get_mask_from_rm(leaf_value);

        unused = 8;
        while (mask) {
          unused -= mask & 1;
          mask = (mask >> 1);
        }
        if (unused) {
          mod_node_page_state(page_pgdat(page), NR_MEM_RESERVATIONS_RESERVED, -unused);
        }

        for (i = 0; i < RESERV_NR; i++) {
          put_page(page + i);
        }
      }
    }
  }
  kfree(cur_node);
  return;
}
