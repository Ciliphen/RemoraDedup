// SPDX-License-Identifier: GPL-2.0
/*
 * fs/f2fs/gc.c
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 */

#include <linux/fs.h>
#include <linux/module.h>
#include <linux/backing-dev.h>
#include <linux/init.h>
#include <linux/f2fs_fs.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/freezer.h>
#include <linux/sched/signal.h>
#include <linux/pagevec.h>

#include "f2fs.h"
#include "fingerprint.h"
#include "trace.h"
#include "node.h"
#include "segment.h"
#include "gc.h"
#include <trace/events/f2fs.h>

static struct kmem_cache *victim_entry_slab;

static unsigned int count_bits(const unsigned long *addr, unsigned int offset,
			       unsigned int len);

static int gc_thread_func(void *data)
{
	struct f2fs_sb_info *sbi      = data;
	struct f2fs_gc_kthread *gc_th = sbi->gc_thread;
	wait_queue_head_t *wq	      = &sbi->gc_thread->gc_wait_queue_head;
	unsigned int wait_ms;

	wait_ms = gc_th->min_sleep_time;

	set_freezable();

	do {
		bool sync_mode;

		wait_event_interruptible_timeout(*wq,
						 kthread_should_stop() ||
							 freezing(current) ||
							 gc_th->gc_wake,
						 msecs_to_jiffies(wait_ms));

		if (gc_th->gc_wake)
			gc_th->gc_wake = 0;

		if (try_to_freeze()) {
			stat_other_skip_bggc_count(sbi);
			continue;
		}

		if (kthread_should_stop())
			break;

		if (sbi->sb->s_writers.frozen >= SB_FREEZE_WRITE) {
			increase_sleep_time(gc_th, &wait_ms);
			stat_other_skip_bggc_count(sbi);
			continue;
		}

		if (time_to_inject(sbi, FAULT_CHECKPOINT)) {
			f2fs_show_injection_info(sbi, FAULT_CHECKPOINT);
			f2fs_stop_checkpoint(sbi, false);
		}

		if (!sb_start_write_trylock(sbi->sb)) {
			stat_other_skip_bggc_count(sbi);
			continue;
		}

		if (sbi->gc_mode == GC_URGENT_HIGH) {
			wait_ms = gc_th->urgent_sleep_time;
			down_write(&sbi->gc_lock);
			goto do_gc;
		}

		if (!down_write_trylock(&sbi->gc_lock)) {
			stat_other_skip_bggc_count(sbi);
			goto next;
		}

		if (!is_idle(sbi, GC_TIME)) {
			increase_sleep_time(gc_th, &wait_ms);
			up_write(&sbi->gc_lock);
			stat_io_skip_bggc_count(sbi);
			goto next;
		}

		if (has_enough_invalid_blocks(sbi))
			decrease_sleep_time(gc_th, &wait_ms);
		else
			increase_sleep_time(gc_th, &wait_ms);

	do_gc:

		stat_inc_bggc_count(sbi->stat_info);

		sync_mode = F2FS_OPTION(sbi).bggc_mode == BGGC_MODE_SYNC;

		f2dfs_merge_rc_delta_to_base(sbi, false);

		if (f2fs_gc(sbi, sync_mode, true, false, NULL_SEGNO))
			wait_ms = gc_th->no_gc_sleep_time;

		trace_f2fs_background_gc(sbi->sb, wait_ms,
					 prefree_segments(sbi),
					 free_segments(sbi));

		f2fs_balance_fs_bg(sbi, true);

	next:

		sb_end_write(sbi->sb);

	} while (!kthread_should_stop());

	return 0;
}

int f2fs_start_gc_thread(struct f2fs_sb_info *sbi)
{
	struct f2fs_gc_kthread *gc_th;
	dev_t dev = sbi->sb->s_bdev->bd_dev;
	int err	  = 0;

	gc_th = f2fs_kmalloc(sbi, sizeof(struct f2fs_gc_kthread), GFP_KERNEL);
	if (!gc_th) {
		err = -ENOMEM;
		goto out;
	}

	gc_th->urgent_sleep_time = DEF_GC_THREAD_URGENT_SLEEP_TIME;
	gc_th->min_sleep_time	 = DEF_GC_THREAD_MIN_SLEEP_TIME;
	gc_th->max_sleep_time	 = DEF_GC_THREAD_MAX_SLEEP_TIME;
	gc_th->no_gc_sleep_time	 = DEF_GC_THREAD_NOGC_SLEEP_TIME;

	gc_th->gc_wake = 0;

	sbi->gc_thread = gc_th;
	init_waitqueue_head(&sbi->gc_thread->gc_wait_queue_head);
	sbi->gc_thread->f2fs_gc_task = kthread_run(
		gc_thread_func, sbi, "f2fs_gc-%u:%u", MAJOR(dev), MINOR(dev));
	if (IS_ERR(gc_th->f2fs_gc_task)) {
		err = PTR_ERR(gc_th->f2fs_gc_task);
		kfree(gc_th);
		sbi->gc_thread = NULL;
	}
out:
	return err;
}

void f2fs_stop_gc_thread(struct f2fs_sb_info *sbi)
{
	struct f2fs_gc_kthread *gc_th = sbi->gc_thread;
	if (!gc_th)
		return;
	kthread_stop(gc_th->f2fs_gc_task);
	kfree(gc_th);
	sbi->gc_thread = NULL;
}

static int select_gc_type(struct f2fs_sb_info *sbi, int gc_type)
{
	int gc_mode;

	if (gc_type == BG_GC) {
		if (sbi->am.atgc_enabled)
			gc_mode = GC_AT;
		else
			gc_mode = GC_CB;
	} else {
		gc_mode = GC_GREEDY;
	}

	switch (sbi->gc_mode) {
	case GC_IDLE_CB:
		gc_mode = GC_CB;
		break;
	case GC_IDLE_GREEDY:
	case GC_URGENT_HIGH:
		gc_mode = GC_GREEDY;
		break;
	case GC_IDLE_AT:
		gc_mode = GC_AT;
		break;
	}

	return gc_mode;
}

static void select_policy(struct f2fs_sb_info *sbi, int gc_type, int type,
			  struct victim_sel_policy *p)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);

	if (p->alloc_mode == SSR) {
		p->gc_mode	= GC_GREEDY;
		p->dirty_bitmap = dirty_i->dirty_segmap[type];
		p->max_search	= dirty_i->nr_dirty[type];
		p->ofs_unit	= 1;
	} else if (p->alloc_mode == AT_SSR) {
		p->gc_mode	= GC_GREEDY;
		p->dirty_bitmap = dirty_i->dirty_segmap[type];
		p->max_search	= dirty_i->nr_dirty[type];
		p->ofs_unit	= 1;
	} else {
		p->gc_mode  = select_gc_type(sbi, gc_type);
		p->ofs_unit = sbi->segs_per_sec;
		if (__is_large_section(sbi)) {
			p->dirty_bitmap = dirty_i->dirty_secmap;
			p->max_search =
				count_bits(p->dirty_bitmap, 0, MAIN_SECS(sbi));
		} else {
			p->dirty_bitmap = dirty_i->dirty_segmap[DIRTY];
			p->max_search	= dirty_i->nr_dirty[DIRTY];
		}
	}

	if (gc_type != FG_GC && (sbi->gc_mode != GC_URGENT_HIGH) &&
	    (p->gc_mode != GC_AT && p->alloc_mode != AT_SSR) &&
	    p->max_search > sbi->max_victim_search)
		p->max_search = sbi->max_victim_search;

	if (test_opt(sbi, NOHEAP) &&
	    (type == CURSEG_HOT_DATA || IS_NODESEG(type)))
		p->offset = 0;
	else
		p->offset = SIT_I(sbi)->last_victim[p->gc_mode];
}

static unsigned int get_max_cost(struct f2fs_sb_info *sbi,
				 struct victim_sel_policy *p)
{
	if (p->alloc_mode == SSR)
		return sbi->blocks_per_seg;
	else if (p->alloc_mode == AT_SSR)
		return UINT_MAX;

	if (p->gc_mode == GC_GREEDY)
		return 2 * sbi->blocks_per_seg * p->ofs_unit;
	else if (p->gc_mode == GC_CB)
		return UINT_MAX;
	else if (p->gc_mode == GC_AT)
		return UINT_MAX;
	else
		return 0;
}

static unsigned int check_bg_victims(struct f2fs_sb_info *sbi)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	unsigned int secno;

	for_each_set_bit (secno, dirty_i->victim_secmap, MAIN_SECS(sbi)) {
		if (sec_usage_check(sbi, secno))
			continue;
		clear_bit(secno, dirty_i->victim_secmap);
		return GET_SEG_FROM_SEC(sbi, secno);
	}
	return NULL_SEGNO;
}

static unsigned int get_cb_cost(struct f2fs_sb_info *sbi, unsigned int segno)
{
	struct sit_info *sit_i	 = SIT_I(sbi);
	unsigned int secno	 = GET_SEC_FROM_SEG(sbi, segno);
	unsigned int start	 = GET_SEG_FROM_SEC(sbi, secno);
	unsigned long long mtime = 0;
	unsigned int vblocks;
	unsigned char age = 0;
	unsigned char u;
	unsigned int i;
	unsigned int usable_segs_per_sec = f2fs_usable_segs_in_sec(sbi, segno);

	for (i = 0; i < usable_segs_per_sec; i++)
		mtime += get_seg_entry(sbi, start + i)->mtime;
	vblocks = get_valid_blocks(sbi, segno, true);

	mtime	= div_u64(mtime, usable_segs_per_sec);
	vblocks = div_u64(vblocks, usable_segs_per_sec);

	u = (vblocks * 100) >> sbi->log_blocks_per_seg;

	if (mtime < sit_i->min_mtime)
		sit_i->min_mtime = mtime;
	if (mtime > sit_i->max_mtime)
		sit_i->max_mtime = mtime;
	if (sit_i->max_mtime != sit_i->min_mtime)
		age = 100 - div64_u64(100 * (mtime - sit_i->min_mtime),
				      sit_i->max_mtime - sit_i->min_mtime);

	return UINT_MAX - ((100 * (100 - u) * age) / (100 + u));
}

static inline unsigned int get_gc_cost(struct f2fs_sb_info *sbi,
				       unsigned int segno,
				       struct victim_sel_policy *p)
{
	if (p->alloc_mode == SSR)
		return get_seg_entry(sbi, segno)->ckpt_valid_blocks;

	if (p->gc_mode == GC_GREEDY)
		return get_valid_blocks(sbi, segno, true);
	else if (p->gc_mode == GC_CB)
		return get_cb_cost(sbi, segno);

	f2fs_bug_on(sbi, 1);
	return 0;
}

static unsigned int count_bits(const unsigned long *addr, unsigned int offset,
			       unsigned int len)
{
	unsigned int end = offset + len, sum = 0;

	while (offset < end) {
		if (test_bit(offset++, addr))
			++sum;
	}
	return sum;
}

static struct victim_entry *
attach_victim_entry(struct f2fs_sb_info *sbi, unsigned long long mtime,
		    unsigned int segno, struct rb_node *parent,
		    struct rb_node **p, bool left_most)
{
	struct atgc_management *am = &sbi->am;
	struct victim_entry *ve;

	ve = f2fs_kmem_cache_alloc(victim_entry_slab, GFP_NOFS);

	ve->mtime = mtime;
	ve->segno = segno;

	rb_link_node(&ve->rb_node, parent, p);
	rb_insert_color_cached(&ve->rb_node, &am->root, left_most);

	list_add_tail(&ve->list, &am->victim_list);

	am->victim_count++;

	return ve;
}

static void insert_victim_entry(struct f2fs_sb_info *sbi,
				unsigned long long mtime, unsigned int segno)
{
	struct atgc_management *am = &sbi->am;
	struct rb_node **p;
	struct rb_node *parent = NULL;
	bool left_most	       = true;

	p = f2fs_lookup_rb_tree_ext(sbi, &am->root, &parent, mtime, &left_most);
	attach_victim_entry(sbi, mtime, segno, parent, p, left_most);
}

static void add_victim_entry(struct f2fs_sb_info *sbi,
			     struct victim_sel_policy *p, unsigned int segno)
{
	struct sit_info *sit_i	 = SIT_I(sbi);
	unsigned int secno	 = GET_SEC_FROM_SEG(sbi, segno);
	unsigned int start	 = GET_SEG_FROM_SEC(sbi, secno);
	unsigned long long mtime = 0;
	unsigned int i;

	if (unlikely(is_sbi_flag_set(sbi, SBI_CP_DISABLED))) {
		if (p->gc_mode == GC_AT &&
		    get_valid_blocks(sbi, segno, true) == 0)
			return;
	}

	for (i = 0; i < sbi->segs_per_sec; i++)
		mtime += get_seg_entry(sbi, start + i)->mtime;
	mtime = div_u64(mtime, sbi->segs_per_sec);

	if (mtime < sit_i->min_mtime)
		sit_i->min_mtime = mtime;
	if (mtime > sit_i->max_mtime)
		sit_i->max_mtime = mtime;
	if (mtime < sit_i->dirty_min_mtime)
		sit_i->dirty_min_mtime = mtime;
	if (mtime > sit_i->dirty_max_mtime)
		sit_i->dirty_max_mtime = mtime;

	if (sit_i->dirty_max_mtime - mtime < p->age_threshold)
		return;

	insert_victim_entry(sbi, mtime, segno);
}

static struct rb_node *lookup_central_victim(struct f2fs_sb_info *sbi,
					     struct victim_sel_policy *p)
{
	struct atgc_management *am = &sbi->am;
	struct rb_node *parent	   = NULL;
	bool left_most;

	f2fs_lookup_rb_tree_ext(sbi, &am->root, &parent, p->age, &left_most);

	return parent;
}

static void atgc_lookup_victim(struct f2fs_sb_info *sbi,
			       struct victim_sel_policy *p)
{
	struct sit_info *sit_i	    = SIT_I(sbi);
	struct atgc_management *am  = &sbi->am;
	struct rb_root_cached *root = &am->root;
	struct rb_node *node;
	struct rb_entry *re;
	struct victim_entry *ve;
	unsigned long long total_time;
	unsigned long long age, u, accu;
	unsigned long long max_mtime = sit_i->dirty_max_mtime;
	unsigned long long min_mtime = sit_i->dirty_min_mtime;
	unsigned int sec_blocks	     = BLKS_PER_SEC(sbi);
	unsigned int vblocks;
	unsigned int dirty_threshold =
		max(am->max_candidate_count,
		    am->candidate_ratio * am->victim_count / 100);
	unsigned int age_weight = am->age_weight;
	unsigned int cost;
	unsigned int iter = 0;

	if (max_mtime < min_mtime)
		return;

	max_mtime += 1;
	total_time = max_mtime - min_mtime;

	accu = div64_u64(ULLONG_MAX, total_time);
	accu = min_t(unsigned long long, div_u64(accu, 100),
		     DEFAULT_ACCURACY_CLASS);

	node = rb_first_cached(root);
next:
	re = rb_entry_safe(node, struct rb_entry, rb_node);
	if (!re)
		return;

	ve = (struct victim_entry *)re;

	if (ve->mtime >= max_mtime || ve->mtime < min_mtime)
		goto skip;

	age = div64_u64(accu * (max_mtime - ve->mtime), total_time) *
	      age_weight;

	vblocks = get_valid_blocks(sbi, ve->segno, true);
	f2fs_bug_on(sbi, !vblocks || vblocks == sec_blocks);

	u = div64_u64(accu * (sec_blocks - vblocks), sec_blocks) *
	    (100 - age_weight);

	f2fs_bug_on(sbi, age + u >= UINT_MAX);

	cost = UINT_MAX - (age + u);
	iter++;

	if (cost < p->min_cost ||
	    (cost == p->min_cost && age > p->oldest_age)) {
		p->min_cost   = cost;
		p->oldest_age = age;
		p->min_segno  = ve->segno;
	}
skip:
	if (iter < dirty_threshold) {
		node = rb_next(node);
		goto next;
	}
}

static void atssr_lookup_victim(struct f2fs_sb_info *sbi,
				struct victim_sel_policy *p)
{
	struct sit_info *sit_i	   = SIT_I(sbi);
	struct atgc_management *am = &sbi->am;
	struct rb_node *node;
	struct rb_entry *re;
	struct victim_entry *ve;
	unsigned long long age;
	unsigned long long max_mtime = sit_i->dirty_max_mtime;
	unsigned long long min_mtime = sit_i->dirty_min_mtime;
	unsigned int seg_blocks	     = sbi->blocks_per_seg;
	unsigned int vblocks;
	unsigned int dirty_threshold =
		max(am->max_candidate_count,
		    am->candidate_ratio * am->victim_count / 100);
	unsigned int cost;
	unsigned int iter = 0;
	int stage	  = 0;

	if (max_mtime < min_mtime)
		return;
	max_mtime += 1;
next_stage:
	node = lookup_central_victim(sbi, p);
next_node:
	re = rb_entry_safe(node, struct rb_entry, rb_node);
	if (!re) {
		if (stage == 0)
			goto skip_stage;
		return;
	}

	ve = (struct victim_entry *)re;

	if (ve->mtime >= max_mtime || ve->mtime < min_mtime)
		goto skip_node;

	age = max_mtime - ve->mtime;

	vblocks = get_seg_entry(sbi, ve->segno)->ckpt_valid_blocks;
	f2fs_bug_on(sbi, !vblocks);

	if (vblocks == seg_blocks)
		goto skip_node;

	iter++;

	age  = max_mtime - abs(p->age - age);
	cost = UINT_MAX - vblocks;

	if (cost < p->min_cost ||
	    (cost == p->min_cost && age > p->oldest_age)) {
		p->min_cost   = cost;
		p->oldest_age = age;
		p->min_segno  = ve->segno;
	}
skip_node:
	if (iter < dirty_threshold) {
		if (stage == 0)
			node = rb_prev(node);
		else if (stage == 1)
			node = rb_next(node);
		goto next_node;
	}
skip_stage:
	if (stage < 1) {
		stage++;
		iter = 0;
		goto next_stage;
	}
}
static void lookup_victim_by_age(struct f2fs_sb_info *sbi,
				 struct victim_sel_policy *p)
{
	f2fs_bug_on(sbi,
		    !f2fs_check_rb_tree_consistence(sbi, &sbi->am.root, true));

	if (p->gc_mode == GC_AT)
		atgc_lookup_victim(sbi, p);
	else if (p->alloc_mode == AT_SSR)
		atssr_lookup_victim(sbi, p);
	else
		f2fs_bug_on(sbi, 1);
}

static void release_victim_entry(struct f2fs_sb_info *sbi)
{
	struct atgc_management *am = &sbi->am;
	struct victim_entry *ve, *tmp;

	list_for_each_entry_safe (ve, tmp, &am->victim_list, list) {
		list_del(&ve->list);
		kmem_cache_free(victim_entry_slab, ve);
		am->victim_count--;
	}

	am->root = RB_ROOT_CACHED;

	f2fs_bug_on(sbi, am->victim_count);
	f2fs_bug_on(sbi, !list_empty(&am->victim_list));
}

static int get_victim_by_default(struct f2fs_sb_info *sbi, unsigned int *result,
				 int gc_type, int type, char alloc_mode,
				 unsigned long long age)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	struct sit_info *sm		   = SIT_I(sbi);
	struct victim_sel_policy p;
	unsigned int secno, last_victim;
	unsigned int last_segment;
	unsigned int nsearched;
	bool is_atgc;
	int ret = 0;

	mutex_lock(&dirty_i->seglist_lock);
	last_segment = MAIN_SECS(sbi) * sbi->segs_per_sec;

	p.alloc_mode	= alloc_mode;
	p.age		= age;
	p.age_threshold = sbi->am.age_threshold;

retry:
	select_policy(sbi, gc_type, type, &p);
	p.min_segno  = NULL_SEGNO;
	p.oldest_age = 0;
	p.min_cost   = get_max_cost(sbi, &p);

	is_atgc	  = (p.gc_mode == GC_AT || p.alloc_mode == AT_SSR);
	nsearched = 0;

	if (is_atgc)
		SIT_I(sbi)->dirty_min_mtime = ULLONG_MAX;

	if (*result != NULL_SEGNO) {
		if (!get_valid_blocks(sbi, *result, false)) {
			ret = -ENODATA;
			goto out;
		}

		if (sec_usage_check(sbi, GET_SEC_FROM_SEG(sbi, *result)))
			ret = -EBUSY;
		else
			p.min_segno = *result;
		goto out;
	}

	ret = -ENODATA;
	if (p.max_search == 0)
		goto out;

	if (__is_large_section(sbi) && p.alloc_mode == LFS) {
		if (sbi->next_victim_seg[BG_GC] != NULL_SEGNO) {
			p.min_segno = sbi->next_victim_seg[BG_GC];
			*result	    = p.min_segno;
			sbi->next_victim_seg[BG_GC] = NULL_SEGNO;
			goto got_result;
		}
		if (gc_type == FG_GC &&
		    sbi->next_victim_seg[FG_GC] != NULL_SEGNO) {
			p.min_segno = sbi->next_victim_seg[FG_GC];
			*result	    = p.min_segno;
			sbi->next_victim_seg[FG_GC] = NULL_SEGNO;
			goto got_result;
		}
	}

	last_victim = sm->last_victim[p.gc_mode];
	if (p.alloc_mode == LFS && gc_type == FG_GC) {
		p.min_segno = check_bg_victims(sbi);
		if (p.min_segno != NULL_SEGNO)
			goto got_it;
	}

	while (1) {
		unsigned long cost, *dirty_bitmap;
		unsigned int unit_no, segno;

		dirty_bitmap = p.dirty_bitmap;
		unit_no = find_next_bit(dirty_bitmap, last_segment / p.ofs_unit,
					p.offset / p.ofs_unit);
		segno	= unit_no * p.ofs_unit;
		if (segno >= last_segment) {
			if (sm->last_victim[p.gc_mode]) {
				last_segment = sm->last_victim[p.gc_mode];
				sm->last_victim[p.gc_mode] = 0;
				p.offset		   = 0;
				continue;
			}
			break;
		}

		p.offset = segno + p.ofs_unit;
		nsearched++;

#ifdef CONFIG_F2FS_CHECK_FS

		if (test_bit(segno, sm->invalid_segmap))
			goto next;
#endif

		secno = GET_SEC_FROM_SEG(sbi, segno);

		if (sec_usage_check(sbi, secno))
			goto next;

		if (unlikely(is_sbi_flag_set(sbi, SBI_CP_DISABLED))) {
			if (p.alloc_mode == LFS) {
				if (get_ckpt_valid_blocks(sbi, segno, true))
					goto next;
			} else {
				if (!f2fs_segment_has_free_slot(sbi, segno))
					goto next;
			}
		}

		if (gc_type == BG_GC && test_bit(secno, dirty_i->victim_secmap))
			goto next;

		if (is_atgc) {
			add_victim_entry(sbi, &p, segno);
			goto next;
		}

		cost = get_gc_cost(sbi, segno, &p);

		if (p.min_cost > cost) {
			p.min_segno = segno;
			p.min_cost  = cost;
		}
	next:
		if (nsearched >= p.max_search) {
			if (!sm->last_victim[p.gc_mode] && segno <= last_victim)
				sm->last_victim[p.gc_mode] =
					last_victim + p.ofs_unit;
			else
				sm->last_victim[p.gc_mode] = segno + p.ofs_unit;
			sm->last_victim[p.gc_mode] %=
				(MAIN_SECS(sbi) * sbi->segs_per_sec);
			break;
		}
	}

	if (is_atgc) {
		lookup_victim_by_age(sbi, &p);
		release_victim_entry(sbi);
	}

	if (is_atgc && p.min_segno == NULL_SEGNO &&
	    sm->elapsed_time < p.age_threshold) {
		p.age_threshold = 0;
		goto retry;
	}

	if (p.min_segno != NULL_SEGNO) {
	got_it:
		*result = (p.min_segno / p.ofs_unit) * p.ofs_unit;
	got_result:
		if (p.alloc_mode == LFS) {
			secno = GET_SEC_FROM_SEG(sbi, p.min_segno);
			if (gc_type == FG_GC)
				sbi->cur_victim_sec = secno;
			else
				set_bit(secno, dirty_i->victim_secmap);
		}
		ret = 0;
	}
out:
	if (p.min_segno != NULL_SEGNO)
		trace_f2fs_get_victim(sbi->sb, type, gc_type, &p,
				      sbi->cur_victim_sec,
				      prefree_segments(sbi),
				      free_segments(sbi));
	mutex_unlock(&dirty_i->seglist_lock);

	return ret;
}

static const struct victim_selection default_v_ops = {
	.get_victim = get_victim_by_default,
};

static struct inode *find_gc_inode(struct gc_inode_list *gc_list, nid_t ino)
{
	struct inode_entry *ie;

	ie = radix_tree_lookup(&gc_list->iroot, ino);
	if (ie)
		return ie->inode;
	return NULL;
}

static void add_gc_inode(struct gc_inode_list *gc_list, struct inode *inode)
{
	struct inode_entry *new_ie;

	if (inode == find_gc_inode(gc_list, inode->i_ino)) {
		iput(inode);
		return;
	}
	new_ie	      = f2fs_kmem_cache_alloc(f2fs_inode_entry_slab, GFP_NOFS);
	new_ie->inode = inode;

	f2fs_radix_tree_insert(&gc_list->iroot, inode->i_ino, new_ie);
	list_add_tail(&new_ie->list, &gc_list->ilist);
}

static void put_gc_inode(struct gc_inode_list *gc_list)
{
	struct inode_entry *ie, *next_ie;
	list_for_each_entry_safe (ie, next_ie, &gc_list->ilist, list) {
		radix_tree_delete(&gc_list->iroot, ie->inode->i_ino);
		iput(ie->inode);
		list_del(&ie->list);
		kmem_cache_free(f2fs_inode_entry_slab, ie);
	}
}

static int check_valid_map(struct f2fs_sb_info *sbi, unsigned int segno,
			   int offset)
{
	struct sit_info *sit_i = SIT_I(sbi);
	struct seg_entry *sentry;
	int ret;

	down_read(&sit_i->sentry_lock);
	sentry = get_seg_entry(sbi, segno);
	ret    = f2fs_test_bit(offset, sentry->cur_valid_map);
	up_read(&sit_i->sentry_lock);
	return ret;
}

static int gc_node_segment(struct f2fs_sb_info *sbi, struct f2fs_summary *sum,
			   unsigned int segno, int gc_type)
{
	struct f2fs_summary *entry;
	block_t start_addr;
	int off;
	int phase			= 0;
	bool fggc			= (gc_type == FG_GC);
	int submitted			= 0;
	unsigned int usable_blks_in_seg = f2fs_usable_blks_in_seg(sbi, segno);

	start_addr = START_BLOCK(sbi, segno);

next_step:
	entry = sum;

	if (fggc && phase == 2)
		atomic_inc(&sbi->wb_sync_req[NODE]);

	for (off = 0; off < usable_blks_in_seg; off++, entry++) {
		nid_t nid = le32_to_cpu(entry->nid);
		struct page *node_page;
		struct node_info ni;
		int err;

		if (gc_type == BG_GC && has_not_enough_free_secs(sbi, 0, 0))
			return submitted;

		if (check_valid_map(sbi, segno, off) == 0)
			continue;

		if (phase == 0) {
			f2fs_ra_meta_pages(sbi, NAT_BLOCK_OFFSET(nid), 1,
					   META_NAT, true);
			continue;
		}

		if (phase == 1) {
			f2fs_ra_node_page(sbi, nid);
			continue;
		}

		node_page = f2fs_get_node_page(sbi, nid);
		if (IS_ERR(node_page))
			continue;

		if (check_valid_map(sbi, segno, off) == 0) {
			f2fs_put_page(node_page, 1);
			continue;
		}

		if (f2fs_get_node_info(sbi, nid, &ni)) {
			f2fs_put_page(node_page, 1);
			continue;
		}

		if (ni.blk_addr != start_addr + off) {
			f2fs_put_page(node_page, 1);
			continue;
		}

		err = f2fs_move_node_page(node_page, gc_type);
		if (!err && gc_type == FG_GC)
			submitted++;
		stat_inc_node_blk_count(sbi, 1, gc_type);
	}

	if (++phase < 3)
		goto next_step;

	if (fggc)
		atomic_dec(&sbi->wb_sync_req[NODE]);
	return submitted;
}

block_t f2fs_start_bidx_of_node(unsigned int node_ofs, struct inode *inode)
{
	unsigned int indirect_blks = 2 * NIDS_PER_BLOCK + 4;
	unsigned int bidx;

	if (node_ofs == 0)
		return 0;

	if (node_ofs <= 2) {
		bidx = node_ofs - 1;
	} else if (node_ofs <= indirect_blks) {
		int dec = (node_ofs - 4) / (NIDS_PER_BLOCK + 1);
		bidx	= node_ofs - 2 - dec;
	} else {
		int dec = (node_ofs - indirect_blks - 3) / (NIDS_PER_BLOCK + 1);
		bidx	= node_ofs - 5 - dec;
	}
	return bidx * ADDRS_PER_BLOCK(inode) + ADDRS_PER_INODE(inode);
}

static bool is_alive(struct f2fs_sb_info *sbi, struct f2fs_summary *sum,
		     struct node_info *dni, block_t blkaddr, unsigned int *nofs)
{
	struct page *node_page;
	nid_t nid;
	unsigned int ofs_in_node;
	block_t source_blkaddr;

	nid	    = le32_to_cpu(sum->nid);
	ofs_in_node = le16_to_cpu(sum->ofs_in_node);

	node_page = f2fs_get_node_page(sbi, nid);
	if (IS_ERR(node_page))
		return false;

	if (f2fs_get_node_info(sbi, nid, dni)) {
		f2fs_put_page(node_page, 1);
		return false;
	}

	if (sum->version != dni->version) {
		f2fs_warn(sbi, "%s: valid data with mismatched node version.",
			  __func__);
		set_sbi_flag(sbi, SBI_NEED_FSCK);
	}

	*nofs	       = ofs_of_node(node_page);
	source_blkaddr = data_blkaddr(NULL, node_page, ofs_in_node);
	f2fs_put_page(node_page, 1);

	if (source_blkaddr != blkaddr) {
#ifdef CONFIG_F2FS_CHECK_FS
		unsigned int segno   = GET_SEGNO(sbi, blkaddr);
		unsigned long offset = GET_BLKOFF_FROM_SEG0(sbi, blkaddr);

		if (unlikely(check_valid_map(sbi, segno, offset))) {
			if (!test_and_set_bit(segno,
					      SIT_I(sbi)->invalid_segmap)) {
				f2fs_err(
					sbi,
					"mismatched blkaddr %u (source_blkaddr %u) in seg %u\n",
					blkaddr, source_blkaddr, segno);
				f2fs_bug_on(sbi, 1);
			}
		}
#endif
		return false;
	}
	return true;
}

static int ra_data_block(struct inode *inode, pgoff_t index)
{
	struct f2fs_sb_info *sbi      = F2FS_I_SB(inode);
	struct address_space *mapping = inode->i_mapping;
	struct dnode_of_data dn;
	struct page *page;
	struct extent_info ei	= { 0, 0, 0 };
	struct f2fs_io_info fio = {
		.sbi		= sbi,
		.ino		= inode->i_ino,
		.type		= DATA,
		.temp		= COLD,
		.op		= REQ_OP_READ,
		.op_flags	= 0,
		.encrypted_page = NULL,
		.in_list	= false,
		.retry		= false,
	};
	int err;

	page = f2fs_grab_cache_page(mapping, index, true);
	if (!page)
		return -ENOMEM;

	if (f2fs_lookup_extent_cache(inode, index, &ei)) {
		dn.vaddr	= ei.blk + index - ei.fofs;
		dn.data_blkaddr = f2dfs_address_translation(sbi, dn.vaddr);

		if (unlikely(!f2fs_is_valid_blkaddr(
			    sbi, dn.data_blkaddr, DATA_GENERIC_ENHANCE_READ))) {
			err = -EFSCORRUPTED;
			goto put_page;
		}
		goto got_it;
	}

	set_new_dnode(&dn, inode, NULL, NULL, 0);
	err = f2fs_get_dnode_of_data(&dn, index, LOOKUP_NODE, true);
	if (err)
		goto put_page;
	f2fs_put_dnode(&dn);

	if (!__is_valid_data_blkaddr(dn.data_blkaddr)) {
		err = -ENOENT;
		goto put_page;
	}
	if (unlikely(!f2fs_is_valid_blkaddr(sbi, dn.data_blkaddr,
					    DATA_GENERIC_ENHANCE))) {
		err = -EFSCORRUPTED;
		goto put_page;
	}
got_it:

	fio.page	= page;
	fio.new_blkaddr = fio.old_blkaddr = dn.data_blkaddr;

	f2fs_wait_on_page_writeback(page, DATA, true, true);

	f2fs_wait_on_block_writeback(inode, dn.data_blkaddr);

	fio.encrypted_page =
		f2fs_pagecache_get_page(META_MAPPING(sbi), dn.data_blkaddr,
					FGP_LOCK | FGP_CREAT, GFP_NOFS);
	if (!fio.encrypted_page) {
		err = -ENOMEM;
		goto put_page;
	}

	err = f2fs_submit_page_bio(&fio);
	if (err)
		goto put_encrypted_page;
	f2fs_put_page(fio.encrypted_page, 0);
	f2fs_put_page(page, 1);

	f2fs_update_iostat(sbi, FS_DATA_READ_IO, F2FS_BLKSIZE);
	f2fs_update_iostat(sbi, FS_GDATA_READ_IO, F2FS_BLKSIZE);

	return 0;
put_encrypted_page:
	f2fs_put_page(fio.encrypted_page, 1);
put_page:
	f2fs_put_page(page, 1);
	return err;
}

static int move_data_block(struct inode *inode, block_t bidx, int gc_type,
			   unsigned int segno, int off)
{
	struct f2fs_io_info fio = {
		.sbi		= F2FS_I_SB(inode),
		.ino		= inode->i_ino,
		.type		= DATA,
		.temp		= COLD,
		.op		= REQ_OP_READ,
		.op_flags	= 0,
		.encrypted_page = NULL,
		.in_list	= false,
		.retry		= false,
	};
	struct dnode_of_data dn;
	struct f2fs_summary sum;
	struct node_info ni;
	struct page *page, *mpage;
	block_t newaddr;
	int err	      = 0;
	bool lfs_mode = f2fs_lfs_mode(fio.sbi);
	int type      = fio.sbi->am.atgc_enabled ? CURSEG_ALL_DATA_ATGC :
						   CURSEG_COLD_DATA;

	page = f2fs_grab_cache_page(inode->i_mapping, bidx, false);
	if (!page)
		return -ENOMEM;

	if (!check_valid_map(F2FS_I_SB(inode), segno, off)) {
		err = -ENOENT;
		goto out;
	}

	if (f2fs_is_atomic_file(inode)) {
		F2FS_I(inode)->i_gc_failures[GC_FAILURE_ATOMIC]++;
		F2FS_I_SB(inode)->skipped_atomic_files[gc_type]++;
		err = -EAGAIN;
		goto out;
	}

	if (f2fs_is_pinned_file(inode)) {
		f2fs_pin_file_control(inode, true);
		err = -EAGAIN;
		goto out;
	}

	set_new_dnode(&dn, inode, NULL, NULL, 0);
	err = f2fs_get_dnode_of_data(&dn, bidx, LOOKUP_NODE, true);
	if (err)
		goto out;

	if (unlikely(dn.data_blkaddr == NULL_ADDR)) {
		ClearPageUptodate(page);
		err = -ENOENT;
		goto put_out;
	}

	f2fs_wait_on_page_writeback(page, DATA, true, true);

	f2fs_wait_on_block_writeback(inode, dn.data_blkaddr);

	err = f2fs_get_node_info(fio.sbi, dn.nid, &ni);
	if (err)
		goto put_out;

	set_summary(&sum, dn.nid, dn.ofs_in_node, ni.version);

	fio.page	= page;
	fio.new_blkaddr = fio.old_blkaddr = dn.data_blkaddr;

	if (lfs_mode)
		down_write(&fio.sbi->io_order_lock);

	mpage = f2fs_grab_cache_page(META_MAPPING(fio.sbi), fio.old_blkaddr,
				     false);
	if (!mpage) {
		err = -ENOMEM;
		goto up_out;
	}

	fio.encrypted_page = mpage;

	if (!PageUptodate(mpage)) {
		err = f2fs_submit_page_bio(&fio);
		if (err) {
			f2fs_put_page(mpage, 1);
			goto up_out;
		}

		f2fs_update_iostat(fio.sbi, FS_DATA_READ_IO, F2FS_BLKSIZE);
		f2fs_update_iostat(fio.sbi, FS_GDATA_READ_IO, F2FS_BLKSIZE);

		lock_page(mpage);
		if (unlikely(mpage->mapping != META_MAPPING(fio.sbi) ||
			     !PageUptodate(mpage))) {
			err = -EIO;
			f2fs_put_page(mpage, 1);
			goto up_out;
		}
	}

	f2fs_allocate_data_block(fio.sbi, NULL, fio.old_blkaddr, &newaddr, &sum,
				 type, NULL);

	fio.encrypted_page = f2fs_pagecache_get_page(
		META_MAPPING(fio.sbi), newaddr, FGP_LOCK | FGP_CREAT, GFP_NOFS);
	if (!fio.encrypted_page) {
		err = -ENOMEM;
		f2fs_put_page(mpage, 1);
		goto recover_block;
	}

	f2fs_wait_on_page_writeback(fio.encrypted_page, DATA, true, true);
	memcpy(page_address(fio.encrypted_page), page_address(mpage),
	       PAGE_SIZE);
	f2fs_put_page(mpage, 1);
	invalidate_mapping_pages(META_MAPPING(fio.sbi), fio.old_blkaddr,
				 fio.old_blkaddr);

	set_page_dirty(fio.encrypted_page);
	if (clear_page_dirty_for_io(fio.encrypted_page))
		dec_page_count(fio.sbi, F2FS_DIRTY_META);

	set_page_writeback(fio.encrypted_page);
	ClearPageError(page);

	f2fs_wait_on_page_writeback(dn.node_page, NODE, true, true);

	fio.op		= REQ_OP_WRITE;
	fio.op_flags	= REQ_SYNC;
	fio.new_blkaddr = newaddr;
	f2fs_submit_page_write(&fio);
	if (fio.retry) {
		err = -EAGAIN;
		if (PageWriteback(fio.encrypted_page))
			end_page_writeback(fio.encrypted_page);
		goto put_page_out;
	}

	f2fs_update_iostat(fio.sbi, FS_GC_DATA_IO, F2FS_BLKSIZE);

	f2fs_update_data_blkaddr(&dn, newaddr, true);
	set_inode_flag(inode, FI_APPEND_WRITE);
	if (page->index == 0)
		set_inode_flag(inode, FI_FIRST_BLOCK_WRITTEN);
put_page_out:
	f2fs_put_page(fio.encrypted_page, 1);
recover_block:
	if (err)
		f2fs_do_replace_block(fio.sbi, &sum, newaddr, fio.old_blkaddr,
				      true, true, true);
up_out:
	if (lfs_mode)
		up_write(&fio.sbi->io_order_lock);
put_out:
	f2fs_put_dnode(&dn);
out:
	f2fs_put_page(page, 1);
	return err;
}

static int move_data_page(struct inode *inode, block_t bidx, int gc_type,
			  unsigned int segno, int off)
{
	struct page *page;
	int err = 0;

	page = f2fs_get_lock_data_page(inode, bidx, true);
	if (IS_ERR(page))
		return PTR_ERR(page);

	if (!check_valid_map(F2FS_I_SB(inode), segno, off)) {
		err = -ENOENT;
		goto out;
	}

	if (f2fs_is_atomic_file(inode)) {
		F2FS_I(inode)->i_gc_failures[GC_FAILURE_ATOMIC]++;
		F2FS_I_SB(inode)->skipped_atomic_files[gc_type]++;
		err = -EAGAIN;
		goto out;
	}

	if (f2fs_is_pinned_file(inode)) {
		if (gc_type == FG_GC)
			f2fs_pin_file_control(inode, true);
		err = -EAGAIN;
		goto out;
	}

	if (gc_type == BG_GC) {
		if (PageWriteback(page)) {
			err = -EAGAIN;
			goto out;
		}
		set_page_dirty(page);
		set_cold_data(page);
	} else {
		struct f2fs_io_info fio = {
			.sbi		= F2FS_I_SB(inode),
			.ino		= inode->i_ino,
			.type		= DATA,
			.temp		= COLD,
			.op		= REQ_OP_WRITE,
			.op_flags	= REQ_SYNC,
			.old_blkaddr	= NULL_ADDR,
			.page		= page,
			.encrypted_page = NULL,
			.need_lock	= LOCK_REQ,
			.io_type	= FS_GC_DATA_IO,
		};
		bool is_dirty			      = PageDirty(page);
		struct f2dfs_global_counter g_counter = {
			.valid_rc_change  = 0,
			.unique_rc_change = 0,
			.dupl_rc_change	  = 0,
			.zero_rc_change	  = 0,
		};

	retry:
		f2fs_wait_on_page_writeback(page, DATA, true, true);

		set_page_dirty(page);
		if (clear_page_dirty_for_io(page)) {
			inode_dec_dirty_pages(inode);
			f2fs_remove_dirty_inode(inode);
		}

		set_cold_data(page);

		err = f2fs_do_write_data_page(&fio, &g_counter);
		if (err) {
			clear_cold_data(page);
			if (err == -ENOMEM) {
				congestion_wait(BLK_RW_ASYNC,
						DEFAULT_IO_TIMEOUT);
				goto retry;
			}
			if (is_dirty)
				set_page_dirty(page);
		}
	}
out:
	f2fs_put_page(page, 1);
	return err;
}

#ifdef CONFIG_F2FS_FS_DEDUP

static inline void f2dfs_do_write_gc_page(struct f2fs_io_info *fio,
					  virtual_t vaddr, bool is_bggc)
{
	struct f2fs_summary sum;

	set_summary(&sum, vaddr, SSA_VIRTUAL_ADDR, 0);

	do_write_page(&sum, fio);

	f2fs_update_iostat(fio->sbi, fio->io_type, F2FS_BLKSIZE);

	invalidate_mapping_pages(GC_MAPPING(fio->sbi), vaddr, vaddr);
}

static inline int __write_gc_page(struct page *page, bool *submitted,
				  struct writeback_control *wbc,
				  enum iostat_type io_type, virtual_t vaddr,
				  bool is_bggc)
{
	struct f2fs_sb_info *sbi = F2FS_P_SB(page);
	struct node_info ni;
	struct f2fs_io_info fio = {

		.sbi		= sbi,
		.ino		= F2FS_GC_INO(sbi),
		.type		= DATA,
		.temp		= COLD,
		.op		= REQ_OP_WRITE,
		.op_flags	= wbc_to_write_flags(wbc),
		.page		= page,
		.encrypted_page = NULL,
		.submitted	= false,
		.io_type	= io_type,
		.io_wbc		= wbc,
	};

	if (is_bggc)
		vaddr = le32_to_cpu(page->index);

	trace_f2fs_writepage(page, DATA);

	if (unlikely(f2fs_cp_error(sbi))) {
		if (is_sbi_flag_set(sbi, SBI_IS_CLOSE)) {
			ClearPageUptodate(page);
			dec_page_count(sbi, F2FS_DIRTY_DATA);
			unlock_page(page);
			return 0;
		}
		goto redirty_out;
	}

	if (unlikely(is_sbi_flag_set(sbi, SBI_POR_DOING)))
		goto redirty_out;

	if (f2dfs_get_virtual_address_info(sbi, vaddr, &ni))
		goto redirty_out;

	if (unlikely(ni.blk_addr == NULL_ADDR)) {
		ClearPageUptodate(page);
		dec_page_count(sbi, F2FS_DIRTY_DATA);
		unlock_page(page);
		return 0;
	}

	if (__is_valid_data_blkaddr(ni.blk_addr) &&
	    !f2fs_is_valid_blkaddr(sbi, ni.blk_addr, DATA_GENERIC_ENHANCE))
		goto redirty_out;

	set_page_writeback(page);
	ClearPageError(page);

	fio.old_blkaddr = ni.blk_addr;
	f2dfs_do_write_gc_page(&fio, vaddr, is_bggc);
	set_virtual_blkaddr(sbi, &ni, fio.new_blkaddr, false);
	dec_page_count(sbi, F2FS_DIRTY_DATA);

	if (wbc->for_reclaim) {
		f2fs_submit_merged_write_cond(sbi, NULL, page, 0, DATA);
		submitted = NULL;
	}

	unlock_page(page);

	if (unlikely(f2fs_cp_error(sbi))) {
		f2fs_submit_merged_write(sbi, DATA);
		submitted = NULL;
	}

	if (submitted)
		*submitted = fio.submitted;

	return 0;

redirty_out:

	redirty_page_for_writepage(wbc, page);
	return AOP_WRITEPAGE_ACTIVATE;
}

static int f2dfs_move_gc_page(struct page *data_page, int gc_type,
			      virtual_t virtual_addr)
{
	int err = 0;

	if (gc_type == FG_GC) {
		struct writeback_control wbc = {

			.sync_mode   = WB_SYNC_ALL,
			.nr_to_write = 1,
			.for_reclaim = 0,
		};

		f2fs_wait_on_page_writeback(data_page, DATA, true, true);

		set_page_dirty(data_page);

		if (!clear_page_dirty_for_io(data_page)) {
			err = -EAGAIN;
			goto out_page;
		}

		if (__write_gc_page(data_page, NULL, &wbc, FS_DATA_IO,
				    virtual_addr, false)) {
			err = -EAGAIN;
			unlock_page(data_page);
		}

		goto release_page;
	} else {
		if (!PageWriteback(data_page))
			set_page_dirty(data_page);
	}

out_page:
	unlock_page(data_page);

release_page:
	f2fs_put_page(data_page, 0);
	return err;
}

static int read_gc_page(struct page *page, virtual_t virtual_addr, int op_flags)
{
	struct f2fs_sb_info *sbi = F2FS_P_SB(page);
	block_t block_addr;
	struct f2fs_io_info fio = {

		.sbi		= sbi,
		.ino		= F2FS_GC_INO(sbi),
		.type		= NODE,
		.op		= REQ_OP_READ,
		.op_flags	= op_flags,
		.page		= page,
		.encrypted_page = NULL,
	};
	int err;

	if (PageUptodate(page))
		return LOCKED_PAGE;

	block_addr = f2dfs_address_translation(sbi, virtual_addr);

	if (!__is_valid_data_blkaddr(block_addr) ||
	    le32_to_cpu(page->index) != virtual_addr)
		return -ENOENT;

	if (unlikely(block_addr == NULL_ADDR) ||
	    is_sbi_flag_set(sbi, SBI_IS_SHUTDOWN)) {
		ClearPageUptodate(page);
		return -ENOENT;
	}

	fio.new_blkaddr = fio.old_blkaddr = block_addr;

	err = f2fs_submit_page_bio(&fio);

	if (!err)
		f2fs_update_iostat(sbi, FS_DATA_READ_IO, F2FS_BLKSIZE);

	return err;
}

static struct page *__get_gc_page(struct f2fs_sb_info *sbi,
				  virtual_t virtual_addr)
{
	struct page *page;
	int err;

	if (!virtual_addr)
		return ERR_PTR(-ENOENT);

	if (f2fs_check_nid_range(sbi, virtual_addr))
		return ERR_PTR(-EINVAL);

repeat:

	page = f2fs_grab_cache_page(GC_MAPPING(sbi), virtual_addr, false);
	if (!page)
		return ERR_PTR(-ENOMEM);

	err = read_gc_page(page, virtual_addr, 0);

	if (err < 0) {
		f2fs_put_page(page, 1);
		return ERR_PTR(err);
	} else if (err == LOCKED_PAGE) {
		err = 0;
		goto page_hit;
	}

	lock_page(page);

	if (unlikely(page->mapping != GC_MAPPING(sbi))) {
		f2fs_put_page(page, 1);
		goto repeat;
	}

	if (unlikely(!PageUptodate(page))) {
		err = -EIO;
		goto out_err;
	}

page_hit:

	return page;

out_err:

	ClearPageUptodate(page);
	f2fs_put_page(page, 1);
	return ERR_PTR(err);
}

static struct page *f2dfs_get_gc_page(struct f2fs_sb_info *sbi, virtual_t vaddr)
{
	return __get_gc_page(sbi, vaddr);
}

#else

static int gc_data_segment(struct f2fs_sb_info *sbi, struct f2fs_summary *sum,
			   struct gc_inode_list *gc_list, unsigned int segno,
			   int gc_type, bool force_migrate)
{
	struct super_block *sb = sbi->sb;
	struct f2fs_summary *entry;
	block_t start_addr;
	int off;
	int phase			= 0;
	int submitted			= 0;
	unsigned int usable_blks_in_seg = f2fs_usable_blks_in_seg(sbi, segno);

	start_addr = START_BLOCK(sbi, segno);

next_step:
	entry = sum;

	for (off = 0; off < usable_blks_in_seg; off++, entry++) {
		struct page *data_page;
		struct inode *inode;
		struct node_info dni;
		unsigned int ofs_in_node, nofs;
		block_t start_bidx;
		nid_t nid = le32_to_cpu(entry->nid);

		if ((gc_type == BG_GC && has_not_enough_free_secs(sbi, 0, 0)) ||
		    (!force_migrate &&
		     get_valid_blocks(sbi, segno, true) == BLKS_PER_SEC(sbi)))
			return submitted;

		if (check_valid_map(sbi, segno, off) == 0)
			continue;

		if (phase == 0) {
			f2fs_ra_meta_pages(sbi, NAT_BLOCK_OFFSET(nid), 1,
					   META_NAT, true);
			continue;
		}

		if (phase == 1) {
			f2fs_ra_node_page(sbi, nid);
			continue;
		}

		if (!is_alive(sbi, entry, &dni, start_addr + off, &nofs))
			continue;

		if (phase == 2) {
			f2fs_ra_node_page(sbi, dni.ino);
			continue;
		}

		ofs_in_node = le16_to_cpu(entry->ofs_in_node);

		if (phase == 3) {
			inode = f2fs_iget(sb, dni.ino);
			if (IS_ERR(inode) || is_bad_inode(inode)) {
				set_sbi_flag(sbi, SBI_NEED_FSCK);
				continue;
			}

			if (!down_write_trylock(
				    &F2FS_I(inode)->i_gc_rwsem[WRITE])) {
				iput(inode);
				sbi->skipped_gc_rwsem++;
				continue;
			}

			start_bidx = f2fs_start_bidx_of_node(nofs, inode) +
				     ofs_in_node;

			if (f2fs_post_read_required(inode)) {
				int err = ra_data_block(inode, start_bidx);

				up_write(&F2FS_I(inode)->i_gc_rwsem[WRITE]);
				if (err) {
					iput(inode);
					continue;
				}
				add_gc_inode(gc_list, inode);
				continue;
			}

			data_page = f2fs_get_read_data_page(inode, start_bidx,
							    REQ_RAHEAD, true);
			up_write(&F2FS_I(inode)->i_gc_rwsem[WRITE]);
			if (IS_ERR(data_page)) {
				iput(inode);
				continue;
			}

			f2fs_put_page(data_page, 0);
			add_gc_inode(gc_list, inode);
			continue;
		}

		inode = find_gc_inode(gc_list, dni.ino);
		if (inode) {
			struct f2fs_inode_info *fi = F2FS_I(inode);
			bool locked		   = false;
			int err;

			if (S_ISREG(inode->i_mode)) {
				if (!down_write_trylock(&fi->i_gc_rwsem[READ]))
					continue;

				if (!down_write_trylock(
					    &fi->i_gc_rwsem[WRITE])) {
					sbi->skipped_gc_rwsem++;
					up_write(&fi->i_gc_rwsem[READ]);
					continue;
				}
				locked = true;

				inode_dio_wait(inode);
			}

			start_bidx = f2fs_start_bidx_of_node(nofs, inode) +
				     ofs_in_node;

			if (f2fs_post_read_required(inode))

				err = move_data_block(inode, start_bidx,
						      gc_type, segno, off);
			else

				err = move_data_page(inode, start_bidx, gc_type,
						     segno, off);

			if (!err && (gc_type == FG_GC ||
				     f2fs_post_read_required(inode)))
				submitted++;

			if (locked) {
				up_write(&fi->i_gc_rwsem[WRITE]);
				up_write(&fi->i_gc_rwsem[READ]);
			}

			stat_inc_data_blk_count(sbi, 1, gc_type);
		}
	}

	if (++phase < 5)
		goto next_step;

	return submitted;
}
#endif

static int __get_victim(struct f2fs_sb_info *sbi, unsigned int *victim,
			int gc_type)
{
	struct sit_info *sit_i = SIT_I(sbi);
	int ret;

	down_write(&sit_i->sentry_lock);

	ret = DIRTY_I(sbi)->v_ops->get_victim(sbi, victim, gc_type,
					      NO_CHECK_TYPE, LFS, 0);

	up_write(&sit_i->sentry_lock);

	return ret;
}

static int f2dfs_gc_data_segment(struct f2fs_sb_info *sbi,
				 struct f2fs_summary *sum,
				 struct gc_inode_list *gc_list,
				 unsigned int segno, int gc_type,
				 bool force_migrate)
{
	struct super_block *sb = sbi->sb;
	struct f2fs_summary *entry;
	block_t start_addr = START_BLOCK(sbi, segno);
	int off;
	int phase			= 0;
	int submitted			= 0;
	unsigned int usable_blks_in_seg = f2fs_usable_blks_in_seg(sbi, segno);

next_step:
	entry = sum;

	for (off = 0; off < usable_blks_in_seg; off++, entry++) {
		nid_t nid = le32_to_cpu(entry->nid);
		struct page *data_page;
		struct inode *inode;
		struct node_info data_ni, dni;
		unsigned int ofs_in_node = le16_to_cpu(entry->ofs_in_node),
			     nofs;
		block_t start_bidx;
		virtual_t vaddr;
		bool is_vaddr = (ofs_in_node == SSA_VIRTUAL_ADDR);
		int err	      = 0;

		if ((gc_type == BG_GC && has_not_enough_free_secs(sbi, 0, 0)) ||
		    (!force_migrate &&
		     get_valid_blocks(sbi, segno, true) == BLKS_PER_SEC(sbi)))
			return submitted;

		if (check_valid_map(sbi, segno, off) == 0)
			continue;

		if (phase == 0) {
			f2fs_ra_meta_pages(sbi, NAT_BLOCK_OFFSET(nid), 1,
					   META_NAT, true);
			continue;
		}

		if (phase == 1) {
			f2dfs_ra_gc_page(sbi, nid);
			continue;
		}

		if (is_vaddr) {
			if (!is_alive(sbi, entry, &dni, start_addr + off,
				      &nofs))
				continue;
		}

		if (phase == 2) {
			if (is_vaddr)
				continue;

			f2fs_ra_node_page(sbi, dni.ino);
			continue;
		}

		if (phase == 3) {
			if (is_vaddr)
				continue;

			inode = f2fs_iget(sb, dni.ino);
			if (IS_ERR(inode) || is_bad_inode(inode)) {
				set_sbi_flag(sbi, SBI_NEED_FSCK);
				continue;
			}

			if (!down_write_trylock(
				    &F2FS_I(inode)->i_gc_rwsem[WRITE])) {
				iput(inode);
				sbi->skipped_gc_rwsem++;
				continue;
			}

			start_bidx = f2fs_start_bidx_of_node(nofs, inode) +
				     ofs_in_node;

			if (f2fs_post_read_required(inode)) {
				int err = ra_data_block(inode, start_bidx);

				up_write(&F2FS_I(inode)->i_gc_rwsem[WRITE]);
				if (err) {
					iput(inode);
					continue;
				}
				add_gc_inode(gc_list, inode);
				continue;
			}

			data_page = f2fs_get_read_data_page(inode, start_bidx,
							    REQ_RAHEAD, true);
			up_write(&F2FS_I(inode)->i_gc_rwsem[WRITE]);
			if (IS_ERR(data_page)) {
				iput(inode);
				continue;
			}

			f2fs_put_page(data_page, 0);
			add_gc_inode(gc_list, inode);
			continue;
		}

		if (is_vaddr) {
			vaddr	  = nid;
			data_page = f2dfs_get_gc_page(sbi, vaddr);

			if (IS_ERR(data_page))
				continue;

			if (check_valid_map(sbi, segno, off) == 0) {
				f2fs_put_page(data_page, 1);
				continue;
			}

			if (f2dfs_get_virtual_address_info(sbi, vaddr,
							   &data_ni)) {
				f2fs_put_page(data_page, 1);
				continue;
			}

			if (data_ni.blk_addr != start_addr + off) {
				f2fs_put_page(data_page, 1);
				continue;
			}

			err = f2dfs_move_gc_page(data_page, gc_type, vaddr);
			if (!err && gc_type == FG_GC)
				submitted++;
			stat_inc_data_blk_count(sbi, 1, gc_type);
		} else {
			inode = find_gc_inode(gc_list, dni.ino);
			if (inode) {
				struct f2fs_inode_info *fi = F2FS_I(inode);
				bool locked		   = false;
				int err;

				if (S_ISREG(inode->i_mode)) {
					if (!down_write_trylock(
						    &fi->i_gc_rwsem[READ]))
						continue;

					if (!down_write_trylock(
						    &fi->i_gc_rwsem[WRITE])) {
						sbi->skipped_gc_rwsem++;
						up_write(&fi->i_gc_rwsem[READ]);
						continue;
					}
					locked = true;

					inode_dio_wait(inode);
				}

				start_bidx =
					f2fs_start_bidx_of_node(nofs, inode) +
					ofs_in_node;

				if (f2fs_post_read_required(inode))

					err = move_data_block(inode, start_bidx,
							      gc_type, segno,
							      off);
				else

					err = move_data_page(inode, start_bidx,
							     gc_type, segno,
							     off);

				if (!err && (gc_type == FG_GC ||
					     f2fs_post_read_required(inode)))
					submitted++;

				if (locked) {
					up_write(&fi->i_gc_rwsem[WRITE]);
					up_write(&fi->i_gc_rwsem[READ]);
				}

				stat_inc_data_blk_count(sbi, 1, gc_type);
			}
		}
	}

	if (++phase < 5)
		goto next_step;

	return submitted;
}

static int do_garbage_collect(struct f2fs_sb_info *sbi,
			      unsigned int start_segno,
			      struct gc_inode_list *gc_list, int gc_type,
			      bool force_migrate)
{
	struct page *sum_page;
	struct f2fs_summary_block *sum;
	struct blk_plug plug;
	unsigned int segno     = start_segno;
	unsigned int end_segno = start_segno + sbi->segs_per_sec;
	int seg_freed = 0, migrated = 0;
	unsigned char type = IS_DATASEG(get_seg_entry(sbi, segno)->type) ?
				     SUM_TYPE_DATA :
				     SUM_TYPE_NODE;
	int submitted	   = 0;

	if (__is_large_section(sbi))
		end_segno = rounddown(end_segno, sbi->segs_per_sec);

	if (f2fs_sb_has_blkzoned(sbi))
		end_segno -=
			sbi->segs_per_sec - f2fs_usable_segs_in_sec(sbi, segno);

	sanity_check_seg_type(sbi, get_seg_entry(sbi, segno)->type);

	if (__is_large_section(sbi))
		f2fs_ra_meta_pages(sbi, GET_SUM_BLOCK(sbi, segno),
				   end_segno - segno, META_SSA, true);

	while (segno < end_segno) {
		sum_page = f2fs_get_sum_page(sbi, segno++);
		if (IS_ERR(sum_page)) {
			int err = PTR_ERR(sum_page);

			end_segno = segno - 1;
			for (segno = start_segno; segno < end_segno; segno++) {
				sum_page = find_get_page(META_MAPPING(sbi),
							 GET_SUM_BLOCK(sbi,
								       segno));
				f2fs_put_page(sum_page, 0);
				f2fs_put_page(sum_page, 0);
			}
			return err;
		}
		unlock_page(sum_page);
	}

	blk_start_plug(&plug);

	for (segno = start_segno; segno < end_segno; segno++) {
		sum_page = find_get_page(META_MAPPING(sbi),
					 GET_SUM_BLOCK(sbi, segno));
		f2fs_put_page(sum_page, 0);

		if (get_valid_blocks(sbi, segno, false) == 0)
			goto freed;

		if (gc_type == BG_GC && __is_large_section(sbi) &&
		    migrated >= sbi->migration_granularity)
			goto skip;

		if (!PageUptodate(sum_page) || unlikely(f2fs_cp_error(sbi)))
			goto skip;

		sum = page_address(sum_page);

		if (type != GET_SUM_TYPE((&sum->footer))) {
			f2fs_err(
				sbi,
				"Inconsistent segment (%u) type [%d, %d] in SSA and SIT",
				segno, type, GET_SUM_TYPE((&sum->footer)));
			set_sbi_flag(sbi, SBI_NEED_FSCK);
			f2fs_stop_checkpoint(sbi, false);
			goto skip;
		}

		if (type == SUM_TYPE_NODE) {
			print_info(PRINT_IMPORTANT_INFO_ENABLED,
				   "GC: migrating NODE segment %u", segno);
			submitted += gc_node_segment(sbi, sum->entries, segno,
						     gc_type);
		} else {
			print_info(PRINT_IMPORTANT_INFO_ENABLED,
				   "GC: migrating DATA segment %u", segno);
			submitted +=
				f2dfs_gc_data_segment(sbi, sum->entries,
						      gc_list, segno, gc_type,
						      force_migrate);
		}

		stat_inc_seg_count(sbi, type, gc_type);
		migrated++;

	freed:

		if (gc_type == FG_GC &&
		    get_valid_blocks(sbi, segno, false) == 0)
			seg_freed++;

		if (__is_large_section(sbi) && segno + 1 < end_segno)
			sbi->next_victim_seg[gc_type] = segno + 1;
	skip:
		f2fs_put_page(sum_page, 0);
	}

	if (submitted)
		f2fs_submit_merged_write(sbi,
					 (type == SUM_TYPE_NODE) ? NODE : DATA);

	blk_finish_plug(&plug);

	stat_inc_call_count(sbi->stat_info);

	return seg_freed;
}

int f2fs_gc(struct f2fs_sb_info *sbi, bool sync, bool background, bool force,
	    unsigned int segno)
{
	int gc_type   = sync ? FG_GC : BG_GC;
	int sec_freed = 0, seg_freed = 0, total_freed = 0;
	int ret = 0;
	struct cp_control cpc;
	unsigned int init_segno	     = segno;
	struct gc_inode_list gc_list = {

		.ilist = LIST_HEAD_INIT(gc_list.ilist),
		.iroot = RADIX_TREE_INIT(gc_list.iroot, GFP_NOFS),
	};
	unsigned long long last_skipped = sbi->skipped_atomic_files[FG_GC];
	unsigned long long first_skipped;
	unsigned int skipped_round = 0, round = 0;

	trace_f2fs_gc_begin(sbi->sb, sync, background,
			    get_pages(sbi, F2FS_DIRTY_NODES),
			    get_pages(sbi, F2FS_DIRTY_DENTS),
			    get_pages(sbi, F2FS_DIRTY_IMETA),
			    free_sections(sbi), free_segments(sbi),
			    reserved_segments(sbi), prefree_segments(sbi));

	cpc.reason	      = __get_cp_reason(sbi);
	sbi->skipped_gc_rwsem = 0;
	first_skipped	      = last_skipped;

gc_more:

	if (unlikely(!(sbi->sb->s_flags & SB_ACTIVE))) {
		ret = -EINVAL;
		goto stop;
	}

	if (unlikely(f2fs_cp_error(sbi))) {
		ret = -EIO;
		goto stop;
	}

	if (gc_type == BG_GC && has_not_enough_free_secs(sbi, 0, 0)) {
		if (prefree_segments(sbi) &&
		    !is_sbi_flag_set(sbi, SBI_CP_DISABLED)) {
			ret = f2fs_write_checkpoint(sbi, &cpc);
			if (ret)
				goto stop;
		}

		if (has_not_enough_free_secs(sbi, 0, 0))
			gc_type = FG_GC;
	}

	if (gc_type == BG_GC && !background) {
		ret = -EINVAL;
		goto stop;
	}

	ret = __get_victim(sbi, &segno, gc_type);
	if (ret)
		goto stop;

	seg_freed = do_garbage_collect(sbi, segno, &gc_list, gc_type, force);

	if (gc_type == FG_GC &&
	    seg_freed == f2fs_usable_segs_in_sec(sbi, segno))
		sec_freed++;

	total_freed += seg_freed;

	if (gc_type == FG_GC) {
		if (sbi->skipped_atomic_files[FG_GC] > last_skipped ||
		    sbi->skipped_gc_rwsem)
			skipped_round++;

		last_skipped = sbi->skipped_atomic_files[FG_GC];
		round++;
	}

	if (gc_type == FG_GC && seg_freed)
		sbi->cur_victim_sec = NULL_SEGNO;

	if (sync)
		goto stop;

	if (has_not_enough_free_secs(sbi, sec_freed, 0)) {
		if (skipped_round <= MAX_SKIP_GC_COUNT ||
		    skipped_round * 2 < round) {
			segno = NULL_SEGNO;
			goto gc_more;
		}

		if (first_skipped < last_skipped &&
		    (last_skipped - first_skipped) > sbi->skipped_gc_rwsem) {
			f2fs_drop_inmem_pages_all(sbi, true);
			segno = NULL_SEGNO;
			goto gc_more;
		}

		if (gc_type == FG_GC && !is_sbi_flag_set(sbi, SBI_CP_DISABLED))
			ret = f2fs_write_checkpoint(sbi, &cpc);
	}

stop:

	SIT_I(sbi)->last_victim[ALLOC_NEXT]   = 0;
	SIT_I(sbi)->last_victim[FLUSH_DEVICE] = init_segno;

	trace_f2fs_gc_end(sbi->sb, ret, total_freed, sec_freed,
			  get_pages(sbi, F2FS_DIRTY_NODES),
			  get_pages(sbi, F2FS_DIRTY_DENTS),
			  get_pages(sbi, F2FS_DIRTY_IMETA), free_sections(sbi),
			  free_segments(sbi), reserved_segments(sbi),
			  prefree_segments(sbi));

	up_write(&sbi->gc_lock);

	put_gc_inode(&gc_list);

	if (sync && !ret)
		ret = sec_freed ? 0 : -EAGAIN;

	return ret;
}

int __init f2fs_create_garbage_collection_cache(void)
{
	victim_entry_slab = f2fs_kmem_cache_create("f2fs_victim_entry",
						   sizeof(struct victim_entry));
	if (!victim_entry_slab)
		return -ENOMEM;
	return 0;
}

void f2fs_destroy_garbage_collection_cache(void)
{
	kmem_cache_destroy(victim_entry_slab);
}

static void init_atgc_management(struct f2fs_sb_info *sbi)
{
	struct atgc_management *am = &sbi->am;

	if (test_opt(sbi, ATGC) &&
	    SIT_I(sbi)->elapsed_time >= DEF_GC_THREAD_AGE_THRESHOLD)
		am->atgc_enabled = true;

	am->root = RB_ROOT_CACHED;
	INIT_LIST_HEAD(&am->victim_list);
	am->victim_count = 0;

	am->candidate_ratio	= DEF_GC_THREAD_CANDIDATE_RATIO;
	am->max_candidate_count = DEF_GC_THREAD_MAX_CANDIDATE_COUNT;
	am->age_weight		= DEF_GC_THREAD_AGE_WEIGHT;
}

void f2fs_build_gc_manager(struct f2fs_sb_info *sbi)
{
	DIRTY_I(sbi)->v_ops = &default_v_ops;

	sbi->gc_pin_file_threshold = DEF_GC_FAILED_PINNED_FILES;

	if (f2fs_is_multi_device(sbi) && !__is_large_section(sbi))
		SIT_I(sbi)->last_victim[ALLOC_NEXT] =
			GET_SEGNO(sbi, FDEV(0).end_blk) + 1;

	init_atgc_management(sbi);
}

static int free_segment_range(struct f2fs_sb_info *sbi, unsigned int secs,
			      bool gc_only)
{
	unsigned int segno, next_inuse, start, end;
	struct cp_control cpc = { CP_RESIZE, 0, 0, 0 };
	int gc_mode, gc_type;
	int err = 0;
	int type;

	MAIN_SECS(sbi) -= secs;
	start = MAIN_SECS(sbi) * sbi->segs_per_sec;
	end   = MAIN_SEGS(sbi) - 1;

	mutex_lock(&DIRTY_I(sbi)->seglist_lock);
	for (gc_mode = 0; gc_mode < MAX_GC_POLICY; gc_mode++)
		if (SIT_I(sbi)->last_victim[gc_mode] >= start)
			SIT_I(sbi)->last_victim[gc_mode] = 0;

	for (gc_type = BG_GC; gc_type <= FG_GC; gc_type++)
		if (sbi->next_victim_seg[gc_type] >= start)
			sbi->next_victim_seg[gc_type] = NULL_SEGNO;
	mutex_unlock(&DIRTY_I(sbi)->seglist_lock);

	for (type = CURSEG_HOT_DATA; type < NR_CURSEG_PERSIST_TYPE; type++)
		f2fs_allocate_segment_for_resize(sbi, type, start, end);

	for (segno = start; segno <= end; segno += sbi->segs_per_sec) {
		struct gc_inode_list gc_list = {
			.ilist = LIST_HEAD_INIT(gc_list.ilist),
			.iroot = RADIX_TREE_INIT(gc_list.iroot, GFP_NOFS),
		};

		do_garbage_collect(sbi, segno, &gc_list, FG_GC, true);
		put_gc_inode(&gc_list);

		if (!gc_only && get_valid_blocks(sbi, segno, true)) {
			err = -EAGAIN;
			goto out;
		}
		if (fatal_signal_pending(current)) {
			err = -ERESTARTSYS;
			goto out;
		}
	}
	if (gc_only)
		goto out;

	err = f2fs_write_checkpoint(sbi, &cpc);
	if (err)
		goto out;

	next_inuse = find_next_inuse(FREE_I(sbi), end + 1, start);
	if (next_inuse <= end) {
		f2fs_err(sbi, "segno %u should be free but still inuse!",
			 next_inuse);
		f2fs_bug_on(sbi, 1);
	}
out:
	MAIN_SECS(sbi) += secs;
	return err;
}

static void update_sb_metadata(struct f2fs_sb_info *sbi, int secs)
{
	struct f2fs_super_block *raw_sb = F2FS_RAW_SUPER(sbi);
	int section_count;
	int segment_count;
	int segment_count_main;
	long long block_count;
	int segs = secs * sbi->segs_per_sec;

	down_write(&sbi->sb_lock);

	section_count	   = le32_to_cpu(raw_sb->section_count);
	segment_count	   = le32_to_cpu(raw_sb->segment_count);
	segment_count_main = le32_to_cpu(raw_sb->segment_count_main);
	block_count	   = le64_to_cpu(raw_sb->block_count);

	raw_sb->section_count	   = cpu_to_le32(section_count + secs);
	raw_sb->segment_count	   = cpu_to_le32(segment_count + segs);
	raw_sb->segment_count_main = cpu_to_le32(segment_count_main + segs);
	raw_sb->block_count	   = cpu_to_le64(
		       block_count + (long long)segs * sbi->blocks_per_seg);
	if (f2fs_is_multi_device(sbi)) {
		int last_dev = sbi->s_ndevs - 1;
		int dev_segs =
			le32_to_cpu(raw_sb->devs[last_dev].total_segments);

		raw_sb->devs[last_dev].total_segments =
			cpu_to_le32(dev_segs + segs);
	}

	up_write(&sbi->sb_lock);
}

static void update_fs_metadata(struct f2fs_sb_info *sbi, int secs)
{
	int segs       = secs * sbi->segs_per_sec;
	long long blks = (long long)segs * sbi->blocks_per_seg;
	long long user_block_count =
		le64_to_cpu(F2FS_CKPT(sbi)->user_block_count);

	SM_I(sbi)->segment_count = (int)SM_I(sbi)->segment_count + segs;
	MAIN_SEGS(sbi)		 = (int)MAIN_SEGS(sbi) + segs;
	MAIN_SECS(sbi) += secs;
	FREE_I(sbi)->free_sections = (int)FREE_I(sbi)->free_sections + secs;
	FREE_I(sbi)->free_segments = (int)FREE_I(sbi)->free_segments + segs;
	F2FS_CKPT(sbi)->user_block_count = cpu_to_le64(user_block_count + blks);

	if (f2fs_is_multi_device(sbi)) {
		int last_dev = sbi->s_ndevs - 1;

		FDEV(last_dev).total_segments =
			(int)FDEV(last_dev).total_segments + segs;
		FDEV(last_dev).end_blk =
			(long long)FDEV(last_dev).end_blk + blks;
#ifdef CONFIG_BLK_DEV_ZONED
		FDEV(last_dev).nr_blkz =
			(int)FDEV(last_dev).nr_blkz +
			(int)(blks >> sbi->log_blocks_per_blkz);
#endif
	}
}

int f2fs_resize_fs(struct f2fs_sb_info *sbi, __u64 block_count)
{
	__u64 old_block_count, shrunk_blocks;
	struct cp_control cpc = { CP_RESIZE, 0, 0, 0 };
	unsigned int secs;
	int err = 0;
	__u32 rem;

	old_block_count = le64_to_cpu(F2FS_RAW_SUPER(sbi)->block_count);
	if (block_count > old_block_count)
		return -EINVAL;

	if (f2fs_is_multi_device(sbi)) {
		int last_dev	= sbi->s_ndevs - 1;
		__u64 last_segs = FDEV(last_dev).total_segments;

		if (block_count + last_segs * sbi->blocks_per_seg <=
		    old_block_count)
			return -EINVAL;
	}

	div_u64_rem(block_count, BLKS_PER_SEC(sbi), &rem);
	if (rem)
		return -EINVAL;

	if (block_count == old_block_count)
		return 0;

	if (is_sbi_flag_set(sbi, SBI_NEED_FSCK)) {
		f2fs_err(sbi, "Should run fsck to repair first.");
		return -EFSCORRUPTED;
	}

	if (test_opt(sbi, DISABLE_CHECKPOINT)) {
		f2fs_err(sbi, "Checkpoint should be enabled.");
		return -EINVAL;
	}

	shrunk_blocks = old_block_count - block_count;
	secs	      = div_u64(shrunk_blocks, BLKS_PER_SEC(sbi));

	if (!down_write_trylock(&sbi->gc_lock))
		return -EAGAIN;

	f2fs_lock_op(sbi);

	spin_lock(&sbi->stat_lock);
	if (shrunk_blocks + valid_user_blocks(sbi) +
		    sbi->current_reserved_blocks + sbi->unusable_block_count +
		    F2FS_OPTION(sbi).root_reserved_blocks >
	    sbi->user_block_count)
		err = -ENOSPC;
	spin_unlock(&sbi->stat_lock);

	if (err)
		goto out_unlock;

	err = free_segment_range(sbi, secs, true);

out_unlock:
	f2fs_unlock_op(sbi);
	up_write(&sbi->gc_lock);
	if (err)
		return err;

	set_sbi_flag(sbi, SBI_IS_RESIZEFS);

	freeze_super(sbi->sb);
	down_write(&sbi->gc_lock);
	mutex_lock(&sbi->cp_mutex);

	spin_lock(&sbi->stat_lock);
	if (shrunk_blocks + valid_user_blocks(sbi) +
		    sbi->current_reserved_blocks + sbi->unusable_block_count +
		    F2FS_OPTION(sbi).root_reserved_blocks >
	    sbi->user_block_count)
		err = -ENOSPC;
	else
		sbi->user_block_count -= shrunk_blocks;
	spin_unlock(&sbi->stat_lock);
	if (err)
		goto out_err;

	err = free_segment_range(sbi, secs, false);
	if (err)
		goto recover_out;

	update_sb_metadata(sbi, -secs);

	err = f2fs_commit_super(sbi, false);
	if (err) {
		update_sb_metadata(sbi, secs);
		goto recover_out;
	}

	update_fs_metadata(sbi, -secs);
	clear_sbi_flag(sbi, SBI_IS_RESIZEFS);
	set_sbi_flag(sbi, SBI_IS_DIRTY);

	err = f2fs_write_checkpoint(sbi, &cpc);
	if (err) {
		update_fs_metadata(sbi, secs);
		update_sb_metadata(sbi, secs);
		f2fs_commit_super(sbi, false);
	}
recover_out:
	if (err) {
		set_sbi_flag(sbi, SBI_NEED_FSCK);
		f2fs_err(sbi, "resize_fs failed, should run fsck to repair!");

		spin_lock(&sbi->stat_lock);
		sbi->user_block_count += shrunk_blocks;
		spin_unlock(&sbi->stat_lock);
	}
out_err:
	mutex_unlock(&sbi->cp_mutex);
	up_write(&sbi->gc_lock);
	thaw_super(sbi->sb);
	clear_sbi_flag(sbi, SBI_IS_RESIZEFS);
	return err;
}

#ifdef CONFIG_F2FS_FS_DEDUP

void f2dfs_clear_gc_page_dirty(struct f2fs_sb_info *sbi, virtual_t vaddr)
{
	struct page *page;

	return;

	if (!__is_valid_data_blkaddr(vaddr))
		goto direct_out;

	page = f2fs_grab_cache_page(GC_MAPPING(sbi), vaddr, false);
	if (!page)
		return;

	if ((page->index != vaddr) || (page->mapping != GC_MAPPING(sbi))) {
		goto not_clear;
	}

	clear_cold_data(page);

	if (PageDirty(page)) {
		f2fs_clear_page_cache_dirty_tag(page);
		clear_page_dirty_for_io(page);

		dec_page_count(sbi, F2FS_DIRTY_DATA);
	}

	ClearPageUptodate(page);

not_clear:

	f2fs_put_page(page, 1);

	invalidate_mapping_pages(GC_MAPPING(sbi), vaddr, vaddr);

direct_out:

	return;
}

static int f2dfs_write_gc_page(struct page *page, struct writeback_control *wbc)
{
	return __write_gc_page(page, NULL, wbc, FS_DATA_IO,
			       le32_to_cpu(page->index), true);
}

int f2dfs_sync_gc_pages(struct f2fs_sb_info *sbi, struct writeback_control *wbc,
			enum iostat_type io_type)
{
	pgoff_t index;
	struct pagevec pvec;
	int step     = 0;
	int nwritten = 0;
	int ret	     = 0;
	int nr_pages, done = 0;

	pagevec_init(&pvec);

next_step:
	index = 0;

	while (!done &&
	       (nr_pages = pagevec_lookup_tag(&pvec, GC_MAPPING(sbi), &index,
					      PAGECACHE_TAG_DIRTY))) {
		int i;

		for (i = 0; i < nr_pages; i++) {
			struct page *page = pvec.pages[i];
			bool submitted	  = false;

			if (atomic_read(&sbi->wb_sync_req[DATA]) &&
			    wbc->sync_mode == WB_SYNC_NONE) {
				done = 1;
				break;
			}

			if (wbc->sync_mode == WB_SYNC_ALL)
				lock_page(page);
			else if (!trylock_page(page))
				continue;

			if (unlikely(page->mapping != GC_MAPPING(sbi))) {
				goto continue_unlock;
			}

			if (!PageDirty(page)) {
				goto continue_unlock;
			}

			f2fs_wait_on_page_writeback(page, DATA, true, true);

			if (!clear_page_dirty_for_io(page))
				goto continue_unlock;

			ret = __write_gc_page(page, &submitted, wbc, io_type,
					      le32_to_cpu(page->index), true);
			if (ret) {
			continue_unlock:
				unlock_page(page);
			} else if (submitted)
				nwritten++;

			if (--wbc->nr_to_write == 0)
				break;
		}

		pagevec_release(&pvec);

		cond_resched();

		if (wbc->nr_to_write == 0) {
			step = 2;
			break;
		}
	}

	if (step < 2) {
		if (!is_sbi_flag_set(sbi, SBI_CP_DISABLED) &&
		    wbc->sync_mode == WB_SYNC_NONE && step == 1)
			goto out;

		step++;
		goto next_step;
	}

out:

	if (nwritten)
		f2fs_submit_merged_write(sbi, DATA);

	if (unlikely(f2fs_cp_error(sbi)))
		return -EIO;

	return ret;
}

static int f2dfs_write_gc_pages(struct address_space *mapping,
				struct writeback_control *wbc)
{
	struct f2fs_sb_info *sbi = F2FS_M_SB(mapping);
	struct blk_plug plug;
	long diff;

	if (unlikely(is_sbi_flag_set(sbi, SBI_POR_DOING)))
		goto skip_write;

	if (wbc->sync_mode != WB_SYNC_ALL &&
	    get_pages(sbi, F2FS_DIRTY_DATA) < nr_pages_to_skip(sbi, DATA))
		goto skip_write;

	if (wbc->sync_mode == WB_SYNC_ALL)
		atomic_inc(&sbi->wb_sync_req[DATA]);
	else if (atomic_read(&sbi->wb_sync_req[DATA]))

		goto skip_write;

	trace_f2fs_writepages(mapping->host, wbc, DATA);

	diff = nr_pages_to_write(sbi, DATA, wbc);

	blk_start_plug(&plug);

	f2dfs_sync_gc_pages(sbi, wbc, FS_DATA_IO);

	blk_finish_plug(&plug);

	wbc->nr_to_write = max((long)0, wbc->nr_to_write - diff);

	if (wbc->sync_mode == WB_SYNC_ALL)
		atomic_dec(&sbi->wb_sync_req[DATA]);

	return 0;

skip_write:

	wbc->pages_skipped += get_pages(sbi, F2FS_DIRTY_DATA);

	trace_f2fs_writepages(mapping->host, wbc, DATA);

	return 0;
}

static int f2dfs_set_gc_page_dirty(struct page *page)
{
	trace_f2fs_set_page_dirty(page, DATA);

	if (!PageUptodate(page))
		SetPageUptodate(page);

	if (!PageDirty(page)) {
		__set_page_dirty_nobuffers(page);

		inc_page_count(F2FS_P_SB(page), F2FS_DIRTY_DATA);

		f2fs_set_page_private(page, 0);

		f2fs_trace_pid(page);

		return 1;
	}

	return 0;
}

const struct address_space_operations f2dfs_gc_aops = {
	.writepage	= f2dfs_write_gc_page,
	.writepages	= f2dfs_write_gc_pages,
	.set_page_dirty = f2dfs_set_gc_page_dirty,
	.invalidatepage = f2fs_invalidate_page,
	.releasepage	= f2fs_release_page,
#ifdef CONFIG_MIGRATION
	.migratepage = f2fs_migrate_page,
#endif
};

#endif
