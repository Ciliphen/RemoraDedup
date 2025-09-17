/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fs/f2fs/segment.h
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 */

#include <linux/blkdev.h>
#include <linux/backing-dev.h>

#define NULL_SEGNO ((unsigned int)(~0))
#define NULL_SECNO ((unsigned int)(~0))

#define DEF_RECLAIM_PREFREE_SEGMENTS	 5
#define DEF_MAX_RECLAIM_PREFREE_SEGMENTS 4096

#define F2FS_MIN_SEGMENTS      9
#define F2FS_MIN_META_SEGMENTS 8

#define GET_L2R_SEGNO(free_i, segno) ((segno) - (free_i)->start_segno)
#define GET_R2L_SEGNO(free_i, segno) ((segno) + (free_i)->start_segno)

#define IS_DATASEG(t) ((t) <= CURSEG_COLD_DATA)
#define IS_NODESEG(t) ((t) >= CURSEG_HOT_NODE && (t) <= CURSEG_COLD_NODE)

static inline void sanity_check_seg_type(struct f2fs_sb_info *sbi,
					 unsigned short seg_type)
{
	f2fs_bug_on(sbi, seg_type >= NR_PERSISTENT_LOG);
}

#define IS_HOT(t)  ((t) == CURSEG_HOT_NODE || (t) == CURSEG_HOT_DATA)
#define IS_WARM(t) ((t) == CURSEG_WARM_NODE || (t) == CURSEG_WARM_DATA)
#define IS_COLD(t) ((t) == CURSEG_COLD_NODE || (t) == CURSEG_COLD_DATA)

#define IS_CURSEG(sbi, seg)                                                    \
	(((seg) == CURSEG_I(sbi, CURSEG_HOT_DATA)->segno) ||                   \
	 ((seg) == CURSEG_I(sbi, CURSEG_WARM_DATA)->segno) ||                  \
	 ((seg) == CURSEG_I(sbi, CURSEG_COLD_DATA)->segno) ||                  \
	 ((seg) == CURSEG_I(sbi, CURSEG_HOT_NODE)->segno) ||                   \
	 ((seg) == CURSEG_I(sbi, CURSEG_WARM_NODE)->segno) ||                  \
	 ((seg) == CURSEG_I(sbi, CURSEG_COLD_NODE)->segno) ||                  \
	 ((seg) == CURSEG_I(sbi, CURSEG_COLD_DATA_PINNED)->segno) ||           \
	 ((seg) == CURSEG_I(sbi, CURSEG_ALL_DATA_ATGC)->segno))

#define IS_CURSEC(sbi, secno)                                                  \
	(((secno) ==                                                           \
	  CURSEG_I(sbi, CURSEG_HOT_DATA)->segno / (sbi)->segs_per_sec) ||      \
	 ((secno) ==                                                           \
	  CURSEG_I(sbi, CURSEG_WARM_DATA)->segno / (sbi)->segs_per_sec) ||     \
	 ((secno) ==                                                           \
	  CURSEG_I(sbi, CURSEG_COLD_DATA)->segno / (sbi)->segs_per_sec) ||     \
	 ((secno) ==                                                           \
	  CURSEG_I(sbi, CURSEG_HOT_NODE)->segno / (sbi)->segs_per_sec) ||      \
	 ((secno) ==                                                           \
	  CURSEG_I(sbi, CURSEG_WARM_NODE)->segno / (sbi)->segs_per_sec) ||     \
	 ((secno) ==                                                           \
	  CURSEG_I(sbi, CURSEG_COLD_NODE)->segno / (sbi)->segs_per_sec) ||     \
	 ((secno) == CURSEG_I(sbi, CURSEG_COLD_DATA_PINNED)->segno /           \
			     (sbi)->segs_per_sec) ||                           \
	 ((secno) ==                                                           \
	  CURSEG_I(sbi, CURSEG_ALL_DATA_ATGC)->segno / (sbi)->segs_per_sec))

#define MAIN_BLKADDR(sbi)                                                      \
	(SM_I(sbi) ? SM_I(sbi)->main_blkaddr :                                 \
		     le32_to_cpu(F2FS_RAW_SUPER(sbi)->main_blkaddr))
#define SEG0_BLKADDR(sbi)                                                      \
	(SM_I(sbi) ? SM_I(sbi)->seg0_blkaddr :                                 \
		     le32_to_cpu(F2FS_RAW_SUPER(sbi)->segment0_blkaddr))

#define MAIN_SEGS(sbi) (SM_I(sbi)->main_segments)
#define MAIN_SECS(sbi) ((sbi)->total_sections)

#define TOTAL_SEGS(sbi)                                                        \
	(SM_I(sbi) ? SM_I(sbi)->segment_count :                                \
		     le32_to_cpu(F2FS_RAW_SUPER(sbi)->segment_count))
#define TOTAL_BLKS(sbi) (TOTAL_SEGS(sbi) << (sbi)->log_blocks_per_seg)

#define MAX_BLKADDR(sbi) (SEG0_BLKADDR(sbi) + TOTAL_BLKS(sbi))
#define SEGMENT_SIZE(sbi)                                                      \
	(1ULL << ((sbi)->log_blocksize + (sbi)->log_blocks_per_seg))

#define START_BLOCK(sbi, segno)                                                \
	(SEG0_BLKADDR(sbi) +                                                   \
	 (GET_R2L_SEGNO(FREE_I(sbi), segno) << (sbi)->log_blocks_per_seg))

#define NEXT_FREE_BLKADDR(sbi, curseg)                                         \
	(START_BLOCK(sbi, (curseg)->segno) + (curseg)->next_blkoff)

#define GET_SEGOFF_FROM_SEG0(sbi, blk_addr) ((blk_addr) - SEG0_BLKADDR(sbi))
#define GET_SEGNO_FROM_SEG0(sbi, blk_addr)                                     \
	(GET_SEGOFF_FROM_SEG0(sbi, blk_addr) >> (sbi)->log_blocks_per_seg)
#define GET_BLKOFF_FROM_SEG0(sbi, blk_addr)                                    \
	(GET_SEGOFF_FROM_SEG0(sbi, blk_addr) & ((sbi)->blocks_per_seg - 1))

#define GET_SEGNO(sbi, blk_addr)                                               \
	((!__is_valid_data_blkaddr(blk_addr)) ?                                \
		 NULL_SEGNO :                                                  \
		 GET_L2R_SEGNO(FREE_I(sbi),                                    \
			       GET_SEGNO_FROM_SEG0(sbi, blk_addr)))
#define BLKS_PER_SEC(sbi) ((sbi)->segs_per_sec * (sbi)->blocks_per_seg)
#define GET_SEC_FROM_SEG(sbi, segno)                                           \
	(((segno) == -1) ? -1 : (segno) / (sbi)->segs_per_sec)
#define GET_SEG_FROM_SEC(sbi, secno) ((secno) * (sbi)->segs_per_sec)
#define GET_ZONE_FROM_SEC(sbi, secno)                                          \
	(((secno) == -1) ? -1 : (secno) / (sbi)->secs_per_zone)
#define GET_ZONE_FROM_SEG(sbi, segno)                                          \
	GET_ZONE_FROM_SEC(sbi, GET_SEC_FROM_SEG(sbi, segno))

#define GET_SUM_BLOCK(sbi, segno) ((sbi)->sm_info->ssa_blkaddr + (segno))

#define GET_SUM_TYPE(footer)	   ((footer)->entry_type)
#define SET_SUM_TYPE(footer, type) ((footer)->entry_type = (type))

#define SIT_ENTRY_OFFSET(sit_i, segno) ((segno) % (sit_i)->sents_per_block)
#define SIT_BLOCK_OFFSET(segno)	       ((segno) / SIT_ENTRY_PER_BLOCK)
#define START_SEGNO(segno)	       (SIT_BLOCK_OFFSET(segno) * SIT_ENTRY_PER_BLOCK)
#define SIT_BLK_CNT(sbi)	       DIV_ROUND_UP(MAIN_SEGS(sbi), SIT_ENTRY_PER_BLOCK)
#define f2fs_bitmap_size(nr)	       (BITS_TO_LONGS(nr) * sizeof(unsigned long))

#define SECTOR_FROM_BLOCK(blk_addr)                                            \
	(((sector_t)blk_addr) << F2FS_LOG_SECTORS_PER_BLOCK)
#define SECTOR_TO_BLOCK(sectors) ((sectors) >> F2FS_LOG_SECTORS_PER_BLOCK)

enum { ALLOC_RIGHT = 0, ALLOC_LEFT };

enum {
	LFS = 0,
	SSR,
	AT_SSR,
};

enum {
	GC_CB = 0,
	GC_GREEDY,
	GC_AT,
	ALLOC_NEXT,
	FLUSH_DEVICE,
	MAX_GC_POLICY,
};

enum {
	BG_GC = 0,
	FG_GC,
	FORCE_FG_GC,
};

struct victim_sel_policy {
	int alloc_mode;
	int gc_mode;
	unsigned long *dirty_bitmap;
	unsigned int max_search;
	unsigned int offset;
	unsigned int ofs_unit;
	unsigned int min_cost;
	unsigned long long oldest_age;
	unsigned int min_segno;
	unsigned long long age;
	unsigned long long age_threshold;
};

struct seg_entry {
	unsigned int type : 6;
	unsigned int valid_blocks : 10;
	unsigned int ckpt_valid_blocks : 10;
	unsigned int padding : 6;
	unsigned char *cur_valid_map;
#ifdef CONFIG_F2FS_CHECK_FS
	unsigned char *cur_valid_map_mir;
#endif

	unsigned char *ckpt_valid_map;
	unsigned char *discard_map;
	unsigned long long mtime;
};

struct sec_entry {
	unsigned int valid_blocks;
};

struct segment_allocation {
	void (*allocate_segment)(struct f2fs_sb_info *, int, bool);
};

#define MAX_SKIP_GC_COUNT 16

struct inmem_pages {
	struct list_head list;
	struct page *page;
	block_t old_addr;
};

struct sit_info {
	const struct segment_allocation *s_ops;

	block_t sit_base_addr;
	block_t sit_blocks;
	block_t written_valid_blocks;
	char *bitmap;
	char *sit_bitmap;
#ifdef CONFIG_F2FS_CHECK_FS
	char *sit_bitmap_mir;

	unsigned long *invalid_segmap;
#endif
	unsigned int bitmap_size;

	unsigned long *tmp_map;
	unsigned long *dirty_sentries_bitmap;
	unsigned int dirty_sentries;
	unsigned int sents_per_block;
	struct rw_semaphore sentry_lock;
	struct seg_entry *sentries;
	struct sec_entry *sec_entries;

	unsigned long long elapsed_time;
	unsigned long long mounted_time;
	unsigned long long min_mtime;
	unsigned long long max_mtime;
	unsigned long long dirty_min_mtime;
	unsigned long long dirty_max_mtime;

	unsigned int last_victim[MAX_GC_POLICY];
};

struct free_segmap_info {
	unsigned int start_segno;
	unsigned int free_segments;
	unsigned int free_sections;
	spinlock_t segmap_lock;
	unsigned long *free_segmap;
	unsigned long *free_secmap;
};

enum dirty_type {
	DIRTY_HOT_DATA,
	DIRTY_WARM_DATA,
	DIRTY_COLD_DATA,
	DIRTY_HOT_NODE,
	DIRTY_WARM_NODE,
	DIRTY_COLD_NODE,
	DIRTY,
	PRE,
	NR_DIRTY_TYPE
};

struct dirty_seglist_info {
	const struct victim_selection *v_ops;
	unsigned long *dirty_segmap[NR_DIRTY_TYPE];
	unsigned long *dirty_secmap;
	struct mutex seglist_lock;
	int nr_dirty[NR_DIRTY_TYPE];
	unsigned long *victim_secmap;
};

struct victim_selection {
	int (*get_victim)(struct f2fs_sb_info *, unsigned int *, int, int, char,
			  unsigned long long);
};

struct curseg_info {
	struct mutex curseg_mutex;
	struct f2fs_summary_block *sum_blk;
	struct rw_semaphore journal_rwsem;
	struct f2fs_journal *journal;
	unsigned char alloc_type;
	unsigned short seg_type;
	unsigned int segno;
	unsigned short next_blkoff;
	unsigned int zone;
	unsigned int next_segno;
	bool inited;
};

struct sit_entry_set {
	struct list_head set_list;
	unsigned int start_segno;
	unsigned int entry_cnt;
};

static inline struct curseg_info *CURSEG_I(struct f2fs_sb_info *sbi, int type)
{
	return (struct curseg_info *)(SM_I(sbi)->curseg_array + type);
}

static inline struct seg_entry *get_seg_entry(struct f2fs_sb_info *sbi,
					      unsigned int segno)
{
	struct sit_info *sit_i = SIT_I(sbi);
	return &sit_i->sentries[segno];
}

static inline struct sec_entry *get_sec_entry(struct f2fs_sb_info *sbi,
					      unsigned int segno)
{
	struct sit_info *sit_i = SIT_I(sbi);
	return &sit_i->sec_entries[GET_SEC_FROM_SEG(sbi, segno)];
}

static inline unsigned int
get_valid_blocks(struct f2fs_sb_info *sbi, unsigned int segno, bool use_section)
{
	if (use_section && __is_large_section(sbi))
		return get_sec_entry(sbi, segno)->valid_blocks;
	else
		return get_seg_entry(sbi, segno)->valid_blocks;
}

static inline unsigned int get_ckpt_valid_blocks(struct f2fs_sb_info *sbi,
						 unsigned int segno,
						 bool use_section)
{
	if (use_section && __is_large_section(sbi)) {
		unsigned int start_segno = START_SEGNO(segno);
		unsigned int blocks	 = 0;
		int i;

		for (i = 0; i < sbi->segs_per_sec; i++, start_segno++) {
			struct seg_entry *se = get_seg_entry(sbi, start_segno);

			blocks += se->ckpt_valid_blocks;
		}
		return blocks;
	}
	return get_seg_entry(sbi, segno)->ckpt_valid_blocks;
}

static inline void seg_info_from_raw_sit(struct seg_entry *se,
					 struct f2fs_sit_entry *rs)
{
	se->valid_blocks      = GET_SIT_VBLOCKS(rs);
	se->ckpt_valid_blocks = GET_SIT_VBLOCKS(rs);
	memcpy(se->cur_valid_map, rs->valid_map, SIT_VBLOCK_MAP_SIZE);
	memcpy(se->ckpt_valid_map, rs->valid_map, SIT_VBLOCK_MAP_SIZE);
#ifdef CONFIG_F2FS_CHECK_FS
	memcpy(se->cur_valid_map_mir, rs->valid_map, SIT_VBLOCK_MAP_SIZE);
#endif
	se->type  = GET_SIT_TYPE(rs);
	se->mtime = le64_to_cpu(rs->mtime);
}

static inline void __seg_info_to_raw_sit(struct seg_entry *se,
					 struct f2fs_sit_entry *rs)
{
	unsigned short raw_vblocks =
		(se->type << SIT_VBLOCKS_SHIFT) | se->valid_blocks;
	rs->vblocks = cpu_to_le16(raw_vblocks);
	memcpy(rs->valid_map, se->cur_valid_map, SIT_VBLOCK_MAP_SIZE);
	rs->mtime = cpu_to_le64(se->mtime);
}

static inline void seg_info_to_sit_page(struct f2fs_sb_info *sbi,
					struct page *page, unsigned int start)
{
	struct f2fs_sit_block *raw_sit;
	struct seg_entry *se;
	struct f2fs_sit_entry *rs;
	unsigned int end =
		min(start + SIT_ENTRY_PER_BLOCK, (unsigned long)MAIN_SEGS(sbi));
	int i;

	raw_sit = (struct f2fs_sit_block *)page_address(page);
	memset(raw_sit, 0, PAGE_SIZE);
	for (i = 0; i < end - start; i++) {
		rs = &raw_sit->entries[i];
		se = get_seg_entry(sbi, start + i);
		__seg_info_to_raw_sit(se, rs);
	}
}

static inline void seg_info_to_raw_sit(struct seg_entry *se,
				       struct f2fs_sit_entry *rs)
{
	__seg_info_to_raw_sit(se, rs);

	memcpy(se->ckpt_valid_map, rs->valid_map, SIT_VBLOCK_MAP_SIZE);
	se->ckpt_valid_blocks = se->valid_blocks;
}

static inline unsigned int find_next_inuse(struct free_segmap_info *free_i,
					   unsigned int max, unsigned int segno)
{
	unsigned int ret;
	spin_lock(&free_i->segmap_lock);
	ret = find_next_bit(free_i->free_segmap, max, segno);
	spin_unlock(&free_i->segmap_lock);
	return ret;
}

static inline void __set_free(struct f2fs_sb_info *sbi, unsigned int segno)
{
	struct free_segmap_info *free_i = FREE_I(sbi);
	unsigned int secno		= GET_SEC_FROM_SEG(sbi, segno);
	unsigned int start_segno	= GET_SEG_FROM_SEC(sbi, secno);
	unsigned int next;
	unsigned int usable_segs = f2fs_usable_segs_in_sec(sbi, segno);

	spin_lock(&free_i->segmap_lock);
	clear_bit(segno, free_i->free_segmap);
	free_i->free_segments++;

	next = find_next_bit(free_i->free_segmap,
			     start_segno + sbi->segs_per_sec, start_segno);
	if (next >= start_segno + usable_segs) {
		clear_bit(secno, free_i->free_secmap);
		free_i->free_sections++;
	}
	spin_unlock(&free_i->segmap_lock);
}

static inline void __set_inuse(struct f2fs_sb_info *sbi, unsigned int segno)
{
	struct free_segmap_info *free_i = FREE_I(sbi);
	unsigned int secno		= GET_SEC_FROM_SEG(sbi, segno);

	set_bit(segno, free_i->free_segmap);
	free_i->free_segments--;
	if (!test_and_set_bit(secno, free_i->free_secmap))
		free_i->free_sections--;
}

static inline void __set_test_and_free(struct f2fs_sb_info *sbi,
				       unsigned int segno, bool inmem)
{
	struct free_segmap_info *free_i = FREE_I(sbi);
	unsigned int secno		= GET_SEC_FROM_SEG(sbi, segno);
	unsigned int start_segno	= GET_SEG_FROM_SEC(sbi, secno);
	unsigned int next;
	unsigned int usable_segs = f2fs_usable_segs_in_sec(sbi, segno);

	spin_lock(&free_i->segmap_lock);
	if (test_and_clear_bit(segno, free_i->free_segmap)) {
		free_i->free_segments++;

		if (!inmem && IS_CURSEC(sbi, secno))
			goto skip_free;
		next = find_next_bit(free_i->free_segmap,
				     start_segno + sbi->segs_per_sec,
				     start_segno);
		if (next >= start_segno + usable_segs) {
			if (test_and_clear_bit(secno, free_i->free_secmap))
				free_i->free_sections++;
		}
	}
skip_free:
	spin_unlock(&free_i->segmap_lock);
}

static inline void __set_test_and_inuse(struct f2fs_sb_info *sbi,
					unsigned int segno)
{
	struct free_segmap_info *free_i = FREE_I(sbi);
	unsigned int secno		= GET_SEC_FROM_SEG(sbi, segno);

	spin_lock(&free_i->segmap_lock);
	if (!test_and_set_bit(segno, free_i->free_segmap)) {
		free_i->free_segments--;
		if (!test_and_set_bit(secno, free_i->free_secmap))
			free_i->free_sections--;
	}
	spin_unlock(&free_i->segmap_lock);
}

static inline void get_sit_bitmap(struct f2fs_sb_info *sbi, void *dst_addr)
{
	struct sit_info *sit_i = SIT_I(sbi);

#ifdef CONFIG_F2FS_CHECK_FS
	if (memcmp(sit_i->sit_bitmap, sit_i->sit_bitmap_mir,
		   sit_i->bitmap_size))
		f2fs_bug_on(sbi, 1);
#endif
	memcpy(dst_addr, sit_i->sit_bitmap, sit_i->bitmap_size);
}

static inline block_t written_block_count(struct f2fs_sb_info *sbi)
{
	return SIT_I(sbi)->written_valid_blocks;
}

static inline unsigned int free_segments(struct f2fs_sb_info *sbi)
{
	return FREE_I(sbi)->free_segments;
}

static inline unsigned int reserved_segments(struct f2fs_sb_info *sbi)
{
	return SM_I(sbi)->reserved_segments;
}

static inline unsigned int free_sections(struct f2fs_sb_info *sbi)
{
	return FREE_I(sbi)->free_sections;
}

static inline unsigned int prefree_segments(struct f2fs_sb_info *sbi)
{
	return DIRTY_I(sbi)->nr_dirty[PRE];
}

static inline unsigned int dirty_segments(struct f2fs_sb_info *sbi)
{
	return DIRTY_I(sbi)->nr_dirty[DIRTY_HOT_DATA] +
	       DIRTY_I(sbi)->nr_dirty[DIRTY_WARM_DATA] +
	       DIRTY_I(sbi)->nr_dirty[DIRTY_COLD_DATA] +
	       DIRTY_I(sbi)->nr_dirty[DIRTY_HOT_NODE] +
	       DIRTY_I(sbi)->nr_dirty[DIRTY_WARM_NODE] +
	       DIRTY_I(sbi)->nr_dirty[DIRTY_COLD_NODE];
}

static inline int overprovision_segments(struct f2fs_sb_info *sbi)
{
	return SM_I(sbi)->ovp_segments;
}

static inline int reserved_sections(struct f2fs_sb_info *sbi)
{
	return GET_SEC_FROM_SEG(sbi, reserved_segments(sbi));
}

static inline bool has_curseg_enough_space(struct f2fs_sb_info *sbi)
{
	unsigned int node_blocks = get_pages(sbi, F2FS_DIRTY_NODES) +
				   get_pages(sbi, F2FS_DIRTY_DENTS);
	unsigned int dent_blocks = get_pages(sbi, F2FS_DIRTY_DENTS);
	unsigned int segno, left_blocks;
	int i;

	for (i = CURSEG_HOT_NODE; i <= CURSEG_COLD_NODE; i++) {
		segno	    = CURSEG_I(sbi, i)->segno;
		left_blocks = f2fs_usable_blks_in_seg(sbi, segno) -
			      get_seg_entry(sbi, segno)->ckpt_valid_blocks;

		if (node_blocks > left_blocks)
			return false;
	}

	segno	    = CURSEG_I(sbi, CURSEG_HOT_DATA)->segno;
	left_blocks = f2fs_usable_blks_in_seg(sbi, segno) -
		      get_seg_entry(sbi, segno)->ckpt_valid_blocks;
	if (dent_blocks > left_blocks)
		return false;
	return true;
}

static inline bool has_not_enough_free_secs(struct f2fs_sb_info *sbi, int freed,
					    int needed)
{
	int node_secs  = get_blocktype_secs(sbi, F2FS_DIRTY_NODES);
	int dent_secs  = get_blocktype_secs(sbi, F2FS_DIRTY_DENTS);
	int imeta_secs = get_blocktype_secs(sbi, F2FS_DIRTY_IMETA);

	if (unlikely(is_sbi_flag_set(sbi, SBI_POR_DOING)))
		return false;

	if (free_sections(sbi) + freed == reserved_sections(sbi) + needed &&
	    has_curseg_enough_space(sbi))
		return false;
	return (free_sections(sbi) + freed) <=
	       (node_secs + 2 * dent_secs + imeta_secs +
		reserved_sections(sbi) + needed);
}

static inline bool f2fs_is_checkpoint_ready(struct f2fs_sb_info *sbi)
{
	if (likely(!is_sbi_flag_set(sbi, SBI_CP_DISABLED)))
		return true;
	if (likely(!has_not_enough_free_secs(sbi, 0, 0)))
		return true;
	return false;
}

static inline bool excess_prefree_segs(struct f2fs_sb_info *sbi)
{
	return prefree_segments(sbi) > SM_I(sbi)->rec_prefree_segments;
}

static inline int utilization(struct f2fs_sb_info *sbi)
{
	return div_u64((u64)valid_user_blocks(sbi) * 100,
		       sbi->user_block_count);
}

#define DEF_MIN_IPU_UTIL     70
#define DEF_MIN_FSYNC_BLOCKS 8
#define DEF_MIN_HOT_BLOCKS   16

#define SMALL_VOLUME_SEGMENTS (16 * 512)

enum {
	F2FS_IPU_FORCE,
	F2FS_IPU_SSR,
	F2FS_IPU_UTIL,
	F2FS_IPU_SSR_UTIL,
	F2FS_IPU_FSYNC,
	F2FS_IPU_ASYNC,
	F2FS_IPU_NOCACHE,
};

static inline unsigned int curseg_segno(struct f2fs_sb_info *sbi, int type)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);
	return curseg->segno;
}

static inline unsigned char curseg_alloc_type(struct f2fs_sb_info *sbi,
					      int type)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);
	return curseg->alloc_type;
}

static inline unsigned short curseg_blkoff(struct f2fs_sb_info *sbi, int type)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);
	return curseg->next_blkoff;
}

static inline void check_seg_range(struct f2fs_sb_info *sbi, unsigned int segno)
{
	f2fs_bug_on(sbi, segno > TOTAL_SEGS(sbi) - 1);
}

static inline void verify_fio_blkaddr(struct f2fs_io_info *fio)
{
	struct f2fs_sb_info *sbi = fio->sbi;

	if (__is_valid_data_blkaddr(fio->old_blkaddr))
		verify_blkaddr(sbi, fio->old_blkaddr,
			       __is_meta_io(fio) ? META_GENERIC : DATA_GENERIC);
	verify_blkaddr(sbi, fio->new_blkaddr,
		       __is_meta_io(fio) ? META_GENERIC : DATA_GENERIC_ENHANCE);
}

static inline int check_block_count(struct f2fs_sb_info *sbi, int segno,
				    struct f2fs_sit_entry *raw_sit)
{
	bool is_valid	 = test_bit_le(0, raw_sit->valid_map) ? true : false;
	int valid_blocks = 0;
	int cur_pos	 = 0, next_pos;
	unsigned int usable_blks_per_seg = f2fs_usable_blks_in_seg(sbi, segno);

	do {
		if (is_valid) {
			next_pos = find_next_zero_bit_le(&raw_sit->valid_map,
							 usable_blks_per_seg,
							 cur_pos);
			valid_blocks += next_pos - cur_pos;
		} else
			next_pos =
				find_next_bit_le(&raw_sit->valid_map,
						 usable_blks_per_seg, cur_pos);
		cur_pos	 = next_pos;
		is_valid = !is_valid;
	} while (cur_pos < usable_blks_per_seg);

	if (unlikely(GET_SIT_VBLOCKS(raw_sit) != valid_blocks)) {
		f2fs_err(sbi, "Mismatch valid blocks %d vs. %d",
			 GET_SIT_VBLOCKS(raw_sit), valid_blocks);
		set_sbi_flag(sbi, SBI_NEED_FSCK);
		return -EFSCORRUPTED;
	}

	if (usable_blks_per_seg < sbi->blocks_per_seg)
		f2fs_bug_on(sbi, find_next_bit_le(&raw_sit->valid_map,
						  sbi->blocks_per_seg,
						  usable_blks_per_seg) !=
					 sbi->blocks_per_seg);

	if (unlikely(GET_SIT_VBLOCKS(raw_sit) > usable_blks_per_seg ||
		     segno > TOTAL_SEGS(sbi) - 1)) {
		f2fs_err(sbi, "Wrong valid blocks %d or segno %u",
			 GET_SIT_VBLOCKS(raw_sit), segno);
		set_sbi_flag(sbi, SBI_NEED_FSCK);
		return -EFSCORRUPTED;
	}
	return 0;
}

static inline pgoff_t current_sit_addr(struct f2fs_sb_info *sbi,
				       unsigned int start)
{
	struct sit_info *sit_i = SIT_I(sbi);
	unsigned int offset    = SIT_BLOCK_OFFSET(start);
	block_t blk_addr       = sit_i->sit_base_addr + offset;

	check_seg_range(sbi, start);

#ifdef CONFIG_F2FS_CHECK_FS
	if (f2fs_test_bit(offset, sit_i->sit_bitmap) !=
	    f2fs_test_bit(offset, sit_i->sit_bitmap_mir))
		f2fs_bug_on(sbi, 1);
#endif

	if (f2fs_test_bit(offset, sit_i->sit_bitmap))
		blk_addr += sit_i->sit_blocks;

	return blk_addr;
}

static inline pgoff_t next_sit_addr(struct f2fs_sb_info *sbi,
				    pgoff_t block_addr)
{
	struct sit_info *sit_i = SIT_I(sbi);
	block_addr -= sit_i->sit_base_addr;
	if (block_addr < sit_i->sit_blocks)
		block_addr += sit_i->sit_blocks;
	else
		block_addr -= sit_i->sit_blocks;

	return block_addr + sit_i->sit_base_addr;
}

static inline void set_to_next_sit(struct sit_info *sit_i, unsigned int start)
{
	unsigned int block_off = SIT_BLOCK_OFFSET(start);

	f2fs_change_bit(block_off, sit_i->sit_bitmap);
#ifdef CONFIG_F2FS_CHECK_FS
	f2fs_change_bit(block_off, sit_i->sit_bitmap_mir);
#endif
}

static inline unsigned long long get_mtime(struct f2fs_sb_info *sbi,
					   bool base_time)
{
	struct sit_info *sit_i = SIT_I(sbi);
	time64_t diff, now = ktime_get_boottime_seconds();

	if (now >= sit_i->mounted_time)
		return sit_i->elapsed_time + now - sit_i->mounted_time;

	if (!base_time) {
		diff = sit_i->mounted_time - now;
		if (sit_i->elapsed_time >= diff)
			return sit_i->elapsed_time - diff;
		return 0;
	}
	return sit_i->elapsed_time;
}

static inline void set_summary(struct f2fs_summary *sum, nid_t nid,
			       unsigned int ofs_in_node, unsigned char version)
{
	sum->nid	 = cpu_to_le32(nid);
	sum->ofs_in_node = cpu_to_le16(ofs_in_node);
	sum->version	 = version;
}

static inline block_t start_sum_block(struct f2fs_sb_info *sbi)
{
	return __start_cp_addr(sbi) +
	       le32_to_cpu(F2FS_CKPT(sbi)->cp_pack_start_sum);
}

static inline block_t sum_blk_addr(struct f2fs_sb_info *sbi, int base, int type)
{
	return __start_cp_addr(sbi) +
	       le32_to_cpu(F2FS_CKPT(sbi)->cp_pack_total_block_count) -
	       (base + 1) + type;
}

static inline bool sec_usage_check(struct f2fs_sb_info *sbi, unsigned int secno)
{
	if (IS_CURSEC(sbi, secno) || (sbi->cur_victim_sec == secno))
		return true;
	return false;
}

static inline int nr_pages_to_skip(struct f2fs_sb_info *sbi, int type)
{
	if (sbi->sb->s_bdi->wb.dirty_exceeded)
		return 0;

	if (type == DATA)
		return sbi->blocks_per_seg;
	else if (type == NODE)
		return 8 * sbi->blocks_per_seg;
	else if (type == META)
		return 8 * BIO_MAX_PAGES;
	else
		return 0;
}

static inline long nr_pages_to_write(struct f2fs_sb_info *sbi, int type,
				     struct writeback_control *wbc)
{
	long nr_to_write, desired;

	if (wbc->sync_mode != WB_SYNC_NONE)
		return 0;

	nr_to_write = wbc->nr_to_write;
	desired	    = BIO_MAX_PAGES;
	if (type == NODE)
		desired <<= 1;

	wbc->nr_to_write = desired;
	return desired - nr_to_write;
}

static inline void wake_up_discard_thread(struct f2fs_sb_info *sbi, bool force)
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	bool wakeup			= false;
	int i;

	if (force)
		goto wake_up;

	mutex_lock(&dcc->cmd_lock);
	for (i = MAX_PLIST_NUM - 1; i >= 0; i--) {
		if (i + 1 < dcc->discard_granularity)
			break;
		if (!list_empty(&dcc->pend_list[i])) {
			wakeup = true;
			break;
		}
	}
	mutex_unlock(&dcc->cmd_lock);
	if (!wakeup || !is_idle(sbi, DISCARD_TIME))
		return;
wake_up:
	dcc->discard_wake = 1;
	wake_up_interruptible_all(&dcc->discard_wait_queue);
}
