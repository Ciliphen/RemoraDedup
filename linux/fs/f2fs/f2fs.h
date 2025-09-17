/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fs/f2fs/f2fs.h
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 */

#ifndef _LINUX_F2FS_H
#define _LINUX_F2FS_H

#include "linux/spinlock_types.h"
#include <linux/rwsem.h>
#include <linux/uio.h>
#include <linux/types.h>
#include <linux/page-flags.h>
#include <linux/buffer_head.h>
#include <linux/slab.h>
#include <linux/crc32.h>
#include <linux/magic.h>
#include <linux/kobject.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/vmalloc.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/quotaops.h>
#include <linux/part_stat.h>
#include <crypto/hash.h>
#include <linux/f2fs_fs.h>
#include <linux/writeback.h>

#include <linux/fscrypt.h>
#include <linux/fsverity.h>

#ifdef CONFIG_F2FS_CHECK_FS
#define f2fs_bug_on(sbi, condition) BUG_ON(condition)
#else
#define f2fs_bug_on(sbi, condition)                                            \
	do {                                                                   \
		if (unlikely(condition)) {                                     \
			f2dfs_err(sbi, "file:%s, line:%d, condition:%s",       \
				  __FILE__, __LINE__, #condition);             \
			WARN_ON(1);                                            \
			set_sbi_flag(sbi, SBI_NEED_FSCK);                      \
		}                                                              \
	} while (0)
#endif

enum {
	FAULT_KMALLOC,
	FAULT_KVMALLOC,
	FAULT_PAGE_ALLOC,
	FAULT_PAGE_GET,
	FAULT_ALLOC_BIO,
	FAULT_ALLOC_NID,
	FAULT_ORPHAN,
	FAULT_BLOCK,
	FAULT_DIR_DEPTH,
	FAULT_EVICT_INODE,
	FAULT_TRUNCATE,
	FAULT_READ_IO,
	FAULT_CHECKPOINT,
	FAULT_DISCARD,
	FAULT_WRITE_IO,
	FAULT_MAX,
};

#ifdef CONFIG_F2FS_FAULT_INJECTION
#define F2FS_ALL_FAULT_TYPE ((1 << FAULT_MAX) - 1)

struct f2fs_fault_info {
	atomic_t inject_ops;
	unsigned int inject_rate;
	unsigned int inject_type;
};

extern const char *f2fs_fault_name[FAULT_MAX];
#define IS_FAULT_SET(fi, type) ((fi)->inject_type & (1 << (type)))
#endif

#define F2FS_MOUNT_DISABLE_ROLL_FORWARD 0x00000002
#define F2FS_MOUNT_DISCARD		0x00000004
#define F2FS_MOUNT_NOHEAP		0x00000008
#define F2FS_MOUNT_XATTR_USER		0x00000010
#define F2FS_MOUNT_POSIX_ACL		0x00000020
#define F2FS_MOUNT_DISABLE_EXT_IDENTIFY 0x00000040
#define F2FS_MOUNT_INLINE_XATTR		0x00000080
#define F2FS_MOUNT_INLINE_DATA		0x00000100
#define F2FS_MOUNT_INLINE_DENTRY	0x00000200
#define F2FS_MOUNT_FLUSH_MERGE		0x00000400
#define F2FS_MOUNT_NOBARRIER		0x00000800
#define F2FS_MOUNT_FASTBOOT		0x00001000
#define F2FS_MOUNT_EXTENT_CACHE		0x00002000
#define F2FS_MOUNT_DATA_FLUSH		0x00008000
#define F2FS_MOUNT_FAULT_INJECTION	0x00010000
#define F2FS_MOUNT_USRQUOTA		0x00080000
#define F2FS_MOUNT_GRPQUOTA		0x00100000
#define F2FS_MOUNT_PRJQUOTA		0x00200000
#define F2FS_MOUNT_QUOTA		0x00400000
#define F2FS_MOUNT_INLINE_XATTR_SIZE	0x00800000
#define F2FS_MOUNT_RESERVE_ROOT		0x01000000
#define F2FS_MOUNT_DISABLE_CHECKPOINT	0x02000000
#define F2FS_MOUNT_NORECOVERY		0x04000000
#define F2FS_MOUNT_ATGC			0x08000000

#define F2FS_OPTION(sbi)       ((sbi)->mount_opt)
#define clear_opt(sbi, option) (F2FS_OPTION(sbi).opt &= ~F2FS_MOUNT_##option)
#define set_opt(sbi, option)   (F2FS_OPTION(sbi).opt |= F2FS_MOUNT_##option)
#define test_opt(sbi, option)  (F2FS_OPTION(sbi).opt & F2FS_MOUNT_##option)

#define ver_after(a, b)                                                        \
	(typecheck(unsigned long long, a) &&                                   \
	 typecheck(unsigned long long, b) && ((long long)((a) - (b)) > 0))

typedef u32 block_t;
#ifdef CONFIG_F2FS_FS_DEDUP
typedef u32 virtual_t;
#endif

typedef u32 nid_t;

#define COMPRESS_EXT_NUM 16

struct f2fs_mount_info {
	unsigned int opt;
	int write_io_size_bits;
	block_t root_reserved_blocks;
	kuid_t s_resuid;
	kgid_t s_resgid;
	int active_logs;
	int inline_xattr_size;
#ifdef CONFIG_F2FS_FAULT_INJECTION
	struct f2fs_fault_info fault_info;
#endif
#ifdef CONFIG_QUOTA

	char *s_qf_names[MAXQUOTAS];
	int s_jquota_fmt;
#endif

	int whint_mode;
	int alloc_mode;
	int fsync_mode;
	int fs_mode;
	int bggc_mode;
	struct fscrypt_dummy_policy dummy_enc_policy;
	block_t unusable_cap_perc;
	block_t unusable_cap;

	unsigned char compress_algorithm;
	unsigned compress_log_size;
	unsigned char compress_ext_cnt;
	unsigned char extensions[COMPRESS_EXT_NUM][F2FS_EXTENSION_LEN];
};

#define F2FS_FEATURE_ENCRYPT		   0x0001
#define F2FS_FEATURE_BLKZONED		   0x0002
#define F2FS_FEATURE_ATOMIC_WRITE	   0x0004
#define F2FS_FEATURE_EXTRA_ATTR		   0x0008
#define F2FS_FEATURE_PRJQUOTA		   0x0010
#define F2FS_FEATURE_INODE_CHKSUM	   0x0020
#define F2FS_FEATURE_FLEXIBLE_INLINE_XATTR 0x0040
#define F2FS_FEATURE_QUOTA_INO		   0x0080
#define F2FS_FEATURE_INODE_CRTIME	   0x0100
#define F2FS_FEATURE_LOST_FOUND		   0x0200
#define F2FS_FEATURE_VERITY		   0x0400
#define F2FS_FEATURE_SB_CHKSUM		   0x0800
#define F2FS_FEATURE_CASEFOLD		   0x1000
#define F2FS_FEATURE_COMPRESSION	   0x2000

#define __F2FS_HAS_FEATURE(raw_super, mask)                                    \
	((raw_super->feature & cpu_to_le32(mask)) != 0)
#define F2FS_HAS_FEATURE(sbi, mask) __F2FS_HAS_FEATURE(sbi->raw_super, mask)
#define F2FS_SET_FEATURE(sbi, mask)                                            \
	(sbi->raw_super->feature |= cpu_to_le32(mask))
#define F2FS_CLEAR_FEATURE(sbi, mask)                                          \
	(sbi->raw_super->feature &= ~cpu_to_le32(mask))

#define F2FS_DEF_RESUID 0
#define F2FS_DEF_RESGID 0

enum { NAT_BITMAP, SIT_BITMAP };

#define CP_UMOUNT   0x00000001
#define CP_FASTBOOT 0x00000002
#define CP_SYNC	    0x00000004
#define CP_RECOVERY 0x00000008
#define CP_DISCARD  0x00000010
#define CP_TRIMMED  0x00000020
#define CP_PAUSE    0x00000040
#define CP_RESIZE   0x00000080

#define MAX_DISCARD_BLOCKS(sbi)	   BLKS_PER_SEC(sbi)
#define DEF_MAX_DISCARD_REQUEST	   8
#define DEF_MIN_DISCARD_ISSUE_TIME 50
#define DEF_MID_DISCARD_ISSUE_TIME 500
#define DEF_MAX_DISCARD_ISSUE_TIME 60000
#define DEF_DISCARD_URGENT_UTIL	   80
#define DEF_CP_INTERVAL		   60
#define DEF_IDLE_INTERVAL	   5
#define DEF_DISABLE_INTERVAL	   5
#define DEF_DISABLE_QUICK_INTERVAL 1
#define DEF_UMOUNT_DISCARD_TIMEOUT 5

struct cp_control {
	int reason;
	__u64 trim_start;
	__u64 trim_end;
	__u64 trim_minlen;
};

enum {
	META_CP,
	META_NAT,
	META_SIT,
	META_SSA,
	META_MAX,
	META_POR,
	DATA_GENERIC,
	DATA_GENERIC_ENHANCE,
	DATA_GENERIC_ENHANCE_READ,
	META_GENERIC,
};

enum {
	ORPHAN_INO,
	APPEND_INO,
	UPDATE_INO,
	TRANS_DIR_INO,
	FLUSH_INO,
	MAX_INO_ENTRY,
};

struct ino_entry {
	struct list_head list;
	nid_t ino;
	unsigned int dirty_device;
};

struct inode_entry {
	struct list_head list;
	struct inode *inode;
};

struct fsync_node_entry {
	struct list_head list;
	struct page *page;
	unsigned int seq_id;
};

struct discard_entry {
	struct list_head list;
	block_t start_blkaddr;
	unsigned char discard_map[SIT_VBLOCK_MAP_SIZE];
};

#define DEFAULT_DISCARD_GRANULARITY 16

#define MAX_PLIST_NUM 512
#define plist_idx(blk_num)                                                     \
	((blk_num) >= MAX_PLIST_NUM ? (MAX_PLIST_NUM - 1) : ((blk_num) - 1))

enum {
	D_PREP,
	D_PARTIAL,
	D_SUBMIT,
	D_DONE,
};

struct discard_info {
	block_t lstart;
	block_t len;
	block_t start;
};

struct discard_cmd {
	struct rb_node rb_node;
	union {
		struct {
			block_t lstart;
			block_t len;
			block_t start;
		};
		struct discard_info di;
	};
	struct list_head list;
	struct completion wait;
	struct block_device *bdev;
	unsigned short ref;
	unsigned char state;
	unsigned char queued;
	int error;
	spinlock_t lock;
	unsigned short bio_ref;
};

enum {
	DPOLICY_BG,
	DPOLICY_FORCE,
	DPOLICY_FSTRIM,
	DPOLICY_UMOUNT,
	MAX_DPOLICY,
};

struct discard_policy {
	int type;
	unsigned int min_interval;
	unsigned int mid_interval;
	unsigned int max_interval;
	unsigned int max_requests;
	unsigned int io_aware_gran;
	bool io_aware;
	bool sync;
	bool ordered;
	bool timeout;
	unsigned int granularity;
};

struct discard_cmd_control {
	struct task_struct *f2fs_issue_discard;
	struct list_head entry_list;
	struct list_head pend_list[MAX_PLIST_NUM];
	struct list_head wait_list;
	struct list_head fstrim_list;
	wait_queue_head_t discard_wait_queue;
	unsigned int discard_wake;
	struct mutex cmd_lock;
	unsigned int nr_discards;
	unsigned int max_discards;
	unsigned int discard_granularity;
	unsigned int undiscard_blks;
	unsigned int next_pos;
	atomic_t issued_discard;
	atomic_t queued_discard;
	atomic_t discard_cmd_cnt;
	struct rb_root_cached root;
	bool rbtree_check;
};

struct fsync_inode_entry {
	struct list_head list;
	struct inode *inode;
	block_t blkaddr;
	block_t last_dentry;
};

#define nats_in_cursum(jnl) (le16_to_cpu((jnl)->n_nats))
#define sits_in_cursum(jnl) (le16_to_cpu((jnl)->n_sits))

#define nat_in_journal(jnl, i)	 ((jnl)->nat_j.entries[i].ne)
#define nid_in_journal(jnl, i)	 ((jnl)->nat_j.entries[i].nid)
#define sit_in_journal(jnl, i)	 ((jnl)->sit_j.entries[i].se)
#define segno_in_journal(jnl, i) ((jnl)->sit_j.entries[i].segno)

#define MAX_NAT_JENTRIES(jnl) (NAT_JOURNAL_ENTRIES - nats_in_cursum(jnl))
#define MAX_SIT_JENTRIES(jnl) (SIT_JOURNAL_ENTRIES - sits_in_cursum(jnl))

static inline int update_nats_in_cursum(struct f2fs_journal *journal, int i)
{
	int before = nats_in_cursum(journal);

	journal->n_nats = cpu_to_le16(before + i);
	return before;
}

static inline int update_sits_in_cursum(struct f2fs_journal *journal, int i)
{
	int before = sits_in_cursum(journal);

	journal->n_sits = cpu_to_le16(before + i);
	return before;
}

static inline bool __has_cursum_space(struct f2fs_journal *journal, int size,
				      int type)
{
	if (type == NAT_JOURNAL)
		return size <= MAX_NAT_JENTRIES(journal);
	return size <= MAX_SIT_JENTRIES(journal);
}

#define DEF_INLINE_RESERVED_SIZE 1
static inline int get_extra_isize(struct inode *inode);
static inline int get_inline_xattr_addrs(struct inode *inode);
#define MAX_INLINE_DATA(inode)                                                 \
	(sizeof(__le32) *                                                      \
	 (CUR_ADDRS_PER_INODE(inode) - get_inline_xattr_addrs(inode) -         \
	  DEF_INLINE_RESERVED_SIZE))

#define NR_INLINE_DENTRY(inode)                                                \
	(MAX_INLINE_DATA(inode) * BITS_PER_BYTE /                              \
	 ((SIZE_OF_DIR_ENTRY + F2FS_SLOT_LEN) * BITS_PER_BYTE + 1))
#define INLINE_DENTRY_BITMAP_SIZE(inode)                                       \
	DIV_ROUND_UP(NR_INLINE_DENTRY(inode), BITS_PER_BYTE)
#define INLINE_RESERVED_SIZE(inode)                                            \
	(MAX_INLINE_DATA(inode) -                                              \
	 ((SIZE_OF_DIR_ENTRY + F2FS_SLOT_LEN) * NR_INLINE_DENTRY(inode) +      \
	  INLINE_DENTRY_BITMAP_SIZE(inode)))

struct f2fs_filename {
	const struct qstr *usr_fname;

	struct fscrypt_str disk_name;

	f2fs_hash_t hash;

#ifdef CONFIG_FS_ENCRYPTION

	struct fscrypt_str crypto_buf;
#endif
#ifdef CONFIG_UNICODE

	struct fscrypt_str cf_name;
#endif
};

struct f2fs_dentry_ptr {
	struct inode *inode;
	void *bitmap;
	struct f2fs_dir_entry *dentry;
	__u8 (*filename)[F2FS_SLOT_LEN];
	int max;
	int nr_bitmap;
};

static inline void make_dentry_ptr_block(struct inode *inode,
					 struct f2fs_dentry_ptr *d,
					 struct f2fs_dentry_block *t)
{
	d->inode     = inode;
	d->max	     = NR_DENTRY_IN_BLOCK;
	d->nr_bitmap = SIZE_OF_DENTRY_BITMAP;
	d->bitmap    = t->dentry_bitmap;
	d->dentry    = t->dentry;
	d->filename  = t->filename;
}

static inline void make_dentry_ptr_inline(struct inode *inode,
					  struct f2fs_dentry_ptr *d, void *t)
{
	int entry_cnt	  = NR_INLINE_DENTRY(inode);
	int bitmap_size	  = INLINE_DENTRY_BITMAP_SIZE(inode);
	int reserved_size = INLINE_RESERVED_SIZE(inode);

	d->inode     = inode;
	d->max	     = entry_cnt;
	d->nr_bitmap = bitmap_size;
	d->bitmap    = t;
	d->dentry    = t + bitmap_size + reserved_size;
	d->filename =
		t + bitmap_size + reserved_size + SIZE_OF_DIR_ENTRY * entry_cnt;
}

#define XATTR_NODE_OFFSET                                                      \
	((((unsigned int)-1) << OFFSET_BIT_SHIFT) >> OFFSET_BIT_SHIFT)
enum {
	ALLOC_NODE,
	LOOKUP_NODE,
	LOOKUP_NODE_RA,
};

#define DEFAULT_RETRY_IO_COUNT 8

#define DEFAULT_IO_TIMEOUT (msecs_to_jiffies(20))

#define DEFAULT_RETRY_QUOTA_FLUSH_COUNT 8

#define F2FS_LINK_MAX 0xffffffff

#define MAX_DIR_RA_PAGES 4

#define F2FS_MIN_EXTENT_LEN 64

#define EXTENT_CACHE_SHRINK_NUMBER 128

struct rb_entry {
	struct rb_node rb_node;
	union {
		struct {
			unsigned int ofs;
			unsigned int len;
		};
		unsigned long long key;
	} __packed;
};

struct extent_info {
	unsigned int fofs;
	unsigned int len;
	u32 blk;
};

struct extent_node {
	struct rb_node rb_node;
	struct extent_info ei;
	struct list_head list;
	struct extent_tree *et;
};

struct extent_tree {
	nid_t ino;
	struct rb_root_cached root;
	struct extent_node *cached_en;
	struct extent_info largest;
	struct list_head list;
	rwlock_t lock;
	atomic_t node_cnt;
	bool largest_updated;
};

#define F2FS_MAP_NEW	   (1 << BH_New)
#define F2FS_MAP_MAPPED	   (1 << BH_Mapped)
#define F2FS_MAP_UNWRITTEN (1 << BH_Unwritten)
#define F2FS_MAP_FLAGS	   (F2FS_MAP_NEW | F2FS_MAP_MAPPED | F2FS_MAP_UNWRITTEN)

struct f2fs_map_blocks {
	block_t m_pblk;
	block_t m_lblk;
	unsigned int m_len;
	unsigned int m_flags;
	pgoff_t *m_next_pgofs;
	pgoff_t *m_next_extent;
	int m_seg_type;
	bool m_may_create;
};

enum {
	F2FS_GET_BLOCK_DEFAULT,
	F2FS_GET_BLOCK_FIEMAP,
	F2FS_GET_BLOCK_BMAP,
	F2FS_GET_BLOCK_DIO,
	F2FS_GET_BLOCK_PRE_DIO,
	F2FS_GET_BLOCK_PRE_AIO,
	F2FS_GET_BLOCK_PRECACHE,
};

#define FADVISE_COLD_BIT      0x01
#define FADVISE_LOST_PINO_BIT 0x02
#define FADVISE_ENCRYPT_BIT   0x04
#define FADVISE_ENC_NAME_BIT  0x08
#define FADVISE_KEEP_SIZE_BIT 0x10
#define FADVISE_HOT_BIT	      0x20
#define FADVISE_VERITY_BIT    0x40

#define FADVISE_MODIFIABLE_BITS (FADVISE_COLD_BIT | FADVISE_HOT_BIT)

#define file_is_cold(inode)	   is_file(inode, FADVISE_COLD_BIT)
#define file_wrong_pino(inode)	   is_file(inode, FADVISE_LOST_PINO_BIT)
#define file_set_cold(inode)	   set_file(inode, FADVISE_COLD_BIT)
#define file_lost_pino(inode)	   set_file(inode, FADVISE_LOST_PINO_BIT)
#define file_clear_cold(inode)	   clear_file(inode, FADVISE_COLD_BIT)
#define file_got_pino(inode)	   clear_file(inode, FADVISE_LOST_PINO_BIT)
#define file_is_encrypt(inode)	   is_file(inode, FADVISE_ENCRYPT_BIT)
#define file_set_encrypt(inode)	   set_file(inode, FADVISE_ENCRYPT_BIT)
#define file_clear_encrypt(inode)  clear_file(inode, FADVISE_ENCRYPT_BIT)
#define file_enc_name(inode)	   is_file(inode, FADVISE_ENC_NAME_BIT)
#define file_set_enc_name(inode)   set_file(inode, FADVISE_ENC_NAME_BIT)
#define file_keep_isize(inode)	   is_file(inode, FADVISE_KEEP_SIZE_BIT)
#define file_set_keep_isize(inode) set_file(inode, FADVISE_KEEP_SIZE_BIT)
#define file_is_hot(inode)	   is_file(inode, FADVISE_HOT_BIT)
#define file_set_hot(inode)	   set_file(inode, FADVISE_HOT_BIT)
#define file_clear_hot(inode)	   clear_file(inode, FADVISE_HOT_BIT)
#define file_is_verity(inode)	   is_file(inode, FADVISE_VERITY_BIT)
#define file_set_verity(inode)	   set_file(inode, FADVISE_VERITY_BIT)

#define DEF_DIR_LEVEL 0

enum { GC_FAILURE_PIN, GC_FAILURE_ATOMIC, MAX_GC_FAILURE };

enum {
	FI_NEW_INODE,
	FI_DIRTY_INODE,
	FI_AUTO_RECOVER,
	FI_DIRTY_DIR,
	FI_INC_LINK,
	FI_ACL_MODE,
	FI_NO_ALLOC,
	FI_FREE_NID,
	FI_NO_EXTENT,
	FI_INLINE_XATTR,
	FI_INLINE_DATA,
	FI_INLINE_DENTRY,
	FI_APPEND_WRITE,
	FI_UPDATE_WRITE,
	FI_NEED_IPU,
	FI_ATOMIC_FILE,
	FI_ATOMIC_COMMIT,
	FI_VOLATILE_FILE,
	FI_FIRST_BLOCK_WRITTEN,
	FI_DROP_CACHE,
	FI_DATA_EXIST,
	FI_INLINE_DOTS,
	FI_DO_DEFRAG,
	FI_DIRTY_FILE,
	FI_NO_PREALLOC,
	FI_HOT_DATA,
	FI_EXTRA_ATTR,
	FI_PROJ_INHERIT,
	FI_PIN_FILE,
	FI_ATOMIC_REVOKE_REQUEST,
	FI_VERITY_IN_PROGRESS,
	FI_COMPRESSED_FILE,
	FI_MMAP_FILE,
	FI_MAX,
};

struct f2fs_inode_info {
	struct inode vfs_inode;
	unsigned long i_flags;
	unsigned char i_advise;
	unsigned char i_dir_level;
	unsigned int i_current_depth;

	unsigned int i_gc_failures[MAX_GC_FAILURE];
	unsigned int i_pino;
	umode_t i_acl_mode;

	unsigned long flags[BITS_TO_LONGS(FI_MAX)];
	struct rw_semaphore i_sem;
	atomic_t dirty_pages;
	f2fs_hash_t chash;
	unsigned int clevel;
	struct task_struct *task;
	struct task_struct *cp_task;
	nid_t i_xattr_nid;
	loff_t last_disk_size;
	spinlock_t i_size_lock;

#ifdef CONFIG_QUOTA
	struct dquot *i_dquot[MAXQUOTAS];

	qsize_t i_reserved_quota;
#endif
	struct list_head dirty_list;
	struct list_head gdirty_list;
	struct list_head inmem_ilist;
	struct list_head inmem_pages;
	struct task_struct *inmem_task;
	struct mutex inmem_lock;
	pgoff_t ra_offset;
	struct extent_tree *extent_tree;

	struct rw_semaphore i_gc_rwsem[2];
	struct rw_semaphore i_mmap_sem;
	struct rw_semaphore i_xattr_sem;

	int i_extra_isize;
	kprojid_t i_projid;
	int i_inline_xattr_size;
	struct timespec64 i_crtime;
	struct timespec64 i_disk_time[4];

	atomic_t i_compr_blocks;
	unsigned char i_compress_algorithm;
	unsigned char i_log_cluster_size;
	unsigned int i_cluster_size;
};

static inline void get_extent_info(struct extent_info *ext,
				   struct f2fs_extent *i_ext)
{
	ext->fofs = le32_to_cpu(i_ext->fofs);
	ext->blk  = le32_to_cpu(i_ext->blk);
	ext->len  = le32_to_cpu(i_ext->len);
}

static inline void set_raw_extent(struct extent_info *ext,
				  struct f2fs_extent *i_ext)
{
	i_ext->fofs = cpu_to_le32(ext->fofs);
	i_ext->blk  = cpu_to_le32(ext->blk);
	i_ext->len  = cpu_to_le32(ext->len);
}

static inline void set_extent_info(struct extent_info *ei, unsigned int fofs,
				   u32 blk, unsigned int len)
{
	ei->fofs = fofs;
	ei->blk	 = blk;
	ei->len	 = len;
}

static inline bool __is_discard_mergeable(struct discard_info *back,
					  struct discard_info *front,
					  unsigned int max_len)
{
	return (back->lstart + back->len == front->lstart) &&
	       (back->len + front->len <= max_len);
}

static inline bool __is_discard_back_mergeable(struct discard_info *cur,
					       struct discard_info *back,
					       unsigned int max_len)
{
	return __is_discard_mergeable(back, cur, max_len);
}

static inline bool __is_discard_front_mergeable(struct discard_info *cur,
						struct discard_info *front,
						unsigned int max_len)
{
	return __is_discard_mergeable(cur, front, max_len);
}

static inline bool __is_extent_mergeable(struct extent_info *back,
					 struct extent_info *front)
{
	return (back->fofs + back->len == front->fofs &&
		back->blk + back->len == front->blk);
}

static inline bool __is_back_mergeable(struct extent_info *cur,
				       struct extent_info *back)
{
	return __is_extent_mergeable(back, cur);
}

static inline bool __is_front_mergeable(struct extent_info *cur,
					struct extent_info *front)
{
	return __is_extent_mergeable(cur, front);
}

extern void f2fs_mark_inode_dirty_sync(struct inode *inode, bool sync);
static inline void __try_update_largest_extent(struct extent_tree *et,
					       struct extent_node *en)
{
	if (en->ei.len > et->largest.len) {
		et->largest	    = en->ei;
		et->largest_updated = true;
	}
}

enum nid_state {
	FREE_NID,
	PREALLOC_NID,
	MAX_NID_STATE,
};

enum nat_state {
	TOTAL_NAT,
	DIRTY_NAT,
	RECLAIMABLE_NAT,
	MAX_NAT_STATE,
};

struct f2fs_nm_info {
	block_t nat_blkaddr;
	nid_t max_nid;
	nid_t available_nids;
	nid_t next_scan_nid;
	unsigned int ram_thresh;
	unsigned int ra_nid_pages;
	unsigned int dirty_nats_ratio;

	struct radix_tree_root nat_root;
	struct radix_tree_root nat_set_root;
	struct rw_semaphore nat_tree_lock;
	struct list_head nat_entries;
	spinlock_t nat_list_lock;
	unsigned int nat_cnt[MAX_NAT_STATE];
	unsigned int nat_blocks;

	struct radix_tree_root free_nid_root;
	struct list_head free_nid_list;
	unsigned int nid_cnt[MAX_NID_STATE];
	spinlock_t nid_list_lock;
	struct mutex build_lock;
	unsigned char **free_nid_bitmap;
	unsigned char *nat_block_bitmap;
	unsigned short *free_nid_count;

	char *nat_bitmap;

	unsigned int nat_bits_blocks;
	unsigned char *nat_bits;
	unsigned char *full_nat_bits;
	unsigned char *empty_nat_bits;
#ifdef CONFIG_F2FS_CHECK_FS
	char *nat_bitmap_mir;
#endif
	int bitmap_size;
};

struct dnode_of_data {
	struct inode *inode;
	struct page *inode_page;
	struct page *node_page;
	nid_t nid;
	unsigned int ofs_in_node;
	bool inode_page_locked;
	bool node_changed;
	char cur_level;
	char max_level;
	block_t data_blkaddr;
#ifdef CONFIG_F2FS_FS_DEDUP
	block_t vaddr;
#endif
};

static inline void set_new_dnode(struct dnode_of_data *dn, struct inode *inode,
				 struct page *ipage, struct page *npage,
				 nid_t nid)
{
	memset(dn, 0, sizeof(*dn));
	dn->inode      = inode;
	dn->inode_page = ipage;
	dn->node_page  = npage;
	dn->nid	       = nid;
}

struct vnode_of_data {
	block_t data_blkaddr;
	virtual_t vaddr;

	bool set_addr;
};

static inline void set_new_vnode(struct vnode_of_data *vn, virtual_t vaddr,
				 block_t data_blkaddr, bool set_addr)
{
	memset(vn, 0, sizeof(*vn));
	vn->vaddr	 = vaddr;
	vn->data_blkaddr = data_blkaddr;
	vn->set_addr	 = set_addr;
}

#define NR_CURSEG_DATA_TYPE    (3)
#define NR_CURSEG_NODE_TYPE    (3)
#define NR_CURSEG_INMEM_TYPE   (2)
#define NR_CURSEG_PERSIST_TYPE (NR_CURSEG_DATA_TYPE + NR_CURSEG_NODE_TYPE)
#define NR_CURSEG_TYPE	       (NR_CURSEG_INMEM_TYPE + NR_CURSEG_PERSIST_TYPE)

enum {
	CURSEG_HOT_DATA = 0,
	CURSEG_WARM_DATA,
	CURSEG_COLD_DATA,
	CURSEG_HOT_NODE,
	CURSEG_WARM_NODE,
	CURSEG_COLD_NODE,
	NR_PERSISTENT_LOG,
	CURSEG_COLD_DATA_PINNED = NR_PERSISTENT_LOG,

	CURSEG_ALL_DATA_ATGC,
	NO_CHECK_TYPE,
};

struct flush_cmd {
	struct completion wait;
	struct llist_node llnode;
	nid_t ino;
	int ret;
};

struct flush_cmd_control {
	struct task_struct *f2fs_issue_flush;
	wait_queue_head_t flush_wait_queue;
	atomic_t issued_flush;
	atomic_t queued_flush;
	struct llist_head issue_list;
	struct llist_node *dispatch_list;
};

struct f2fs_sm_info {
	struct sit_info *sit_info;
	struct free_segmap_info *free_info;
	struct dirty_seglist_info *dirty_info;
	struct curseg_info *curseg_array;

	struct rw_semaphore curseg_lock;

	block_t seg0_blkaddr;
	block_t main_blkaddr;
	block_t ssa_blkaddr;

	unsigned int segment_count;
	unsigned int main_segments;
	unsigned int reserved_segments;
	unsigned int ovp_segments;

	unsigned int rec_prefree_segments;

	unsigned int trim_sections;

	struct list_head sit_entry_set;

	unsigned int ipu_policy;
	unsigned int min_ipu_util;
	unsigned int min_fsync_blocks;
	unsigned int min_seq_blocks;
	unsigned int min_hot_blocks;
	unsigned int min_ssr_sections;

	struct flush_cmd_control *fcc_info;

	struct discard_cmd_control *dcc_info;
};

#define WB_DATA_TYPE(p) (__is_cp_guaranteed(p) ? F2FS_WB_CP_DATA : F2FS_WB_DATA)
enum count_type {
	F2FS_DIRTY_DENTS,
	F2FS_DIRTY_DATA,
	F2FS_DIRTY_QDATA,
	F2FS_DIRTY_NODES,
	F2FS_DIRTY_META,
	F2FS_INMEM_PAGES,
	F2FS_DIRTY_IMETA,
	F2FS_WB_CP_DATA,
	F2FS_WB_DATA,
	F2FS_RD_DATA,
	F2FS_RD_NODE,
	F2FS_RD_META,
	F2FS_DIO_WRITE,
	F2FS_DIO_READ,
	F2FS_RD_GC,
	NR_COUNT_TYPE,
};

#define PAGE_TYPE_OF_BIO(type) ((type) > META ? META : (type))
enum page_type {
	DATA,
	NODE,
	META,
	NR_PAGE_TYPE,
	META_FLUSH,
	INMEM,
	INMEM_DROP,
	INMEM_INVALIDATE,
	INMEM_REVOKE,
	IPU,
	OPU,
};

enum temp_type {
	HOT = 0,
	WARM,
	COLD,
	NR_TEMP_TYPE,
};

enum need_lock_type {
	LOCK_REQ = 0,
	LOCK_DONE,
	LOCK_RETRY,
};

enum cp_reason_type {
	CP_NO_NEEDED,
	CP_NON_REGULAR,
	CP_COMPRESSED,
	CP_HARDLINK,
	CP_SB_NEED_CP,
	CP_WRONG_PINO,
	CP_NO_SPC_ROLL,
	CP_NODE_NEED_CP,
	CP_FASTBOOT_MODE,
	CP_SPEC_LOG_NUM,
	CP_RECOVER_DIR,
};

enum iostat_type {

	APP_DIRECT_IO,
	APP_BUFFERED_IO,
	APP_WRITE_IO,
	APP_MAPPED_IO,
	FS_DATA_IO,
	FS_NODE_IO,
	FS_META_IO,
	FS_GC_DATA_IO,
	FS_GC_NODE_IO,
	FS_CP_DATA_IO,
	FS_CP_NODE_IO,
	FS_CP_META_IO,

	APP_DIRECT_READ_IO,
	APP_BUFFERED_READ_IO,
	APP_READ_IO,
	APP_MAPPED_READ_IO,
	FS_DATA_READ_IO,
	FS_GDATA_READ_IO,
	FS_CDATA_READ_IO,
	FS_NODE_READ_IO,
	FS_META_READ_IO,

	FS_DISCARD,
	NR_IO_TYPE,
};

struct f2fs_io_info {
	struct f2fs_sb_info *sbi;
	nid_t ino;
	enum page_type type;
	enum temp_type temp;
	int op;
	int op_flags;
	block_t new_blkaddr;
	block_t old_blkaddr;
	struct page *page;
	struct page *encrypted_page;
	struct page *compressed_page;
	struct list_head list;
	bool submitted;
	int need_lock;
	bool in_list;
	bool is_por;
	bool retry;
	int compr_blocks;
	bool encrypted;
	enum iostat_type io_type;
	struct writeback_control *io_wbc;
	struct bio **bio;
	sector_t *last_block;
	unsigned char version;
};

struct bio_entry {
	struct bio *bio;
	struct list_head list;
};

#define is_read_io(rw) ((rw) == READ)
struct f2fs_bio_info {
	struct f2fs_sb_info *sbi;
	struct bio *bio;
	sector_t last_block_in_bio;
	struct f2fs_io_info fio;
	struct rw_semaphore io_rwsem;
	spinlock_t io_lock;
	struct list_head io_list;
	struct list_head bio_list;
	struct rw_semaphore bio_list_lock;
};

#define FDEV(i) (sbi->devs[i])
#define RDEV(i) (raw_super->devs[i])
struct f2fs_dev_info {
	struct block_device *bdev;
	char path[MAX_PATH_LEN];
	unsigned int total_segments;
	block_t start_blk;
	block_t end_blk;
#ifdef CONFIG_BLK_DEV_ZONED
	unsigned int nr_blkz;
	unsigned long *blkz_seq;
	block_t *zone_capacity_blocks;
#endif
};

enum inode_type {
	DIR_INODE,
	FILE_INODE,
	DIRTY_META,
	ATOMIC_FILE,
	NR_INODE_TYPE,
};

struct inode_management {
	struct radix_tree_root ino_root;
	spinlock_t ino_lock;
	struct list_head ino_list;
	unsigned long ino_num;
};

struct atgc_management {
	bool atgc_enabled;
	struct rb_root_cached root;
	struct list_head victim_list;
	unsigned int victim_count;
	unsigned int candidate_ratio;
	unsigned int max_candidate_count;
	unsigned int age_weight;
	unsigned long long age_threshold;
};

enum {
	SBI_IS_DIRTY,
	SBI_IS_CLOSE,
	SBI_NEED_FSCK,
	SBI_POR_DOING,
	SBI_NEED_SB_WRITE,
	SBI_NEED_CP,
	SBI_IS_SHUTDOWN,
	SBI_IS_RECOVERED,
	SBI_CP_DISABLED,
	SBI_CP_DISABLED_QUICK,
	SBI_QUOTA_NEED_FLUSH,
	SBI_QUOTA_SKIP_FLUSH,
	SBI_QUOTA_NEED_REPAIR,
	SBI_IS_RESIZEFS,
};

enum {
	CP_TIME,
	REQ_TIME,
	DISCARD_TIME,
	GC_TIME,
	DISABLE_TIME,
	UMOUNT_DISCARD_TIMEOUT,
	MAX_TIME,
};

enum {
	GC_NORMAL,
	GC_IDLE_CB,
	GC_IDLE_GREEDY,
	GC_IDLE_AT,
	GC_URGENT_HIGH,
	GC_URGENT_LOW,
};

enum {
	BGGC_MODE_ON,
	BGGC_MODE_OFF,
	BGGC_MODE_SYNC,
};

enum {
	FS_MODE_ADAPTIVE,
	FS_MODE_LFS,
};

enum {
	WHINT_MODE_OFF,
	WHINT_MODE_USER,
	WHINT_MODE_FS,
};

enum {
	ALLOC_MODE_DEFAULT,
	ALLOC_MODE_REUSE,
};

enum fsync_mode {
	FSYNC_MODE_POSIX,
	FSYNC_MODE_STRICT,
	FSYNC_MODE_NOBARRIER,
};

#define ATOMIC_WRITTEN_PAGE ((unsigned long)-1)
#define DUMMY_WRITTEN_PAGE  ((unsigned long)-2)

#define IS_ATOMIC_WRITTEN_PAGE(page) (page_private(page) == ATOMIC_WRITTEN_PAGE)
#define IS_DUMMY_WRITTEN_PAGE(page)  (page_private(page) == DUMMY_WRITTEN_PAGE)

#ifdef CONFIG_F2FS_IO_TRACE
#define IS_IO_TRACED_PAGE(page)                                                \
	(page_private(page) > 0 &&                                             \
	 page_private(page) < (unsigned long)PID_MAX_LIMIT)
#else
#define IS_IO_TRACED_PAGE(page) (0)
#endif

enum compress_algorithm_type {
	COMPRESS_LZO,
	COMPRESS_LZ4,
	COMPRESS_ZSTD,
	COMPRESS_LZORLE,
	COMPRESS_MAX,
};

#define COMPRESS_DATA_RESERVED_SIZE 5
struct compress_data {
	__le32 clen;
	__le32 reserved[COMPRESS_DATA_RESERVED_SIZE];
	u8 cdata[];
};

#define COMPRESS_HEADER_SIZE (sizeof(struct compress_data))

#define F2FS_COMPRESSED_PAGE_MAGIC 0xF5F2C000

struct compress_ctx {
	struct inode *inode;
	pgoff_t cluster_idx;
	unsigned int cluster_size;
	unsigned int log_cluster_size;
	struct page **rpages;
	unsigned int nr_rpages;
	struct page **cpages;
	unsigned int nr_cpages;
	void *rbuf;
	struct compress_data *cbuf;
	size_t rlen;
	size_t clen;
	void *private;
	void *private2;
};

struct compress_io_ctx {
	u32 magic;
	struct inode *inode;
	struct page **rpages;
	unsigned int nr_rpages;
	atomic_t pending_pages;
};

struct decompress_io_ctx {
	u32 magic;
	struct inode *inode;
	pgoff_t cluster_idx;
	unsigned int cluster_size;
	unsigned int log_cluster_size;
	struct page **rpages;
	unsigned int nr_rpages;
	struct page **cpages;
	unsigned int nr_cpages;
	struct page **tpages;
	void *rbuf;
	struct compress_data *cbuf;
	size_t rlen;
	size_t clen;
	atomic_t pending_pages;
	atomic_t verity_pages;
	bool failed;
	void *private;
	void *private2;
};

#define NULL_CLUSTER			   ((unsigned int)(~0))
#define MIN_COMPRESS_LOG_SIZE		   2
#define MAX_COMPRESS_LOG_SIZE		   8
#define MAX_COMPRESS_WINDOW_SIZE(log_size) ((PAGE_SIZE) << (log_size))

struct f2fs_sb_info {
	struct super_block *sb;
	struct proc_dir_entry *s_proc;
	struct f2fs_super_block *raw_super;
	struct rw_semaphore sb_lock;
	int valid_super_block;
	unsigned long s_flag;
	struct mutex writepages;

#ifdef CONFIG_BLK_DEV_ZONED
	unsigned int blocks_per_blkz;
	unsigned int log_blocks_per_blkz;
#endif

	struct f2fs_nm_info *nm_info;
	struct inode *node_inode;

	struct f2fs_sm_info *sm_info;

	struct f2fs_bio_info *write_io[NR_PAGE_TYPE];
	struct rw_semaphore io_order_lock;
	mempool_t *write_io_dummy;

	struct f2fs_checkpoint *ckpt;
	int cur_cp_pack;
	spinlock_t cp_lock;
	struct inode *meta_inode;
	struct mutex cp_mutex;
	struct rw_semaphore cp_rwsem;
	struct rw_semaphore node_write;
	struct rw_semaphore node_change;
	wait_queue_head_t cp_wait;
	unsigned long last_time[MAX_TIME];
	long interval_time[MAX_TIME];

	struct inode_management im[MAX_INO_ENTRY];

	spinlock_t fsync_node_lock;
	struct list_head fsync_node_list;
	unsigned int fsync_seg_id;
	unsigned int fsync_node_num;

	unsigned int max_orphans;

	struct list_head inode_list[NR_INODE_TYPE];
	spinlock_t inode_lock[NR_INODE_TYPE];
	struct mutex flush_lock;

	struct radix_tree_root extent_tree_root;
	struct mutex extent_tree_lock;
	struct list_head extent_list;
	spinlock_t extent_lock;
	atomic_t total_ext_tree;
	struct list_head zombie_list;
	atomic_t total_zombie_tree;
	atomic_t total_ext_node;

	unsigned int log_sectors_per_block;
	unsigned int log_blocksize;
	unsigned int blocksize;
	unsigned int root_ino_num;
	unsigned int node_ino_num;
	unsigned int meta_ino_num;
	unsigned int log_blocks_per_seg;
	unsigned int blocks_per_seg;
	unsigned int segs_per_sec;
	unsigned int secs_per_zone;
	unsigned int total_sections;
	unsigned int total_node_count;
	unsigned int total_valid_node_count;
	loff_t max_file_blocks;
	int dir_level;
	int readdir_ra;

	block_t user_block_count;
	block_t total_valid_block_count;
	block_t discard_blks;
	block_t last_valid_block_count;
	block_t reserved_blocks;
	block_t current_reserved_blocks;

	block_t unusable_block_count;

	unsigned int nquota_files;
	struct rw_semaphore quota_sem;

	atomic_t nr_pages[NR_COUNT_TYPE];

	struct percpu_counter alloc_valid_block_count;

	atomic_t wb_sync_req[META];

	struct percpu_counter total_valid_inode_count;

	struct f2fs_mount_info mount_opt;

	struct rw_semaphore gc_lock;
	struct f2fs_gc_kthread *gc_thread;
	struct atgc_management am;
	unsigned int cur_victim_sec;
	unsigned int gc_mode;
	unsigned int next_victim_seg[2];

	unsigned int atomic_files;
	unsigned long long skipped_atomic_files[2];
	unsigned long long skipped_gc_rwsem;

	u64 gc_pin_file_threshold;
	struct rw_semaphore pin_sem;

	unsigned int max_victim_search;

	unsigned int migration_granularity;

#ifdef CONFIG_F2FS_STAT_FS
	struct f2fs_stat_info *stat_info;
	atomic_t meta_count[META_MAX];
	unsigned int segment_count[2];
	unsigned int block_count[2];
	atomic_t inplace_count;
	atomic64_t total_hit_ext;
	atomic64_t read_hit_rbtree;
	atomic64_t read_hit_largest;
	atomic64_t read_hit_cached;
	atomic_t inline_xattr;
	atomic_t inline_inode;
	atomic_t inline_dir;
	atomic_t compr_inode;
	atomic64_t compr_blocks;
	atomic_t vw_cnt;
	atomic_t max_aw_cnt;
	atomic_t max_vw_cnt;
	unsigned int io_skip_bggc;
	unsigned int other_skip_bggc;
	unsigned int ndirty_inode[NR_INODE_TYPE];

#ifdef CONFIG_F2FS_FS_DEDUP
	unsigned int io_skip_bgfp;
	unsigned int resource_skip_bgfp;
	unsigned int other_skip_bgfp;
#endif
#endif
	spinlock_t stat_lock;

	spinlock_t iostat_lock;
	unsigned long long rw_iostat[NR_IO_TYPE];
	unsigned long long prev_rw_iostat[NR_IO_TYPE];
	bool iostat_enable;
	unsigned long iostat_next_period;
	unsigned int iostat_period_ms;

	unsigned int data_io_flag;
	unsigned int node_io_flag;

	struct kobject s_kobj;
	struct completion s_kobj_unregister;

	struct list_head s_list;
	int s_ndevs;
	struct f2fs_dev_info *devs;
	unsigned int dirty_device;
	spinlock_t dev_lock;
	struct mutex umount_mutex;
	unsigned int shrinker_run_no;

	u64 sectors_written_start;
	u64 kbytes_written;

	struct crypto_shash *s_chksum_driver;

	__u32 s_chksum_seed;

	struct workqueue_struct *post_read_wq;

	struct kmem_cache *inline_xattr_slab;
	unsigned int inline_xattr_slab_size;

#ifdef CONFIG_F2FS_FS_COMPRESSION
	struct kmem_cache *page_array_slab;
	unsigned int page_array_slab_size;
#endif

#ifdef CONFIG_F2FS_FS_DEDUP
	block_t duplication_block_count_high;
	block_t duplication_block_count_low;
	block_t unique_block_count;
	block_t zero_block_count;
	block_t offline_block_count;

	struct f2dfs_dm_info *dm_info;

	unsigned int gc_ino_num;
	struct inode *gc_inode;

	struct f2dfs_fingerprint_hash *s_fp_hash;

	struct f2dfs_fp_bucket_list *s_fp_bucket;
	struct rw_semaphore s_fp_bucket_lock;

	struct f2dfs_fp_bucket *fp_buffer;
	struct rw_semaphore fp_buffer_lock;

	struct f2dfs_rc_base_buffer *rcb_buffer;
	spinlock_t rcb_buffer_lock;

	struct f2dfs_rc_delta_buffer *rcd_buffer;
	spinlock_t rcd_buffer_lock;
#endif
};

struct f2fs_private_dio {
	struct inode *inode;
	void *orig_private;
	bio_end_io_t *orig_end_io;
	bool write;
};

#ifdef CONFIG_F2FS_FAULT_INJECTION
#define f2fs_show_injection_info(sbi, type)                                    \
	printk_ratelimited("%sF2FS-fs (%s) : inject %s in %s of %pS\n",        \
			   KERN_INFO, sbi->sb->s_id, f2fs_fault_name[type],    \
			   __func__, __builtin_return_address(0))
static inline bool time_to_inject(struct f2fs_sb_info *sbi, int type)
{
	struct f2fs_fault_info *ffi = &F2FS_OPTION(sbi).fault_info;

	if (!ffi->inject_rate)
		return false;

	if (!IS_FAULT_SET(ffi, type))
		return false;

	atomic_inc(&ffi->inject_ops);
	if (atomic_read(&ffi->inject_ops) >= ffi->inject_rate) {
		atomic_set(&ffi->inject_ops, 0);
		return true;
	}
	return false;
}
#else
#define f2fs_show_injection_info(sbi, type)                                    \
	do {                                                                   \
	} while (0)
static inline bool time_to_inject(struct f2fs_sb_info *sbi, int type)
{
	return false;
}
#endif

static inline bool f2fs_is_multi_device(struct f2fs_sb_info *sbi)
{
	return sbi->s_ndevs > 1;
}

#define BD_PART_WRITTEN(s)                                                     \
	(((u64)part_stat_read((s)->sb->s_bdev->bd_part, sectors[STAT_WRITE]) - \
	  (s)->sectors_written_start) >>                                       \
	 1)

static inline void f2fs_update_time(struct f2fs_sb_info *sbi, int type)
{
	unsigned long now = jiffies;

	sbi->last_time[type] = now;

	if (type == REQ_TIME) {
		sbi->last_time[DISCARD_TIME] = now;
		sbi->last_time[GC_TIME]	     = now;
	}
}

static inline bool f2fs_time_over(struct f2fs_sb_info *sbi, int type)
{
	unsigned long interval = sbi->interval_time[type] * HZ;

	return time_after(jiffies, sbi->last_time[type] + interval);
}

static inline unsigned int f2fs_time_to_wait(struct f2fs_sb_info *sbi, int type)
{
	unsigned long interval = sbi->interval_time[type] * HZ;
	unsigned int wait_ms   = 0;
	long delta;

	delta = (sbi->last_time[type] + interval) - jiffies;
	if (delta > 0)
		wait_ms = jiffies_to_msecs(delta);

	return wait_ms;
}

static inline u32 __f2fs_crc32(struct f2fs_sb_info *sbi, u32 crc,
			       const void *address, unsigned int length)
{
	struct {
		struct shash_desc shash;
		char ctx[4];
	} desc;
	int err;

	BUG_ON(crypto_shash_descsize(sbi->s_chksum_driver) != sizeof(desc.ctx));

	desc.shash.tfm	 = sbi->s_chksum_driver;
	*(u32 *)desc.ctx = crc;

	err = crypto_shash_update(&desc.shash, address, length);
	BUG_ON(err);

	return *(u32 *)desc.ctx;
}

static inline u32 f2fs_crc32(struct f2fs_sb_info *sbi, const void *address,
			     unsigned int length)
{
	return __f2fs_crc32(sbi, F2FS_SUPER_MAGIC, address, length);
}

static inline bool f2fs_crc_valid(struct f2fs_sb_info *sbi, __u32 blk_crc,
				  void *buf, size_t buf_size)
{
	return f2fs_crc32(sbi, buf, buf_size) == blk_crc;
}

static inline u32 f2fs_chksum(struct f2fs_sb_info *sbi, u32 crc,
			      const void *address, unsigned int length)
{
	return __f2fs_crc32(sbi, crc, address, length);
}

static inline struct f2fs_inode_info *F2FS_I(struct inode *inode)
{
	return container_of(inode, struct f2fs_inode_info, vfs_inode);
}

static inline struct f2fs_sb_info *F2FS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline struct f2fs_sb_info *F2FS_I_SB(struct inode *inode)
{
	return F2FS_SB(inode->i_sb);
}

static inline struct f2fs_sb_info *F2FS_M_SB(struct address_space *mapping)
{
	return F2FS_I_SB(mapping->host);
}

static inline struct f2fs_sb_info *F2FS_P_SB(struct page *page)
{
	return F2FS_M_SB(page_file_mapping(page));
}

static inline struct f2fs_super_block *F2FS_RAW_SUPER(struct f2fs_sb_info *sbi)
{
	return (struct f2fs_super_block *)(sbi->raw_super);
}

static inline struct f2fs_checkpoint *F2FS_CKPT(struct f2fs_sb_info *sbi)
{
	return (struct f2fs_checkpoint *)(sbi->ckpt);
}

static inline struct f2fs_node *F2FS_NODE(struct page *page)
{
	return (struct f2fs_node *)page_address(page);
}

static inline struct f2fs_inode *F2FS_INODE(struct page *page)
{
	return &((struct f2fs_node *)page_address(page))->i;
}

static inline struct f2fs_nm_info *NM_I(struct f2fs_sb_info *sbi)
{
	return (struct f2fs_nm_info *)(sbi->nm_info);
}

static inline struct f2fs_sm_info *SM_I(struct f2fs_sb_info *sbi)
{
	return (struct f2fs_sm_info *)(sbi->sm_info);
}

static inline struct sit_info *SIT_I(struct f2fs_sb_info *sbi)
{
	return (struct sit_info *)(SM_I(sbi)->sit_info);
}

static inline struct free_segmap_info *FREE_I(struct f2fs_sb_info *sbi)
{
	return (struct free_segmap_info *)(SM_I(sbi)->free_info);
}

static inline struct dirty_seglist_info *DIRTY_I(struct f2fs_sb_info *sbi)
{
	return (struct dirty_seglist_info *)(SM_I(sbi)->dirty_info);
}

static inline struct address_space *META_MAPPING(struct f2fs_sb_info *sbi)
{
	return sbi->meta_inode->i_mapping;
}

static inline struct address_space *NODE_MAPPING(struct f2fs_sb_info *sbi)
{
	return sbi->node_inode->i_mapping;
}

static inline struct address_space *GC_MAPPING(struct f2fs_sb_info *sbi)
{
	return sbi->gc_inode->i_mapping;
}

static inline bool is_sbi_flag_set(struct f2fs_sb_info *sbi, unsigned int type)
{
	return test_bit(type, &sbi->s_flag);
}

static inline void set_sbi_flag(struct f2fs_sb_info *sbi, unsigned int type)
{
	set_bit(type, &sbi->s_flag);
}

static inline void clear_sbi_flag(struct f2fs_sb_info *sbi, unsigned int type)
{
	clear_bit(type, &sbi->s_flag);
}

static inline unsigned long long cur_cp_version(struct f2fs_checkpoint *cp)
{
	return le64_to_cpu(cp->checkpoint_ver);
}

static inline unsigned long f2fs_qf_ino(struct super_block *sb, int type)
{
	if (type < F2FS_MAX_QUOTAS)
		return le32_to_cpu(F2FS_SB(sb)->raw_super->qf_ino[type]);
	return 0;
}

static inline __u64 cur_cp_crc(struct f2fs_checkpoint *cp)
{
	size_t crc_offset = le32_to_cpu(cp->checksum_offset);
	return le32_to_cpu(*((__le32 *)((unsigned char *)cp + crc_offset)));
}

static inline bool __is_set_ckpt_flags(struct f2fs_checkpoint *cp,
				       unsigned int f)
{
	unsigned int ckpt_flags = le32_to_cpu(cp->ckpt_flags);

	return ckpt_flags & f;
}

static inline bool is_set_ckpt_flags(struct f2fs_sb_info *sbi, unsigned int f)
{
	return __is_set_ckpt_flags(F2FS_CKPT(sbi), f);
}

static inline void __set_ckpt_flags(struct f2fs_checkpoint *cp, unsigned int f)
{
	unsigned int ckpt_flags;

	ckpt_flags = le32_to_cpu(cp->ckpt_flags);
	ckpt_flags |= f;
	cp->ckpt_flags = cpu_to_le32(ckpt_flags);
}

static inline void set_ckpt_flags(struct f2fs_sb_info *sbi, unsigned int f)
{
	unsigned long flags;

	spin_lock_irqsave(&sbi->cp_lock, flags);
	__set_ckpt_flags(F2FS_CKPT(sbi), f);
	spin_unlock_irqrestore(&sbi->cp_lock, flags);
}

static inline void __clear_ckpt_flags(struct f2fs_checkpoint *cp,
				      unsigned int f)
{
	unsigned int ckpt_flags;

	ckpt_flags = le32_to_cpu(cp->ckpt_flags);
	ckpt_flags &= (~f);
	cp->ckpt_flags = cpu_to_le32(ckpt_flags);
}

static inline void clear_ckpt_flags(struct f2fs_sb_info *sbi, unsigned int f)
{
	unsigned long flags;

	spin_lock_irqsave(&sbi->cp_lock, flags);
	__clear_ckpt_flags(F2FS_CKPT(sbi), f);
	spin_unlock_irqrestore(&sbi->cp_lock, flags);
}

static inline void disable_nat_bits(struct f2fs_sb_info *sbi, bool lock)
{
	unsigned long flags;
	unsigned char *nat_bits;

	if (lock)
		spin_lock_irqsave(&sbi->cp_lock, flags);
	__clear_ckpt_flags(F2FS_CKPT(sbi), CP_NAT_BITS_FLAG);
	nat_bits	    = NM_I(sbi)->nat_bits;
	NM_I(sbi)->nat_bits = NULL;
	if (lock)
		spin_unlock_irqrestore(&sbi->cp_lock, flags);

	kvfree(nat_bits);
}

static inline bool enabled_nat_bits(struct f2fs_sb_info *sbi,
				    struct cp_control *cpc)
{
	bool set = is_set_ckpt_flags(sbi, CP_NAT_BITS_FLAG);

	return (cpc) ? (cpc->reason & CP_UMOUNT) && set : set;
}

static inline void f2fs_lock_op(struct f2fs_sb_info *sbi)
{
	down_read(&sbi->cp_rwsem);
}

static inline int f2fs_trylock_op(struct f2fs_sb_info *sbi)
{
	return down_read_trylock(&sbi->cp_rwsem);
}

static inline void f2fs_unlock_op(struct f2fs_sb_info *sbi)
{
	up_read(&sbi->cp_rwsem);
}

static inline void f2fs_lock_all(struct f2fs_sb_info *sbi)
{
	down_write(&sbi->cp_rwsem);
}

static inline void f2fs_unlock_all(struct f2fs_sb_info *sbi)
{
	up_write(&sbi->cp_rwsem);
}

static inline int __get_cp_reason(struct f2fs_sb_info *sbi)
{
	int reason = CP_SYNC;

	if (test_opt(sbi, FASTBOOT))
		reason = CP_FASTBOOT;
	if (is_sbi_flag_set(sbi, SBI_IS_CLOSE))
		reason = CP_UMOUNT;
	return reason;
}

static inline bool __remain_node_summaries(int reason)
{
	return (reason & (CP_UMOUNT | CP_FASTBOOT));
}

static inline bool __exist_node_summaries(struct f2fs_sb_info *sbi)
{
	return (is_set_ckpt_flags(sbi, CP_UMOUNT_FLAG) ||
		is_set_ckpt_flags(sbi, CP_FASTBOOT_FLAG));
}

static inline int F2FS_HAS_BLOCKS(struct inode *inode)
{
	block_t xattr_block = F2FS_I(inode)->i_xattr_nid ? 1 : 0;

	return (inode->i_blocks >> F2FS_LOG_SECTORS_PER_BLOCK) > xattr_block;
}

static inline bool f2fs_has_xattr_block(unsigned int ofs)
{
	return ofs == XATTR_NODE_OFFSET;
}

static inline bool __allow_reserved_blocks(struct f2fs_sb_info *sbi,
					   struct inode *inode, bool cap)
{
	if (!inode)
		return true;
	if (!test_opt(sbi, RESERVE_ROOT))
		return false;
	if (IS_NOQUOTA(inode))
		return true;
	if (uid_eq(F2FS_OPTION(sbi).s_resuid, current_fsuid()))
		return true;
	if (!gid_eq(F2FS_OPTION(sbi).s_resgid, GLOBAL_ROOT_GID) &&
	    in_group_p(F2FS_OPTION(sbi).s_resgid))
		return true;
	if (cap && capable(CAP_SYS_RESOURCE))
		return true;
	return false;
}

static inline void f2fs_i_blocks_write(struct inode *, block_t, bool, bool);

static inline int inc_valid_block_count(struct f2fs_sb_info *sbi,
					struct inode *inode, blkcnt_t *count)
{
	blkcnt_t diff = 0, release = 0;
	block_t avail_user_block_count;
	int ret;

	ret = dquot_reserve_block(inode, *count);
	if (ret)
		return ret;

	if (time_to_inject(sbi, FAULT_BLOCK)) {
		f2fs_show_injection_info(sbi, FAULT_BLOCK);
		release = *count;
		goto release_quota;
	}

	percpu_counter_add(&sbi->alloc_valid_block_count, (*count));

	spin_lock(&sbi->stat_lock);
	sbi->total_valid_block_count += (block_t)(*count);
	avail_user_block_count =
		sbi->user_block_count - sbi->current_reserved_blocks;

	if (!__allow_reserved_blocks(sbi, inode, true))
		avail_user_block_count -= F2FS_OPTION(sbi).root_reserved_blocks;

	if (unlikely(is_sbi_flag_set(sbi, SBI_CP_DISABLED))) {
		if (avail_user_block_count > sbi->unusable_block_count)
			avail_user_block_count -= sbi->unusable_block_count;
		else
			avail_user_block_count = 0;
	}

	if (unlikely(sbi->total_valid_block_count > avail_user_block_count)) {
		diff = sbi->total_valid_block_count - avail_user_block_count;
		if (diff > *count)
			diff = *count;
		*count -= diff;
		release = diff;
		sbi->total_valid_block_count -= diff;
		if (!*count) {
			spin_unlock(&sbi->stat_lock);
			goto enospc;
		}
	}
	spin_unlock(&sbi->stat_lock);

	if (unlikely(release)) {
		percpu_counter_sub(&sbi->alloc_valid_block_count, release);
		dquot_release_reservation_block(inode, release);
	}

	f2fs_i_blocks_write(inode, *count, true, true);
	return 0;

enospc:

	percpu_counter_sub(&sbi->alloc_valid_block_count, release);
release_quota:

	dquot_release_reservation_block(inode, release);
	return -ENOSPC;
}

__printf(2, 3) void f2fs_printk(struct f2fs_sb_info *sbi, const char *fmt, ...);

#ifdef CONFIG_F2FS_FS_DEDUP
void f2dfs_printk(struct f2fs_sb_info *sbi, const char *fmt, ...);
#define f2dfs_err(sbi, fmt, ...) f2dfs_printk(sbi, KERN_ERR fmt, ##__VA_ARGS__)
#define f2dfs_warn(sbi, fmt, ...)                                              \
	f2dfs_printk(sbi, KERN_WARNING fmt, ##__VA_ARGS__)
#define f2dfs_notice(sbi, fmt, ...)                                            \
	f2dfs_printk(sbi, KERN_NOTICE fmt, ##__VA_ARGS__)
#define f2dfs_info(sbi, fmt, ...)                                              \
	f2dfs_printk(sbi, KERN_INFO fmt, ##__VA_ARGS__)
#define f2dfs_debug(sbi, fmt, ...)                                             \
	f2dfs_printk(sbi, KERN_DEBUG fmt, ##__VA_ARGS__)
#endif

#define f2fs_err(sbi, fmt, ...) f2fs_printk(sbi, KERN_ERR fmt, ##__VA_ARGS__)
#define f2fs_warn(sbi, fmt, ...)                                               \
	f2fs_printk(sbi, KERN_WARNING fmt, ##__VA_ARGS__)
#define f2fs_notice(sbi, fmt, ...)                                             \
	f2fs_printk(sbi, KERN_NOTICE fmt, ##__VA_ARGS__)
#define f2fs_info(sbi, fmt, ...) f2fs_printk(sbi, KERN_INFO fmt, ##__VA_ARGS__)
#define f2fs_debug(sbi, fmt, ...)                                              \
	f2fs_printk(sbi, KERN_DEBUG fmt, ##__VA_ARGS__)

static inline void dec_valid_block_count(struct f2fs_sb_info *sbi,
					 struct inode *inode, block_t count)
{
	blkcnt_t sectors = count << F2FS_LOG_SECTORS_PER_BLOCK;

	spin_lock(&sbi->stat_lock);
	f2fs_bug_on(sbi, sbi->total_valid_block_count < (block_t)count);
	sbi->total_valid_block_count -= (block_t)count;
	if (sbi->reserved_blocks &&
	    sbi->current_reserved_blocks < sbi->reserved_blocks)
		sbi->current_reserved_blocks =
			min(sbi->reserved_blocks,
			    sbi->current_reserved_blocks + count);
	spin_unlock(&sbi->stat_lock);
	if (unlikely(inode->i_blocks < sectors)) {
		f2fs_warn(
			sbi,
			"Inconsistent i_blocks, ino:%lu, iblocks:%llu, sectors:%llu",
			inode->i_ino, (unsigned long long)inode->i_blocks,
			(unsigned long long)sectors);
		set_sbi_flag(sbi, SBI_NEED_FSCK);
		return;
	}
	f2fs_i_blocks_write(inode, count, false, true);
}

static inline void inc_page_count(struct f2fs_sb_info *sbi, int count_type)
{
	atomic_inc(&sbi->nr_pages[count_type]);

	if (count_type == F2FS_DIRTY_DENTS || count_type == F2FS_DIRTY_NODES ||
	    count_type == F2FS_DIRTY_META || count_type == F2FS_DIRTY_QDATA ||
	    count_type == F2FS_DIRTY_IMETA)
		set_sbi_flag(sbi, SBI_IS_DIRTY);
}

static inline void inode_inc_dirty_pages(struct inode *inode)
{
	atomic_inc(&F2FS_I(inode)->dirty_pages);
	inc_page_count(F2FS_I_SB(inode), S_ISDIR(inode->i_mode) ?
						 F2FS_DIRTY_DENTS :
						 F2FS_DIRTY_DATA);
	if (IS_NOQUOTA(inode))
		inc_page_count(F2FS_I_SB(inode), F2FS_DIRTY_QDATA);
}

static inline void dec_page_count(struct f2fs_sb_info *sbi, int count_type)
{
	atomic_dec(&sbi->nr_pages[count_type]);
}

static inline void inode_dec_dirty_pages(struct inode *inode)
{
	if (!S_ISDIR(inode->i_mode) && !S_ISREG(inode->i_mode) &&
	    !S_ISLNK(inode->i_mode))
		return;

	atomic_dec(&F2FS_I(inode)->dirty_pages);
	dec_page_count(F2FS_I_SB(inode), S_ISDIR(inode->i_mode) ?
						 F2FS_DIRTY_DENTS :
						 F2FS_DIRTY_DATA);
	if (IS_NOQUOTA(inode))
		dec_page_count(F2FS_I_SB(inode), F2FS_DIRTY_QDATA);
}

static inline s64 get_pages(struct f2fs_sb_info *sbi, int count_type)
{
	return atomic_read(&sbi->nr_pages[count_type]);
}

static inline int get_dirty_pages(struct inode *inode)
{
	return atomic_read(&F2FS_I(inode)->dirty_pages);
}

static inline int get_blocktype_secs(struct f2fs_sb_info *sbi, int block_type)
{
	unsigned int pages_per_sec = sbi->segs_per_sec * sbi->blocks_per_seg;
	unsigned int segs = (get_pages(sbi, block_type) + pages_per_sec - 1) >>
			    sbi->log_blocks_per_seg;

	return segs / sbi->segs_per_sec;
}

static inline block_t valid_user_blocks(struct f2fs_sb_info *sbi)
{
	return sbi->total_valid_block_count;
}

static inline block_t discard_blocks(struct f2fs_sb_info *sbi)
{
	return sbi->discard_blks;
}

#ifdef CONFIG_F2FS_FS_DEDUP
static inline block_t dedupe_user_blocks_high(struct f2fs_sb_info *sbi)
{
	return sbi->duplication_block_count_high;
}

static inline block_t dedupe_user_blocks_low(struct f2fs_sb_info *sbi)
{
	return sbi->duplication_block_count_low;
}

static inline block_t unique_user_blocks(struct f2fs_sb_info *sbi)
{
	return sbi->unique_block_count;
}

static inline block_t zero_user_blocks(struct f2fs_sb_info *sbi)
{
	return sbi->zero_block_count;
}

static inline block_t offline_user_blocks(struct f2fs_sb_info *sbi)
{
	return sbi->offline_block_count;
}
#endif

static inline unsigned long __bitmap_size(struct f2fs_sb_info *sbi, int flag)
{
	struct f2fs_checkpoint *ckpt = F2FS_CKPT(sbi);

	if (flag == NAT_BITMAP)
		return le32_to_cpu(ckpt->nat_ver_bitmap_bytesize);
	else if (flag == SIT_BITMAP)
		return le32_to_cpu(ckpt->sit_ver_bitmap_bytesize);

	return 0;
}

static inline block_t __cp_payload(struct f2fs_sb_info *sbi)
{
	return le32_to_cpu(F2FS_RAW_SUPER(sbi)->cp_payload);
}

static inline void *__bitmap_ptr(struct f2fs_sb_info *sbi, int flag)
{
	struct f2fs_checkpoint *ckpt = F2FS_CKPT(sbi);
	int offset;

	if (is_set_ckpt_flags(sbi, CP_LARGE_NAT_BITMAP_FLAG)) {
		offset = (flag == SIT_BITMAP) ?
				 le32_to_cpu(ckpt->nat_ver_bitmap_bytesize) :
				 0;

		return &ckpt->sit_nat_version_bitmap + offset + sizeof(__le32);
	}

	if (__cp_payload(sbi) > 0) {
		if (flag == NAT_BITMAP)
			return &ckpt->sit_nat_version_bitmap;
		else
			return (unsigned char *)ckpt + F2FS_BLKSIZE;
	} else {
		offset = (flag == NAT_BITMAP) ?
				 le32_to_cpu(ckpt->sit_ver_bitmap_bytesize) :
				 0;
		return &ckpt->sit_nat_version_bitmap + offset;
	}
}

static inline block_t __start_cp_addr(struct f2fs_sb_info *sbi)
{
	block_t start_addr = le32_to_cpu(F2FS_RAW_SUPER(sbi)->cp_blkaddr);

	if (sbi->cur_cp_pack == 2)
		start_addr += sbi->blocks_per_seg;
	return start_addr;
}

static inline block_t __start_cp_next_addr(struct f2fs_sb_info *sbi)
{
	block_t start_addr = le32_to_cpu(F2FS_RAW_SUPER(sbi)->cp_blkaddr);

	if (sbi->cur_cp_pack == 1)
		start_addr += sbi->blocks_per_seg;
	return start_addr;
}

static inline void __set_cp_next_pack(struct f2fs_sb_info *sbi)
{
	sbi->cur_cp_pack = (sbi->cur_cp_pack == 1) ? 2 : 1;
}

static inline block_t __start_sum_addr(struct f2fs_sb_info *sbi)
{
	return le32_to_cpu(F2FS_CKPT(sbi)->cp_pack_start_sum);
}

static inline int inc_valid_node_count(struct f2fs_sb_info *sbi,
				       struct inode *inode, bool is_inode)
{
	block_t valid_block_count;
	unsigned int valid_node_count, user_block_count;
	int err;

	if (is_inode) {
		if (inode) {
			err = dquot_alloc_inode(inode);
			if (err)
				return err;
		}
	} else {
		err = dquot_reserve_block(inode, 1);
		if (err)
			return err;
	}

	if (time_to_inject(sbi, FAULT_BLOCK)) {
		f2fs_show_injection_info(sbi, FAULT_BLOCK);
		goto enospc;
	}

	spin_lock(&sbi->stat_lock);

	valid_block_count =
		sbi->total_valid_block_count + sbi->current_reserved_blocks + 1;

	if (!__allow_reserved_blocks(sbi, inode, false))
		valid_block_count += F2FS_OPTION(sbi).root_reserved_blocks;
	user_block_count = sbi->user_block_count;
	if (unlikely(is_sbi_flag_set(sbi, SBI_CP_DISABLED)))
		user_block_count -= sbi->unusable_block_count;

	if (unlikely(valid_block_count > user_block_count)) {
		spin_unlock(&sbi->stat_lock);
		goto enospc;
	}

	valid_node_count = sbi->total_valid_node_count + 1;
	if (unlikely(valid_node_count > sbi->total_node_count)) {
		spin_unlock(&sbi->stat_lock);
		goto enospc;
	}

	sbi->total_valid_node_count++;
	sbi->total_valid_block_count++;
	spin_unlock(&sbi->stat_lock);

	if (inode) {
		if (is_inode)
			f2fs_mark_inode_dirty_sync(inode, true);
		else
			f2fs_i_blocks_write(inode, 1, true, true);
	}

	percpu_counter_inc(&sbi->alloc_valid_block_count);
	return 0;

enospc:
	if (is_inode) {
		if (inode)
			dquot_free_inode(inode);
	} else {
		dquot_release_reservation_block(inode, 1);
	}
	return -ENOSPC;
}

static inline void dec_valid_node_count(struct f2fs_sb_info *sbi,
					struct inode *inode, bool is_inode)
{
	spin_lock(&sbi->stat_lock);

	f2fs_bug_on(sbi, !sbi->total_valid_block_count);
	f2fs_bug_on(sbi, !sbi->total_valid_node_count);

	sbi->total_valid_node_count--;
	sbi->total_valid_block_count--;
	if (sbi->reserved_blocks &&
	    sbi->current_reserved_blocks < sbi->reserved_blocks)
		sbi->current_reserved_blocks++;

	spin_unlock(&sbi->stat_lock);

	if (is_inode) {
		dquot_free_inode(inode);
	} else {
		if (unlikely(inode->i_blocks == 0)) {
			f2fs_warn(
				sbi,
				"dec_valid_node_count: inconsistent i_blocks, ino:%lu, iblocks:%llu",
				inode->i_ino,
				(unsigned long long)inode->i_blocks);
			set_sbi_flag(sbi, SBI_NEED_FSCK);
			return;
		}
		f2fs_i_blocks_write(inode, 1, false, true);
	}
}

static inline unsigned int valid_node_count(struct f2fs_sb_info *sbi)
{
	return sbi->total_valid_node_count;
}

static inline void inc_valid_inode_count(struct f2fs_sb_info *sbi)
{
	percpu_counter_inc(&sbi->total_valid_inode_count);
}

static inline void dec_valid_inode_count(struct f2fs_sb_info *sbi)
{
	percpu_counter_dec(&sbi->total_valid_inode_count);
}

static inline s64 valid_inode_count(struct f2fs_sb_info *sbi)
{
	return percpu_counter_sum_positive(&sbi->total_valid_inode_count);
}

static inline struct page *f2fs_grab_cache_page(struct address_space *mapping,
						pgoff_t index, bool for_write)
{
	struct page *page;

	if (IS_ENABLED(CONFIG_F2FS_FAULT_INJECTION)) {
		if (!for_write)
			page = find_get_page_flags(mapping, index,
						   FGP_LOCK | FGP_ACCESSED);
		else
			page = find_lock_page(mapping, index);
		if (page)
			return page;

		if (time_to_inject(F2FS_M_SB(mapping), FAULT_PAGE_ALLOC)) {
			f2fs_show_injection_info(F2FS_M_SB(mapping),
						 FAULT_PAGE_ALLOC);
			return NULL;
		}
	}

	if (!for_write)
		return grab_cache_page(mapping, index);
	return grab_cache_page_write_begin(mapping, index, AOP_FLAG_NOFS);
}

static inline struct page *
f2fs_pagecache_get_page(struct address_space *mapping, pgoff_t index,
			int fgp_flags, gfp_t gfp_mask)
{
	if (time_to_inject(F2FS_M_SB(mapping), FAULT_PAGE_GET)) {
		f2fs_show_injection_info(F2FS_M_SB(mapping), FAULT_PAGE_GET);
		return NULL;
	}

	return pagecache_get_page(mapping, index, fgp_flags, gfp_mask);
}

static inline void f2fs_copy_page(struct page *src, struct page *dst)
{
	char *src_kaddr = kmap(src);
	char *dst_kaddr = kmap(dst);

	memcpy(dst_kaddr, src_kaddr, PAGE_SIZE);
	kunmap(dst);
	kunmap(src);
}

static inline void f2fs_put_page(struct page *page, int unlock)
{
	if (!page)
		return;

	if (unlock) {
		f2fs_bug_on(F2FS_P_SB(page), !PageLocked(page));
		unlock_page(page);
	}
	put_page(page);
}

static inline void f2fs_put_dnode(struct dnode_of_data *dn)
{
	if (dn->node_page)
		f2fs_put_page(dn->node_page, 1);

	if (dn->inode_page && dn->node_page != dn->inode_page)
		f2fs_put_page(dn->inode_page, 0);

	dn->node_page  = NULL;
	dn->inode_page = NULL;
}

static inline struct kmem_cache *f2fs_kmem_cache_create(const char *name,
							size_t size)
{
	return kmem_cache_create(name, size, 0, SLAB_RECLAIM_ACCOUNT, NULL);
}

static inline void *f2fs_kmem_cache_alloc(struct kmem_cache *cachep,
					  gfp_t flags)
{
	void *entry;

	entry = kmem_cache_alloc(cachep, flags);
	if (!entry)
		entry = kmem_cache_alloc(cachep, flags | __GFP_NOFAIL);
	return entry;
}

static inline bool is_idle(struct f2fs_sb_info *sbi, int type)
{
	if (sbi->gc_mode == GC_URGENT_HIGH)
		return true;

	if (get_pages(sbi, F2FS_RD_DATA) || get_pages(sbi, F2FS_RD_NODE) ||
	    get_pages(sbi, F2FS_RD_META) || get_pages(sbi, F2FS_WB_DATA) ||
	    get_pages(sbi, F2FS_WB_CP_DATA) || get_pages(sbi, F2FS_DIO_READ) ||
	    get_pages(sbi, F2FS_DIO_WRITE))
		return false;

	if (type != DISCARD_TIME && SM_I(sbi) && SM_I(sbi)->dcc_info &&
	    atomic_read(&SM_I(sbi)->dcc_info->queued_discard))
		return false;

	if (SM_I(sbi) && SM_I(sbi)->fcc_info &&
	    atomic_read(&SM_I(sbi)->fcc_info->queued_flush))
		return false;

	if (sbi->gc_mode == GC_URGENT_LOW &&
	    (type == DISCARD_TIME || type == GC_TIME))
		return true;

	return f2fs_time_over(sbi, type);
}

static inline void f2fs_radix_tree_insert(struct radix_tree_root *root,
					  unsigned long index, void *item)
{
	while (radix_tree_insert(root, index, item))
		cond_resched();
}

#define RAW_IS_INODE(p) ((p)->footer.nid == (p)->footer.ino)

static inline bool IS_INODE(struct page *page)
{
	struct f2fs_node *p = F2FS_NODE(page);

	return RAW_IS_INODE(p);
}

static inline int offset_in_addr(struct f2fs_inode *i)
{
	return (i->i_inline & F2FS_EXTRA_ATTR) ?
		       (le16_to_cpu(i->i_extra_isize) / sizeof(__le32)) :
		       0;
}

static inline __le32 *blkaddr_in_node(struct f2fs_node *node)
{
	return RAW_IS_INODE(node) ? node->i.i_addr : node->dn.addr;
}

static inline int f2fs_has_extra_attr(struct inode *inode);

#ifndef CONFIG_F2FS_FS_DEDUP
static inline block_t data_blkaddr(struct inode *inode, struct page *node_page,
				   unsigned int offset)
{
	struct f2fs_node *raw_node;
	__le32 *addr_array;
	int base      = 0;
	bool is_inode = IS_INODE(node_page);

	raw_node = F2FS_NODE(node_page);

	if (is_inode) {
		if (!inode)

			base = offset_in_addr(&raw_node->i);
		else if (f2fs_has_extra_attr(inode))
			base = get_extra_isize(inode);
	}

	addr_array = blkaddr_in_node(raw_node);
	return le32_to_cpu(addr_array[base + offset]);
}

static inline block_t f2fs_data_blkaddr(struct dnode_of_data *dn)
{
	return data_blkaddr(dn->inode, dn->node_page, dn->ofs_in_node);
}
#endif

static inline int f2fs_test_bit(unsigned int nr, char *addr)
{
	int mask;

	addr += (nr >> 3);
	mask = 1 << (7 - (nr & 0x07));
	return mask & *addr;
}

static inline void f2fs_set_bit(unsigned int nr, char *addr)
{
	int mask;

	addr += (nr >> 3);
	mask = 1 << (7 - (nr & 0x07));
	*addr |= mask;
}

static inline void f2fs_clear_bit(unsigned int nr, char *addr)
{
	int mask;

	addr += (nr >> 3);
	mask = 1 << (7 - (nr & 0x07));
	*addr &= ~mask;
}

static inline int f2fs_test_and_set_bit(unsigned int nr, char *addr)
{
	int mask;
	int ret;

	addr += (nr >> 3);
	mask = 1 << (7 - (nr & 0x07));
	ret  = mask & *addr;
	*addr |= mask;
	return ret;
}

static inline int f2fs_test_and_clear_bit(unsigned int nr, char *addr)
{
	int mask;
	int ret;

	addr += (nr >> 3);
	mask = 1 << (7 - (nr & 0x07));
	ret  = mask & *addr;
	*addr &= ~mask;
	return ret;
}

static inline void f2fs_change_bit(unsigned int nr, char *addr)
{
	int mask;

	addr += (nr >> 3);
	mask = 1 << (7 - (nr & 0x07));
	*addr ^= mask;
}

#define F2FS_COMPR_FL	    0x00000004
#define F2FS_SYNC_FL	    0x00000008
#define F2FS_IMMUTABLE_FL   0x00000010
#define F2FS_APPEND_FL	    0x00000020
#define F2FS_NODUMP_FL	    0x00000040
#define F2FS_NOATIME_FL	    0x00000080
#define F2FS_NOCOMP_FL	    0x00000400
#define F2FS_INDEX_FL	    0x00001000
#define F2FS_DIRSYNC_FL	    0x00010000
#define F2FS_PROJINHERIT_FL 0x20000000
#define F2FS_CASEFOLD_FL    0x40000000

#define F2FS_FL_INHERITED                                                      \
	(F2FS_SYNC_FL | F2FS_NODUMP_FL | F2FS_NOATIME_FL | F2FS_DIRSYNC_FL |   \
	 F2FS_PROJINHERIT_FL | F2FS_CASEFOLD_FL | F2FS_COMPR_FL |              \
	 F2FS_NOCOMP_FL)

#define F2FS_REG_FLMASK                                                        \
	(~(F2FS_DIRSYNC_FL | F2FS_PROJINHERIT_FL | F2FS_CASEFOLD_FL))

#define F2FS_OTHER_FLMASK (F2FS_NODUMP_FL | F2FS_NOATIME_FL)

static inline __u32 f2fs_mask_flags(umode_t mode, __u32 flags)
{
	if (S_ISDIR(mode))
		return flags;
	else if (S_ISREG(mode))
		return flags & F2FS_REG_FLMASK;
	else
		return flags & F2FS_OTHER_FLMASK;
}

static inline void __mark_inode_dirty_flag(struct inode *inode, int flag,
					   bool set)
{
	switch (flag) {
	case FI_INLINE_XATTR:
	case FI_INLINE_DATA:
	case FI_INLINE_DENTRY:
	case FI_NEW_INODE:
		if (set)
			return;
		fallthrough;
	case FI_DATA_EXIST:
	case FI_INLINE_DOTS:
	case FI_PIN_FILE:
		f2fs_mark_inode_dirty_sync(inode, true);
	}
}

static inline void set_inode_flag(struct inode *inode, int flag)
{
	set_bit(flag, F2FS_I(inode)->flags);
	__mark_inode_dirty_flag(inode, flag, true);
}

static inline int is_inode_flag_set(struct inode *inode, int flag)
{
	return test_bit(flag, F2FS_I(inode)->flags);
}

static inline void clear_inode_flag(struct inode *inode, int flag)
{
	clear_bit(flag, F2FS_I(inode)->flags);
	__mark_inode_dirty_flag(inode, flag, false);
}

static inline bool f2fs_verity_in_progress(struct inode *inode)
{
	return IS_ENABLED(CONFIG_FS_VERITY) &&
	       is_inode_flag_set(inode, FI_VERITY_IN_PROGRESS);
}

static inline void set_acl_inode(struct inode *inode, umode_t mode)
{
	F2FS_I(inode)->i_acl_mode = mode;
	set_inode_flag(inode, FI_ACL_MODE);
	f2fs_mark_inode_dirty_sync(inode, false);
}

static inline void f2fs_i_links_write(struct inode *inode, bool inc)
{
	if (inc)
		inc_nlink(inode);
	else
		drop_nlink(inode);
	f2fs_mark_inode_dirty_sync(inode, true);
}

static inline void f2fs_i_blocks_write(struct inode *inode, block_t diff,
				       bool add, bool claim)
{
	bool clean   = !is_inode_flag_set(inode, FI_DIRTY_INODE);
	bool recover = is_inode_flag_set(inode, FI_AUTO_RECOVER);

	if (add) {
		if (claim)
			dquot_claim_block(inode, diff);
		else
			dquot_alloc_block_nofail(inode, diff);
	} else {
		dquot_free_block(inode, diff);
	}

	f2fs_mark_inode_dirty_sync(inode, true);
	if (clean || recover)
		set_inode_flag(inode, FI_AUTO_RECOVER);
}

static inline void f2fs_i_size_write(struct inode *inode, loff_t i_size)
{
	bool clean   = !is_inode_flag_set(inode, FI_DIRTY_INODE);
	bool recover = is_inode_flag_set(inode, FI_AUTO_RECOVER);

	if (i_size_read(inode) == i_size)
		return;

	i_size_write(inode, i_size);
	f2fs_mark_inode_dirty_sync(inode, true);

	if (clean || recover)
		set_inode_flag(inode, FI_AUTO_RECOVER);
}

static inline void f2fs_i_depth_write(struct inode *inode, unsigned int depth)
{
	F2FS_I(inode)->i_current_depth = depth;
	f2fs_mark_inode_dirty_sync(inode, true);
}

static inline void f2fs_i_gc_failures_write(struct inode *inode,
					    unsigned int count)
{
	F2FS_I(inode)->i_gc_failures[GC_FAILURE_PIN] = count;
	f2fs_mark_inode_dirty_sync(inode, true);
}

static inline void f2fs_i_xnid_write(struct inode *inode, nid_t xnid)
{
	F2FS_I(inode)->i_xattr_nid = xnid;
	f2fs_mark_inode_dirty_sync(inode, true);
}

static inline void f2fs_i_pino_write(struct inode *inode, nid_t pino)
{
	F2FS_I(inode)->i_pino = pino;
	f2fs_mark_inode_dirty_sync(inode, true);
}

static inline void get_inline_info(struct inode *inode, struct f2fs_inode *ri)
{
	struct f2fs_inode_info *fi = F2FS_I(inode);

	if (ri->i_inline & F2FS_INLINE_XATTR)
		set_bit(FI_INLINE_XATTR, fi->flags);
	if (ri->i_inline & F2FS_INLINE_DATA)
		set_bit(FI_INLINE_DATA, fi->flags);
	if (ri->i_inline & F2FS_INLINE_DENTRY)
		set_bit(FI_INLINE_DENTRY, fi->flags);
	if (ri->i_inline & F2FS_DATA_EXIST)
		set_bit(FI_DATA_EXIST, fi->flags);
	if (ri->i_inline & F2FS_INLINE_DOTS)
		set_bit(FI_INLINE_DOTS, fi->flags);
	if (ri->i_inline & F2FS_EXTRA_ATTR)
		set_bit(FI_EXTRA_ATTR, fi->flags);
	if (ri->i_inline & F2FS_PIN_FILE)
		set_bit(FI_PIN_FILE, fi->flags);
}

static inline void set_raw_inline(struct inode *inode, struct f2fs_inode *ri)
{
	ri->i_inline = 0;

	if (is_inode_flag_set(inode, FI_INLINE_XATTR))
		ri->i_inline |= F2FS_INLINE_XATTR;
	if (is_inode_flag_set(inode, FI_INLINE_DATA))
		ri->i_inline |= F2FS_INLINE_DATA;
	if (is_inode_flag_set(inode, FI_INLINE_DENTRY))
		ri->i_inline |= F2FS_INLINE_DENTRY;
	if (is_inode_flag_set(inode, FI_DATA_EXIST))
		ri->i_inline |= F2FS_DATA_EXIST;
	if (is_inode_flag_set(inode, FI_INLINE_DOTS))
		ri->i_inline |= F2FS_INLINE_DOTS;
	if (is_inode_flag_set(inode, FI_EXTRA_ATTR))
		ri->i_inline |= F2FS_EXTRA_ATTR;
	if (is_inode_flag_set(inode, FI_PIN_FILE))
		ri->i_inline |= F2FS_PIN_FILE;
}

static inline int f2fs_has_extra_attr(struct inode *inode)
{
	return is_inode_flag_set(inode, FI_EXTRA_ATTR);
}

static inline int f2fs_has_inline_xattr(struct inode *inode)
{
	return is_inode_flag_set(inode, FI_INLINE_XATTR);
}

static inline int f2fs_compressed_file(struct inode *inode)
{
	return S_ISREG(inode->i_mode) &&
	       is_inode_flag_set(inode, FI_COMPRESSED_FILE);
}

static inline unsigned int addrs_per_inode(struct inode *inode)
{
	unsigned int addrs =
		CUR_ADDRS_PER_INODE(inode) - get_inline_xattr_addrs(inode);

	if (!f2fs_compressed_file(inode))
		return addrs;
	return ALIGN_DOWN(addrs, F2FS_I(inode)->i_cluster_size);
}

static inline unsigned int addrs_per_block(struct inode *inode)
{
	if (!f2fs_compressed_file(inode))
		return DEF_ADDRS_PER_BLOCK;
	return ALIGN_DOWN(DEF_ADDRS_PER_BLOCK, F2FS_I(inode)->i_cluster_size);
}

static inline void *inline_xattr_addr(struct inode *inode, struct page *page)
{
	struct f2fs_inode *ri = F2FS_INODE(page);

	return (void *)&(
		ri->i_addr[DEF_ADDRS_PER_INODE - get_inline_xattr_addrs(inode)]);
}

static inline int inline_xattr_size(struct inode *inode)
{
	if (f2fs_has_inline_xattr(inode))
		return get_inline_xattr_addrs(inode) * sizeof(__le32);
	return 0;
}

static inline int f2fs_has_inline_data(struct inode *inode)
{
	return is_inode_flag_set(inode, FI_INLINE_DATA);
}

static inline int f2fs_exist_data(struct inode *inode)
{
	return is_inode_flag_set(inode, FI_DATA_EXIST);
}

static inline int f2fs_has_inline_dots(struct inode *inode)
{
	return is_inode_flag_set(inode, FI_INLINE_DOTS);
}

static inline int f2fs_is_mmap_file(struct inode *inode)
{
	return is_inode_flag_set(inode, FI_MMAP_FILE);
}

static inline bool f2fs_is_pinned_file(struct inode *inode)
{
	return is_inode_flag_set(inode, FI_PIN_FILE);
}

static inline bool f2fs_is_atomic_file(struct inode *inode)
{
	return is_inode_flag_set(inode, FI_ATOMIC_FILE);
}

static inline bool f2fs_is_commit_atomic_write(struct inode *inode)
{
	return is_inode_flag_set(inode, FI_ATOMIC_COMMIT);
}

static inline bool f2fs_is_volatile_file(struct inode *inode)
{
	return is_inode_flag_set(inode, FI_VOLATILE_FILE);
}

static inline bool f2fs_is_first_block_written(struct inode *inode)
{
	return is_inode_flag_set(inode, FI_FIRST_BLOCK_WRITTEN);
}

static inline bool f2fs_is_drop_cache(struct inode *inode)
{
	return is_inode_flag_set(inode, FI_DROP_CACHE);
}

static inline void *inline_data_addr(struct inode *inode, struct page *page)
{
	struct f2fs_inode *ri = F2FS_INODE(page);
	int extra_size	      = get_extra_isize(inode);

	return (void *)&(ri->i_addr[extra_size + DEF_INLINE_RESERVED_SIZE]);
}

static inline int f2fs_has_inline_dentry(struct inode *inode)
{
	return is_inode_flag_set(inode, FI_INLINE_DENTRY);
}

static inline int is_file(struct inode *inode, int type)
{
	return F2FS_I(inode)->i_advise & type;
}

static inline void set_file(struct inode *inode, int type)
{
	F2FS_I(inode)->i_advise |= type;
	f2fs_mark_inode_dirty_sync(inode, true);
}

static inline void clear_file(struct inode *inode, int type)
{
	F2FS_I(inode)->i_advise &= ~type;
	f2fs_mark_inode_dirty_sync(inode, true);
}

static inline bool f2fs_is_time_consistent(struct inode *inode)
{
	if (!timespec64_equal(F2FS_I(inode)->i_disk_time, &inode->i_atime))
		return false;
	if (!timespec64_equal(F2FS_I(inode)->i_disk_time + 1, &inode->i_ctime))
		return false;
	if (!timespec64_equal(F2FS_I(inode)->i_disk_time + 2, &inode->i_mtime))
		return false;
	if (!timespec64_equal(F2FS_I(inode)->i_disk_time + 3,
			      &F2FS_I(inode)->i_crtime))
		return false;
	return true;
}

static inline bool f2fs_skip_inode_update(struct inode *inode, int dsync)
{
	bool ret;

	if (dsync) {
		struct f2fs_sb_info *sbi = F2FS_I_SB(inode);

		spin_lock(&sbi->inode_lock[DIRTY_META]);
		ret = list_empty(&F2FS_I(inode)->gdirty_list);
		spin_unlock(&sbi->inode_lock[DIRTY_META]);
		return ret;
	}
	if (!is_inode_flag_set(inode, FI_AUTO_RECOVER) ||
	    file_keep_isize(inode) || i_size_read(inode) & ~PAGE_MASK)
		return false;

	if (!f2fs_is_time_consistent(inode))
		return false;

	spin_lock(&F2FS_I(inode)->i_size_lock);
	ret = F2FS_I(inode)->last_disk_size == i_size_read(inode);
	spin_unlock(&F2FS_I(inode)->i_size_lock);

	return ret;
}

static inline bool f2fs_readonly(struct super_block *sb)
{
	return sb_rdonly(sb);
}

static inline bool f2fs_cp_error(struct f2fs_sb_info *sbi)
{
	return is_set_ckpt_flags(sbi, CP_ERROR_FLAG);
}

static inline bool is_dot_dotdot(const u8 *name, size_t len)
{
	if (len == 1 && name[0] == '.')
		return true;

	if (len == 2 && name[0] == '.' && name[1] == '.')
		return true;

	return false;
}

static inline bool f2fs_may_extent_tree(struct inode *inode)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);

	if (!test_opt(sbi, EXTENT_CACHE) ||
	    is_inode_flag_set(inode, FI_NO_EXTENT) ||
	    is_inode_flag_set(inode, FI_COMPRESSED_FILE))
		return false;

	if (list_empty(&sbi->s_list))
		return false;

	return S_ISREG(inode->i_mode);
}

static inline void *f2fs_kmalloc(struct f2fs_sb_info *sbi, size_t size,
				 gfp_t flags)
{
	if (time_to_inject(sbi, FAULT_KMALLOC)) {
		f2fs_show_injection_info(sbi, FAULT_KMALLOC);
		return NULL;
	}

	return kmalloc(size, flags);
}

static inline void *f2fs_kzalloc(struct f2fs_sb_info *sbi, size_t size,
				 gfp_t flags)
{
	return f2fs_kmalloc(sbi, size, flags | __GFP_ZERO);
}

static inline void *f2fs_kvmalloc(struct f2fs_sb_info *sbi, size_t size,
				  gfp_t flags)
{
	if (time_to_inject(sbi, FAULT_KVMALLOC)) {
		f2fs_show_injection_info(sbi, FAULT_KVMALLOC);
		return NULL;
	}

	return kvmalloc(size, flags);
}

static inline void *f2fs_kvzalloc(struct f2fs_sb_info *sbi, size_t size,
				  gfp_t flags)
{
	return f2fs_kvmalloc(sbi, size, flags | __GFP_ZERO);
}

static inline int get_extra_isize(struct inode *inode)
{
	return F2FS_I(inode)->i_extra_isize / sizeof(__le32);
}

static inline int get_inline_xattr_addrs(struct inode *inode)
{
	return F2FS_I(inode)->i_inline_xattr_size;
}

#define f2fs_get_inode_mode(i)                                                 \
	((is_inode_flag_set(i, FI_ACL_MODE)) ? (F2FS_I(i)->i_acl_mode) :       \
					       ((i)->i_mode))

#define F2FS_TOTAL_EXTRA_ATTR_SIZE                                             \
	(offsetof(struct f2fs_inode, i_extra_end) -                            \
	 offsetof(struct f2fs_inode, i_extra_isize))

#define F2FS_OLD_ATTRIBUTE_SIZE (offsetof(struct f2fs_inode, i_addr))
#define F2FS_FITS_IN_INODE(f2fs_inode, extra_isize, field)                     \
	((offsetof(typeof(*(f2fs_inode)), field) +                             \
	  sizeof((f2fs_inode)->field)) <=                                      \
	 (F2FS_OLD_ATTRIBUTE_SIZE + (extra_isize)))

#define DEFAULT_IOSTAT_PERIOD_MS 3000
#define MIN_IOSTAT_PERIOD_MS	 100

#define MAX_IOSTAT_PERIOD_MS 8640000

static inline void f2fs_reset_iostat(struct f2fs_sb_info *sbi)
{
	int i;

	spin_lock(&sbi->iostat_lock);
	for (i = 0; i < NR_IO_TYPE; i++) {
		sbi->rw_iostat[i]      = 0;
		sbi->prev_rw_iostat[i] = 0;
	}
	spin_unlock(&sbi->iostat_lock);
}

extern void f2fs_record_iostat(struct f2fs_sb_info *sbi);

static inline void f2fs_update_iostat(struct f2fs_sb_info *sbi,
				      enum iostat_type type,
				      unsigned long long io_bytes)
{
	if (!sbi->iostat_enable)
		return;
	spin_lock(&sbi->iostat_lock);
	sbi->rw_iostat[type] += io_bytes;

	if (type == APP_WRITE_IO || type == APP_DIRECT_IO)
		sbi->rw_iostat[APP_BUFFERED_IO] = sbi->rw_iostat[APP_WRITE_IO] -
						  sbi->rw_iostat[APP_DIRECT_IO];

	if (type == APP_READ_IO || type == APP_DIRECT_READ_IO)
		sbi->rw_iostat[APP_BUFFERED_READ_IO] =
			sbi->rw_iostat[APP_READ_IO] -
			sbi->rw_iostat[APP_DIRECT_READ_IO];
	spin_unlock(&sbi->iostat_lock);

	f2fs_record_iostat(sbi);
}

#define __is_large_section(sbi) ((sbi)->segs_per_sec > 1)

#define __is_meta_io(fio) (PAGE_TYPE_OF_BIO((fio)->type) == META)

bool f2fs_is_valid_blkaddr(struct f2fs_sb_info *sbi, block_t blkaddr, int type);
static inline void verify_blkaddr(struct f2fs_sb_info *sbi, block_t blkaddr,
				  int type)
{
	if (!f2fs_is_valid_blkaddr(sbi, blkaddr, type)) {
		f2fs_err(sbi, "invalid blkaddr: %u, type: %d, run fsck to fix.",
			 blkaddr, type);
		f2fs_bug_on(sbi, 1);
	}
}

static inline bool __is_valid_data_blkaddr(block_t blkaddr)
{
	if (blkaddr == NEW_ADDR || blkaddr == NULL_ADDR ||
	    blkaddr == COMPRESS_ADDR)
		return false;
	return true;
}

static inline void f2fs_set_page_private(struct page *page, unsigned long data)
{
	if (PagePrivate(page))
		return;

	attach_page_private(page, (void *)data);
}

static inline void f2fs_clear_page_private(struct page *page)
{
	detach_page_private(page);
}

static inline bool
should_allocate_virtual_address(struct address_space *mapping,
				struct writeback_control *wbc)
{
	if (mapping->host->i_ino <= F2FS_GC_INO(F2FS_M_SB(mapping))) {
		printk("file:%s line:%d inode %lu is special, no need to allocate virtual address",
		       __FILE__, __LINE__, mapping->host->i_ino);
		return false;
	}

	return true;
}

int f2fs_compute_page_fingerprint(struct f2fs_sb_info *sbi, struct page *page,
				  __u8 fingerprint[]);

int f2fs_sync_file(struct file *file, loff_t start, loff_t end, int datasync);
void f2fs_truncate_data_blocks(struct dnode_of_data *dn);
int f2fs_do_truncate_blocks(struct inode *inode, u64 from, bool lock);
int f2fs_truncate_blocks(struct inode *inode, u64 from, bool lock);
int f2fs_truncate(struct inode *inode);
int f2fs_getattr(const struct path *path, struct kstat *stat, u32 request_mask,
		 unsigned int flags);
int f2fs_setattr(struct dentry *dentry, struct iattr *attr);
int f2fs_truncate_hole(struct inode *inode, pgoff_t pg_start, pgoff_t pg_end);
void f2fs_truncate_data_blocks_range(struct dnode_of_data *dn, int count);
int f2fs_precache_extents(struct inode *inode);
long f2fs_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
long f2fs_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
int f2fs_transfer_project_quota(struct inode *inode, kprojid_t kprojid);
int f2fs_pin_file_control(struct inode *inode, bool inc);

void f2fs_set_inode_flags(struct inode *inode);
bool f2fs_inode_chksum_verify(struct f2fs_sb_info *sbi, struct page *page);
void f2fs_inode_chksum_set(struct f2fs_sb_info *sbi, struct page *page);
struct inode *f2fs_iget(struct super_block *sb, unsigned long ino);
struct inode *f2fs_iget_retry(struct super_block *sb, unsigned long ino);
int f2fs_try_to_free_nats(struct f2fs_sb_info *sbi, int nr_shrink);
void f2fs_update_inode(struct inode *inode, struct page *node_page);
void f2fs_update_inode_page(struct inode *inode);
int f2fs_write_inode(struct inode *inode, struct writeback_control *wbc);
void f2fs_evict_inode(struct inode *inode);
void f2fs_handle_failed_inode(struct inode *inode);

int f2fs_update_extension_list(struct f2fs_sb_info *sbi, const char *name,
			       bool hot, bool set);
struct dentry *f2fs_get_parent(struct dentry *child);

unsigned char f2fs_get_de_type(struct f2fs_dir_entry *de);
int f2fs_init_casefolded_name(const struct inode *dir,
			      struct f2fs_filename *fname);
int f2fs_setup_filename(struct inode *dir, const struct qstr *iname, int lookup,
			struct f2fs_filename *fname);
int f2fs_prepare_lookup(struct inode *dir, struct dentry *dentry,
			struct f2fs_filename *fname);
void f2fs_free_filename(struct f2fs_filename *fname);
struct f2fs_dir_entry *
f2fs_find_target_dentry(const struct f2fs_dentry_ptr *d,
			const struct f2fs_filename *fname, int *max_slots);
int f2fs_fill_dentries(struct dir_context *ctx, struct f2fs_dentry_ptr *d,
		       unsigned int start_pos, struct fscrypt_str *fstr);
void f2fs_do_make_empty_dir(struct inode *inode, struct inode *parent,
			    struct f2fs_dentry_ptr *d);
struct page *f2fs_init_inode_metadata(struct inode *inode, struct inode *dir,
				      const struct f2fs_filename *fname,
				      struct page *dpage);
void f2fs_update_parent_metadata(struct inode *dir, struct inode *inode,
				 unsigned int current_depth);
int f2fs_room_for_filename(const void *bitmap, int slots, int max_slots);
void f2fs_drop_nlink(struct inode *dir, struct inode *inode);
struct f2fs_dir_entry *__f2fs_find_entry(struct inode *dir,
					 const struct f2fs_filename *fname,
					 struct page **res_page);
struct f2fs_dir_entry *f2fs_find_entry(struct inode *dir,
				       const struct qstr *child,
				       struct page **res_page);
struct f2fs_dir_entry *f2fs_parent_dir(struct inode *dir, struct page **p);
ino_t f2fs_inode_by_name(struct inode *dir, const struct qstr *qstr,
			 struct page **page);
void f2fs_set_link(struct inode *dir, struct f2fs_dir_entry *de,
		   struct page *page, struct inode *inode);
bool f2fs_has_enough_room(struct inode *dir, struct page *ipage,
			  const struct f2fs_filename *fname);
void f2fs_update_dentry(nid_t ino, umode_t mode, struct f2fs_dentry_ptr *d,
			const struct fscrypt_str *name, f2fs_hash_t name_hash,
			unsigned int bit_pos);
int f2fs_add_regular_entry(struct inode *dir, const struct f2fs_filename *fname,
			   struct inode *inode, nid_t ino, umode_t mode);
int f2fs_add_dentry(struct inode *dir, const struct f2fs_filename *fname,
		    struct inode *inode, nid_t ino, umode_t mode);
int f2fs_do_add_link(struct inode *dir, const struct qstr *name,
		     struct inode *inode, nid_t ino, umode_t mode);
void f2fs_delete_entry(struct f2fs_dir_entry *dentry, struct page *page,
		       struct inode *dir, struct inode *inode);
int f2fs_do_tmpfile(struct inode *inode, struct inode *dir);
bool f2fs_empty_dir(struct inode *dir);

static inline int f2fs_add_link(struct dentry *dentry, struct inode *inode)
{
	if (fscrypt_is_nokey_name(dentry))
		return -ENOKEY;
	return f2fs_do_add_link(d_inode(dentry->d_parent), &dentry->d_name,
				inode, inode->i_ino, inode->i_mode);
}

int f2dfs_build_dedup_manager(struct f2fs_sb_info *sbi);
int f2fs_inode_dirtied(struct inode *inode, bool sync);
void f2fs_inode_synced(struct inode *inode);
int f2fs_enable_quota_files(struct f2fs_sb_info *sbi, bool rdonly);
int f2fs_quota_sync(struct super_block *sb, int type);
void f2fs_quota_off_umount(struct super_block *sb);
int f2fs_commit_super(struct f2fs_sb_info *sbi, bool recover);
int f2fs_sync_fs(struct super_block *sb, int sync);
int f2fs_sanity_check_ckpt(struct f2fs_sb_info *sbi);

void f2fs_hash_filename(const struct inode *dir, struct f2fs_filename *fname);

struct dnode_of_data;
struct node_info;

#ifdef CONFIG_F2FS_FS_DEDUP
void set_virtual_blkaddr(struct f2fs_sb_info *sbi, struct node_info *ni,
			 block_t new_blkaddr, bool init);
block_t data_blkaddr(struct inode *inode, struct page *node_page,
		     unsigned int offset);
#else
inline block_t data_blkaddr(struct inode *inode, struct page *node_page,
			    unsigned int offset);
#endif
int f2dfs_get_virtual_address_info(struct f2fs_sb_info *sbi, virtual_t vaddr,
				   struct node_info *ni);
inline block_t f2fs_data_blkaddr(struct dnode_of_data *dn);
int f2fs_check_nid_range(struct f2fs_sb_info *sbi, nid_t nid);
bool f2fs_available_free_memory(struct f2fs_sb_info *sbi, int type);
bool f2fs_in_warm_node_list(struct f2fs_sb_info *sbi, struct page *page);
void f2fs_init_fsync_node_info(struct f2fs_sb_info *sbi);
void f2fs_del_fsync_node_entry(struct f2fs_sb_info *sbi, struct page *page);
void f2fs_reset_fsync_node_info(struct f2fs_sb_info *sbi);
int f2fs_need_dentry_mark(struct f2fs_sb_info *sbi, nid_t nid);
bool f2fs_is_checkpointed_node(struct f2fs_sb_info *sbi, nid_t nid);
bool f2fs_need_inode_block_update(struct f2fs_sb_info *sbi, nid_t ino);
int f2fs_get_node_info(struct f2fs_sb_info *sbi, nid_t nid,
		       struct node_info *ni);
pgoff_t f2fs_get_next_page_offset(struct dnode_of_data *dn, pgoff_t pgofs);
#ifdef CONFIG_F2FS_FS_DEDUP
int f2fs_get_dnode_of_data(struct dnode_of_data *dn, pgoff_t index, int mode,
			   bool need_blkaddr);
int f2dfs_get_dnode_of_data_write_path(struct dnode_of_data *dn, pgoff_t index,
				       int mode);
void f2dfs_data_blkaddr_write_path(struct dnode_of_data *dn);
#else
int f2fs_get_dnode_of_data(struct dnode_of_data *dn, pgoff_t index, int mode);
#endif
int f2fs_truncate_inode_blocks(struct inode *inode, pgoff_t from);
int f2fs_truncate_xattr_node(struct inode *inode);
int f2fs_wait_on_node_pages_writeback(struct f2fs_sb_info *sbi,
				      unsigned int seq_id);
int f2fs_remove_inode_page(struct inode *inode);
struct page *f2fs_new_inode_page(struct inode *inode);
struct page *f2fs_new_node_page(struct dnode_of_data *dn, unsigned int ofs);
void f2fs_ra_node_page(struct f2fs_sb_info *sbi, nid_t nid);
struct page *f2fs_get_node_page(struct f2fs_sb_info *sbi, pgoff_t nid);
struct page *f2fs_get_node_page_ra(struct page *parent, int start);
int f2fs_move_node_page(struct page *node_page, int gc_type);
void f2fs_flush_inline_data(struct f2fs_sb_info *sbi);
int f2fs_fsync_node_pages(struct f2fs_sb_info *sbi, struct inode *inode,
			  struct writeback_control *wbc, bool atomic,
			  unsigned int *seq_id);
int f2fs_sync_node_pages(struct f2fs_sb_info *sbi,
			 struct writeback_control *wbc, bool do_balance,
			 enum iostat_type io_type);
int f2fs_build_free_nids(struct f2fs_sb_info *sbi, bool sync, bool mount);
bool f2fs_alloc_nid(struct f2fs_sb_info *sbi, nid_t *nid);
void f2fs_alloc_nid_done(struct f2fs_sb_info *sbi, nid_t nid);
void f2fs_alloc_nid_failed(struct f2fs_sb_info *sbi, nid_t nid);
int f2fs_try_to_free_nids(struct f2fs_sb_info *sbi, int nr_shrink);
int f2fs_recover_inline_xattr(struct inode *inode, struct page *page);
int f2fs_recover_xattr_data(struct inode *inode, struct page *page);
int f2fs_recover_inode_page(struct f2fs_sb_info *sbi, struct page *page);
int f2fs_restore_node_summary(struct f2fs_sb_info *sbi, unsigned int segno,
			      struct f2fs_summary_block *sum);
int f2fs_flush_nat_entries(struct f2fs_sb_info *sbi, struct cp_control *cpc);
int f2fs_build_node_manager(struct f2fs_sb_info *sbi);
void f2fs_destroy_node_manager(struct f2fs_sb_info *sbi);
int __init f2fs_create_node_manager_caches(void);
void f2fs_destroy_node_manager_caches(void);

bool f2fs_need_SSR(struct f2fs_sb_info *sbi);
void f2fs_register_inmem_page(struct inode *inode, struct page *page);
void f2fs_drop_inmem_pages_all(struct f2fs_sb_info *sbi, bool gc_failure);
void f2fs_drop_inmem_pages(struct inode *inode);
void f2fs_drop_inmem_page(struct inode *inode, struct page *page);
int f2fs_commit_inmem_pages(struct inode *inode);
void f2fs_balance_fs(struct f2fs_sb_info *sbi, bool need);
void f2fs_balance_fs_bg(struct f2fs_sb_info *sbi, bool from_bg);
int f2fs_issue_flush(struct f2fs_sb_info *sbi, nid_t ino);
int f2fs_create_flush_cmd_control(struct f2fs_sb_info *sbi);
int f2fs_flush_device_cache(struct f2fs_sb_info *sbi);
void f2fs_destroy_flush_cmd_control(struct f2fs_sb_info *sbi, bool free);
void f2fs_invalidate_blocks(struct f2fs_sb_info *sbi, block_t addr);
bool f2fs_is_checkpointed_data(struct f2fs_sb_info *sbi, block_t blkaddr);
void f2fs_drop_discard_cmd(struct f2fs_sb_info *sbi);
void f2fs_stop_discard_thread(struct f2fs_sb_info *sbi);
bool f2fs_issue_discard_timeout(struct f2fs_sb_info *sbi);
void f2fs_clear_prefree_segments(struct f2fs_sb_info *sbi,
				 struct cp_control *cpc);
void f2fs_dirty_to_prefree(struct f2fs_sb_info *sbi);
block_t f2fs_get_unusable_blocks(struct f2fs_sb_info *sbi);
int f2fs_disable_cp_again(struct f2fs_sb_info *sbi, block_t unusable);
void f2fs_release_discard_addrs(struct f2fs_sb_info *sbi);
int f2fs_npages_for_summary_flush(struct f2fs_sb_info *sbi, bool for_ra);
bool f2fs_segment_has_free_slot(struct f2fs_sb_info *sbi, int segno);
void f2fs_init_inmem_curseg(struct f2fs_sb_info *sbi);
void f2fs_save_inmem_curseg(struct f2fs_sb_info *sbi);
void f2fs_restore_inmem_curseg(struct f2fs_sb_info *sbi);
void f2fs_get_new_segment(struct f2fs_sb_info *sbi, unsigned int *newseg,
			  bool new_sec, int dir);
void f2fs_allocate_segment_for_resize(struct f2fs_sb_info *sbi, int type,
				      unsigned int start, unsigned int end);
void f2fs_allocate_new_section(struct f2fs_sb_info *sbi, int type);
void f2fs_allocate_new_segments(struct f2fs_sb_info *sbi);
int f2fs_trim_fs(struct f2fs_sb_info *sbi, struct fstrim_range *range);
bool f2fs_exist_trim_candidates(struct f2fs_sb_info *sbi,
				struct cp_control *cpc);
struct page *f2fs_get_sum_page(struct f2fs_sb_info *sbi, unsigned int segno);
void f2fs_update_meta_page(struct f2fs_sb_info *sbi, void *src,
			   block_t blk_addr);
void f2fs_do_write_meta_page(struct f2fs_sb_info *sbi, struct page *page,
			     enum iostat_type io_type);
void f2fs_do_write_node_page(unsigned int nid, struct f2fs_io_info *fio);
#ifdef CONFIG_F2FS_FS_DEDUP
#else
void f2fs_outplace_write_data(struct dnode_of_data *dn,
			      struct f2fs_io_info *fio);
#endif
int f2fs_inplace_write_data(struct f2fs_io_info *fio);
void f2fs_do_replace_block(struct f2fs_sb_info *sbi, struct f2fs_summary *sum,
			   block_t old_blkaddr, block_t new_blkaddr,
			   bool recover_curseg, bool recover_newaddr,
			   bool from_gc);
void f2fs_replace_block(struct f2fs_sb_info *sbi, struct dnode_of_data *dn,
			block_t old_addr, block_t new_addr,
			unsigned char version, bool recover_curseg,
			bool recover_newaddr);
void f2fs_allocate_data_block(struct f2fs_sb_info *sbi, struct page *page,
			      block_t old_blkaddr, block_t *new_blkaddr,
			      struct f2fs_summary *sum, int type,
			      struct f2fs_io_info *fio);
void f2fs_wait_on_page_writeback(struct page *page, enum page_type type,
				 bool ordered, bool locked);
void f2fs_wait_on_block_writeback(struct inode *inode, block_t blkaddr);
void f2fs_wait_on_block_writeback_range(struct inode *inode, block_t blkaddr,
					block_t len);
void f2fs_write_data_summaries(struct f2fs_sb_info *sbi, block_t start_blk);
void f2fs_write_node_summaries(struct f2fs_sb_info *sbi, block_t start_blk);
int f2fs_lookup_journal_in_cursum(struct f2fs_journal *journal, int type,
				  unsigned int val, int alloc);
void f2fs_flush_sit_entries(struct f2fs_sb_info *sbi, struct cp_control *cpc);
int f2fs_fix_curseg_write_pointer(struct f2fs_sb_info *sbi);
int f2fs_check_write_pointer(struct f2fs_sb_info *sbi);
int f2fs_build_segment_manager(struct f2fs_sb_info *sbi);
void f2fs_destroy_segment_manager(struct f2fs_sb_info *sbi);
int __init f2fs_create_segment_manager_caches(void);
void f2fs_destroy_segment_manager_caches(void);
int f2fs_rw_hint_to_seg_type(enum rw_hint hint);
enum rw_hint f2fs_io_type_to_rw_hint(struct f2fs_sb_info *sbi,
				     enum page_type type, enum temp_type temp);
unsigned int f2fs_usable_segs_in_sec(struct f2fs_sb_info *sbi,
				     unsigned int segno);
unsigned int f2fs_usable_blks_in_seg(struct f2fs_sb_info *sbi,
				     unsigned int segno);

int f2fs_write_meta_page(struct page *page, struct writeback_control *wbc);
void f2fs_stop_checkpoint(struct f2fs_sb_info *sbi, bool end_io);
struct page *f2fs_grab_meta_page(struct f2fs_sb_info *sbi, pgoff_t index);
struct page *f2fs_get_meta_page(struct f2fs_sb_info *sbi, pgoff_t index);
struct page *f2fs_get_meta_page_retry(struct f2fs_sb_info *sbi, pgoff_t index);
struct page *f2fs_get_tmp_page(struct f2fs_sb_info *sbi, pgoff_t index);
bool f2fs_is_valid_blkaddr(struct f2fs_sb_info *sbi, block_t blkaddr, int type);
int f2fs_ra_meta_pages(struct f2fs_sb_info *sbi, block_t start, int nrpages,
		       int type, bool sync);
void f2fs_ra_meta_pages_cond(struct f2fs_sb_info *sbi, pgoff_t index);
long f2fs_sync_meta_pages(struct f2fs_sb_info *sbi, enum page_type type,
			  long nr_to_write, enum iostat_type io_type);
void f2fs_add_ino_entry(struct f2fs_sb_info *sbi, nid_t ino, int type);
void f2fs_remove_ino_entry(struct f2fs_sb_info *sbi, nid_t ino, int type);
void f2fs_release_ino_entry(struct f2fs_sb_info *sbi, bool all);
bool f2fs_exist_written_data(struct f2fs_sb_info *sbi, nid_t ino, int mode);
void f2fs_set_dirty_device(struct f2fs_sb_info *sbi, nid_t ino,
			   unsigned int devidx, int type);
bool f2fs_is_dirty_device(struct f2fs_sb_info *sbi, nid_t ino,
			  unsigned int devidx, int type);
int f2fs_sync_inode_meta(struct f2fs_sb_info *sbi);
int f2fs_acquire_orphan_inode(struct f2fs_sb_info *sbi);
void f2fs_release_orphan_inode(struct f2fs_sb_info *sbi);
void f2fs_add_orphan_inode(struct inode *inode);
void f2fs_remove_orphan_inode(struct f2fs_sb_info *sbi, nid_t ino);
int f2fs_recover_orphan_inodes(struct f2fs_sb_info *sbi);
int f2fs_get_valid_checkpoint(struct f2fs_sb_info *sbi);
void f2fs_update_dirty_page(struct inode *inode, struct page *page);
void f2fs_remove_dirty_inode(struct inode *inode);
int f2fs_sync_dirty_inodes(struct f2fs_sb_info *sbi, enum inode_type type);
void f2fs_wait_on_all_pages(struct f2fs_sb_info *sbi, int type);
int f2fs_write_checkpoint(struct f2fs_sb_info *sbi, struct cp_control *cpc);
void f2fs_init_ino_entry_info(struct f2fs_sb_info *sbi);
int __init f2fs_create_checkpoint_caches(void);
void f2fs_destroy_checkpoint_caches(void);

#ifdef CONFIG_F2FS_FS_DEDUP
int f2dfs_update_data_blkaddr(struct dnode_of_data *dn,
			      struct vnode_of_data *vn);
virtual_t data_virtualaddr(struct inode *inode, struct page *node_page,
			   unsigned int offset);
block_t f2dfs_address_translation(struct f2fs_sb_info *sbi, virtual_t vaddr);
virtual_t f2fs_data_virtualaddr(struct dnode_of_data *dn);
#endif
int __init f2fs_init_bioset(void);
void f2fs_destroy_bioset(void);
struct bio *f2fs_bio_alloc(struct f2fs_sb_info *sbi, int npages, bool noio);
int f2fs_init_bio_entry_cache(void);
void f2fs_destroy_bio_entry_cache(void);
void f2fs_submit_bio(struct f2fs_sb_info *sbi, struct bio *bio,
		     enum page_type type);
void f2fs_submit_merged_write(struct f2fs_sb_info *sbi, enum page_type type);
void f2fs_submit_merged_write_cond(struct f2fs_sb_info *sbi,
				   struct inode *inode, struct page *page,
				   nid_t ino, enum page_type type);
void f2fs_submit_merged_ipu_write(struct f2fs_sb_info *sbi, struct bio **bio,
				  struct page *page);
void f2fs_flush_merged_writes(struct f2fs_sb_info *sbi);
int f2fs_submit_page_bio(struct f2fs_io_info *fio);
int f2fs_merge_page_bio(struct f2fs_io_info *fio);
void f2fs_submit_page_write(struct f2fs_io_info *fio);
struct block_device *f2fs_target_device(struct f2fs_sb_info *sbi,
					block_t blk_addr, struct bio *bio);
int f2fs_target_device_index(struct f2fs_sb_info *sbi, block_t blkaddr);
void f2fs_set_data_blkaddr(struct dnode_of_data *dn);
#ifdef CONFIG_F2FS_FS_DEDUP
void f2fs_update_data_blkaddr(struct dnode_of_data *dn, virtual_t virtual_addr,
			      bool update_extent);
#else
void f2fs_update_data_blkaddr(struct dnode_of_data *dn, block_t blkaddr);
#endif
int f2fs_reserve_new_blocks(struct dnode_of_data *dn, blkcnt_t count);
int f2fs_reserve_new_block(struct dnode_of_data *dn);
int f2fs_get_block(struct dnode_of_data *dn, pgoff_t index);
int f2fs_preallocate_blocks(struct kiocb *iocb, struct iov_iter *from);
int f2fs_reserve_block(struct dnode_of_data *dn, pgoff_t index);
struct page *f2fs_get_read_data_page(struct inode *inode, pgoff_t index,
				     int op_flags, bool for_write);
struct page *f2fs_find_data_page(struct inode *inode, pgoff_t index);
struct page *f2fs_get_lock_data_page(struct inode *inode, pgoff_t index,
				     bool for_write);
struct page *f2fs_get_new_data_page(struct inode *inode, struct page *ipage,
				    pgoff_t index, bool new_i_size);
#ifndef CONFIG_F2FS_FS_DEDUP
int f2fs_do_write_data_page(struct f2fs_io_info *fio);
#endif
void f2fs_do_map_lock(struct f2fs_sb_info *sbi, int flag, bool lock);
int f2fs_map_blocks(struct inode *inode, struct f2fs_map_blocks *map,
		    int create, int flag);
int f2fs_fiemap(struct inode *inode, struct fiemap_extent_info *fieinfo,
		u64 start, u64 len);
int f2fs_encrypt_one_page(struct f2fs_io_info *fio);
bool f2fs_should_update_inplace(struct inode *inode, struct f2fs_io_info *fio);
bool f2fs_should_update_outplace(struct inode *inode, struct f2fs_io_info *fio);
#ifdef CONFIG_F2FS_FS_DEDUP
#else
int f2fs_write_single_data_page(struct page *page, int *submitted,
				struct bio **bio, sector_t *last_block,
				struct writeback_control *wbc,
				enum iostat_type io_type, int compr_blocks,
				bool allow_balance);
#endif
void f2fs_invalidate_page(struct page *page, unsigned int offset,
			  unsigned int length);
int f2fs_release_page(struct page *page, gfp_t wait);
#ifdef CONFIG_MIGRATION
int f2fs_migrate_page(struct address_space *mapping, struct page *newpage,
		      struct page *page, enum migrate_mode mode);
#endif
bool f2fs_overwrite_io(struct inode *inode, loff_t pos, size_t len);
void f2fs_clear_page_cache_dirty_tag(struct page *page);
int f2fs_init_post_read_processing(void);
void f2fs_destroy_post_read_processing(void);
int f2fs_init_post_read_wq(struct f2fs_sb_info *sbi);
void f2fs_destroy_post_read_wq(struct f2fs_sb_info *sbi);

#ifdef CONFIG_F2FS_FS_DEDUP
void f2dfs_clear_gc_page_dirty(struct f2fs_sb_info *sbi, virtual_t vaddr);
#endif
int f2fs_start_gc_thread(struct f2fs_sb_info *sbi);
void f2fs_stop_gc_thread(struct f2fs_sb_info *sbi);
block_t f2fs_start_bidx_of_node(unsigned int node_ofs, struct inode *inode);
int f2fs_gc(struct f2fs_sb_info *sbi, bool sync, bool background, bool force,
	    unsigned int segno);
void f2fs_build_gc_manager(struct f2fs_sb_info *sbi);
int f2fs_resize_fs(struct f2fs_sb_info *sbi, __u64 block_count);
int __init f2fs_create_garbage_collection_cache(void);
void f2fs_destroy_garbage_collection_cache(void);

int f2fs_recover_fsync_data(struct f2fs_sb_info *sbi, bool check_only);
bool f2fs_space_for_roll_forward(struct f2fs_sb_info *sbi);

#ifdef CONFIG_F2FS_STAT_FS
struct f2fs_stat_info {
	struct list_head stat_list;
	struct f2fs_sb_info *sbi;
	int all_area_segs, sit_area_segs, nat_area_segs, ssa_area_segs;
	int main_area_segs, main_area_sections, main_area_zones;
	unsigned long long hit_largest, hit_cached, hit_rbtree;
	unsigned long long hit_total, total_ext;
	int ext_tree, zombie_tree, ext_node;
	int ndirty_node, ndirty_dent, ndirty_meta, ndirty_imeta;
	int ndirty_data, ndirty_qdata;
	int inmem_pages;
	unsigned int ndirty_dirs, ndirty_files, nquota_files, ndirty_all;
	int nats, dirty_nats, sits, dirty_sits;
	int free_nids, avail_nids, alloc_nids;
	int total_count, utilization;
	int bg_gc, nr_wb_cp_data, nr_wb_data;
	int nr_rd_data, nr_rd_node, nr_rd_meta;
	int nr_dio_read, nr_dio_write;
	unsigned int io_skip_bggc, other_skip_bggc;
	int nr_flushing, nr_flushed, flush_list_empty;
	int nr_discarding, nr_discarded;
	int nr_discard_cmd;
	unsigned int undiscard_blks;
	int inline_xattr, inline_inode, inline_dir, append, update, orphans;
	int compr_inode;
	unsigned long long compr_blocks;
	int aw_cnt, max_aw_cnt, vw_cnt, max_vw_cnt;
	unsigned int valid_count, valid_node_count, valid_inode_count,
		discard_blks;
	unsigned int bimodal, avg_vblocks;
	int util_free, util_valid, util_invalid;
	int rsvd_segs, overp_segs;
	int dirty_count, node_pages, meta_pages;
	int prefree_count, call_count, cp_count, bg_cp_count;
	int tot_segs, node_segs, data_segs, free_segs, free_secs;
	int bg_node_segs, bg_data_segs;
	int tot_blks, data_blks, node_blks;
	int bg_data_blks, bg_node_blks;
	unsigned long long skipped_atomic_files[2];
	int curseg[NR_CURSEG_TYPE];
	int cursec[NR_CURSEG_TYPE];
	int curzone[NR_CURSEG_TYPE];
	unsigned int dirty_seg[NR_CURSEG_TYPE];
	unsigned int full_seg[NR_CURSEG_TYPE];
	unsigned int valid_blks[NR_CURSEG_TYPE];

	unsigned int meta_count[META_MAX];
	unsigned int segment_count[2];
	unsigned int block_count[2];
	unsigned int inplace_count;
	unsigned long long base_mem, cache_mem, page_mem;

#ifdef CONFIG_F2FS_FS_DEDUP

	int gc_pages;
	unsigned int io_skip_bgfp, resource_skip_bgfp, other_skip_bgfp;

	int fp_area_segs;
	int rc_base_segs;
	int rc_delta_segs;

	int ndirty_fp_blocks;
	int ndirty_rc_base_blocks;
	int ndirty_rc_delta_blocks;

	unsigned int root_ino_num;
	unsigned int node_ino_num;
	unsigned int meta_ino_num;
	unsigned int gc_ino_num;

	block_t duplication_block_count_high;
	block_t duplication_block_count_low;
	block_t unique_block_count;
	block_t zero_block_count;
	block_t offline_block_count;
	block_t data_blocks_count;
#endif
};

static inline struct f2fs_stat_info *F2FS_STAT(struct f2fs_sb_info *sbi)
{
	return (struct f2fs_stat_info *)sbi->stat_info;
}

#define stat_inc_cp_count(si)		((si)->cp_count++)
#define stat_inc_bg_cp_count(si)	((si)->bg_cp_count++)
#define stat_inc_call_count(si)		((si)->call_count++)
#define stat_inc_bggc_count(si)		((si)->bg_gc++)
#define stat_io_skip_bggc_count(sbi)	((sbi)->io_skip_bggc++)
#define stat_other_skip_bggc_count(sbi) ((sbi)->other_skip_bggc++)
#define stat_inc_dirty_inode(sbi, type) ((sbi)->ndirty_inode[type]++)
#define stat_dec_dirty_inode(sbi, type) ((sbi)->ndirty_inode[type]--)
#define stat_inc_total_hit(sbi)		(atomic64_inc(&(sbi)->total_hit_ext))
#define stat_inc_rbtree_node_hit(sbi)	(atomic64_inc(&(sbi)->read_hit_rbtree))
#define stat_inc_largest_node_hit(sbi)	(atomic64_inc(&(sbi)->read_hit_largest))
#define stat_inc_cached_node_hit(sbi)	(atomic64_inc(&(sbi)->read_hit_cached))
#define stat_inc_inline_xattr(inode)                                           \
	do {                                                                   \
		if (f2fs_has_inline_xattr(inode))                              \
			(atomic_inc(&F2FS_I_SB(inode)->inline_xattr));         \
	} while (0)
#define stat_dec_inline_xattr(inode)                                           \
	do {                                                                   \
		if (f2fs_has_inline_xattr(inode))                              \
			(atomic_dec(&F2FS_I_SB(inode)->inline_xattr));         \
	} while (0)
#define stat_inc_inline_inode(inode)                                           \
	do {                                                                   \
		if (f2fs_has_inline_data(inode))                               \
			(atomic_inc(&F2FS_I_SB(inode)->inline_inode));         \
	} while (0)
#define stat_dec_inline_inode(inode)                                           \
	do {                                                                   \
		if (f2fs_has_inline_data(inode))                               \
			(atomic_dec(&F2FS_I_SB(inode)->inline_inode));         \
	} while (0)
#define stat_inc_inline_dir(inode)                                             \
	do {                                                                   \
		if (f2fs_has_inline_dentry(inode))                             \
			(atomic_inc(&F2FS_I_SB(inode)->inline_dir));           \
	} while (0)
#define stat_dec_inline_dir(inode)                                             \
	do {                                                                   \
		if (f2fs_has_inline_dentry(inode))                             \
			(atomic_dec(&F2FS_I_SB(inode)->inline_dir));           \
	} while (0)
#define stat_inc_compr_inode(inode)                                            \
	do {                                                                   \
		if (f2fs_compressed_file(inode))                               \
			(atomic_inc(&F2FS_I_SB(inode)->compr_inode));          \
	} while (0)
#define stat_dec_compr_inode(inode)                                            \
	do {                                                                   \
		if (f2fs_compressed_file(inode))                               \
			(atomic_dec(&F2FS_I_SB(inode)->compr_inode));          \
	} while (0)
#define stat_add_compr_blocks(inode, blocks)                                   \
	(atomic64_add(blocks, &F2FS_I_SB(inode)->compr_blocks))
#define stat_sub_compr_blocks(inode, blocks)                                   \
	(atomic64_sub(blocks, &F2FS_I_SB(inode)->compr_blocks))
#define stat_inc_meta_count(sbi, blkaddr)                                      \
	do {                                                                   \
		if (blkaddr < SIT_I(sbi)->sit_base_addr)                       \
			atomic_inc(&(sbi)->meta_count[META_CP]);               \
		else if (blkaddr < NM_I(sbi)->nat_blkaddr)                     \
			atomic_inc(&(sbi)->meta_count[META_SIT]);              \
		else if (blkaddr < SM_I(sbi)->ssa_blkaddr)                     \
			atomic_inc(&(sbi)->meta_count[META_NAT]);              \
		else if (blkaddr < SM_I(sbi)->main_blkaddr)                    \
			atomic_inc(&(sbi)->meta_count[META_SSA]);              \
	} while (0)
#define stat_inc_seg_type(sbi, curseg)                                         \
	((sbi)->segment_count[(curseg)->alloc_type]++)
#define stat_inc_block_count(sbi, curseg)                                      \
	((sbi)->block_count[(curseg)->alloc_type]++)
#define stat_inc_inplace_blocks(sbi) (atomic_inc(&(sbi)->inplace_count))
#define stat_update_max_atomic_write(inode)                                    \
	do {                                                                   \
		int cur = F2FS_I_SB(inode)->atomic_files;                      \
		int max = atomic_read(&F2FS_I_SB(inode)->max_aw_cnt);          \
		if (cur > max)                                                 \
			atomic_set(&F2FS_I_SB(inode)->max_aw_cnt, cur);        \
	} while (0)
#define stat_inc_volatile_write(inode) (atomic_inc(&F2FS_I_SB(inode)->vw_cnt))
#define stat_dec_volatile_write(inode) (atomic_dec(&F2FS_I_SB(inode)->vw_cnt))
#define stat_update_max_volatile_write(inode)                                  \
	do {                                                                   \
		int cur = atomic_read(&F2FS_I_SB(inode)->vw_cnt);              \
		int max = atomic_read(&F2FS_I_SB(inode)->max_vw_cnt);          \
		if (cur > max)                                                 \
			atomic_set(&F2FS_I_SB(inode)->max_vw_cnt, cur);        \
	} while (0)
#define stat_inc_seg_count(sbi, type, gc_type)                                 \
	do {                                                                   \
		struct f2fs_stat_info *si = F2FS_STAT(sbi);                    \
		si->tot_segs++;                                                \
		if ((type) == SUM_TYPE_DATA) {                                 \
			si->data_segs++;                                       \
			si->bg_data_segs += (gc_type == BG_GC) ? 1 : 0;        \
		} else {                                                       \
			si->node_segs++;                                       \
			si->bg_node_segs += (gc_type == BG_GC) ? 1 : 0;        \
		}                                                              \
	} while (0)

#define stat_inc_tot_blk_count(si, blks) ((si)->tot_blks += (blks))

#define stat_inc_data_blk_count(sbi, blks, gc_type)                            \
	do {                                                                   \
		struct f2fs_stat_info *si = F2FS_STAT(sbi);                    \
		stat_inc_tot_blk_count(si, blks);                              \
		si->data_blks += (blks);                                       \
		si->bg_data_blks += ((gc_type) == BG_GC) ? (blks) : 0;         \
	} while (0)

#define stat_inc_node_blk_count(sbi, blks, gc_type)                            \
	do {                                                                   \
		struct f2fs_stat_info *si = F2FS_STAT(sbi);                    \
		stat_inc_tot_blk_count(si, blks);                              \
		si->node_blks += (blks);                                       \
		si->bg_node_blks += ((gc_type) == BG_GC) ? (blks) : 0;         \
	} while (0)

int f2fs_build_stats(struct f2fs_sb_info *sbi);
void f2fs_destroy_stats(struct f2fs_sb_info *sbi);
void __init f2fs_create_root_stats(void);
void f2fs_destroy_root_stats(void);
void f2fs_update_sit_info(struct f2fs_sb_info *sbi);
#else
#define stat_inc_cp_count(si)                                                  \
	do {                                                                   \
	} while (0)
#define stat_inc_bg_cp_count(si)                                               \
	do {                                                                   \
	} while (0)
#define stat_inc_call_count(si)                                                \
	do {                                                                   \
	} while (0)
#define stat_inc_bggc_count(si)                                                \
	do {                                                                   \
	} while (0)
#define stat_io_skip_bggc_count(sbi)                                           \
	do {                                                                   \
	} while (0)
#define stat_other_skip_bggc_count(sbi)                                        \
	do {                                                                   \
	} while (0)
#define stat_inc_dirty_inode(sbi, type)                                        \
	do {                                                                   \
	} while (0)
#define stat_dec_dirty_inode(sbi, type)                                        \
	do {                                                                   \
	} while (0)
#define stat_inc_total_hit(sbi)                                                \
	do {                                                                   \
	} while (0)
#define stat_inc_rbtree_node_hit(sbi)                                          \
	do {                                                                   \
	} while (0)
#define stat_inc_largest_node_hit(sbi)                                         \
	do {                                                                   \
	} while (0)
#define stat_inc_cached_node_hit(sbi)                                          \
	do {                                                                   \
	} while (0)
#define stat_inc_inline_xattr(inode)                                           \
	do {                                                                   \
	} while (0)
#define stat_dec_inline_xattr(inode)                                           \
	do {                                                                   \
	} while (0)
#define stat_inc_inline_inode(inode)                                           \
	do {                                                                   \
	} while (0)
#define stat_dec_inline_inode(inode)                                           \
	do {                                                                   \
	} while (0)
#define stat_inc_inline_dir(inode)                                             \
	do {                                                                   \
	} while (0)
#define stat_dec_inline_dir(inode)                                             \
	do {                                                                   \
	} while (0)
#define stat_inc_compr_inode(inode)                                            \
	do {                                                                   \
	} while (0)
#define stat_dec_compr_inode(inode)                                            \
	do {                                                                   \
	} while (0)
#define stat_add_compr_blocks(inode, blocks)                                   \
	do {                                                                   \
	} while (0)
#define stat_sub_compr_blocks(inode, blocks)                                   \
	do {                                                                   \
	} while (0)
#define stat_inc_atomic_write(inode)                                           \
	do {                                                                   \
	} while (0)
#define stat_dec_atomic_write(inode)                                           \
	do {                                                                   \
	} while (0)
#define stat_update_max_atomic_write(inode)                                    \
	do {                                                                   \
	} while (0)
#define stat_inc_volatile_write(inode)                                         \
	do {                                                                   \
	} while (0)
#define stat_dec_volatile_write(inode)                                         \
	do {                                                                   \
	} while (0)
#define stat_update_max_volatile_write(inode)                                  \
	do {                                                                   \
	} while (0)
#define stat_inc_meta_count(sbi, blkaddr)                                      \
	do {                                                                   \
	} while (0)
#define stat_inc_seg_type(sbi, curseg)                                         \
	do {                                                                   \
	} while (0)
#define stat_inc_block_count(sbi, curseg)                                      \
	do {                                                                   \
	} while (0)
#define stat_inc_inplace_blocks(sbi)                                           \
	do {                                                                   \
	} while (0)
#define stat_inc_seg_count(sbi, type, gc_type)                                 \
	do {                                                                   \
	} while (0)
#define stat_inc_tot_blk_count(si, blks)                                       \
	do {                                                                   \
	} while (0)
#define stat_inc_data_blk_count(sbi, blks, gc_type)                            \
	do {                                                                   \
	} while (0)
#define stat_inc_node_blk_count(sbi, blks, gc_type)                            \
	do {                                                                   \
	} while (0)

static inline int f2fs_build_stats(struct f2fs_sb_info *sbi)
{
	return 0;
}
static inline void f2fs_destroy_stats(struct f2fs_sb_info *sbi)
{
}
static inline void __init f2fs_create_root_stats(void)
{
}
static inline void f2fs_destroy_root_stats(void)
{
}
static inline void f2fs_update_sit_info(struct f2fs_sb_info *sbi)
{
}
#endif

extern const struct file_operations f2fs_dir_operations;
#ifdef CONFIG_UNICODE
extern const struct dentry_operations f2fs_dentry_ops;
#endif
extern const struct file_operations f2fs_file_operations;
extern const struct inode_operations f2fs_file_inode_operations;
extern const struct address_space_operations f2fs_dblock_aops;
extern const struct address_space_operations f2fs_node_aops;
extern const struct address_space_operations f2fs_meta_aops;
#ifdef CONFIG_F2FS_FS_DEDUP
extern const struct address_space_operations f2dfs_gc_aops;
#endif
extern const struct inode_operations f2fs_dir_inode_operations;
extern const struct inode_operations f2fs_symlink_inode_operations;
extern const struct inode_operations f2fs_encrypted_symlink_inode_operations;
extern const struct inode_operations f2fs_special_inode_operations;
extern struct kmem_cache *f2fs_inode_entry_slab;

bool f2fs_may_inline_data(struct inode *inode);
bool f2fs_may_inline_dentry(struct inode *inode);
void f2fs_do_read_inline_data(struct page *page, struct page *ipage);
void f2fs_truncate_inline_inode(struct inode *inode, struct page *ipage,
				u64 from);
int f2fs_read_inline_data(struct inode *inode, struct page *page);
int f2fs_convert_inline_page(struct dnode_of_data *dn, struct page *page);
int f2fs_convert_inline_inode(struct inode *inode);
int f2fs_try_convert_inline_dir(struct inode *dir, struct dentry *dentry);
int f2fs_write_inline_data(struct inode *inode, struct page *page);
int f2fs_recover_inline_data(struct inode *inode, struct page *npage);
struct f2fs_dir_entry *
f2fs_find_in_inline_dir(struct inode *dir, const struct f2fs_filename *fname,
			struct page **res_page);
int f2fs_make_empty_inline_dir(struct inode *inode, struct inode *parent,
			       struct page *ipage);
int f2fs_add_inline_entry(struct inode *dir, const struct f2fs_filename *fname,
			  struct inode *inode, nid_t ino, umode_t mode);
void f2fs_delete_inline_entry(struct f2fs_dir_entry *dentry, struct page *page,
			      struct inode *dir, struct inode *inode);
bool f2fs_empty_inline_dir(struct inode *dir);
int f2fs_read_inline_dir(struct file *file, struct dir_context *ctx,
			 struct fscrypt_str *fstr);
int f2fs_inline_data_fiemap(struct inode *inode,
			    struct fiemap_extent_info *fieinfo, __u64 start,
			    __u64 len);

unsigned long f2fs_shrink_count(struct shrinker *shrink,
				struct shrink_control *sc);
unsigned long f2fs_shrink_scan(struct shrinker *shrink,
			       struct shrink_control *sc);
void f2fs_join_shrinker(struct f2fs_sb_info *sbi);
void f2fs_leave_shrinker(struct f2fs_sb_info *sbi);

struct rb_entry *f2fs_lookup_rb_tree(struct rb_root_cached *root,
				     struct rb_entry *cached_re,
				     unsigned int ofs);
struct rb_node **f2fs_lookup_rb_tree_ext(struct f2fs_sb_info *sbi,
					 struct rb_root_cached *root,
					 struct rb_node **parent,
					 unsigned long long key,
					 bool *left_most);
struct rb_node **f2fs_lookup_rb_tree_for_insert(struct f2fs_sb_info *sbi,
						struct rb_root_cached *root,
						struct rb_node **parent,
						unsigned int ofs,
						bool *leftmost);
struct rb_entry *f2fs_lookup_rb_tree_ret(
	struct rb_root_cached *root, struct rb_entry *cached_re,
	unsigned int ofs, struct rb_entry **prev_entry,
	struct rb_entry **next_entry, struct rb_node ***insert_p,
	struct rb_node **insert_parent, bool force, bool *leftmost);
bool f2fs_check_rb_tree_consistence(struct f2fs_sb_info *sbi,
				    struct rb_root_cached *root,
				    bool check_key);
unsigned int f2fs_shrink_extent_tree(struct f2fs_sb_info *sbi, int nr_shrink);
void f2fs_init_extent_tree(struct inode *inode, struct page *ipage);
void f2fs_drop_extent_tree(struct inode *inode);
unsigned int f2fs_destroy_extent_node(struct inode *inode);
void f2fs_destroy_extent_tree(struct inode *inode);
bool f2fs_lookup_extent_cache(struct inode *inode, pgoff_t pgofs,
			      struct extent_info *ei);
void f2fs_update_extent_cache(struct dnode_of_data *dn);
void f2fs_update_extent_cache_range(struct dnode_of_data *dn, pgoff_t fofs,
				    block_t blkaddr, unsigned int len);
void f2fs_init_extent_cache_info(struct f2fs_sb_info *sbi);
int __init f2fs_create_extent_cache(void);
void f2fs_destroy_extent_cache(void);

int __init f2fs_init_sysfs(void);
void f2fs_exit_sysfs(void);
int f2fs_register_sysfs(struct f2fs_sb_info *sbi);
void f2fs_unregister_sysfs(struct f2fs_sb_info *sbi);

extern const struct fsverity_operations f2fs_verityops;

static inline bool f2fs_encrypted_file(struct inode *inode)
{
	return IS_ENCRYPTED(inode) && S_ISREG(inode->i_mode);
}

static inline void f2fs_set_encrypted_inode(struct inode *inode)
{
#ifdef CONFIG_FS_ENCRYPTION
	file_set_encrypt(inode);
	f2fs_set_inode_flags(inode);
#endif
}

static inline bool f2fs_post_read_required(struct inode *inode)
{
	return f2fs_encrypted_file(inode) || fsverity_active(inode) ||
	       f2fs_compressed_file(inode);
}

#ifdef CONFIG_F2FS_FS_COMPRESSION
bool f2fs_is_compressed_page(struct page *page);
struct page *f2fs_compress_control_page(struct page *page);
int f2fs_prepare_compress_overwrite(struct inode *inode, struct page **pagep,
				    pgoff_t index, void **fsdata);
bool f2fs_compress_write_end(struct inode *inode, void *fsdata, pgoff_t index,
			     unsigned copied);
int f2fs_truncate_partial_cluster(struct inode *inode, u64 from, bool lock);
void f2fs_compress_write_end_io(struct bio *bio, struct page *page);
bool f2fs_is_compress_backend_ready(struct inode *inode);
int f2fs_init_compress_mempool(void);
void f2fs_destroy_compress_mempool(void);
void f2fs_decompress_pages(struct bio *bio, struct page *page, bool verity);
bool f2fs_cluster_is_empty(struct compress_ctx *cc);
bool f2fs_cluster_can_merge_page(struct compress_ctx *cc, pgoff_t index);
void f2fs_compress_ctx_add_page(struct compress_ctx *cc, struct page *page);
int f2fs_write_multi_pages(struct compress_ctx *cc, int *submitted,
			   struct writeback_control *wbc,
			   enum iostat_type io_type);
int f2fs_is_compressed_cluster(struct inode *inode, pgoff_t index);
int f2fs_read_multi_pages(struct compress_ctx *cc, struct bio **bio_ret,
			  unsigned nr_pages, sector_t *last_block_in_bio,
			  bool is_readahead, bool for_write);
struct decompress_io_ctx *f2fs_alloc_dic(struct compress_ctx *cc);
void f2fs_free_dic(struct decompress_io_ctx *dic);
void f2fs_decompress_end_io(struct page **rpages, unsigned int cluster_size,
			    bool err, bool verity);
int f2fs_init_compress_ctx(struct compress_ctx *cc);
void f2fs_destroy_compress_ctx(struct compress_ctx *cc, bool reuse);
void f2fs_init_compress_info(struct f2fs_sb_info *sbi);
int f2fs_init_page_array_cache(struct f2fs_sb_info *sbi);
void f2fs_destroy_page_array_cache(struct f2fs_sb_info *sbi);
int __init f2fs_init_compress_cache(void);
void f2fs_destroy_compress_cache(void);
#else
static inline bool f2fs_is_compressed_page(struct page *page)
{
	return false;
}
static inline bool f2fs_is_compress_backend_ready(struct inode *inode)
{
	if (!f2fs_compressed_file(inode))
		return true;

	return false;
}
static inline struct page *f2fs_compress_control_page(struct page *page)
{
	WARN_ON_ONCE(1);
	return ERR_PTR(-EINVAL);
}
static inline int f2fs_init_compress_mempool(void)
{
	return 0;
}
static inline void f2fs_destroy_compress_mempool(void)
{
}
static inline int f2fs_init_page_array_cache(struct f2fs_sb_info *sbi)
{
	return 0;
}
static inline void f2fs_destroy_page_array_cache(struct f2fs_sb_info *sbi)
{
}
static inline int __init f2fs_init_compress_cache(void)
{
	return 0;
}
static inline void f2fs_destroy_compress_cache(void)
{
}
#endif

static inline void set_compress_context(struct inode *inode)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);

	F2FS_I(inode)->i_compress_algorithm =
		F2FS_OPTION(sbi).compress_algorithm;
	F2FS_I(inode)->i_log_cluster_size = F2FS_OPTION(sbi).compress_log_size;
	F2FS_I(inode)->i_cluster_size = 1 << F2FS_I(inode)->i_log_cluster_size;
	F2FS_I(inode)->i_flags |= F2FS_COMPR_FL;
	set_inode_flag(inode, FI_COMPRESSED_FILE);
	stat_inc_compr_inode(inode);
	f2fs_mark_inode_dirty_sync(inode, true);
}

static inline bool f2fs_disable_compressed_file(struct inode *inode)
{
	struct f2fs_inode_info *fi = F2FS_I(inode);

	if (!f2fs_compressed_file(inode))
		return true;
	if (S_ISREG(inode->i_mode) &&
	    (get_dirty_pages(inode) || atomic_read(&fi->i_compr_blocks)))
		return false;

	fi->i_flags &= ~F2FS_COMPR_FL;
	stat_dec_compr_inode(inode);
	clear_inode_flag(inode, FI_COMPRESSED_FILE);
	f2fs_mark_inode_dirty_sync(inode, true);
	return true;
}

#define F2FS_FEATURE_FUNCS(name, flagname)                                     \
	static inline int f2fs_sb_has_##name(struct f2fs_sb_info *sbi)         \
	{                                                                      \
		return F2FS_HAS_FEATURE(sbi, F2FS_FEATURE_##flagname);         \
	}

F2FS_FEATURE_FUNCS(encrypt, ENCRYPT);
F2FS_FEATURE_FUNCS(blkzoned, BLKZONED);
F2FS_FEATURE_FUNCS(extra_attr, EXTRA_ATTR);
F2FS_FEATURE_FUNCS(project_quota, PRJQUOTA);
F2FS_FEATURE_FUNCS(inode_chksum, INODE_CHKSUM);
F2FS_FEATURE_FUNCS(flexible_inline_xattr, FLEXIBLE_INLINE_XATTR);
F2FS_FEATURE_FUNCS(quota_ino, QUOTA_INO);
F2FS_FEATURE_FUNCS(inode_crtime, INODE_CRTIME);
F2FS_FEATURE_FUNCS(lost_found, LOST_FOUND);
F2FS_FEATURE_FUNCS(verity, VERITY);
F2FS_FEATURE_FUNCS(sb_chksum, SB_CHKSUM);
F2FS_FEATURE_FUNCS(casefold, CASEFOLD);
F2FS_FEATURE_FUNCS(compression, COMPRESSION);

#ifdef CONFIG_BLK_DEV_ZONED
static inline bool f2fs_blkz_is_seq(struct f2fs_sb_info *sbi, int devi,
				    block_t blkaddr)
{
	unsigned int zno = blkaddr >> sbi->log_blocks_per_blkz;

	return test_bit(zno, FDEV(devi).blkz_seq);
}
#endif

static inline bool f2fs_hw_should_discard(struct f2fs_sb_info *sbi)
{
	return f2fs_sb_has_blkzoned(sbi);
}

static inline bool f2fs_bdev_support_discard(struct block_device *bdev)
{
	return blk_queue_discard(bdev_get_queue(bdev)) || bdev_is_zoned(bdev);
}

static inline bool f2fs_hw_support_discard(struct f2fs_sb_info *sbi)
{
	int i;

	if (!f2fs_is_multi_device(sbi))
		return f2fs_bdev_support_discard(sbi->sb->s_bdev);

	for (i = 0; i < sbi->s_ndevs; i++)
		if (f2fs_bdev_support_discard(FDEV(i).bdev))
			return true;
	return false;
}

static inline bool f2fs_realtime_discard_enable(struct f2fs_sb_info *sbi)
{
	return (test_opt(sbi, DISCARD) && f2fs_hw_support_discard(sbi)) ||
	       f2fs_hw_should_discard(sbi);
}

static inline bool f2fs_hw_is_readonly(struct f2fs_sb_info *sbi)
{
	int i;

	if (!f2fs_is_multi_device(sbi))
		return bdev_read_only(sbi->sb->s_bdev);

	for (i = 0; i < sbi->s_ndevs; i++)
		if (bdev_read_only(FDEV(i).bdev))
			return true;
	return false;
}

static inline bool f2fs_lfs_mode(struct f2fs_sb_info *sbi)
{
	return F2FS_OPTION(sbi).fs_mode == FS_MODE_LFS;
}

static inline bool f2fs_may_compress(struct inode *inode)
{
	if (IS_SWAPFILE(inode) || f2fs_is_pinned_file(inode) ||
	    f2fs_is_atomic_file(inode) || f2fs_is_volatile_file(inode))
		return false;
	return S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode);
}

static inline void f2fs_i_compr_blocks_update(struct inode *inode, u64 blocks,
					      bool add)
{
	int diff		   = F2FS_I(inode)->i_cluster_size - blocks;
	struct f2fs_inode_info *fi = F2FS_I(inode);

	if (!add && !atomic_read(&fi->i_compr_blocks))
		return;

	if (add) {
		atomic_add(diff, &fi->i_compr_blocks);
		stat_add_compr_blocks(inode, diff);
	} else {
		atomic_sub(diff, &fi->i_compr_blocks);
		stat_sub_compr_blocks(inode, diff);
	}
	f2fs_mark_inode_dirty_sync(inode, true);
}

static inline int block_unaligned_IO(struct inode *inode, struct kiocb *iocb,
				     struct iov_iter *iter)
{
	unsigned int i_blkbits	    = READ_ONCE(inode->i_blkbits);
	unsigned int blocksize_mask = (1 << i_blkbits) - 1;
	loff_t offset		    = iocb->ki_pos;
	unsigned long align	    = offset | iov_iter_alignment(iter);

	return align & blocksize_mask;
}

static inline int allow_outplace_dio(struct inode *inode, struct kiocb *iocb,
				     struct iov_iter *iter)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	int rw			 = iov_iter_rw(iter);

	return (f2fs_lfs_mode(sbi) && (rw == WRITE) &&
		!block_unaligned_IO(inode, iocb, iter));
}

static inline bool f2fs_force_buffered_io(struct inode *inode,
					  struct kiocb *iocb,
					  struct iov_iter *iter)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	int rw			 = iov_iter_rw(iter);

	if (f2fs_post_read_required(inode))
		return true;
	if (f2fs_is_multi_device(sbi))
		return true;

	if (f2fs_sb_has_blkzoned(sbi))
		return true;
	if (f2fs_lfs_mode(sbi) && (rw == WRITE)) {
		if (block_unaligned_IO(inode, iocb, iter))
			return true;
		if (F2FS_IO_ALIGNED(sbi))
			return true;
	}
	if (is_sbi_flag_set(F2FS_I_SB(inode), SBI_CP_DISABLED) &&
	    !IS_SWAPFILE(inode))
		return true;

	return false;
}

#ifdef CONFIG_F2FS_FAULT_INJECTION
extern void f2fs_build_fault_attr(struct f2fs_sb_info *sbi, unsigned int rate,
				  unsigned int type);
#else
#define f2fs_build_fault_attr(sbi, rate, type)                                 \
	do {                                                                   \
	} while (0)
#endif

static inline bool is_journalled_quota(struct f2fs_sb_info *sbi)
{
#ifdef CONFIG_QUOTA
	if (f2fs_sb_has_quota_ino(sbi))
		return true;
	if (F2FS_OPTION(sbi).s_qf_names[USRQUOTA] ||
	    F2FS_OPTION(sbi).s_qf_names[GRPQUOTA] ||
	    F2FS_OPTION(sbi).s_qf_names[PRJQUOTA])
		return true;
#endif
	return false;
}

#define EFSBADCRC    EBADMSG
#define EFSCORRUPTED EUCLEAN

#ifdef CONFIG_F2FS_DEDUP

#define DEDUP_HASH_SIZE 32

struct f2fs_fp_entry {
	u8 fingerprint[DEDUP_HASH_SIZE];
	block_t pblk;
}

struct f2fs_ref_count_entry {
	block_t pblk;
	u8 ref_count;
	struct f2fs_fp_entry *fp_entry;
};

struct f2fs_ref_count_delta_entry {
	block_t pblk;
	u8 delta_count;
};

static struct dedup_table global_dedup_table;

int dedup_table_init(struct dedup_table *table);
void dedup_table_exit(struct dedup_table *table);
struct dedup_entry *dedup_table_lookup(struct dedup_table *table, u8 *hash);
int dedup_table_insert(struct dedup_table *table, u8 *hash, block_t pblk);
int dedup_table_inc_ref(struct dedup_table *table, u8 *hash);
int dedup_table_dec_ref(struct dedup_table *table, u8 *hash);
#endif
#endif
