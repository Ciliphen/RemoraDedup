#include <linux/spinlock_types.h>
#include <linux/rwsem.h>
#include <crypto/hash.h>
#include <linux/f2fs_fs.h>
#include <linux/hashtable.h>
#include "f2fs.h"

struct rc_merge_hash_entry {
	struct hlist_node hnode;
	virtual_t vaddr;
	struct rc_base_entry *base_entry;
};

struct f2dfs_dio_completion {
	struct completion completion;
	int error;
};

enum {
	FEMU_ENABLE_GC_DELAY  = 1,
	FEMU_DISABLE_GC_DELAY = 2,

	FEMU_ENABLE_DELAY_EMU  = 3,
	FEMU_DISABLE_DELAY_EMU = 4,

	FEMU_RESET_ACCT	 = 5,
	FEMU_ENABLE_LOG	 = 6,
	FEMU_DISABLE_LOG = 7,

	FEMU_PRINT_DATA = 8,

	FEMU_ENABLE_DEDUP_MERGE	    = 9,
	FEMU_DISABLE_DEDUP_MERGE    = 10,
	FEMU_TRIGGER_RC_DELTA_MERGE = 11,
};

enum {
	FP_HASH_SUCCESS,
	FP_HASH_FAILURE,

	FP_BUFFER_SEARCH_DUPL,
	FP_BUFFER_SEARCH_UNIQUE,
	FP_BUFFER_INSERT_SUCCESS,
	FP_BUFFER_INSERT_FAILURE,

	FP_BUFFER_INTO_BUCKET_SUCCESS,
	FP_BUFFER_INTO_BUCKET_FAILURE,

	FP_BUCKET_INTO_STORAGE_SUCCESS,
	FP_BUCKET_INTO_STORAGE_FAILURE,

	RC_BUFFER_INSERT_SUCCESS,
	RC_BUFFER_INSERT_FAILURE,

	RC_BUFFER_INTO_STORAGE_SUCCESS,
	RC_BUFFER_INTO_STORAGE_FAILURE,

	FP_PAGE_ADDR_MATCH_BUT_NOT_FOUND,
	RAW_BUCKET_EMPTY,

	RCD_EMPTY_SKIP_MERGE
};

#define F2DFS_START_FREE_NID (5 + 1)
#define SSA_VIRTUAL_ADDR     5

#define INO_MAGIC     (0x00494e4f)
#define VERSION_MAGIC (0x41)

struct f2dfs_global_counter {
	int valid_rc_change;
	int unique_rc_change;
	int dupl_rc_change;
	int zero_rc_change;
};

struct f2dfs_basic_hash_info {
	char *name;
	char *simple_name;
	char *full_name;
	unsigned long len;
	unsigned int zero_prefix;
	char *zero_result;
	char *null_result;
	int (*fp_update)(struct shash_desc *shash, const u8 *data,
			 unsigned int len);
	struct crypto_shash *alg;
};

struct sdesc {
	struct shash_desc shash;
	char ctx[];
};

struct fp_rc_info {
	__u8 fingerprint[FP_LEN_MAX];
	virtual_t vaddr;
	virtual_t fp_page_addr;
	bool is_unique;
	char rc_change;
};

#define F2DFS_HASH_JOBS_NUMBER (16384)

struct f2dfs_single_hash_job {
	struct f2fs_sb_info *sbi;
	struct work_struct page_work;
	struct mutex work_mutex;
	struct page *page;
	pgoff_t index;
	struct fp_rc_info search_result;
	struct sdesc *sdesc;
};

struct f2dfs_fingerprint_hash {
	struct f2dfs_basic_hash_info *basic_hash_info;
	struct workqueue_struct *parallel_hash_workqueue;
	struct f2dfs_single_hash_job *hash_jobs;
};

#define FP_ENTRIES_PER_PAGE	    (PAGE_SIZE / sizeof(struct fp_entry))
#define FP_ENTRIES_INVALID_MAP_SIZE (DIV_ROUND_UP(FP_ENTRIES_PER_PAGE, 8))

struct fp_entry {
	__u8 fingerprint[FP_LEN_MAX];
	virtual_t vaddr;
} __packed;

struct f2dfs_fp_bucket {
	struct fp_entry entries[FP_ENTRIES_PER_PAGE];
	block_t blkaddr;
	__u8 valid_count;
	unsigned long atime;
};

#define FP_BUFFER_MAGIC (0x004650)

struct f2dfs_fp_bucket_in_disk {
	struct fp_entry entries[FP_ENTRIES_PER_PAGE];
	__u8 valid_count;
	__u8 invalidmap[FP_ENTRIES_INVALID_MAP_SIZE];
	__le32 magic;
	__u8 reserved[PAGE_SIZE - sizeof(struct fp_entry) * FP_ENTRIES_PER_PAGE -
		      sizeof(__u8) * (FP_ENTRIES_INVALID_MAP_SIZE + 1) -
		      sizeof(__le32)];
} __packed;

static_assert(sizeof(struct f2dfs_fp_bucket_in_disk) == PAGE_SIZE,
	      "f2dfs_fp_buffer_in_disk size mismatch");

#define FP_BUCKET_MAX_NUM   (30)
#define FP_BUCKET_WB_NUM    (FP_BUCKET_MAX_NUM * 2 / 3)
#define FP_BUCKET_SWAP_HIGH ((FP_BUCKET_MAX_NUM) - ((FP_BUCKET_WB_NUM) / 2))

#define FP_BUCKET_REPLACE_OLDEST (FP_BUCKET_MAX_NUM < 50)

#define GIVE_UP_CPU_ENABLE   (0)
#define FP_SCAN_RESCHED_MASK 0x3ff

struct f2dfs_fp_bucket_list {
	unsigned int current_number;
	struct kmem_cache *bucket_cache;
	struct f2dfs_fp_bucket *pointers[FP_BUCKET_MAX_NUM];
};

struct rc_base_entry {
	virtual_t vaddr;
	char rc;
	virtual_t fp_page_addr;
} __packed;

#define rc_overflow(rc, change)                                                \
	(((int)(rc) + (int)(change)) > 127 ||                                  \
	 ((int)(rc) + (int)(change)) < -128)

struct rc_delta_entry {
	virtual_t vaddr;
	char rc;
} __packed;

#define RC_BASE_ENTRIES_PER_PAGE ((PAGE_SIZE) / (sizeof(struct rc_base_entry)))
#define RC_DELTA_ENTRIES_PER_PAGE                                              \
	((PAGE_SIZE) / (sizeof(struct rc_delta_entry)))

#define RC_BASE_ENTRIES_PER_PAGE_MAX  (RC_BASE_ENTRIES_PER_PAGE - 1)
#define RC_DELTA_ENTRIES_PER_PAGE_MAX (RC_DELTA_ENTRIES_PER_PAGE - 1)

struct f2dfs_rc_base_buffer {
	struct rc_base_entry entries[RC_BASE_ENTRIES_PER_PAGE_MAX];
	__u16 valid_count;
	__u8 reserved[PAGE_SIZE -
		      sizeof(struct rc_base_entry) *
			      RC_BASE_ENTRIES_PER_PAGE_MAX -
		      sizeof(__u16)];
} __packed;

__static_assert(sizeof(struct f2dfs_rc_base_buffer) == PAGE_SIZE,
		"f2dfs_rc_base_buffer size mismatch");

struct f2dfs_rc_delta_buffer {
	struct rc_delta_entry entries[RC_DELTA_ENTRIES_PER_PAGE_MAX];
	__u16 valid_count;
	__u8 reserved[PAGE_SIZE -
		      sizeof(struct rc_delta_entry) *
			      RC_DELTA_ENTRIES_PER_PAGE_MAX -
		      sizeof(__u16)];
} __packed;

__static_assert(sizeof(struct f2dfs_rc_delta_buffer) == PAGE_SIZE,
		"f2dfs_rc_delta_buffer size mismatch");

#define PREFIX_LEN		  (20)
#define FP_HASH_TABLE_ENTRIES_NUM (1 << PREFIX_LEN)
#define ENABLE_FP_HASH_TABLE	  (0)

struct f2dfs_dm_info {
	block_t fp_bitmap_blkaddr;
	block_t rc_base_bitmap_blkaddr;
	block_t rc_delta_bitmap_blkaddr;

	block_t fp_blkaddr;
	block_t fp_blks;
	block_t rc_base_blkaddr;
	block_t rc_base_blks;
	block_t rc_delta_blkaddr;
	block_t rc_delta_blks;

	block_t unfull_fp_blkaddr;
	block_t unfull_rc_base_blkaddr;
	block_t unfull_rc_delta_blkaddr;

	char *fp_bitmap;
	char *rc_base_bitmap;
	char *rc_delta_bitmap;

	spinlock_t fp_lock;
	spinlock_t rc_base_lock;
	spinlock_t rc_delta_lock;

	struct fp_entry *fp_hash_table;
};

#define FP_BITMAP_SIZE		 (DIV_ROUND_UP(41472, 8))
#define RC_BASE_BITMAP_SIZE	 (DIV_ROUND_UP(41472, 8))
#define RC_DELTA_BITMAP_SIZE	 (DIV_ROUND_UP(8192, 8))
#define FP_BITMAP_PAGESIZE	 (DIV_ROUND_UP(FP_BITMAP_SIZE, PAGE_SIZE))
#define RC_BASE_BITMAP_PAGESIZE	 (DIV_ROUND_UP(RC_BASE_BITMAP_SIZE, PAGE_SIZE))
#define RC_DELTA_BITMAP_PAGESIZE (DIV_ROUND_UP(RC_DELTA_BITMAP_SIZE, PAGE_SIZE))

#define PRINT_BASIC_INFO_ENABLED     (0)
#define PRINT_IMPORTANT_INFO_ENABLED (1)

#define print_info(condition, fmt, ...)                                        \
	do {                                                                   \
		if (condition) {                                               \
			f2dfs_info(sbi, "file:%s, line:%d: " fmt, __FILE__,    \
				   __LINE__, ##__VA_ARGS__);                   \
		}                                                              \
	} while (0)
#define print_err(fmt, ...)                                                    \
	f2dfs_err(sbi, "file:%s, line:%d: " fmt, __FILE__, __LINE__,           \
		  ##__VA_ARGS__)
#define print_warn(fmt, ...)                                                   \
	f2dfs_warn(sbi, "file:%s, line:%d: " fmt, __FILE__, __LINE__,          \
		   ##__VA_ARGS__)

struct f2dfs_bitmap_disk {
	__u8 bitmap[PAGE_SIZE - sizeof(__le32)];
	__le32 unfull_blkaddr;
} __packed;

#define FP_COUNTER_ZERO	  (5)
#define FP_COUNTER_UNIQUE (FP_COUNTER_ZERO + (1))
#define FP_COUNTER_DUPL	  (FP_COUNTER_ZERO + (2))

static inline struct f2dfs_dm_info *DM_I(struct f2fs_sb_info *sbi)
{
	return (struct f2dfs_dm_info *)(sbi->dm_info);
}

static inline int f2dfs_inode_inc_valid_block_count(struct f2fs_sb_info *sbi,
						    struct inode *inode,
						    blkcnt_t *count)
{
	blkcnt_t diff = 0, release = 0;
	block_t avail_user_block_count, temp_total_valid_block_count;
	int ret;

	ret = dquot_reserve_block(inode, *count);
	if (ret)
		return ret;

	if (time_to_inject(sbi, FAULT_BLOCK)) {
		f2fs_show_injection_info(sbi, FAULT_BLOCK);
		release = *count;
		goto release_quota;
	}

	spin_lock(&sbi->stat_lock);
	temp_total_valid_block_count =
		sbi->total_valid_block_count + (block_t)(*count);
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

	if (unlikely(temp_total_valid_block_count > avail_user_block_count)) {
		diff = temp_total_valid_block_count - avail_user_block_count;
		if (diff > *count)
			diff = *count;
		*count -= diff;
		release = diff;
		temp_total_valid_block_count -= diff;
		if (!*count) {
			spin_unlock(&sbi->stat_lock);

			goto release_quota;
		}
	}
	spin_unlock(&sbi->stat_lock);

	if (unlikely(release)) {
		dquot_release_reservation_block(inode, release);
	}

	f2fs_i_blocks_write(inode, *count, true, true);
	return 0;

release_quota:

	dquot_release_reservation_block(inode, release);
	return -ENOSPC;
}

static inline void f2dfs_inode_dec_valid_block_count(struct f2fs_sb_info *sbi,
						     struct inode *inode,
						     block_t count)
{
	blkcnt_t sectors = count << F2FS_LOG_SECTORS_PER_BLOCK;

	if (unlikely(inode->i_blocks < sectors)) {
		f2fs_warn(sbi,
			  "Inconsistent i_blocks, ino:%lu, iblocks:%llu, "
			  "sectors:%llu",
			  inode->i_ino, (unsigned long long)inode->i_blocks,
			  (unsigned long long)sectors);
		set_sbi_flag(sbi, SBI_NEED_FSCK);
		return;
	}

	f2fs_i_blocks_write(inode, count, false, true);
}

static inline unsigned int f2dfs_dedupe_calculation(unsigned long blocks,
						    unsigned int high,
						    unsigned int low)
{
	unsigned int a = 0;

	if (high > 0) {
		if (high < (1 << 8))
			a = (unsigned int)((high << 4) + (low >> 28) +
					   (blocks >> 28));
		else if (high < (1 << 18))
			a = (unsigned int)(high >> 6);
		else if (high < (1 << 28))
			a = (unsigned int)(high >> 16);
		else
			a = (high >> 28);
	} else {
		if (blocks < (1 << 10))
			a = (unsigned int)(blocks << 2);
		else if (blocks < (1 << 20))
			a = (unsigned int)(blocks >> 8);
		else if (blocks < (1 << 30))
			a = (unsigned int)(blocks >> 18);
		else
			a = (blocks >> 30);
	}

	return a;
}

static inline unsigned int f2dfs_dedupe_unit(unsigned long blocks,
					     unsigned int high)
{
	unsigned int a = 0;

	if (high > 0) {
		if (high < (1 << 8))
			a = 3;
		else if (high < (1 << 18))
			a = 4;
		else if (high < (1 << 28))
			a = 5;
		else
			a = 6;
	} else {
		if (blocks < (1 << 10))
			a = 0;
		else if (blocks < (1 << 20))
			a = 1;
		else if (blocks < (1 << 30))
			a = 2;
		else
			a = 3;
	}

	return a;
}

static inline bool
f2dfs_change_block_count_inline(struct f2fs_sb_info *sbi,
				struct f2dfs_global_counter *g_counter)
{
	blkcnt_t diff = 0, release = 0;
	block_t avail_user_block_count;
	bool valid_inc = false, valid_dec = false;
	block_t valid_rc_change	 = g_counter->valid_rc_change,
		unique_rc_change = g_counter->unique_rc_change,
		dupl_rc_change	 = g_counter->dupl_rc_change,
		zero_rc_change	 = g_counter->zero_rc_change;

	if (((block_t)valid_rc_change == (block_t)0) &&
	    ((block_t)unique_rc_change == (block_t)0) &&
	    ((block_t)dupl_rc_change == (block_t)0) &&
	    ((block_t)zero_rc_change == (block_t)0))
		return true;

	if ((int)valid_rc_change > (int)0)
		valid_inc = true;
	else if ((int)valid_rc_change < (int)0)
		valid_dec = true;

	if (valid_inc)
		percpu_counter_add(&sbi->alloc_valid_block_count,
				   valid_rc_change);

	spin_lock(&sbi->stat_lock);

	if (valid_dec &&
	    ((long long)(sbi->total_valid_block_count +
			 (block_t)valid_rc_change) < (long long)0)) {
		f2fs_bug_on(sbi, (long long)(sbi->total_valid_block_count +
					     (block_t)valid_rc_change) <
					 (long long)0);
		spin_unlock(&sbi->stat_lock);
		return false;
	}

	if (((long long)(sbi->unique_block_count + (block_t)unique_rc_change) <
	     (long long)0) &&
	    ((int)unique_rc_change < (int)0)) {
		f2fs_bug_on(sbi, ((long long)(sbi->unique_block_count +
					      (block_t)unique_rc_change) <
				  (long long)0) &&
					 ((int)unique_rc_change < (int)0));
		spin_unlock(&sbi->stat_lock);
		return false;
	}

	if (((long long)(sbi->zero_block_count + (block_t)zero_rc_change) <
	     (long long)0) &&
	    ((int)zero_rc_change < (int)0)) {
		f2fs_bug_on(sbi, ((long long)(sbi->zero_block_count +
					      (block_t)zero_rc_change) <
				  (long long)0) &&
					 ((int)zero_rc_change < (int)0));
		spin_unlock(&sbi->stat_lock);
		return false;
	}

	if (valid_inc || valid_dec) {
		if (sbi->total_valid_block_count < sbi->unique_block_count) {
			f2fs_bug_on(sbi, sbi->total_valid_block_count <
						 sbi->unique_block_count);
			spin_unlock(&sbi->stat_lock);
			goto enospc;
		}
	}

	if (valid_inc) {
		sbi->total_valid_block_count += (block_t)valid_rc_change;
		avail_user_block_count =
			(blkcnt_t)(sbi->user_block_count -
				   sbi->current_reserved_blocks);

		if (unlikely(is_sbi_flag_set(sbi, SBI_CP_DISABLED))) {
			if ((unsigned long long)avail_user_block_count >
			    (unsigned long long)sbi->unusable_block_count)
				avail_user_block_count -=
					(blkcnt_t)sbi->unusable_block_count;
			else
				avail_user_block_count = (blkcnt_t)0;
		}

		if (unlikely((unsigned long long)sbi->total_valid_block_count >
			     (unsigned long long)avail_user_block_count)) {
			diff = (blkcnt_t)(sbi->total_valid_block_count -
					  (block_t)avail_user_block_count);
			if ((unsigned long long)diff >
			    (unsigned long long)valid_rc_change)
				diff = (blkcnt_t)valid_rc_change;

			valid_rc_change -= (block_t)diff;
			release = (blkcnt_t)diff;
			sbi->total_valid_block_count -= (block_t)diff;

			if (!valid_rc_change) {
				spin_unlock(&sbi->stat_lock);
				goto enospc;
			}
		}
	}

	else if (valid_dec) {
		sbi->total_valid_block_count += (block_t)valid_rc_change;
		if ((sbi->reserved_blocks != (block_t)0) &&
		    ((unsigned int)sbi->current_reserved_blocks <
		     (unsigned int)sbi->reserved_blocks))
			sbi->current_reserved_blocks =
				min((block_t)sbi->reserved_blocks,
				    (block_t)(sbi->current_reserved_blocks -
					      (block_t)valid_rc_change));
	}

	sbi->unique_block_count += (block_t)unique_rc_change;
	sbi->zero_block_count += (block_t)zero_rc_change;

	if ((int)dupl_rc_change > (int)0) {
		if (((unsigned int)(sbi->duplication_block_count_low +
				    (block_t)dupl_rc_change) <
		     (unsigned int)sbi->duplication_block_count_low) &&
		    (sbi->duplication_block_count_high == (block_t)-1)) {
			f2fs_bug_on(sbi, sbi->duplication_block_count_high ==
						 (block_t)-1);
			spin_unlock(&sbi->stat_lock);
			return false;
		}

		if ((unsigned int)(sbi->duplication_block_count_low +
				   (block_t)dupl_rc_change) <
		    (unsigned int)sbi->duplication_block_count_low)
			sbi->duplication_block_count_high += (block_t)1;
	} else if ((int)dupl_rc_change < (int)0) {
		if (((long long)(sbi->duplication_block_count_low +
				 (block_t)dupl_rc_change) < (long long)0) &&
		    (sbi->duplication_block_count_high == (block_t)0)) {
			f2fs_bug_on(sbi, sbi->duplication_block_count_high ==
						 (block_t)0);
			spin_unlock(&sbi->stat_lock);
			return false;
		}

		if ((long long)(sbi->duplication_block_count_low +
				(block_t)dupl_rc_change) < (long long)0)
			sbi->duplication_block_count_high -= (block_t)1;
	}

	if ((int)dupl_rc_change < (int)0) {
		sbi->duplication_block_count_low =
			(block_t)(sbi->duplication_block_count_low -
				  (block_t)dupl_rc_change);
	}

	spin_unlock(&sbi->stat_lock);

enospc:
	return false;
}

static inline bool
f2dfs_change_block_count_direct(struct f2fs_sb_info *sbi,
				struct f2dfs_global_counter *g_counter)
{
	blkcnt_t diff = 0, release = 0;
	block_t avail_user_block_count;
	bool valid_inc		 = false;
	block_t valid_rc_change	 = g_counter->valid_rc_change,
		unique_rc_change = g_counter->unique_rc_change,
		dupl_rc_change	 = g_counter->dupl_rc_change,
		zero_rc_change	 = g_counter->zero_rc_change;

	if (((block_t)valid_rc_change == (block_t)0) &&
	    ((block_t)unique_rc_change == (block_t)0) &&
	    ((block_t)dupl_rc_change == (block_t)0) &&
	    ((block_t)zero_rc_change == (block_t)0))
		return true;

	if ((int)valid_rc_change < (int)0) {
		f2fs_bug_on(sbi, (int)valid_rc_change < (int)0);
		return false;
	}

	if ((int)unique_rc_change < (int)0) {
		f2fs_bug_on(sbi, (int)unique_rc_change < (int)0);
		return false;
	}

	if ((int)dupl_rc_change > (int)0) {
		f2fs_bug_on(sbi, (int)dupl_rc_change > (int)0);
		return false;
	}

	if ((int)zero_rc_change > (int)0) {
		f2fs_bug_on(sbi, (int)zero_rc_change > (int)0);
		return false;
	}

	if ((int)valid_rc_change > (int)0)
		valid_inc = true;

	if (valid_inc)
		percpu_counter_add(&sbi->alloc_valid_block_count,
				   valid_rc_change);

	spin_lock(&sbi->stat_lock);

	if (((long long)(sbi->zero_block_count + (block_t)zero_rc_change) <
	     (long long)0) &&
	    ((int)zero_rc_change < (int)0)) {
		f2fs_bug_on(sbi, ((long long)(sbi->zero_block_count +
					      (block_t)zero_rc_change) <
				  (long long)0) &&
					 ((int)zero_rc_change < (int)0));
		spin_unlock(&sbi->stat_lock);
		return false;
	}

	if (sbi->total_valid_block_count < sbi->unique_block_count) {
		f2fs_bug_on(sbi, sbi->total_valid_block_count <
					 sbi->unique_block_count);
		spin_unlock(&sbi->stat_lock);
		goto enospc;
	}

	if (valid_inc) {
		sbi->total_valid_block_count += (block_t)valid_rc_change;
		avail_user_block_count =
			(blkcnt_t)(sbi->user_block_count -
				   sbi->current_reserved_blocks);

		if (unlikely(is_sbi_flag_set(sbi, SBI_CP_DISABLED))) {
			if ((unsigned long long)avail_user_block_count >
			    (unsigned long long)sbi->unusable_block_count)
				avail_user_block_count -=
					(blkcnt_t)sbi->unusable_block_count;
			else
				avail_user_block_count = (blkcnt_t)0;
		}

		if (unlikely((unsigned long long)sbi->total_valid_block_count >
			     (unsigned long long)avail_user_block_count)) {
			diff = (blkcnt_t)(sbi->total_valid_block_count -
					  (block_t)avail_user_block_count);
			if ((unsigned long long)diff >
			    (unsigned long long)valid_rc_change)
				diff = (blkcnt_t)valid_rc_change;

			valid_rc_change -= (block_t)diff;
			release = (blkcnt_t)diff;
			sbi->total_valid_block_count -= (block_t)diff;

			if (!valid_rc_change) {
				spin_unlock(&sbi->stat_lock);
				goto enospc;
			}
		}
	}

	sbi->unique_block_count += (block_t)unique_rc_change;
	sbi->zero_block_count += (block_t)zero_rc_change;

	if (((long long)(sbi->duplication_block_count_low +
			 (block_t)dupl_rc_change) < (long long)0) &&
	    (sbi->duplication_block_count_high == (block_t)0)) {
		f2fs_bug_on(sbi,
			    sbi->duplication_block_count_high == (block_t)0);
		spin_unlock(&sbi->stat_lock);
		return false;
	}

	if ((long long)(sbi->duplication_block_count_low +
			(block_t)dupl_rc_change) < (long long)0)
		sbi->duplication_block_count_high -= (block_t)1;

	sbi->duplication_block_count_low += (block_t)dupl_rc_change;

	spin_unlock(&sbi->stat_lock);

	if (valid_inc) {
		if (unlikely(release)) {
			percpu_counter_sub(&sbi->alloc_valid_block_count,
					   release);
			return false;
		}
	}

	return true;

enospc:

	if (valid_inc)
		percpu_counter_sub(&sbi->alloc_valid_block_count, release);
	return false;
}

static inline bool
f2dfs_change_block_count_truncate(struct f2fs_sb_info *sbi,
				  struct f2dfs_global_counter *g_counter)
{
	block_t valid_rc_change	 = g_counter->valid_rc_change,
		unique_rc_change = g_counter->unique_rc_change,
		dupl_rc_change	 = g_counter->dupl_rc_change,
		zero_rc_change	 = g_counter->zero_rc_change;

	if (((block_t)valid_rc_change == (block_t)0) &&
	    ((block_t)unique_rc_change == (block_t)0) &&
	    ((block_t)dupl_rc_change == (block_t)0) &&
	    ((block_t)zero_rc_change == (block_t)0))
		return true;

	if ((int)valid_rc_change > (int)0) {
		f2fs_bug_on(sbi, (int)valid_rc_change > (int)0);
		return false;
	}

	if ((int)dupl_rc_change > (int)0) {
		f2fs_bug_on(sbi, (int)dupl_rc_change > (int)0);
		return false;
	}

	if ((int)zero_rc_change > (int)0) {
		f2fs_bug_on(sbi, (int)zero_rc_change > (int)0);
		return false;
	}

	spin_lock(&sbi->stat_lock);

	if ((long long)(sbi->total_valid_block_count +
			(block_t)valid_rc_change) < (long long)0) {
		f2fs_bug_on(sbi, (long long)(sbi->total_valid_block_count +
					     (block_t)valid_rc_change) <
					 (long long)0);
		spin_unlock(&sbi->stat_lock);
		return false;
	}

	if (((long long)(sbi->unique_block_count + (block_t)unique_rc_change) <
	     (long long)0) &&
	    ((int)unique_rc_change < (int)0)) {
		f2fs_bug_on(sbi, ((long long)(sbi->unique_block_count +
					      (block_t)unique_rc_change) <
				  (long long)0) &&
					 ((int)unique_rc_change < (int)0));
		spin_unlock(&sbi->stat_lock);
		return false;
	}

	if ((long long)(sbi->zero_block_count + (block_t)zero_rc_change) <
	    (long long)0) {
		f2fs_bug_on(sbi, (long long)(sbi->zero_block_count +
					     (block_t)zero_rc_change) <
					 (long long)0);
		spin_unlock(&sbi->stat_lock);
		return false;
	}

	if (sbi->total_valid_block_count < sbi->unique_block_count) {
		f2fs_bug_on(sbi, sbi->total_valid_block_count <
					 sbi->unique_block_count);
		spin_unlock(&sbi->stat_lock);
		return false;
	}

	sbi->total_valid_block_count += (block_t)valid_rc_change;
	sbi->unique_block_count += (block_t)unique_rc_change;
	sbi->zero_block_count += (block_t)zero_rc_change;

	if (((block_t)valid_rc_change != (block_t)0) &&
	    ((sbi->reserved_blocks != (block_t)0) &&
	     ((unsigned int)sbi->current_reserved_blocks <
	      (unsigned int)sbi->reserved_blocks)))
		sbi->current_reserved_blocks =
			min((block_t)sbi->reserved_blocks,
			    (block_t)((sbi->current_reserved_blocks -
				       (block_t)valid_rc_change)));

	if ((long long)(sbi->duplication_block_count_low +
			(block_t)dupl_rc_change) < (long long)0) {
		if (sbi->duplication_block_count_high == (block_t)0) {
			f2fs_bug_on(sbi, sbi->duplication_block_count_high ==
						 (block_t)0);
			spin_unlock(&sbi->stat_lock);
			return false;
		}

		sbi->duplication_block_count_high -= (block_t)1;
	}

	sbi->duplication_block_count_low += (block_t)dupl_rc_change;

	spin_unlock(&sbi->stat_lock);
	return true;
}

static inline void f2dfs_dedupe_info_printk(struct f2fs_sb_info *sbi)
{
	unsigned int dedupe_high = 0, dedupe_low = 0, data_blocks_count = 0,
		     unique_blocks_count = 0, zero_blocks_count = 0,
		     unrefer_blocks_count  = 0;
	unsigned long logical_blocks_count = 0;
	char units[8][4] = { { "KB" }, { "MB" }, { "GB" }, { "TB" },
			     { "PB" }, { "EB" }, { "ZB" }, { "YB" } };

	if (!PRINT_IMPORTANT_INFO_ENABLED)
		return;

	dedupe_high	     = dedupe_user_blocks_high(sbi);
	dedupe_low	     = dedupe_user_blocks_low(sbi);
	data_blocks_count    = max((unsigned int)(valid_user_blocks(sbi) -
						  valid_node_count(sbi) - 1),
				   (unsigned int)0);
	unique_blocks_count  = unique_user_blocks(sbi);
	zero_blocks_count    = zero_user_blocks(sbi);
	unrefer_blocks_count = offline_user_blocks(sbi);

	f2dfs_info(sbi, "/-----------------------------"
			"----------------------------\\");

	f2dfs_info(sbi,
		   "| Inode num:   Node(%1u), Meta(%1u), Root(%1u), "
		   "GC(%1u)           |",
		   sbi->node_ino_num, sbi->meta_ino_num, sbi->root_ino_num,
		   sbi->gc_ino_num);

	f2dfs_info(sbi, "| %21s (%5s, %2u B) used as F2DFS's FP. |",
		   sbi->s_fp_hash->basic_hash_info->full_name,
		   sbi->s_fp_hash->basic_hash_info->simple_name,
		   sbi->s_fp_hash->basic_hash_info->len);

	f2dfs_info(sbi, "|-----------------------------"
			"----------------------------|");

	f2dfs_info(
		sbi,
		"| # of valid user blocks:   %10u >>> %4u %2s.     "
		"  |",
		data_blocks_count,
		f2dfs_dedupe_calculation((unsigned long)data_blocks_count, 0,
					 0),
		units[f2dfs_dedupe_unit((unsigned long)data_blocks_count, 0)]);

	f2dfs_info(
		sbi,
		"| # of unique blocks:       %10u >>> %4u %2s.     "
		"  |",
		unique_blocks_count,
		f2dfs_dedupe_calculation((unsigned long)unique_blocks_count, 0,
					 0),
		units[f2dfs_dedupe_unit((unsigned long)unique_blocks_count, 0)]);

	f2dfs_info(
		sbi,
		"| # of full-zero blocks:    %10u >>> %4u %2s.     "
		"  |",
		zero_blocks_count,
		f2dfs_dedupe_calculation((unsigned long)zero_blocks_count, 0,
					 0),
		units[f2dfs_dedupe_unit((unsigned long)zero_blocks_count, 0)]);

	if (dedupe_high > 0)
		f2dfs_info(
			sbi,
			"| # of deduplicated blocks: %10u.%02uE10 >>> "
			"%4u %2s.  |",
			dedupe_high, (dedupe_low / 100000000),
			f2dfs_dedupe_calculation((unsigned long)0, dedupe_high,
						 dedupe_low),
			units[f2dfs_dedupe_unit((unsigned long)0, dedupe_high)]);
	else
		f2dfs_info(
			sbi,
			"| # of deduplicated blocks: %10u >>> %4u %2s."
			"       |",
			dedupe_low,
			f2dfs_dedupe_calculation((unsigned long)dedupe_low, 0,
						 0),
			units[f2dfs_dedupe_unit((unsigned long)dedupe_low, 0)]);

	f2dfs_info(sbi,
		   "| # of unrefer blocks:      %10u >>> %4u %2s.     "
		   "  |",
		   unrefer_blocks_count,
		   f2dfs_dedupe_calculation((unsigned long)unrefer_blocks_count,
					    0, 0),
		   units[f2dfs_dedupe_unit((unsigned long)unrefer_blocks_count,
					   0)]);

	f2dfs_info(sbi, "|-----------------------------"
			"----------------------------|");

	if (dedupe_high > 0)
		f2dfs_info(
			sbi,
			"| # of logical blocks:     %4u %2s for all "
			"files & dirs.  |",
			f2dfs_dedupe_calculation(
				(unsigned long)data_blocks_count, dedupe_high,
				dedupe_low),
			units[f2dfs_dedupe_unit((unsigned long)data_blocks_count,
						dedupe_high)]);
	else {
		logical_blocks_count =
			(unsigned long)(data_blocks_count + dedupe_low +
					zero_blocks_count);
		if ((data_blocks_count + dedupe_low) < data_blocks_count)
			f2dfs_info(sbi,
				   "| # of logical blocks:     %4u %2s for all "
				   "files & dirs.  |",
				   f2dfs_dedupe_calculation(
					   (unsigned long)data_blocks_count, 1,
					   dedupe_low),
				   units[3]);
		else
			f2dfs_info(sbi,
				   "| # of logical blocks: %8lu %2s for all "
				   "files & dirs.  |",
				   f2dfs_dedupe_calculation(
					   (unsigned long)logical_blocks_count,
					   0, 0),
				   units[f2dfs_dedupe_unit(
					   (unsigned long)logical_blocks_count,
					   0)]);
	}

	f2dfs_info(
		sbi,
		"| # of physical blocks:    %4u %2s after "
		"deduplication.   |",
		f2dfs_dedupe_calculation((unsigned long)data_blocks_count, 0,
					 0),
		units[f2dfs_dedupe_unit((unsigned long)data_blocks_count, 0)]);

	f2dfs_info(sbi,
		   "| # of recorded blocks:    %4u %2s wait to be "
		   "released.   |",
		   f2dfs_dedupe_calculation((unsigned long)unrefer_blocks_count,
					    0, 0),
		   units[f2dfs_dedupe_unit((unsigned long)unrefer_blocks_count,
					   0)]);

	if (((data_blocks_count + dedupe_low) < data_blocks_count) &&
	    (dedupe_high > 0)) {
		f2dfs_info(sbi, "|               F2DFS contributes too much."
				"               |");
		f2dfs_info(sbi, "| Space utilization and deduplication ratio "
				"are ignored.  |");
	} else {
		data_blocks_count =
			max((unsigned int)data_blocks_count, (unsigned int)1);
		logical_blocks_count =
			max((unsigned long)(data_blocks_count + dedupe_low +
					    zero_blocks_count),
			    (unsigned long)1);
		f2dfs_info(sbi,
			   "| Space reusage:%8lu.%02lux.  &&  Dedupe "
			   "percent: %3lu%%.  |",
			   ((unsigned long)(logical_blocks_count /
					    data_blocks_count)),
			   ((unsigned long)((logical_blocks_count %
					     data_blocks_count) *
					    100) /
			    data_blocks_count),
			   ((unsigned long)(dedupe_low * 100) /
			    logical_blocks_count));
	}

	f2dfs_info(sbi, "\\-----------------------------"
			"----------------------------/");
	f2dfs_info(sbi, "fp_start_blkaddr: %u", sbi->dm_info->fp_blkaddr);
	f2dfs_info(sbi, "rc_base_blkaddr: %u", sbi->dm_info->rc_base_blkaddr);
	f2dfs_info(sbi, "rc_delta_blkaddr: %u", sbi->dm_info->rc_delta_blkaddr);
}

int f2dfs_insert_refcount(struct f2fs_sb_info *sbi, struct fp_rc_info *insert,
			  struct f2dfs_global_counter *g_counter);
int f2dfs_change_reference_count_inline(struct f2fs_sb_info *sbi,
					virtual_t vaddr, int rc_change,
					struct f2dfs_global_counter *g_counter);
int f2dfs_read_meta_page(struct f2fs_sb_info *sbi, void *dst, block_t blkaddr);
int f2dfs_write_meta_page_direct(struct f2fs_sb_info *sbi, void *src,
				 block_t blkaddr);
int f2dfs_write_meta_page(struct f2fs_sb_info *sbi, void *src, block_t blkaddr);
int f2dfs_read_meta_page_direct(struct f2fs_sb_info *sbi, void *dst,
				block_t blkaddr);
int f2dfs_load_dm_bitmap(struct f2fs_sb_info *sbi, bool power_on, bool load_fp,
			 bool load_rcb, bool load_rcd);
int f2dfs_store_dm_bitmap(struct f2fs_sb_info *sbi, bool store_fp,
			  bool store_rcb, bool store_rcd);
void f2dfs_init_deduplication(struct f2fs_sb_info *sbi);
void f2dfs_exit_deduplication(struct f2fs_sb_info *sbi);
void f2dfs_destroy_dedup_manager(struct f2fs_sb_info *sbi);
int f2dfs_build_dedup_manager(struct f2fs_sb_info *sbi);
int f2dfs_insert_fingerprint_into_buffer(struct f2fs_sb_info *sbi,
					 struct fp_rc_info *insert);
int f2dfs_search_fingerprint(struct f2fs_sb_info *sbi,
			     struct fp_rc_info *search);
int f2dfs_merge_rc_delta_to_base(struct f2fs_sb_info *sbi, bool exit);
void f2dfs_enqueue_single_fp_hash_work(struct f2fs_sb_info *sbi, int job_no,
				       struct page *page);
int f2dfs_calculate_refcount(struct f2fs_sb_info *sbi, virtual_t vaddr);
int f2dfs_invalid_fp_entry(struct f2fs_sb_info *sbi, virtual_t vaddr,
			   block_t fp_page_addr, struct node_info ni);
int delete_fp_in_disk_protected(struct f2fs_sb_info *sbi, virtual_t vaddr,
				bool delete);
inline int f2dfs_send_nvme_admin_command(struct f2fs_sb_info *sbi, __u8 opcode,
					 __u32 cdw10);
int search_in_fp_hash_table(struct f2fs_sb_info *sbi, char *fingerprint,
			    virtual_t *vaddr);
int delete_in_fp_hash_table(struct f2fs_sb_info *sbi, virtual_t vaddr,
			    bool delete);
int insert_in_fp_hash_table(struct f2fs_sb_info *sbi, char *fingerprint,
			    virtual_t vaddr);
block_t f2dfs_find_free_block(struct f2fs_sb_info *sbi, block_t start_blk,
			      block_t blks_num, char *bitmap);
inline bool f2dfs_is_block_set(block_t start_blk, block_t blkaddr,
			       char *bitmap);
inline void copy_raw_bucket_to_bucket(
	struct f2fs_sb_info *sbi, struct f2dfs_fp_bucket *bucket,
	struct f2dfs_fp_bucket_in_disk *raw_bucket, block_t raw_blkaddr);
int f2dfs_insert_buffer_into_bucket(struct f2fs_sb_info *sbi,
				    bool alloc_new_buffer);
inline void f2dfs_free_block(block_t start_blk, block_t blkaddr, char *bitmap);
int f2dfs_insert_rcb_buffer_into_storage(struct f2fs_sb_info *sbi);
int f2dfs_insert_bucket_into_storage(struct f2fs_sb_info *sbi, int write_count);
int f2dfs_insert_rc_delta_buffer_into_storage(struct f2fs_sb_info *sbi);

void f2dfs_outplace_write_data(struct dnode_of_data *dn,
			       struct f2fs_io_info *fio,
			       struct f2dfs_global_counter *g_counter);
void f2dfs_wait_on_virtual_block_writeback_range(struct inode *inode,
						 virtual_t vaddr, block_t len);
void f2fs_outplace_write_data(struct dnode_of_data *dn,
			      struct f2fs_io_info *fio,
			      struct f2dfs_global_counter *g_counter);
int delete_fp_in_buckets(struct f2fs_sb_info *sbi, virtual_t vaddr,
			 block_t fp_page_addr, bool delete);
int delete_fp_in_buffer(struct f2fs_sb_info *sbi, virtual_t vaddr,
			block_t fp_page_addr, bool delete);
void do_write_page(struct f2fs_summary *sum, struct f2fs_io_info *fio);

int f2fs_do_write_data_page(struct f2fs_io_info *fio,
			    struct f2dfs_global_counter *g_counter);
int f2dfs_do_write_data_page(struct f2fs_io_info *fio,
			     struct f2dfs_global_counter *g_counter,
			     __u8 page_fingerprint[]);
int f2fs_write_single_data_page(struct page *page, int *submitted,
				struct bio **bio, sector_t *last_block,
				struct writeback_control *wbc,
				enum iostat_type io_type, int compr_blocks,
				bool allow_balance,
				struct f2dfs_global_counter *g_counter,
				__u8 page_fingerprint[],
				bool should_alloc_vaddr);

inline void release_block(struct f2fs_sb_info *sbi, virtual_t vaddr,
			  block_t fp_addr);
void f2dfs_ra_gc_page(struct f2fs_sb_info *sbi, virtual_t vaddr);