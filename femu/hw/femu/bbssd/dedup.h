#ifndef __DEDUP_H
#define __DEDUP_H

#include "../nvme.h"

#ifndef __packed
#define __packed __attribute__((__packed__))
#endif
#ifndef __static_assert
#define __static_assert(expr, msg, ...) _Static_assert(expr, msg)
#endif

#define DEDUP_COMPRESSION_ENABLED
#define ACCESS_TIME_INIT      0
#define COMPRESS_PAGE_MAX_NUM 4

typedef __u32 virtual_t;
typedef __u32 block_t;
#define PAGE_SIZE 4096
#define NULL_ADDR ((block_t)0)
#define NEW_ADDR  ((block_t) - 1)

#define EXPANSION_FACTOR	   1.25
#define COLD_PAGE_THRESHOLD_NS_MIN (1ULL * 1000 * 1000 * 1000)
#define COLD_PAGE_THRESHOLD_NS_MAX (60ULL * 1000 * 1000 * 1000)
#define COLD_PAGE_THRESHOLD_STEP   (1ULL * 1000 * 1000 * 1000)

#define FEMU_DEBUG_BASIC_INFO 0

#define COMPRESS_LATENCY   9090
#define DECOMPRESS_LATENCY 3846

#define FP_META_BLKADDR	 (29184)
#define FP_META_BLKS	 (512)
#define FP_BLKADDR	 (29696)
#define FP_BLKS		 (41472)
#define RC_BASE_BLKADDR	 (71168)
#define RC_BASE_BLKS	 (41472)
#define RC_DELTA_BLKADDR (112640)
#define RC_DELTA_BLKS	 (8192)
#define MAIN_BLKADDR	 (120832)
#define MAIN_BLKS	 (4072960)

__static_assert(FP_META_BLKADDR + FP_META_BLKS == FP_BLKADDR,
		"FP_META_BLKADDR + FP_META_BLKS != FP_BLKADDR");
__static_assert(FP_BLKADDR + FP_BLKS == RC_BASE_BLKADDR,
		"FP_BLKADDR + FP_BLKS != RC_BASE_BLKADDR");
__static_assert(RC_BASE_BLKADDR + RC_BASE_BLKS == RC_DELTA_BLKADDR,
		"RC_BASE_BLKADDR + RC_BASE_BLKS != RC_DELTA_BLKADDR");
__static_assert(RC_DELTA_BLKADDR + RC_DELTA_BLKS == MAIN_BLKADDR,
		"RC_DELTA_BLKADDR + RC_DELTA_BLKS != MAIN_BLKADDR");

#define FP_BITMAP_SIZE		 (DIV_ROUND_UP(41472, 8))
#define RC_BASE_BITMAP_SIZE	 (DIV_ROUND_UP(41472, 8))
#define RC_DELTA_BITMAP_SIZE	 (DIV_ROUND_UP(8192, 8))
#define FP_BITMAP_PAGESIZE	 (DIV_ROUND_UP(FP_BITMAP_SIZE, PAGE_SIZE))
#define RC_BASE_BITMAP_PAGESIZE	 (DIV_ROUND_UP(RC_BASE_BITMAP_SIZE, PAGE_SIZE))
#define RC_DELTA_BITMAP_PAGESIZE (DIV_ROUND_UP(RC_DELTA_BITMAP_SIZE, PAGE_SIZE))

#define FP_ENTRIES_PER_PAGE	    (PAGE_SIZE / sizeof(struct fp_entry))
#define FP_LEN_MAX		    32
#define FP_ENTRIES_INVALID_MAP_SIZE (DIV_ROUND_UP(FP_ENTRIES_PER_PAGE, 8))

struct fp_entry {
	__u8 fingerprint[FP_LEN_MAX];
	virtual_t vaddr;
} __packed;

struct f2dfs_fp_bucket_in_disk {
	struct fp_entry entries[FP_ENTRIES_PER_PAGE];
	__u8 valid_count;
	__u8 invalidmap[FP_ENTRIES_INVALID_MAP_SIZE];
	__le32 magic;
	__u8 reserved[PAGE_SIZE - sizeof(struct fp_entry) * FP_ENTRIES_PER_PAGE -
		      sizeof(__u8) * (FP_ENTRIES_INVALID_MAP_SIZE + 1) -
		      sizeof(__le32)];
} __packed;

#define TRACE_REPLAY
#ifdef TRACE_REPLAY
typedef int rc_t;
#else
typedef char rc_t;
#endif

struct rc_base_entry {
	virtual_t vaddr;
	rc_t rc;
	virtual_t fp_page_addr;
} __packed;

struct rc_delta_entry {
	virtual_t vaddr;
	rc_t rc;
} __packed;

#define RC_BASE_ENTRIES_PER_PAGE                                               \
	(((PAGE_SIZE) / (sizeof(struct rc_base_entry))) - 1)
#define RC_DELTA_ENTRIES_PER_PAGE                                              \
	(((PAGE_SIZE) / (sizeof(struct rc_delta_entry))) - 1)

struct f2dfs_rc_base_buffer {
	struct rc_base_entry entries[RC_BASE_ENTRIES_PER_PAGE];
	__u16 valid_count;
	__u8 reserved[PAGE_SIZE -
		      sizeof(struct rc_base_entry) * RC_BASE_ENTRIES_PER_PAGE -
		      sizeof(__u16)];
} __packed;

__static_assert(sizeof(struct f2dfs_rc_base_buffer) == PAGE_SIZE,
		"f2dfs_rc_base_buffer size mismatch");

struct f2dfs_rc_delta_buffer {
	struct rc_delta_entry entries[RC_DELTA_ENTRIES_PER_PAGE];
	__u16 valid_count;
	__u8 reserved[PAGE_SIZE -
		      sizeof(struct rc_delta_entry) * RC_DELTA_ENTRIES_PER_PAGE -
		      sizeof(__u16)];
} __packed;

__static_assert(sizeof(struct f2dfs_rc_delta_buffer) == PAGE_SIZE,
		"f2dfs_rc_delta_buffer size mismatch");

struct f2dfs_bitmap_disk {
	__u8 bitmap[PAGE_SIZE - sizeof(__le32)];
	__le32 unfull_blkaddr;
} __packed;

__static_assert(sizeof(struct f2dfs_bitmap_disk) == PAGE_SIZE,
		"f2dfs_bitmap_disk size mismatch");

#define COMPRESS_PAGE_SIZE	  (PAGE_SIZE - sizeof(struct compress_footer))
#define PAGE_NUM_IN_COMPRESS_PAGE (4)

#define is_invalid_compress_index(index)                                       \
	((index) < 0 || (index) >= PAGE_NUM_IN_COMPRESS_PAGE)
#define COMPRESS_PAGE_INDEX_INVALID (-1)

struct compress_page_index {
	block_t lpn;
	char index;
} __packed;

struct compress_footer {
	struct compress_page_index index[PAGE_NUM_IN_COMPRESS_PAGE];
} __packed;

struct compress_page {
	char data[PAGE_NUM_IN_COMPRESS_PAGE]
		 [(COMPRESS_PAGE_SIZE) / PAGE_NUM_IN_COMPRESS_PAGE];
	struct compress_footer footer;
} __packed;

struct f2dfs_dm_info {
	block_t fp_bitmap_blkaddr;
	block_t rc_base_bitmap_blkaddr;
	block_t rc_delta_bitmap_blkaddr;

	block_t rc_base_blkaddr;
	block_t rc_base_blks;
	block_t rc_delta_blkaddr;
	block_t rc_delta_blks;

	char *rc_base_bitmap;
	char *rc_delta_bitmap;

	bool enable_dedup_merge;

	QemuThread merge_thread;
	QemuMutex merge_mutex;
	QemuCond merge_cond;
	bool merge_thread_running;
	bool merge_thread_stop;
	bool trigger_rc_delta_merge;

	bool enable_compress;
	QemuThread compress_thread;
	bool compress_thread_running;
	bool compress_thread_stop;
	bool trigger_compress;
};

enum bitmap_type {
	FP_BITMAP,
	RC_BASE_BITMAP,
	RC_DELTA_BITMAP,
};

void bb_read_data_print(FemuCtrl *n, uint64_t f2fs_blkaddr, size_t size);
void init_dm_info(FemuCtrl *n);
void stop_merge_thread(FemuCtrl *n);
void enable_dedup_merge(FemuCtrl *n, bool enable);
void trigger_rc_delta_merge(FemuCtrl *n);
bool is_dedup_merge_enabled(FemuCtrl *n);
void cleanup_dm_info(FemuCtrl *n);
block_t f2dfs_find_free_block(block_t start_blk, block_t blks_num,
			      char *bitmap);
void f2dfs_set_block(block_t start_blk, block_t blkaddr, char *bitmap);
void f2dfs_free_block(block_t start_blk, block_t blkaddr, char *bitmap);

void enable_compression(FemuCtrl *n, bool enable);
void stop_compress_thread(FemuCtrl *n);
int init_compress_thread(FemuCtrl *n);
void trigger_compression(FemuCtrl *n);
void print_stacktrace(void);

#ifdef DEDUP_COMPRESSION_ENABLED

struct nand_cmd;
struct ppa get_new_page(struct ssd *ssd, bool is_compressed,
			uint64_t access_time);
uint64_t ssd_advance_status(struct ssd *ssd, struct ppa *ppa,
			    struct nand_cmd *ncmd);
void mark_page_valid(struct ssd *ssd, struct ppa *ppa);
void mark_page_invalid(struct ssd *ssd, struct ppa *ppa);
void ssd_advance_write_pointer(struct ssd *ssd, bool is_compress);
#endif
#endif