#include <asm/string_64.h>
#include <linux/spinlock.h>
#include <linux/rwsem.h>
#include <linux/f2fs_fs.h>
#include <linux/nvme_ioctl.h>
#include <linux/bitops.h>
#include <linux/sort.h>
#include <linux/bsearch.h>
#include <asm/unaligned.h>

#include "f2fs.h"
#include "fingerprint.h"
#include "node.h"

struct f2dfs_basic_hash_info sha256_info = {
	.name	     = "sha256",
	.simple_name = "SHA-2",
	.full_name   = "Secure Hash Algorithm",
	.len	     = FP_LEN_MAX,
	.zero_prefix = 0xad7f,
	.zero_result = "\xad\x7f\xac\xb2"
		       "\x58\x6f\xc6\xe9"
		       "\x66\xc0\x04\xd7"
		       "\xd1\xd1\x6b\x02"
		       "\x4f\x58\x05\xff"
		       "\x7c\xb4\x7c\x7a"
		       "\x85\xda\xbd\x8b"
		       "\x48\x89\x2c\xa7",
	.null_result = "\x00\x00\x00\x00"
		       "\x00\x00\x00\x00"
		       "\x00\x00\x00\x00"
		       "\x00\x00\x00\x00"
		       "\x00\x00\x00\x00"
		       "\x00\x00\x00\x00"
		       "\x00\x00\x00\x00"
		       "\x00\x00\x00\x00",
	.fp_update   = crypto_shash_update,
};

static inline struct sdesc *init_sdesc(struct crypto_shash *alg)
{
	struct sdesc *sdesc;
	int size;

	size  = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
	sdesc = kmalloc(size, GFP_KERNEL);

	if (!sdesc)
		return ERR_PTR(-ENOMEM);

	sdesc->shash.tfm = alg;
	return sdesc;
}

static void f2dfs_init_fp_buckets_buffer(struct f2fs_sb_info *sbi)
{
	struct f2dfs_fp_bucket_in_disk *raw_buffer = NULL;
	int i;

	sbi->s_fp_bucket = f2fs_kvmalloc(
		sbi, sizeof(struct f2dfs_fp_bucket_list), GFP_NOFS);
	if (!sbi->s_fp_bucket) {
		print_err("Failed to allocate fingerprint bucket list");
		return;
	}

	sbi->s_fp_bucket->bucket_cache =
		kmem_cache_create("f2dfs_fp_buckets_cache",
				  sizeof(struct f2dfs_fp_bucket), 0, 0, NULL);
	if (!sbi->s_fp_bucket->bucket_cache) {
		kvfree(sbi->s_fp_bucket);
		sbi->s_fp_bucket = NULL;
		print_err("Failed to create fingerprint bucket cache");
		return;
	}

	sbi->s_fp_bucket->current_number = 0;

	for (i = 0; i < FP_BUCKET_MAX_NUM; i++) {
		sbi->s_fp_bucket->pointers[i] = NULL;
	}

	init_rwsem(&sbi->s_fp_bucket_lock);

	sbi->fp_buffer =
		kmem_cache_alloc(sbi->s_fp_bucket->bucket_cache, GFP_KERNEL);
	if (!sbi->fp_buffer) {
		kmem_cache_destroy(sbi->s_fp_bucket->bucket_cache);
		kvfree(sbi->s_fp_bucket);
		sbi->s_fp_bucket = NULL;
		print_err("Failed to allocate fp_buffer");
		return;
	}
	memset(sbi->fp_buffer, 0, sizeof(struct f2dfs_fp_bucket));
	init_rwsem(&sbi->fp_buffer_lock);

	if (sbi->dm_info->unfull_fp_blkaddr != NULL_ADDR) {
		f2fs_bug_on(sbi,
			    !f2dfs_is_block_set(sbi->dm_info->fp_blkaddr,
						sbi->dm_info->unfull_fp_blkaddr,
						sbi->dm_info->fp_bitmap));
		raw_buffer = kmalloc(sizeof(struct f2dfs_fp_bucket_in_disk),
				     GFP_KERNEL);
		if (!raw_buffer) {
			print_err("Failed to allocate raw buffer");
			goto fail_alloc;
		}
		if (f2dfs_read_meta_page(sbi, raw_buffer,
					 sbi->dm_info->unfull_fp_blkaddr) < 0) {
			print_err("bug here");
			kvfree(raw_buffer);
		} else {
			copy_raw_bucket_to_bucket(
				sbi, sbi->fp_buffer, raw_buffer,
				sbi->dm_info->unfull_fp_blkaddr);
			kvfree(raw_buffer);
			print_info(PRINT_IMPORTANT_INFO_ENABLED,
				   "fp use last unfull page, valid_count: %u",
				   sbi->fp_buffer->valid_count);
			return;
		}
		kvfree(raw_buffer);
		sbi->dm_info->unfull_fp_blkaddr = NULL_ADDR;
	}

fail_alloc:
	sbi->fp_buffer->blkaddr =
		f2dfs_find_free_block(sbi, sbi->dm_info->fp_blkaddr,
				      sbi->dm_info->fp_blks,
				      sbi->dm_info->fp_bitmap);
	if (sbi->fp_buffer->blkaddr == NULL_ADDR) {
		kmem_cache_free(sbi->s_fp_bucket->bucket_cache, sbi->fp_buffer);
		kmem_cache_destroy(sbi->s_fp_bucket->bucket_cache);
		kvfree(sbi->s_fp_bucket);
		sbi->s_fp_bucket = NULL;
		sbi->fp_buffer	 = NULL;
		print_err("No free block for fp_buffer");
		return;
	}
}

static void f2dfs_init_fingerprint_hash(struct f2fs_sb_info *sbi)
{
	int i;

	sbi->s_fp_hash = f2fs_kvmalloc(
		sbi, sizeof(struct f2dfs_fingerprint_hash), GFP_NOFS);
	if (!sbi->s_fp_hash) {
		print_err("Failed to allocate fingerprint hash struct");
		return;
	}
	memset(sbi->s_fp_hash, 0, sizeof(struct f2dfs_fingerprint_hash));

	sbi->s_fp_hash->basic_hash_info = &sha256_info;

	sbi->s_fp_hash->basic_hash_info->alg =
		crypto_alloc_shash(sbi->s_fp_hash->basic_hash_info->name, 0, 0);
	if (IS_ERR(sbi->s_fp_hash->basic_hash_info->alg)) {
		print_err("Failed to alloc shash: %s",
			  sbi->s_fp_hash->basic_hash_info->name);
		kvfree(sbi->s_fp_hash);
		sbi->s_fp_hash = NULL;
		return;
	}

	sbi->s_fp_hash->hash_jobs = f2fs_kvmalloc(
		sbi,
		(sizeof(struct f2dfs_single_hash_job) * F2DFS_HASH_JOBS_NUMBER),
		GFP_NOFS);
	if (!sbi->s_fp_hash->hash_jobs) {
		print_err("Failed to allocate hash_jobs");
		crypto_free_shash(sbi->s_fp_hash->basic_hash_info->alg);
		kvfree(sbi->s_fp_hash);
		sbi->s_fp_hash = NULL;
		return;
	}

	sbi->s_fp_hash->parallel_hash_workqueue =
		alloc_workqueue("f2dfs_fingerprint_hash_wq",
				WQ_UNBOUND | WQ_HIGHPRI, num_online_cpus());
	if (!sbi->s_fp_hash->parallel_hash_workqueue) {
		print_err("Failed to allocate workqueue");
		kvfree(sbi->s_fp_hash->hash_jobs);
		crypto_free_shash(sbi->s_fp_hash->basic_hash_info->alg);
		kvfree(sbi->s_fp_hash);
		sbi->s_fp_hash = NULL;
		return;
	}

	for (i = 0; i < F2DFS_HASH_JOBS_NUMBER; i++)
		mutex_init(&sbi->s_fp_hash->hash_jobs[i].work_mutex);
}

static void f2dfs_init_rc_buffer(struct f2fs_sb_info *sbi)
{
	struct f2dfs_rc_base_buffer *tmp_base	= NULL;
	struct f2dfs_rc_delta_buffer *tmp_delta = NULL;

	sbi->rcb_buffer = f2fs_kvmalloc(
		sbi, sizeof(struct f2dfs_rc_base_buffer), GFP_NOFS);
	if (!sbi->rcb_buffer) {
		print_err("Failed to allocate rc base buffer");
		return;
	}
	memset(sbi->rcb_buffer, 0, sizeof(struct f2dfs_rc_base_buffer));

	spin_lock_init(&sbi->rcb_buffer_lock);

	sbi->rcd_buffer = f2fs_kvmalloc(
		sbi, sizeof(struct f2dfs_rc_delta_buffer), GFP_NOFS);
	if (!sbi->rcd_buffer) {
		print_err("Failed to allocate rc delta buffer");
		kvfree(sbi->rcb_buffer);
		sbi->rcb_buffer = NULL;
		return;
	}
	memset(sbi->rcd_buffer, 0, sizeof(struct f2dfs_rc_delta_buffer));

	spin_lock_init(&sbi->rcd_buffer_lock);

	if (sbi->dm_info->unfull_rc_base_blkaddr != NULL_ADDR) {
		f2fs_bug_on(sbi, !f2dfs_is_block_set(
					 sbi->dm_info->rc_base_blkaddr,
					 sbi->dm_info->unfull_rc_base_blkaddr,
					 sbi->dm_info->rc_base_bitmap));
		tmp_base = kmalloc(sizeof(struct f2dfs_rc_base_buffer),
				   GFP_KERNEL);
		if (!tmp_base) {
			print_err("Failed to allocate temp rc base buffer");
			goto skip_base;
		}
		if (f2dfs_read_meta_page_direct(
			    sbi, tmp_base,
			    sbi->dm_info->unfull_rc_base_blkaddr) == 0) {
			if (tmp_base->valid_count <
			    RC_BASE_ENTRIES_PER_PAGE_MAX) {
				memcpy(sbi->rcb_buffer->entries,
				       tmp_base->entries,
				       tmp_base->valid_count *
					       sizeof(struct rc_base_entry));
				sbi->rcb_buffer->valid_count =
					tmp_base->valid_count;

				f2dfs_free_block(
					sbi->dm_info->rc_base_blkaddr,
					sbi->dm_info->unfull_rc_base_blkaddr,
					sbi->dm_info->rc_base_bitmap);
				print_info(
					PRINT_IMPORTANT_INFO_ENABLED,
					"rc base buffer use last unfull page, valid_count: %u",
					sbi->rcb_buffer->valid_count);
			} else {
				print_err(
					"init rc base buffer is full, valid_count: %u",
					tmp_base->valid_count);
			}
		}
		kvfree(tmp_base);
		sbi->dm_info->unfull_rc_base_blkaddr = NULL_ADDR;
		f2dfs_store_dm_bitmap(sbi, false, true, false);
	}
skip_base:

	if (sbi->dm_info->unfull_rc_delta_blkaddr != NULL_ADDR) {
		f2fs_bug_on(sbi, !f2dfs_is_block_set(
					 sbi->dm_info->rc_delta_blkaddr,
					 sbi->dm_info->unfull_rc_delta_blkaddr,
					 sbi->dm_info->rc_delta_bitmap));
		tmp_delta = kmalloc(sizeof(struct f2dfs_rc_delta_buffer),
				    GFP_KERNEL);
		if (!tmp_delta) {
			print_err("Failed to allocate temp rc delta buffer");
			return;
		}
		if (f2dfs_read_meta_page_direct(
			    sbi, tmp_delta,
			    sbi->dm_info->unfull_rc_delta_blkaddr) == 0) {
			if (tmp_delta->valid_count <
			    RC_DELTA_ENTRIES_PER_PAGE) {
				memcpy(sbi->rcd_buffer->entries,
				       tmp_delta->entries,
				       tmp_delta->valid_count *
					       sizeof(struct rc_delta_entry));
				sbi->rcd_buffer->valid_count =
					tmp_delta->valid_count;

				f2dfs_free_block(
					sbi->dm_info->rc_delta_blkaddr,
					sbi->dm_info->unfull_rc_delta_blkaddr,
					sbi->dm_info->rc_delta_bitmap);
				print_info(
					PRINT_IMPORTANT_INFO_ENABLED,
					"rc delta buffer use last unfull page, valid_count: %u",
					sbi->rcd_buffer->valid_count);
			} else {
				print_err(
					"init rc delta buffer is full, valid_count: %u",
					tmp_delta->valid_count);
			}
		}
		kvfree(tmp_delta);
		sbi->dm_info->unfull_rc_delta_blkaddr = NULL_ADDR;
		f2dfs_store_dm_bitmap(sbi, false, false, true);
	}
}

void f2dfs_init_deduplication(struct f2fs_sb_info *sbi)
{
	f2dfs_init_fingerprint_hash(sbi);
	if (!sbi->s_fp_hash) {
		print_err("Failed to initialize fingerprint hash algorithm");
		return;
	}

	f2dfs_init_fp_buckets_buffer(sbi);
	if (!sbi->s_fp_bucket) {
		print_err(
			"Failed to initialize fingerprint buckets and buffer");
		return;
	}

	f2dfs_init_rc_buffer(sbi);
	if (!sbi->rcb_buffer || !sbi->rcd_buffer) {
		print_err(
			"Failed to initialize refcount base and delta buffers");
		if (sbi->rcb_buffer) {
			kvfree(sbi->rcb_buffer);
			sbi->rcb_buffer = NULL;
		}
		if (sbi->rcd_buffer) {
			kvfree(sbi->rcd_buffer);
			sbi->rcd_buffer = NULL;
		}
		return;
	}
}

static void f2dfs_exit_buckets_buffer(struct f2fs_sb_info *sbi)
{
	int err;

	down_write(&sbi->fp_buffer_lock);
	down_write(&sbi->s_fp_bucket_lock);

	err = f2dfs_insert_buffer_into_bucket(sbi, false);
	if (err == -FP_BUFFER_INTO_BUCKET_FAILURE) {
		print_err("Failed to insert fingerprint buffer into bucket");
	}
	print_info(PRINT_BASIC_INFO_ENABLED,
		   "fp buffer written into bucket success");

	err = f2dfs_insert_bucket_into_storage(
		sbi, sbi->s_fp_bucket->current_number);
	if (err == -FP_BUCKET_INTO_STORAGE_FAILURE) {
		print_err("Failed to insert fingerprint bucket into storage");
	}
	print_info(PRINT_BASIC_INFO_ENABLED,
		   "fp buckets written into storage success");

	if (sbi->fp_buffer && sbi->s_fp_bucket->bucket_cache) {
		print_err(
			"Unexpected fp_buffer state during cleanup - should be NULL");
		kmem_cache_free(sbi->s_fp_bucket->bucket_cache, sbi->fp_buffer);
		sbi->fp_buffer = NULL;
	}
	if (sbi->s_fp_bucket) {
		if (sbi->s_fp_bucket->bucket_cache)
			kmem_cache_destroy(sbi->s_fp_bucket->bucket_cache);
	}

	if (sbi->s_fp_bucket) {
		kvfree(sbi->s_fp_bucket);
		sbi->s_fp_bucket = NULL;
	}

	up_write(&sbi->s_fp_bucket_lock);
	up_write(&sbi->fp_buffer_lock);

	print_info(PRINT_BASIC_INFO_ENABLED,
		   "fp buckets and buffer cleaned up");

	spin_lock(&sbi->rcb_buffer_lock);
	spin_lock(&sbi->dm_info->rc_base_lock);
	err = f2dfs_insert_rcb_buffer_into_storage(sbi);
	spin_unlock(&sbi->dm_info->rc_base_lock);
	if (err == -RC_BUFFER_INTO_STORAGE_FAILURE) {
		print_err(
			"Failed to insert fingerprint base buffer into storage");
	}
	if (sbi->rcb_buffer) {
		kvfree(sbi->rcb_buffer);
		sbi->rcb_buffer = NULL;
	}
	spin_unlock(&sbi->rcb_buffer_lock);
	print_info(PRINT_BASIC_INFO_ENABLED,
		   "rc base buffer written into storage success");

	spin_lock(&sbi->rcd_buffer_lock);
	err = f2dfs_insert_rc_delta_buffer_into_storage(sbi);
	if (err == -RC_BUFFER_INTO_STORAGE_FAILURE) {
		print_err(
			"Failed to insert fingerprint delta buffer into storage");
	}
	if (sbi->rcd_buffer) {
		kvfree(sbi->rcd_buffer);
		sbi->rcd_buffer = NULL;
	}
	spin_unlock(&sbi->rcd_buffer_lock);
	print_info(PRINT_BASIC_INFO_ENABLED,
		   "rc delta buffer written into storage success");
}

static void f2dfs_exit_fingerprint_hash(struct f2fs_sb_info *sbi)
{
	int i;

	if (!sbi || !sbi->s_fp_hash) {
		print_err("sbi or s_fp_hash is NULL");
		return;
	}

	if (sbi->s_fp_hash->parallel_hash_workqueue)
		flush_workqueue(sbi->s_fp_hash->parallel_hash_workqueue);

	if (sbi->s_fp_hash->parallel_hash_workqueue)
		destroy_workqueue(sbi->s_fp_hash->parallel_hash_workqueue);

	if (sbi->s_fp_hash->hash_jobs) {
		for (i = 0; i < F2DFS_HASH_JOBS_NUMBER; i++) {
			mutex_lock(&sbi->s_fp_hash->hash_jobs[i].work_mutex);
			mutex_unlock(&sbi->s_fp_hash->hash_jobs[i].work_mutex);
		}
		kvfree(sbi->s_fp_hash->hash_jobs);
		sbi->s_fp_hash->hash_jobs = NULL;
	}

	if (sbi->s_fp_hash->basic_hash_info &&
	    sbi->s_fp_hash->basic_hash_info->alg)
		crypto_free_shash(sbi->s_fp_hash->basic_hash_info->alg);

	kvfree(sbi->s_fp_hash);
	sbi->s_fp_hash = NULL;
}

void f2dfs_exit_deduplication(struct f2fs_sb_info *sbi)
{
	f2dfs_exit_buckets_buffer(sbi);
	f2dfs_exit_fingerprint_hash(sbi);
}

void f2dfs_destroy_dedup_manager(struct f2fs_sb_info *sbi)
{
	int err;

	if (!sbi || !sbi->dm_info) {
		print_err("pointer is null, sbi:%p, dm_info: %p\n", sbi,
			  sbi ? sbi->dm_info : NULL);
		return;
	}

	spin_lock(&sbi->dm_info->fp_lock);
	spin_lock(&sbi->dm_info->rc_base_lock);
	spin_lock(&sbi->dm_info->rc_delta_lock);
	err = f2dfs_store_dm_bitmap(sbi, true, true, true);
	spin_unlock(&sbi->dm_info->rc_delta_lock);
	spin_unlock(&sbi->dm_info->rc_base_lock);
	spin_unlock(&sbi->dm_info->fp_lock);
	if (err) {
		print_err("Failed to store dm bitmap");
	}

	if (sbi->dm_info->fp_bitmap)
		kvfree(sbi->dm_info->fp_bitmap);

	if (sbi->dm_info->rc_base_bitmap)
		kvfree(sbi->dm_info->rc_base_bitmap);

	if (sbi->dm_info->rc_delta_bitmap)
		kvfree(sbi->dm_info->rc_delta_bitmap);

	kvfree(sbi->dm_info);
	sbi->dm_info = NULL;
}

static inline int compute_fingerprint(struct f2fs_sb_info *sbi,
				      __u8 fingerprint[], struct page *page,
				      int page_len, struct sdesc *sdesc)
{
	crypto_shash_init(&sdesc->shash);
	sbi->s_fp_hash->basic_hash_info->fp_update(
		&sdesc->shash, page_address(page), page_len);
	crypto_shash_final(&sdesc->shash, fingerprint);
	return FP_HASH_SUCCESS;
}

static inline int do_fingerprint_of_page(struct f2fs_sb_info *sbi,
					 struct page *page, struct sdesc *sdesc,
					 __u8 fingerprint[])
{
	return compute_fingerprint(sbi, fingerprint, page, PAGE_SIZE, sdesc);
}

int f2fs_compute_page_fingerprint(struct f2fs_sb_info *sbi, struct page *page,
				  __u8 fingerprint[])
{
	struct crypto_shash *alg;
	struct sdesc *sdesc;
	int ret;

	if ((!page) || IS_ERR(page)) {
		print_err("page err");
		goto page_err;
	}

	alg = crypto_alloc_shash(sbi->s_fp_hash->basic_hash_info->name, 0, 0);
	if (IS_ERR(alg)) {
		print_err("crypto alg err");
		goto alg_err;
	}

	sdesc = init_sdesc(alg);
	if (IS_ERR(sdesc)) {
		print_err("sdesc err");
		goto sdesc_err;
	}

	ret = do_fingerprint_of_page(sbi, page, sdesc, fingerprint);
	kvfree(sdesc);
	crypto_free_shash(alg);
	return ret;

sdesc_err:
	kvfree(sdesc);
alg_err:
	crypto_free_shash(alg);
page_err:
	memcpy(fingerprint, sbi->s_fp_hash->basic_hash_info->zero_result,
	       FP_LEN_MAX);
	return -FP_HASH_FAILURE;
}

static inline int fp_is_equal(const __u8 *fp1, const __u8 *fp2)
{
#if FP_LEN_MAX == 32
	u64 d0, d1, d2, d3;
	d0 = get_unaligned((const u64 *)(fp1 + 0)) ^
	     get_unaligned((const u64 *)(fp2 + 0));
	if (unlikely(d0))
		return 1;
	d1 = get_unaligned((const u64 *)(fp1 + 8)) ^
	     get_unaligned((const u64 *)(fp2 + 8));
	if (unlikely(d1))
		return 1;
	d2 = get_unaligned((const u64 *)(fp1 + 16)) ^
	     get_unaligned((const u64 *)(fp2 + 16));
	if (unlikely(d2))
		return 1;
	d3 = get_unaligned((const u64 *)(fp1 + 24)) ^
	     get_unaligned((const u64 *)(fp2 + 24));
	return d3 != 0;
#else
	size_t i = 0;

	for (; i + sizeof(u64) <= FP_LEN_MAX; i += sizeof(u64)) {
		u64 d = get_unaligned((const u64 *)(fp1 + i)) ^
			get_unaligned((const u64 *)(fp2 + i));
		if (unlikely(d))
			return 1;
	}

	for (; i < FP_LEN_MAX; i++) {
		if (unlikely(fp1[i] != fp2[i]))
			return 1;
	}
	return 0;
#endif
}

static inline bool is_bucket_empty(struct f2dfs_fp_bucket *bucket)
{
	return bucket->valid_count == 0;
}

static inline bool is_bucket_full(struct f2dfs_fp_bucket *bucket)
{
	return bucket->valid_count >= FP_ENTRIES_PER_PAGE;
}

static inline bool
is_raw_bucket_empty(struct f2dfs_fp_bucket_in_disk *raw_bucket)
{
	return raw_bucket->valid_count == 0;
}

static inline bool
is_raw_buffer_full(struct f2dfs_fp_bucket_in_disk *raw_bucket)
{
	return raw_bucket->valid_count >= FP_ENTRIES_PER_PAGE;
}

static inline bool is_fp_raw_bucket(struct f2dfs_fp_bucket_in_disk *raw_bucket)
{
	return le32_to_cpu(raw_bucket->magic) == FP_BUFFER_MAGIC;
}

static inline bool is_rc_base_full(struct f2dfs_rc_base_buffer *buffer)
{
	return buffer->valid_count >= RC_BASE_ENTRIES_PER_PAGE_MAX;
}

static inline bool is_rc_delta_full(struct f2dfs_rc_delta_buffer *buffer)
{
	return buffer->valid_count >= RC_DELTA_ENTRIES_PER_PAGE_MAX;
}

static inline bool is_buckets_full(struct f2fs_sb_info *sbi)
{
	return sbi->s_fp_bucket->current_number >= FP_BUCKET_MAX_NUM;
}

inline void copy_raw_bucket_to_bucket(
	struct f2fs_sb_info *sbi, struct f2dfs_fp_bucket *bucket,
	struct f2dfs_fp_bucket_in_disk *raw_bucket, block_t raw_blkaddr)
{
	int i, j;
	f2fs_bug_on(sbi, !is_fp_raw_bucket(raw_bucket));
	memset(bucket, 0, sizeof(struct f2dfs_fp_bucket));
	for (i = 0, j = 0; i < FP_ENTRIES_PER_PAGE; ++i) {
		if (!test_bit_le(i, raw_bucket->invalidmap)) {
			memcpy(bucket->entries[j].fingerprint,
			       raw_bucket->entries[i].fingerprint, FP_LEN_MAX);
			bucket->entries[j].vaddr = raw_bucket->entries[i].vaddr;
			j++;
		}
	}
	f2fs_bug_on(sbi, j != raw_bucket->valid_count);
	bucket->valid_count = j;
	bucket->blkaddr	    = raw_blkaddr;
}

static inline void
copy_bucket_to_raw_bucket(struct f2dfs_fp_bucket_in_disk *raw_bucket,
			  struct f2dfs_fp_bucket *bucket, bool not_full)
{
	__u8 invalidmap[FP_ENTRIES_INVALID_MAP_SIZE];
	int i;

	memset(invalidmap, 0, sizeof(invalidmap));
	memset(raw_bucket, 0, sizeof(struct f2dfs_fp_bucket_in_disk));
	memcpy(raw_bucket->entries, bucket->entries,
	       sizeof(raw_bucket->entries));
	raw_bucket->valid_count = bucket->valid_count;
	raw_bucket->magic	= cpu_to_le32(FP_BUFFER_MAGIC);
	if (not_full) {
		for (i = bucket->valid_count; i < FP_ENTRIES_PER_PAGE; ++i) {
			set_bit_le(i, invalidmap);
		}
		memcpy(raw_bucket->invalidmap, invalidmap,
		       sizeof(raw_bucket->invalidmap));
	}
}

static int search_fp_in_bucket(struct f2fs_sb_info *sbi,
			       struct f2dfs_fp_bucket *bucket,
			       struct fp_rc_info *search_result)
{
	int i, n = bucket->valid_count;
	struct fp_entry *entries = bucket->entries;
	const __u8 *needle	 = search_result->fingerprint;
#if FP_LEN_MAX >= 4
	u32 tag0 = get_unaligned((const u32 *)needle);
#endif

	if (unlikely(is_bucket_empty(bucket)))
		return -FP_BUFFER_SEARCH_UNIQUE;

	prefetch(entries);

	for (i = 0; i < n; ++i) {
		const __u8 *fp = entries[i].fingerprint;

#if FP_LEN_MAX >= 4

		if (unlikely(get_unaligned((const u32 *)fp) != tag0))
			continue;
#endif

		if (unlikely((i & 0x7) == 0))
			prefetch(entries + i + 8);

		if (likely(fp_is_equal(needle, fp) == 0)) {
			search_result->vaddr	    = entries[i].vaddr;
			search_result->fp_page_addr = bucket->blkaddr;
			search_result->is_unique    = false;
			f2fs_bug_on(sbi, search_result->vaddr == NULL_ADDR);
			f2fs_bug_on(sbi,
				    search_result->fp_page_addr == NULL_ADDR);
			return FP_BUFFER_SEARCH_DUPL;
		}
	}
	return -FP_BUFFER_SEARCH_UNIQUE;
}

static int search_fp_in_raw_bucket(struct f2fs_sb_info *sbi,
				   struct f2dfs_fp_bucket_in_disk *raw_bucket,
				   block_t raw_blkaddr,
				   struct fp_rc_info *search_result)
{
	int i = 0, seen = 0;
	const __u8 *needle = search_result->fingerprint;
#if FP_LEN_MAX >= 4
	u32 tag0 = get_unaligned((const u32 *)needle);
#endif

	search_result->vaddr = NULL_ADDR;

	if (is_raw_bucket_empty(raw_bucket)) {
		return -FP_BUFFER_SEARCH_UNIQUE;
	}

	prefetch(raw_bucket->entries);

	for (i = 0, seen = 0;
	     seen < raw_bucket->valid_count && i < FP_ENTRIES_PER_PAGE; ++i) {
		if (test_bit_le(i, raw_bucket->invalidmap))
			continue;

#if FP_LEN_MAX >= 4

		if (unlikely(get_unaligned((const u32 *)raw_bucket->entries[i]
						   .fingerprint) != tag0)) {
			seen++;
			continue;
		}
#endif

		if (unlikely((i & 0x7) == 0))
			prefetch(&raw_bucket->entries[i + 8]);

		if (likely(fp_is_equal(needle,
				       raw_bucket->entries[i].fingerprint) ==
			   0)) {
			search_result->vaddr = raw_bucket->entries[i].vaddr;
			search_result->fp_page_addr = raw_blkaddr;
			search_result->is_unique    = false;
			f2fs_bug_on(sbi, search_result->vaddr == NULL_ADDR);
			f2fs_bug_on(sbi,
				    search_result->fp_page_addr == NULL_ADDR);
			return FP_BUFFER_SEARCH_DUPL;
		}
		seen++;
	}
	return -FP_BUFFER_SEARCH_UNIQUE;
}

int search_fp_in_buffer(struct f2fs_sb_info *sbi,
			struct fp_rc_info *search_result)
{
	struct f2dfs_fp_bucket *buf;
	struct fp_entry *e, *end;
	const __u8 *needle = search_result->fingerprint;
#if FP_LEN_MAX >= 4
	u32 tag0 = get_unaligned((const u32 *)needle);
#endif

	buf = sbi->fp_buffer;
	if (unlikely(!buf)) {
		f2fs_bug_on(sbi, !buf);
		return -FP_BUFFER_SEARCH_UNIQUE;
	}
	f2fs_bug_on(sbi, !rwsem_is_locked(&sbi->fp_buffer_lock));

	if (unlikely(buf->valid_count == 0)) {
		search_result->fp_page_addr = NULL_ADDR;
		search_result->vaddr	    = NULL_ADDR;
		search_result->is_unique    = true;
		return -FP_BUFFER_SEARCH_UNIQUE;
	}

	e   = buf->entries;
	end = e + buf->valid_count;

	prefetch(e);
	for (; e < end; ++e) {
#if FP_LEN_MAX >= 4

		if (unlikely(get_unaligned((const u32 *)e->fingerprint) !=
			     tag0))
			continue;
#endif

		if (unlikely((((unsigned long)(e - buf->entries)) & 0x7) == 0))
			prefetch(e + 8);

		if (unlikely(fp_is_equal(needle, e->fingerprint) == 0)) {
			search_result->vaddr	    = e->vaddr;
			search_result->fp_page_addr = buf->blkaddr;
			search_result->is_unique    = false;
			f2fs_bug_on(sbi, search_result->vaddr == NULL_ADDR);
			f2fs_bug_on(sbi,
				    search_result->fp_page_addr == NULL_ADDR);
			return FP_BUFFER_SEARCH_DUPL;
		}
	}

	search_result->fp_page_addr = NULL_ADDR;
	search_result->vaddr	    = NULL_ADDR;
	search_result->is_unique    = true;
	return -FP_BUFFER_SEARCH_UNIQUE;
}

int search_fp_in_buckets(struct f2fs_sb_info *sbi,
			 struct fp_rc_info *search_result)
{
	int i;
	int ret = -FP_BUFFER_SEARCH_UNIQUE;

	f2fs_bug_on(sbi, !rwsem_is_locked(&sbi->s_fp_bucket_lock));

	for (i = sbi->s_fp_bucket->current_number - 1; i >= 0; i--) {
		struct f2dfs_fp_bucket *bucket = sbi->s_fp_bucket->pointers[i];
		f2fs_bug_on(sbi, !bucket);

		prefetch(bucket);
		prefetch(bucket->entries);

		ret = search_fp_in_bucket(sbi, bucket, search_result);
		if (ret == FP_BUFFER_SEARCH_DUPL) {
			bucket->atime = jiffies;
			return ret;
		}

		if (unlikely(GIVE_UP_CPU_ENABLE &&
			     ((sbi->s_fp_bucket->current_number - 1 - i) &
			      FP_SCAN_RESCHED_MASK) == 0) &&
		    need_resched())
			cond_resched();
	}

	search_result->fp_page_addr = NULL_ADDR;
	search_result->vaddr	    = NULL_ADDR;
	search_result->is_unique    = true;
	return -FP_BUFFER_SEARCH_UNIQUE;
}

block_t f2dfs_find_free_block(struct f2fs_sb_info *sbi, block_t start_blk,
			      block_t blks_num, char *bitmap)
{
	unsigned long idx;

	idx = find_next_zero_bit_le((unsigned long *)bitmap,
				    (unsigned long)blks_num, 0);
	if (idx < (unsigned long)blks_num) {
		__set_bit_le(idx, bitmap);
		return start_blk + (block_t)idx;
	}
	print_err("No free block found in bitmap");
	return NULL_ADDR;
}

inline void f2dfs_free_block(block_t start_blk, block_t blkaddr, char *bitmap)
{
	unsigned int idx = blkaddr - start_blk;
	__clear_bit_le(idx, bitmap);
}

inline void f2dfs_set_block(block_t start_blk, block_t blkaddr, char *bitmap)
{
	unsigned int idx = blkaddr - start_blk;
	__set_bit_le(idx, bitmap);
}

inline bool f2dfs_is_block_set(block_t start_blk, block_t blkaddr, char *bitmap)
{
	unsigned int idx = blkaddr - start_blk;
	return test_bit_le(idx, bitmap);
}

int f2dfs_insert_bucket_into_storage(struct f2fs_sb_info *sbi, int write_count)
{
	int current_number, i, released = 0;
	block_t blkaddr;
	char *bitmap;
	struct f2dfs_fp_bucket_in_disk *raw_bucket;
	f2fs_bug_on(sbi, !rwsem_is_locked(&sbi->s_fp_bucket_lock));
	raw_bucket =
		kmalloc(sizeof(struct f2dfs_fp_bucket_in_disk), GFP_KERNEL);
	if (!raw_bucket) {
		print_err("kmalloc raw_buffer failed");
		return -FP_BUCKET_INTO_STORAGE_FAILURE;
	}
	current_number = sbi->s_fp_bucket->current_number;
	bitmap	       = sbi->dm_info->fp_bitmap;

	if (write_count > current_number)
		write_count = current_number;

	for (i = 0; i < write_count; i++) {
		struct f2dfs_fp_bucket *bucket;
		bucket = sbi->s_fp_bucket->pointers[i];
		f2fs_bug_on(sbi, !bucket);

		blkaddr = bucket->blkaddr;
		f2fs_bug_on(sbi, blkaddr == NULL_ADDR);
		f2fs_bug_on(sbi, !(blkaddr >= sbi->dm_info->fp_blkaddr &&
				   blkaddr < sbi->dm_info->rc_base_blkaddr));
		if (bucket->valid_count > 0) {
			copy_bucket_to_raw_bucket(raw_bucket, bucket,
						  !is_bucket_full(bucket));
			f2fs_bug_on(sbi, raw_bucket->valid_count !=
						 bucket->valid_count);

			f2fs_bug_on(sbi, !f2dfs_is_block_set(
						 sbi->dm_info->fp_blkaddr,
						 blkaddr, bitmap));
			if (f2dfs_write_meta_page(sbi, raw_bucket, blkaddr) <
			    0) {
				print_err(
					"fail to write meta page: bucket %d, blkaddr %u, valid_count %u",
					i, blkaddr, raw_bucket->valid_count);
				spin_lock(&sbi->dm_info->fp_lock);
				f2dfs_free_block(sbi->dm_info->fp_blkaddr,
						 blkaddr, bitmap);
				spin_unlock(&sbi->dm_info->fp_lock);
				kvfree(raw_bucket);
				return -FP_BUCKET_INTO_STORAGE_FAILURE;
			} else {
				print_info(
					PRINT_IMPORTANT_INFO_ENABLED,
					"f2dfs_insert_bucket_into_storage: "
					"bucket %d, blkaddr %u, valid_count %u",
					i, blkaddr, raw_bucket->valid_count);
			}
		} else {
			print_info(
				PRINT_IMPORTANT_INFO_ENABLED,
				"f2dfs_insert_bucket_into_storage: "
				"bucket %d, blkaddr %llx, valid_count %u will be freed",
				i, (unsigned long long)blkaddr,
				bucket->valid_count);

			spin_lock(&sbi->dm_info->fp_lock);
			f2dfs_free_block(sbi->dm_info->fp_blkaddr, blkaddr,
					 bitmap);
			spin_unlock(&sbi->dm_info->fp_lock);
		}
		kmem_cache_free(sbi->s_fp_bucket->bucket_cache, bucket);
		sbi->s_fp_bucket->pointers[i] = NULL;
		released++;
	}

	for (i = write_count; i < current_number; i++) {
		sbi->s_fp_bucket->pointers[i - write_count] =
			sbi->s_fp_bucket->pointers[i];
	}
	for (i = current_number - write_count; i < current_number; i++) {
		sbi->s_fp_bucket->pointers[i] = NULL;
	}
	sbi->s_fp_bucket->current_number -= released;
	kvfree(raw_bucket);

	return (released == write_count) ? FP_BUCKET_INTO_STORAGE_SUCCESS :
					   -FP_BUCKET_INTO_STORAGE_FAILURE;
}

int f2dfs_insert_rcb_buffer_into_storage(struct f2fs_sb_info *sbi)
{
	block_t blkaddr;
	char *bitmap;

	if (!sbi || !sbi->dm_info || !sbi->rcb_buffer) {
		print_err("pointer is NULL, sbi:%p, dm_info:%p, rcb_buffer:%p",
			  sbi, sbi ? sbi->dm_info : NULL,
			  sbi ? sbi->rcb_buffer : NULL);
		return -RC_BUFFER_INTO_STORAGE_FAILURE;
	}

	f2fs_bug_on(sbi, !spin_is_locked(&sbi->rcb_buffer_lock));
	f2fs_bug_on(sbi, !spin_is_locked(&sbi->dm_info->rc_base_lock));

	if (sbi->rcb_buffer->valid_count == 0) {
		print_info(
			PRINT_IMPORTANT_INFO_ENABLED,
			"rc base buffer is empty, valid_count: %u, no need to write",
			sbi->rcb_buffer->valid_count);
		return RC_BUFFER_INTO_STORAGE_SUCCESS;
	}

	f2dfs_load_dm_bitmap(sbi, false, false, true, false);
	bitmap	= sbi->dm_info->rc_base_bitmap;
	blkaddr = f2dfs_find_free_block(sbi, sbi->dm_info->rc_base_blkaddr,
					sbi->dm_info->rc_base_blks, bitmap);
	if (blkaddr == NULL_ADDR) {
		print_err("no free blkaddr for rcb_buffer");
		f2dfs_store_dm_bitmap(sbi, false, true, false);
		return -RC_BUFFER_INTO_STORAGE_FAILURE;
	}

	if (sbi->rcb_buffer->valid_count && !is_rc_base_full(sbi->rcb_buffer)) {
		sbi->dm_info->unfull_rc_base_blkaddr = blkaddr;
		f2fs_bug_on(sbi,
			    !f2dfs_is_block_set(sbi->dm_info->rc_base_blkaddr,
						blkaddr, bitmap));
	}

	if (f2dfs_write_meta_page_direct(sbi, sbi->rcb_buffer, blkaddr) < 0) {
		f2dfs_free_block(sbi->dm_info->rc_base_blkaddr, blkaddr,
				 bitmap);
		print_err("write rcb_buffer to disk failed");
		f2dfs_store_dm_bitmap(sbi, false, true, false);
		return -RC_BUFFER_INTO_STORAGE_FAILURE;
	}
	sbi->rcb_buffer->valid_count = 0;
	f2dfs_store_dm_bitmap(sbi, false, true, false);
	return RC_BUFFER_INTO_STORAGE_SUCCESS;
}

int f2dfs_insert_rc_delta_buffer_into_storage(struct f2fs_sb_info *sbi)
{
	block_t blkaddr;
	char *bitmap;

	if (!sbi || !sbi->dm_info || !sbi->rcd_buffer) {
		f2fs_err(sbi,
			 "pointer is NULL, sbi:%p, dm_info:%p, rcd_buffer:%p",
			 sbi, sbi ? sbi->dm_info : NULL,
			 sbi ? sbi->rcd_buffer : NULL);
		return -RC_BUFFER_INTO_STORAGE_FAILURE;
	}

	f2fs_bug_on(sbi, !spin_is_locked(&sbi->rcd_buffer_lock));

	if (sbi->rcd_buffer->valid_count == 0) {
		print_info(
			PRINT_IMPORTANT_INFO_ENABLED,
			"rc delta buffer is empty, valid_count: %u, no need to write",
			sbi->rcd_buffer->valid_count);
		return RC_BUFFER_INTO_STORAGE_SUCCESS;
	}

	spin_lock(&sbi->dm_info->rc_delta_lock);
	f2dfs_load_dm_bitmap(sbi, false, false, false, true);
	bitmap	= sbi->dm_info->rc_delta_bitmap;
	blkaddr = f2dfs_find_free_block(sbi, sbi->dm_info->rc_delta_blkaddr,
					sbi->dm_info->rc_delta_blks, bitmap);
	if (blkaddr == NULL_ADDR) {
		f2fs_err(sbi, "no free blkaddr for rcd_buffer");
		f2dfs_store_dm_bitmap(sbi, false, false, true);
		spin_unlock(&sbi->dm_info->rc_delta_lock);
		return -RC_BUFFER_INTO_STORAGE_FAILURE;
	}

	if (sbi->rcd_buffer->valid_count &&
	    !is_rc_delta_full(sbi->rcd_buffer)) {
		sbi->dm_info->unfull_rc_delta_blkaddr = blkaddr;
		f2fs_bug_on(sbi,
			    !f2dfs_is_block_set(sbi->dm_info->rc_delta_blkaddr,
						blkaddr, bitmap));
	}

	if (f2dfs_write_meta_page_direct(sbi, sbi->rcd_buffer, blkaddr) < 0) {
		f2dfs_free_block(sbi->dm_info->rc_delta_blkaddr, blkaddr,
				 bitmap);
		f2fs_err(sbi, "write rcd_buffer to disk failed");
		f2dfs_store_dm_bitmap(sbi, false, false, true);
		spin_unlock(&sbi->dm_info->rc_delta_lock);
		return -RC_BUFFER_INTO_STORAGE_FAILURE;
	}
	sbi->rcd_buffer->valid_count = 0;
	f2dfs_store_dm_bitmap(sbi, false, false, true);
	spin_unlock(&sbi->dm_info->rc_delta_lock);
	return RC_BUFFER_INTO_STORAGE_SUCCESS;
}

int f2dfs_insert_buffer_into_bucket(struct f2fs_sb_info *sbi,
				    bool alloc_new_buffer)
{
	int ret = FP_BUFFER_INTO_BUCKET_SUCCESS;
	f2fs_bug_on(sbi, !sbi->fp_buffer);
	f2fs_bug_on(sbi, !rwsem_is_locked(&sbi->fp_buffer_lock));
	f2fs_bug_on(sbi, !rwsem_is_locked(&sbi->s_fp_bucket_lock));
	if (!alloc_new_buffer) {
		if (is_bucket_empty(sbi->fp_buffer)) {
			print_info(
				PRINT_IMPORTANT_INFO_ENABLED,
				"record empty fp blkaddr: %x:%u, buffer.valid_count: %u, set new unfull fp blkaddr NULL",
				sbi->fp_buffer->blkaddr,
				sbi->fp_buffer->blkaddr,
				sbi->fp_buffer->valid_count);
			spin_lock(&sbi->dm_info->fp_lock);
			sbi->dm_info->unfull_fp_blkaddr = NULL_ADDR;

			spin_unlock(&sbi->dm_info->fp_lock);
		} else if (!is_bucket_full(sbi->fp_buffer)) {
			print_info(
				PRINT_IMPORTANT_INFO_ENABLED,
				"record unfull fp blkaddr: %x:%u, buffer.valid_count: %u, set new unfull fp blkaddr",
				sbi->fp_buffer->blkaddr,
				sbi->fp_buffer->blkaddr,
				sbi->fp_buffer->valid_count);
			spin_lock(&sbi->dm_info->fp_lock);
			sbi->dm_info->unfull_fp_blkaddr =
				sbi->fp_buffer->blkaddr;
			f2fs_bug_on(sbi, !f2dfs_is_block_set(
						 sbi->dm_info->fp_blkaddr,
						 sbi->fp_buffer->blkaddr,
						 sbi->dm_info->fp_bitmap));
			spin_unlock(&sbi->dm_info->fp_lock);
		}
	}
	if (is_buckets_full(sbi)) {
		int write_count = alloc_new_buffer ?
					  FP_BUCKET_WB_NUM :
					  sbi->s_fp_bucket->current_number;
		print_info(PRINT_IMPORTANT_INFO_ENABLED,
			   "fp bucket is full, insert into storage");
		if (f2dfs_insert_bucket_into_storage(sbi, write_count) ==
		    -FP_BUCKET_INTO_STORAGE_FAILURE) {
			print_err("Failed to insert bucket into storage");
			ret = -FP_BUFFER_INTO_BUCKET_FAILURE;
			goto out_unlock;
		}
	}
	sbi->fp_buffer->atime = jiffies;
	print_info(
		PRINT_IMPORTANT_INFO_ENABLED,
		"fp buffer(fp page addr:%x:%u, count:%u), insert into bucket 0, after insert buckets.current_number: %d, exit sys: %d",
		sbi->fp_buffer->blkaddr, sbi->fp_buffer->blkaddr,
		sbi->fp_buffer->valid_count,
		sbi->s_fp_bucket->current_number + 1, !alloc_new_buffer);
	sbi->s_fp_bucket->pointers[sbi->s_fp_bucket->current_number++] =
		sbi->fp_buffer;
	if (alloc_new_buffer) {
		struct f2dfs_fp_bucket *new_buffer = kmem_cache_alloc(
			sbi->s_fp_bucket->bucket_cache, GFP_KERNEL);
		if (!new_buffer) {
			sbi->s_fp_bucket->current_number--;
			sbi->s_fp_bucket
				->pointers[sbi->s_fp_bucket->current_number] =
				NULL;
			print_err("Failed to allocate new fingerprint buffer");
			ret = -FP_BUFFER_INTO_BUCKET_FAILURE;
			goto out_unlock;
		}
		memset(new_buffer, 0, sizeof(struct f2dfs_fp_bucket));
		spin_lock(&sbi->dm_info->fp_lock);
		new_buffer->blkaddr =
			f2dfs_find_free_block(sbi, sbi->dm_info->fp_blkaddr,
					      sbi->dm_info->fp_blks,
					      sbi->dm_info->fp_bitmap);
		spin_unlock(&sbi->dm_info->fp_lock);
		if (new_buffer->blkaddr == NULL_ADDR) {
			kmem_cache_free(sbi->s_fp_bucket->bucket_cache,
					new_buffer);
			sbi->s_fp_bucket->current_number--;
			sbi->s_fp_bucket
				->pointers[sbi->s_fp_bucket->current_number] =
				NULL;
			f2fs_err(sbi,
				 "Failed to find free block for new buffer");
			ret = -FP_BUFFER_INTO_BUCKET_FAILURE;
			goto out_unlock;
		}
		sbi->fp_buffer = new_buffer;
		print_info(
			PRINT_BASIC_INFO_ENABLED,
			"new fp buffer(fp page addr:%x:%u, count:%u) allocated",
			sbi->fp_buffer->blkaddr, sbi->fp_buffer->blkaddr,
			sbi->fp_buffer->valid_count);
	} else {
		sbi->fp_buffer = NULL;
	}

out_unlock:
	return ret;
}

static int find_oldest_fp_bucket(struct f2fs_sb_info *sbi)
{
	int i, oldest = -1;
	unsigned long oldest_time;
	f2fs_bug_on(sbi, !rwsem_is_locked(&sbi->s_fp_bucket_lock));

#if FP_BUCKET_REPLACE_OLDEST
	return sbi->s_fp_bucket->current_number - 1;
#endif

	oldest_time = jiffies;
	for (i = 0; i < sbi->s_fp_bucket->current_number; i++) {
		struct f2dfs_fp_bucket *bucket;
		bucket = sbi->s_fp_bucket->pointers[i];
		f2fs_bug_on(sbi, !bucket);
		if (bucket->atime < oldest_time) {
			oldest_time = bucket->atime;
			oldest	    = i;
		}
	}

	return oldest;
}

int f2dfs_insert_fingerprint_into_buffer(struct f2fs_sb_info *sbi,
					 struct fp_rc_info *insert)
{
	int index;
	if (ENABLE_FP_HASH_TABLE)
		insert_in_fp_hash_table(sbi, insert->fingerprint,
					insert->vaddr);

	down_write(&sbi->fp_buffer_lock);
	if (is_bucket_full(sbi->fp_buffer)) {
		down_write(&sbi->s_fp_bucket_lock);
		if (f2dfs_insert_buffer_into_bucket(sbi, true) ==
		    -FP_BUFFER_INTO_BUCKET_FAILURE) {
			up_write(&sbi->s_fp_bucket_lock);
			print_err("Failed to insert buffer into bucket");
			return -FP_BUFFER_INSERT_FAILURE;
		}
		up_write(&sbi->s_fp_bucket_lock);
	}
	index = sbi->fp_buffer->valid_count;
	memcpy(sbi->fp_buffer->entries[index].fingerprint, insert->fingerprint,
	       FP_LEN_MAX);
	sbi->fp_buffer->entries[index].vaddr = insert->vaddr;
	sbi->fp_buffer->valid_count++;
	insert->fp_page_addr = sbi->fp_buffer->blkaddr;
	up_write(&sbi->fp_buffer_lock);
	return FP_BUFFER_INSERT_SUCCESS;
}

static int __f2dfs_insert_refcount(struct f2fs_sb_info *sbi,
				   struct fp_rc_info *insert,
				   struct f2dfs_global_counter *g_counter,
				   bool change_g_counter)
{
	struct rc_base_entry *rc_base_entry;
	struct rc_delta_entry *rc_delta_entry;
	int index, ret, retry = 0;

	if (insert->vaddr == ZERO_ADDR && !change_g_counter) {
		f2fs_bug_on(sbi, insert->is_unique != false);
		f2dfs_change_reference_count_inline(sbi, ZERO_ADDR, 1,
						    g_counter);
		return RC_BUFFER_INSERT_SUCCESS;
	}

	spin_lock(&sbi->rcb_buffer_lock);
base_redo:
	rc_base_entry = sbi->rcb_buffer->entries;
	if (insert->is_unique) {
		index = sbi->rcb_buffer->valid_count;
		if (is_rc_base_full(sbi->rcb_buffer)) {
			spin_lock(&sbi->dm_info->rc_base_lock);
			ret = f2dfs_insert_rcb_buffer_into_storage(sbi);
			spin_unlock(&sbi->dm_info->rc_base_lock);
			if (ret == -RC_BUFFER_INTO_STORAGE_FAILURE ||
			    ++retry > 3) {
				spin_unlock(&sbi->rcb_buffer_lock);
				print_err(
					"Failed to insert base buffer into storage");
				return -RC_BUFFER_INSERT_FAILURE;
			}
			goto base_redo;
		}
		memset(&rc_base_entry[index], 0, sizeof(struct rc_base_entry));
		f2fs_bug_on(sbi, insert->rc_change != 1);
		rc_base_entry[index].rc		  = FP_COUNTER_UNIQUE;
		rc_base_entry[index].fp_page_addr = insert->fp_page_addr;
		rc_base_entry[index].vaddr	  = insert->vaddr;
		f2fs_bug_on(sbi, insert->vaddr == NULL_ADDR);
		f2fs_bug_on(sbi, insert->fp_page_addr == NULL_ADDR);
		sbi->rcb_buffer->valid_count++;
		spin_unlock(&sbi->rcb_buffer_lock);
		return RC_BUFFER_INSERT_SUCCESS;
	}
	spin_unlock(&sbi->rcb_buffer_lock);

	retry = 0;
	spin_lock(&sbi->rcd_buffer_lock);
	rc_delta_entry = sbi->rcd_buffer->entries;
	for (index = 0; index < sbi->rcd_buffer->valid_count; index++) {
		if (rc_delta_entry[index].vaddr == insert->vaddr) {
			if (rc_overflow(rc_delta_entry[index].rc,
					insert->rc_change)) {
				print_err(
					"Reference count overflow for vaddr: %x:%u, rc_change: %d",
					insert->vaddr, insert->vaddr,
					insert->rc_change);
				continue;
			}
			rc_delta_entry[index].rc += insert->rc_change;
			spin_unlock(&sbi->rcd_buffer_lock);
			return RC_BUFFER_INSERT_SUCCESS;
		}
	}
delta_redo:
	index = sbi->rcd_buffer->valid_count;
	if (is_rc_delta_full(sbi->rcd_buffer)) {
		ret = f2dfs_insert_rc_delta_buffer_into_storage(sbi);
		if (ret == -RC_BUFFER_INTO_STORAGE_FAILURE || ++retry > 3) {
			spin_unlock(&sbi->rcd_buffer_lock);
			return -RC_BUFFER_INSERT_FAILURE;
		}
		goto delta_redo;
	}
	memset(&rc_delta_entry[index], 0, sizeof(struct rc_delta_entry));
	rc_delta_entry[index].rc    = insert->rc_change;
	rc_delta_entry[index].vaddr = insert->vaddr;
	sbi->rcd_buffer->valid_count++;
	spin_unlock(&sbi->rcd_buffer_lock);
	return RC_BUFFER_INSERT_SUCCESS;
}

static int f2dfs_change_refcount(struct f2fs_sb_info *sbi, virtual_t vaddr,
				 char rc_change,
				 struct f2dfs_global_counter *g_counter)
{
	struct fp_rc_info insert = {
		.vaddr	      = vaddr,
		.is_unique    = false,
		.rc_change    = rc_change,
		.fp_page_addr = NULL_ADDR,
	};

	__f2dfs_insert_refcount(sbi, &insert, g_counter, true);
	return FP_BUFFER_SEARCH_DUPL;
}

int f2dfs_insert_refcount(struct f2fs_sb_info *sbi, struct fp_rc_info *insert,
			  struct f2dfs_global_counter *g_counter)
{
	return __f2dfs_insert_refcount(sbi, insert, g_counter, false);
}

static inline int
f2dfs_load_disk_bucket(struct f2fs_sb_info *sbi,
		       struct f2dfs_fp_bucket_in_disk *raw_bucket,
		       block_t raw_blkaddr)
{
	struct f2dfs_fp_bucket *new_bucket =
		kmem_cache_alloc(sbi->s_fp_bucket->bucket_cache, GFP_KERNEL);
	f2fs_bug_on(sbi, !rwsem_is_locked(&sbi->s_fp_bucket_lock));
	if (!new_bucket) {
		print_err("Failed to allocate new fingerprint buffer");
		return -FP_BUFFER_INTO_BUCKET_FAILURE;
	}
	copy_raw_bucket_to_bucket(sbi, new_bucket, raw_bucket, raw_blkaddr);
	new_bucket->atime = jiffies;
	sbi->s_fp_bucket->pointers[sbi->s_fp_bucket->current_number++] =
		new_bucket;
	if (!is_bucket_full(new_bucket)) {
		int i, valid_count = 0;
		for (i = 0; i < FP_ENTRIES_PER_PAGE; i++) {
			if (!test_bit_le(i, raw_bucket->invalidmap)) {
				valid_count++;
			}
		}
		if (valid_count != raw_bucket->valid_count) {
			print_err("Invalid count mismatch: expected %u, got %u",
				  raw_bucket->valid_count, valid_count);
		}
	}

	print_info(
		PRINT_IMPORTANT_INFO_ENABLED,
		"Inserted disk bucket %d into memory, blkaddr: %llu, valid_count: %u",
		sbi->s_fp_bucket->current_number,
		(unsigned long long)new_bucket->blkaddr,
		new_bucket->valid_count);
	return 0;
}

static inline int
f2dfs_swap_bucket(struct f2fs_sb_info *sbi,
		  struct f2dfs_fp_bucket_in_disk *raw_bucket_swapin,
		  block_t raw_bucket_blkaddr)
{
	int oldest_bucket;
	struct f2dfs_fp_bucket_in_disk *raw_buffer_swap_out =
		kmalloc(sizeof(struct f2dfs_fp_bucket_in_disk), GFP_KERNEL);
	f2fs_bug_on(sbi, !rwsem_is_locked(&sbi->s_fp_bucket_lock));
	if (!raw_buffer_swap_out) {
		print_err("Failed to allocate memory for oldest buffer");
		return -ENOMEM;
	}

	oldest_bucket = find_oldest_fp_bucket(sbi);
	if (oldest_bucket >= 0) {
		struct f2dfs_fp_bucket *bucket;
		bucket = sbi->s_fp_bucket->pointers[oldest_bucket];
		f2fs_bug_on(sbi, !bucket);

		copy_bucket_to_raw_bucket(raw_buffer_swap_out, bucket,
					  !is_bucket_full(bucket));
		f2dfs_write_meta_page(sbi, raw_buffer_swap_out,
				      bucket->blkaddr);
		copy_raw_bucket_to_bucket(sbi, bucket, raw_bucket_swapin,
					  raw_bucket_blkaddr);
		bucket->atime = jiffies;
		print_info(
			PRINT_IMPORTANT_INFO_ENABLED,
			"Replaced oldest bucket %d with disk bucket blkaddr %llu",
			oldest_bucket, (unsigned long long)raw_bucket_blkaddr);
	}

	kvfree(raw_buffer_swap_out);

	return 0;
}

static int cmp_block_t(const void *a, const void *b)
{
	const block_t A = *(const block_t *)a;
	const block_t B = *(const block_t *)b;
	if (A < B)
		return -1;
	if (A > B)
		return 1;
	return 0;
}

static int search_fp_in_disk_protected(struct f2fs_sb_info *sbi,
				       struct fp_rc_info *search)
{
	block_t start				   = sbi->dm_info->fp_blkaddr;
	block_t count				   = sbi->dm_info->fp_blks;
	block_t fp_buckets_num			   = 0;
	block_t *fp_buckets			   = NULL;
	int ret					   = -FP_BUFFER_SEARCH_UNIQUE;
	struct f2dfs_fp_bucket_in_disk *raw_buffer = NULL;
	unsigned long i;
	char *bitmap = sbi->dm_info->fp_bitmap;

	raw_buffer =
		kmalloc(sizeof(struct f2dfs_fp_bucket_in_disk), GFP_KERNEL);
	if (!raw_buffer) {
		print_err("Failed to allocate memory for raw buffer");
		return -ENOMEM;
	}

	down_read(&sbi->fp_buffer_lock);
	down_read(&sbi->s_fp_bucket_lock);

	{
		block_t need =
			(sbi->s_fp_bucket ? sbi->s_fp_bucket->current_number :
					    0) +
			(sbi->fp_buffer ? 1 : 0);
		fp_buckets = kvmalloc_array(max_t(block_t, need, 1),
					    sizeof(block_t), GFP_KERNEL);
		if (!fp_buckets) {
			up_read(&sbi->s_fp_bucket_lock);
			up_read(&sbi->fp_buffer_lock);
			kvfree(raw_buffer);
			print_err("Failed to allocate memory for fp buckets");
			return -ENOMEM;
		}
	}

	if (sbi->fp_buffer)
		fp_buckets[fp_buckets_num++] = sbi->fp_buffer->blkaddr;

	if (sbi->s_fp_bucket) {
		int k;
		for (k = 0; k < sbi->s_fp_bucket->current_number; k++) {
			struct f2dfs_fp_bucket *mem_bucket =
				sbi->s_fp_bucket->pointers[k];
			f2fs_bug_on(sbi, !mem_bucket);
			fp_buckets[fp_buckets_num++] = mem_bucket->blkaddr;
		}
	}

	up_read(&sbi->s_fp_bucket_lock);
	up_read(&sbi->fp_buffer_lock);

	if (fp_buckets_num > 1)
		sort(fp_buckets, fp_buckets_num, sizeof(block_t), cmp_block_t,
		     NULL);

	for (i = find_next_bit_le((unsigned long *)bitmap, count, 0); i < count;
	     i = find_next_bit_le((unsigned long *)bitmap, count, i + 1)) {
		block_t raw_buffer_blkaddr = start + i;

		if (fp_buckets_num) {
			block_t *found = bsearch(&raw_buffer_blkaddr,
						 fp_buckets, fp_buckets_num,
						 sizeof(block_t), cmp_block_t);
			if (found)
				continue;
		}

		ret = f2dfs_read_meta_page(sbi, raw_buffer, raw_buffer_blkaddr);
		if (ret < 0)
			continue;

		if (unlikely(!is_fp_raw_bucket(raw_buffer)))
			continue;

		ret = search_fp_in_raw_bucket(sbi, raw_buffer,
					      raw_buffer_blkaddr, search);

		if (ret == FP_BUFFER_SEARCH_DUPL) {
			bool already_loaded = false;
			int j;

			down_write(&sbi->s_fp_bucket_lock);
			for (j = 0; j < sbi->s_fp_bucket->current_number; j++) {
				struct f2dfs_fp_bucket *mem_bucket =
					sbi->s_fp_bucket->pointers[j];
				if (mem_bucket->blkaddr == raw_buffer_blkaddr) {
					already_loaded = true;
					break;
				}
			}
			if (!already_loaded) {
				if (sbi->s_fp_bucket->current_number <=
				    FP_BUCKET_SWAP_HIGH)
					f2dfs_load_disk_bucket(
						sbi, raw_buffer,
						raw_buffer_blkaddr);
				else
					f2dfs_swap_bucket(sbi, raw_buffer,
							  raw_buffer_blkaddr);
			}
			up_write(&sbi->s_fp_bucket_lock);

			kvfree(raw_buffer);
			kvfree(fp_buckets);
			print_info(PRINT_BASIC_INFO_ENABLED,
				   "Found fingerprint in disk");
			return FP_BUFFER_SEARCH_DUPL;
		}

		if (unlikely(GIVE_UP_CPU_ENABLE &&
			     (i & FP_SCAN_RESCHED_MASK) == 0) &&
		    need_resched())
			cond_resched();
	}

	search->fp_page_addr = NULL_ADDR;
	search->vaddr	     = NULL_ADDR;
	search->is_unique    = true;

	kvfree(raw_buffer);
	kvfree(fp_buckets);
	print_info(PRINT_BASIC_INFO_ENABLED, "Fingerprint is unique");
	return -FP_BUFFER_SEARCH_UNIQUE;
}

int f2dfs_search_fingerprint(struct f2fs_sb_info *sbi,
			     struct fp_rc_info *search)
{
	int ret;

	if (fp_is_equal(search->fingerprint,
			sbi->s_fp_hash->basic_hash_info->zero_result) == 0) {
		search->vaddr	     = ZERO_ADDR;
		search->fp_page_addr = ZERO_ADDR;
		search->is_unique    = false;
		return FP_BUFFER_SEARCH_DUPL;
	}

	if (ENABLE_FP_HASH_TABLE) {
		ret = search_in_fp_hash_table(sbi, search->fingerprint,
					      &search->vaddr);
		if (ret == FP_BUFFER_SEARCH_DUPL) {
			print_info(PRINT_BASIC_INFO_ENABLED,
				   "Found fingerprint in hash table");
			return ret;
		}
	}

	down_read(&sbi->fp_buffer_lock);
	ret = search_fp_in_buffer(sbi, search);
	up_read(&sbi->fp_buffer_lock);
	if (ret == FP_BUFFER_SEARCH_DUPL) {
		print_info(PRINT_BASIC_INFO_ENABLED,
			   "Found fingerprint in buffer");
		return ret;
	}

	down_read(&sbi->s_fp_bucket_lock);
	ret = search_fp_in_buckets(sbi, search);
	up_read(&sbi->s_fp_bucket_lock);
	if (ret == FP_BUFFER_SEARCH_DUPL) {
		print_info(PRINT_BASIC_INFO_ENABLED,
			   "Found fingerprint in bucket");
		return ret;
	}

	ret = search_fp_in_disk_protected(sbi, search);
	return ret;
}

int f2dfs_change_reference_count_inline(struct f2fs_sb_info *sbi,
					virtual_t vaddr, int rc_change,
					struct f2dfs_global_counter *g_counter)
{
	struct node_info ni;
	int err = 0;

	if (!__is_valid_data_blkaddr(vaddr))
		return 0;

	if (vaddr == ZERO_ADDR) {
		g_counter->zero_rc_change += rc_change;
		return 0;
	}

	if (is_real_dnode_physical(vaddr)) {
		if (rc_change < 0) {
			f2fs_invalidate_blocks(sbi, get_dnode_physical(vaddr));
			g_counter->unique_rc_change += rc_change;
			g_counter->valid_rc_change += rc_change;
		}
		return 0;
	}

	err = f2dfs_get_virtual_address_info(sbi, vaddr, &ni);
	if (err || (!__is_valid_data_blkaddr(ni.blk_addr)) ||
	    (!f2fs_is_valid_blkaddr(sbi, ni.blk_addr,
				    DATA_GENERIC_ENHANCE_READ)))
		return -1;

	return f2dfs_change_refcount(sbi, vaddr, rc_change, g_counter);
}

int f2dfs_write_meta_page(struct f2fs_sb_info *sbi, void *src, block_t blkaddr)
{
	f2fs_update_meta_page(sbi, src, blkaddr);
	return 0;
}

int f2dfs_read_meta_page(struct f2fs_sb_info *sbi, void *dst, block_t blkaddr)
{
	struct page *page;
	void *src;

	page = f2fs_get_meta_page(sbi, blkaddr);
	if (IS_ERR(page)) {
		print_err("Failed to get meta page for blkaddr: %u", blkaddr);
		return PTR_ERR(page);
	}

	src = page_address(page);

	memcpy(dst, src, PAGE_SIZE);

	f2fs_put_page(page, 1);

	return 0;
}

static void f2dfs_dio_end_io(struct bio *bio)
{
	struct f2dfs_dio_completion *dio_comp = bio->bi_private;

	dio_comp->error = blk_status_to_errno(bio->bi_status);
	complete(&dio_comp->completion);
	bio_put(bio);
}

int f2dfs_write_meta_page_direct(struct f2fs_sb_info *sbi, void *src,
				 block_t blkaddr)
{
	struct block_device *bdev = sbi->sb->s_bdev;
	struct bio *bio;
	struct page *page;
	struct f2dfs_dio_completion dio_comp;
	int ret = 0;

	page = alloc_page(GFP_KERNEL);
	if (!page) {
		print_err("Failed to allocate page for direct I/O write");
		return -ENOMEM;
	}

	memcpy(page_address(page), src, PAGE_SIZE);

	bio = bio_alloc(GFP_KERNEL, 1);
	if (!bio) {
		__free_page(page);
		print_err("Failed to allocate bio for direct I/O write");
		return -ENOMEM;
	}

	init_completion(&dio_comp.completion);
	dio_comp.error = 0;

	bio_set_dev(bio, bdev);
	bio->bi_iter.bi_sector = blkaddr << (PAGE_SHIFT - 9);
	bio->bi_opf	       = REQ_OP_WRITE | REQ_SYNC | REQ_FUA;
	bio->bi_private	       = &dio_comp;
	bio->bi_end_io	       = f2dfs_dio_end_io;

	if (bio_add_page(bio, page, PAGE_SIZE, 0) != PAGE_SIZE) {
		bio_put(bio);
		__free_page(page);
		print_err("Failed to add page to bio");
		return -EIO;
	}

	submit_bio(bio);

	wait_for_completion(&dio_comp.completion);
	ret = dio_comp.error;

	__free_page(page);

	if (ret < 0) {
		print_err("Direct I/O write failed for blkaddr: %u, error: %d",
			  blkaddr, ret);
	}

	return ret;
}

int f2dfs_read_meta_page_direct(struct f2fs_sb_info *sbi, void *dst,
				block_t blkaddr)
{
	struct block_device *bdev = sbi->sb->s_bdev;
	struct bio *bio;
	struct page *page;
	struct f2dfs_dio_completion dio_comp;
	int ret = 0;

	page = alloc_page(GFP_KERNEL);
	if (!page) {
		print_err("Failed to allocate page for direct I/O read");
		return -ENOMEM;
	}

	bio = bio_alloc(GFP_KERNEL, 1);
	if (!bio) {
		__free_page(page);
		print_err("Failed to allocate bio for direct I/O read");
		return -ENOMEM;
	}

	init_completion(&dio_comp.completion);
	dio_comp.error = 0;

	bio_set_dev(bio, bdev);
	bio->bi_iter.bi_sector = blkaddr << (PAGE_SHIFT - 9);
	bio->bi_opf	       = REQ_OP_READ | REQ_SYNC;
	bio->bi_private	       = &dio_comp;
	bio->bi_end_io	       = f2dfs_dio_end_io;

	if (bio_add_page(bio, page, PAGE_SIZE, 0) != PAGE_SIZE) {
		bio_put(bio);
		__free_page(page);
		print_err("Failed to add page to bio");
		return -EIO;
	}

	submit_bio(bio);

	wait_for_completion(&dio_comp.completion);
	ret = dio_comp.error;

	if (ret == 0) {
		memcpy(dst, page_address(page), PAGE_SIZE);
	} else {
		print_err("Direct I/O read failed for blkaddr: %u, error: %d",
			  blkaddr, ret);
	}

	__free_page(page);
	return ret;
}

int f2dfs_load_dm_bitmap(struct f2fs_sb_info *sbi, bool power_on, bool load_fp,
			 bool load_rcb, bool load_rcd)
{
	block_t bitmap_blkaddr = sbi->dm_info->fp_bitmap_blkaddr;
	block_t page_num       = FP_BITMAP_PAGESIZE;
	char *bitmap	       = sbi->dm_info->fp_bitmap;
	size_t total_size      = FP_BITMAP_SIZE;
	size_t per_page = sizeof(((struct f2dfs_bitmap_disk *)0)->bitmap);
	size_t copy_bytes;
	int i, ret;
	struct f2dfs_bitmap_disk *disk_bitmap;

	f2fs_bug_on(sbi, !(load_fp || load_rcb || load_rcd));

	disk_bitmap = kmalloc(sizeof(struct f2dfs_bitmap_disk), GFP_KERNEL);
	if (!disk_bitmap) {
		print_err("Failed to allocate disk_bitmap");
		return -ENOMEM;
	}

	if (load_fp) {
		for (i = 0; i < page_num; i++) {
			ret = f2dfs_read_meta_page(sbi, disk_bitmap,
						   bitmap_blkaddr + i);
			if (ret < 0) {
				kvfree(disk_bitmap);
				print_err("Failed to read fp bitmap page %d",
					  i);
				return ret;
			}
			copy_bytes = min(per_page, total_size - i * per_page);
			memcpy(bitmap + i * per_page, disk_bitmap->bitmap,
			       copy_bytes);

			if (power_on)
				print_info(PRINT_IMPORTANT_INFO_ENABLED,
					   "      fp_bitmap: %*phN", 16,
					   bitmap + i * per_page);
		}
		if (power_on) {
			sbi->dm_info->unfull_fp_blkaddr =
				disk_bitmap->unfull_blkaddr;
			print_info(PRINT_IMPORTANT_INFO_ENABLED,
				   "load unfull_fp_blkaddr: %llu",
				   sbi->dm_info->unfull_fp_blkaddr);
			f2fs_bug_on(
				sbi,
				sbi->dm_info->unfull_fp_blkaddr != NULL_ADDR &&
					!f2dfs_is_block_set(
						sbi->dm_info->fp_blkaddr,
						sbi->dm_info->unfull_fp_blkaddr,
						sbi->dm_info->fp_bitmap));
		}
	}

	if (load_rcb) {
		bitmap_blkaddr = sbi->dm_info->rc_base_bitmap_blkaddr;
		page_num       = RC_BASE_BITMAP_PAGESIZE;
		bitmap	       = sbi->dm_info->rc_base_bitmap;
		total_size     = RC_BASE_BITMAP_SIZE;

		for (i = 0; i < page_num; i++) {
			ret = f2dfs_read_meta_page_direct(sbi, disk_bitmap,
							  bitmap_blkaddr + i);
			if (ret < 0) {
				kvfree(disk_bitmap);
				print_err(
					"Failed to read rc base bitmap page %d",
					i);
				return ret;
			}
			copy_bytes = min(per_page, total_size - i * per_page);
			memcpy(bitmap + i * per_page, disk_bitmap->bitmap,
			       copy_bytes);

			print_info(PRINT_IMPORTANT_INFO_ENABLED,
				   " rc_base_bitmap: %*phN", 16,
				   bitmap + i * per_page);
		}
		if (power_on) {
			sbi->dm_info->unfull_rc_base_blkaddr =
				disk_bitmap->unfull_blkaddr;
			print_info(PRINT_IMPORTANT_INFO_ENABLED,
				   "load unfull_rc_base_blkaddr: %llu",
				   sbi->dm_info->unfull_rc_base_blkaddr);
		}
	}
	if (load_rcd) {
		bitmap_blkaddr = sbi->dm_info->rc_delta_bitmap_blkaddr;
		page_num       = RC_DELTA_BITMAP_PAGESIZE;
		bitmap	       = sbi->dm_info->rc_delta_bitmap;
		total_size     = RC_DELTA_BITMAP_SIZE;

		for (i = 0; i < page_num; i++) {
			ret = f2dfs_read_meta_page_direct(sbi, disk_bitmap,
							  bitmap_blkaddr + i);
			if (ret < 0) {
				kvfree(disk_bitmap);
				print_err(
					"Failed to read rc delta bitmap page %d",
					i);
				return ret;
			}
			copy_bytes = min(per_page, total_size - i * per_page);
			memcpy(bitmap + i * per_page, disk_bitmap->bitmap,
			       copy_bytes);

			print_info(PRINT_IMPORTANT_INFO_ENABLED,
				   " rc_delta_bitmap: %*phN", 16,
				   bitmap + i * per_page);
		}
		if (power_on) {
			sbi->dm_info->unfull_rc_delta_blkaddr =
				disk_bitmap->unfull_blkaddr;
			print_info(PRINT_IMPORTANT_INFO_ENABLED,
				   "load unfull_rc_delta_blkaddr: %llu",
				   sbi->dm_info->unfull_rc_delta_blkaddr);
		}
	}
	kvfree(disk_bitmap);
	return 0;
}

int f2dfs_store_dm_bitmap(struct f2fs_sb_info *sbi, bool store_fp,
			  bool store_rcb, bool store_rcd)
{
	block_t bitmap_blkaddr, page_num;
	char *bitmap;
	size_t total_size, per_page, copy_bytes;
	int i, ret;
	struct f2dfs_bitmap_disk *disk_bitmap;

	f2fs_bug_on(sbi, !(store_fp || store_rcb || store_rcd));

	per_page    = sizeof(((struct f2dfs_bitmap_disk *)0)->bitmap);
	disk_bitmap = kmalloc(sizeof(struct f2dfs_bitmap_disk), GFP_KERNEL);
	if (!disk_bitmap) {
		print_err("Failed to allocate disk_bitmap");
		return -ENOMEM;
	}

	if (store_fp) {
		bitmap_blkaddr = sbi->dm_info->fp_bitmap_blkaddr;
		page_num       = FP_BITMAP_PAGESIZE;
		bitmap	       = sbi->dm_info->fp_bitmap;
		total_size     = FP_BITMAP_SIZE;

		for (i = 0; i < page_num; i++) {
			memset(disk_bitmap, 0,
			       sizeof(struct f2dfs_bitmap_disk));
			copy_bytes = min(per_page, total_size - i * per_page);
			memcpy(disk_bitmap->bitmap, bitmap + i * per_page,
			       copy_bytes);
			disk_bitmap->unfull_blkaddr =
				sbi->dm_info->unfull_fp_blkaddr;
			print_info(PRINT_IMPORTANT_INFO_ENABLED,
				   "      fp_bitmap: %*phN", 16,
				   disk_bitmap->bitmap);
			ret = f2dfs_write_meta_page(sbi, disk_bitmap,
						    bitmap_blkaddr + i);
			if (ret < 0) {
				kvfree(disk_bitmap);
				print_err("Failed to write fp bitmap page %d",
					  i);
				return ret;
			}
		}
		print_info(PRINT_IMPORTANT_INFO_ENABLED,
			   "store unfull_fp_blkaddr: %llu",
			   sbi->dm_info->unfull_fp_blkaddr);
		f2fs_bug_on(sbi,
			    sbi->dm_info->unfull_fp_blkaddr != NULL_ADDR &&
				    !f2dfs_is_block_set(
					    sbi->dm_info->fp_blkaddr,
					    sbi->dm_info->unfull_fp_blkaddr,
					    sbi->dm_info->fp_bitmap));
	}
	if (store_rcb) {
		bitmap_blkaddr = sbi->dm_info->rc_base_bitmap_blkaddr;
		page_num       = RC_BASE_BITMAP_PAGESIZE;
		bitmap	       = sbi->dm_info->rc_base_bitmap;
		total_size     = RC_BASE_BITMAP_SIZE;

		for (i = 0; i < page_num; i++) {
			memset(disk_bitmap, 0,
			       sizeof(struct f2dfs_bitmap_disk));
			copy_bytes = min(per_page, total_size - i * per_page);
			memcpy(disk_bitmap->bitmap, bitmap + i * per_page,
			       copy_bytes);
			disk_bitmap->unfull_blkaddr =
				sbi->dm_info->unfull_rc_base_blkaddr;
			print_info(PRINT_IMPORTANT_INFO_ENABLED,
				   " rc_base_bitmap: %*phN", 16,
				   disk_bitmap->bitmap);
			ret = f2dfs_write_meta_page_direct(sbi, disk_bitmap,
							   bitmap_blkaddr + i);
			if (ret < 0) {
				kvfree(disk_bitmap);
				print_err(
					"Failed to write rc base bitmap page %d",
					i);
				return ret;
			}
		}
		print_info(PRINT_IMPORTANT_INFO_ENABLED,
			   "store unfull_rc_base_blkaddr: %llu",
			   sbi->dm_info->unfull_rc_base_blkaddr);
		f2fs_bug_on(
			sbi,
			sbi->dm_info->unfull_rc_base_blkaddr != NULL_ADDR &&
				!f2dfs_is_block_set(
					sbi->dm_info->rc_base_blkaddr,
					sbi->dm_info->unfull_rc_base_blkaddr,
					sbi->dm_info->rc_base_bitmap));
	}
	if (store_rcd) {
		bitmap_blkaddr = sbi->dm_info->rc_delta_bitmap_blkaddr;
		page_num       = RC_DELTA_BITMAP_PAGESIZE;
		bitmap	       = sbi->dm_info->rc_delta_bitmap;
		total_size     = RC_DELTA_BITMAP_SIZE;

		for (i = 0; i < page_num; i++) {
			memset(disk_bitmap, 0,
			       sizeof(struct f2dfs_bitmap_disk));
			copy_bytes = min(per_page, total_size - i * per_page);
			memcpy(disk_bitmap->bitmap, bitmap + i * per_page,
			       copy_bytes);
			disk_bitmap->unfull_blkaddr =
				sbi->dm_info->unfull_rc_delta_blkaddr;
			print_info(PRINT_IMPORTANT_INFO_ENABLED,
				   "rc_delta_bitmap: %*phN", 16,
				   disk_bitmap->bitmap);
			ret = f2dfs_write_meta_page_direct(sbi, disk_bitmap,
							   bitmap_blkaddr + i);
			if (ret < 0) {
				kvfree(disk_bitmap);
				f2fs_err(
					sbi,
					"Failed to write rc delta bitmap page %d",
					i);
				return ret;
			}
		}
		print_info(PRINT_IMPORTANT_INFO_ENABLED,
			   "store unfull_rc_delta_blkaddr: %llu",
			   sbi->dm_info->unfull_rc_delta_blkaddr);
		f2fs_bug_on(
			sbi,
			sbi->dm_info->unfull_rc_delta_blkaddr != NULL_ADDR &&
				!f2dfs_is_block_set(
					sbi->dm_info->rc_delta_blkaddr,
					sbi->dm_info->unfull_rc_delta_blkaddr,
					sbi->dm_info->rc_delta_bitmap));
	}
	kvfree(disk_bitmap);
	return 0;
}

static inline int f2dfs_get_fp_hash_index(char *fingerprint)
{
	__u32 *fp_as_u32 = (__u32 *)fingerprint;

	return (*fp_as_u32) & (FP_HASH_TABLE_ENTRIES_NUM - 1);
}

int insert_in_fp_hash_table(struct f2fs_sb_info *sbi, char *fingerprint,
			    virtual_t vaddr)
{
	int index;
	struct fp_entry *entry;

	if (!sbi || !sbi->dm_info || !sbi->dm_info->fp_hash_table ||
	    !fingerprint || vaddr == NULL_ADDR) {
		print_err("Invalid parameters for insert_in_fp_hash_table");
		return -EINVAL;
	}

	index = f2dfs_get_fp_hash_index(fingerprint);
	if (index < 0 || index >= FP_HASH_TABLE_ENTRIES_NUM) {
		print_err("Invalid index %d for fingerprint hash table", index);
		return -EINVAL;
	}

	entry = &sbi->dm_info->fp_hash_table[index];

	if (entry->vaddr != NULL_ADDR) {
		if (!memcmp(entry->fingerprint, fingerprint, FP_LEN_MAX)) {
			if (entry->vaddr == vaddr) {
				return 0;
			} else {
				print_err(
					"Hash collision: same fingerprint but different vaddr");

				entry->vaddr = vaddr;
				return 0;
			}
		} else {
			print_err(
				"Hash table slot occupied by different fingerprint, replacing");
		}
	}

	memcpy(entry->fingerprint, fingerprint, FP_LEN_MAX);
	entry->vaddr = vaddr;

	return 0;
}

int delete_in_fp_hash_table(struct f2fs_sb_info *sbi, virtual_t vaddr,
			    bool delete)
{
	int index;
	struct fp_entry *entry;

	if (!sbi || !sbi->dm_info || !sbi->dm_info->fp_hash_table ||
	    vaddr == NULL_ADDR) {
		print_err("Invalid parameters for delete_in_fp_hash_table");
		return -EINVAL;
	}

	for (index = 0; index < FP_HASH_TABLE_ENTRIES_NUM; index++) {
		entry = &sbi->dm_info->fp_hash_table[index];
		if (entry->vaddr == vaddr) {
			if (delete) {
				memset(entry->fingerprint, 0, FP_LEN_MAX);
				entry->vaddr = NULL_ADDR;
			}
			return FP_BUFFER_SEARCH_UNIQUE;
		}
	}
	return -FP_BUFFER_SEARCH_DUPL;
}

int search_in_fp_hash_table(struct f2fs_sb_info *sbi, char *fingerprint,
			    virtual_t *vaddr)
{
	int index = 0;
	struct fp_entry *entry;
	if (!sbi || !sbi->dm_info || !sbi->dm_info->fp_hash_table ||
	    !fingerprint || !vaddr) {
		print_err("Invalid parameters for search_in_fp_hash_table");
		return -EINVAL;
	}
	index = f2dfs_get_fp_hash_index(fingerprint);
	f2fs_bug_on(sbi, index < 0 || index >= FP_HASH_TABLE_ENTRIES_NUM);

	entry = &sbi->dm_info->fp_hash_table[index];
	if (entry->vaddr == NULL_ADDR &&
	    !memcmp(entry->fingerprint, fingerprint, FP_LEN_MAX)) {
		*vaddr = entry->vaddr;
		return FP_BUFFER_SEARCH_DUPL;
	}
	*vaddr = NULL_ADDR;
	return -FP_BUFFER_SEARCH_UNIQUE;
}

int f2dfs_build_dedup_manager(struct f2fs_sb_info *sbi)
{
	struct f2fs_super_block *raw_super = sbi->raw_super;
	struct f2dfs_dm_info *dm_info;
	int ret;

	dm_info = f2fs_kzalloc(sbi, sizeof(struct f2dfs_dm_info), GFP_KERNEL);
	if (!dm_info)
		return -ENOMEM;

	dm_info->fp_bitmap_blkaddr = le32_to_cpu(raw_super->fp_meta_blkaddr);
	dm_info->rc_base_bitmap_blkaddr =
		dm_info->fp_bitmap_blkaddr + FP_BITMAP_PAGESIZE;
	dm_info->rc_delta_bitmap_blkaddr =
		dm_info->rc_base_bitmap_blkaddr + RC_BASE_BITMAP_PAGESIZE;

	dm_info->fp_blkaddr	  = le32_to_cpu(raw_super->fp_blkaddr);
	dm_info->rc_base_blkaddr  = le32_to_cpu(raw_super->rc_base_blkaddr);
	dm_info->rc_delta_blkaddr = le32_to_cpu(raw_super->rc_delta_blkaddr);
	dm_info->fp_blks =
		le32_to_cpu(raw_super->segment_count_fp) * sbi->blocks_per_seg;
	dm_info->rc_base_blks = le32_to_cpu(raw_super->segment_count_rc_base) *
				sbi->blocks_per_seg;
	dm_info->rc_delta_blks =
		le32_to_cpu(raw_super->segment_count_rc_delta) *
		sbi->blocks_per_seg;

	dm_info->fp_bitmap = f2fs_kvzalloc(
		sbi, DIV_ROUND_UP(dm_info->fp_blks, 8), GFP_KERNEL);
	if (!dm_info->fp_bitmap) {
		kvfree(dm_info);
		print_err("Failed to allocate fp_bitmap");
		return -ENOMEM;
	}
	dm_info->rc_base_bitmap = f2fs_kvzalloc(
		sbi, DIV_ROUND_UP(dm_info->rc_base_blks, 8), GFP_KERNEL);
	if (!dm_info->rc_base_bitmap) {
		kvfree(dm_info->fp_bitmap);
		kvfree(dm_info);
		print_err("Failed to allocate rc_base_bitmap");
		return -ENOMEM;
	}
	dm_info->rc_delta_bitmap = f2fs_kvzalloc(
		sbi, DIV_ROUND_UP(dm_info->rc_delta_blks, 8), GFP_KERNEL);
	if (!dm_info->rc_delta_bitmap) {
		kvfree(dm_info->fp_bitmap);
		kvfree(dm_info->rc_base_bitmap);
		kvfree(dm_info);
		print_err("Failed to allocate rc_delta_bitmap");
		return -ENOMEM;
	}
	sbi->dm_info = dm_info;
	ret	     = f2dfs_load_dm_bitmap(sbi, true, true, true, true);

	if (ENABLE_FP_HASH_TABLE) {
		dm_info->fp_hash_table = f2fs_kvzalloc(
			sbi,
			sizeof(struct fp_entry) * FP_HASH_TABLE_ENTRIES_NUM,
			GFP_KERNEL);
		if (!dm_info->fp_hash_table) {
			kvfree(dm_info);
			sbi->dm_info = NULL;
			print_err("Failed to allocate fp_hash_table");
			return -ENOMEM;
		}
	} else {
		dm_info->fp_hash_table = NULL;
	}

	spin_lock_init(&dm_info->fp_lock);
	spin_lock_init(&dm_info->rc_base_lock);
	spin_lock_init(&dm_info->rc_delta_lock);

	if (ret) {
		kvfree(dm_info->fp_bitmap);
		kvfree(dm_info->rc_base_bitmap);
		kvfree(dm_info->rc_delta_bitmap);
		kvfree(dm_info);
		sbi->dm_info = NULL;
		print_err("Failed to load dm bitmap");
	}
	return ret;
}

static inline void f2dfs_compute_single_fingerprint(struct f2fs_sb_info *sbi,
						    struct sdesc *sdesc,
						    struct page *page,
						    __u8 digest[])
{
	crypto_shash_init(&sdesc->shash);
	sbi->s_fp_hash->basic_hash_info->fp_update(
		&sdesc->shash, page_address(page), PAGE_SIZE);
	crypto_shash_final(&sdesc->shash, digest);
}

static void f2dfs_do_single_fp_hash_work(struct work_struct *work)
{
	struct f2dfs_single_hash_job *job =
		container_of(work, struct f2dfs_single_hash_job, page_work);
	struct f2fs_sb_info *sbi = job->sbi;

	job->sdesc = init_sdesc(sbi->s_fp_hash->basic_hash_info->alg);
	f2dfs_compute_single_fingerprint(sbi, job->sdesc, job->page,
					 job->search_result.fingerprint);
	kvfree(job->sdesc);
	mutex_unlock(&job->work_mutex);
}

void f2dfs_enqueue_single_fp_hash_work(struct f2fs_sb_info *sbi, int job_no,
				       struct page *page)
{
	struct f2dfs_single_hash_job *job = &sbi->s_fp_hash->hash_jobs[job_no];

	mutex_lock(&job->work_mutex);

	job->sbi = sbi;
	memset(&job->search_result.fingerprint, 0, FP_LEN_MAX);
	job->index = (page->index);
	job->page  = page;

	INIT_WORK(&job->page_work, f2dfs_do_single_fp_hash_work);

	queue_work(sbi->s_fp_hash->parallel_hash_workqueue, &job->page_work);
}

int delete_fp_in_buffer(struct f2fs_sb_info *sbi, virtual_t vaddr,
			block_t fp_page_addr, bool delete)
{
	struct f2dfs_fp_bucket *buf;
	int i, n;

	buf = sbi->fp_buffer;
	if (unlikely(!buf)) {
		print_err("buffer is NULL");
		return -FP_BUFFER_SEARCH_UNIQUE;
	}

	f2fs_bug_on(sbi, !rwsem_is_locked(&sbi->fp_buffer_lock));
	if (delete)
		f2fs_bug_on(sbi,
			    !rwsem_is_locked(&sbi->fp_buffer_lock) ||
				    !rwsem_is_locked(&sbi->fp_buffer_lock));

	if (fp_page_addr != NULL_ADDR && fp_page_addr != buf->blkaddr)
		return -FP_BUFFER_SEARCH_UNIQUE;

	n = buf->valid_count;
	if (unlikely(n == 0))
		return -FP_BUFFER_SEARCH_UNIQUE;

	for (i = 0; i < n; i++) {
		if (buf->entries[i].vaddr != vaddr)
			continue;

		if (delete) {
#ifndef F2DFS_KEEP_ORDER

			int last = n - 1;
			if (likely(i != last))
				buf->entries[i] = buf->entries[last];

			memset(&buf->entries[last], 0, sizeof(struct fp_entry));
			buf->valid_count = last;
#else

			memmove(&buf->entries[i], &buf->entries[i + 1],
				(n - i - 1) * sizeof(struct fp_entry));
			buf->valid_count = n - 1;
#endif
		} else {
			print_info(
				PRINT_BASIC_INFO_ENABLED,
				"Found fingerprint in buffer, but not deleting");
		}
		return FP_BUFFER_SEARCH_DUPL;
	}

	if (fp_page_addr == buf->blkaddr) {
		print_err(
			"Fingerprint page address matches but not found in buffer, vaddr: %u, fp_page_addr: %u, valid_count: %u",
			vaddr, fp_page_addr, buf->valid_count);
		return -FP_PAGE_ADDR_MATCH_BUT_NOT_FOUND;
	}
	return -FP_BUFFER_SEARCH_UNIQUE;
}

static inline int delete_fp_in_bucket(struct f2fs_sb_info *sbi,
				      struct f2dfs_fp_bucket *bucket,
				      virtual_t vaddr, bool delete)
{
	struct f2dfs_fp_bucket_in_disk *raw_bucket;
	struct fp_entry *entries = bucket->entries;
	int i, n = bucket->valid_count;

	if (unlikely(is_bucket_empty(bucket)))
		return -FP_BUFFER_SEARCH_UNIQUE;

	prefetch(entries);

	for (i = 0; i < n; ++i) {
		if (entries[i].vaddr != vaddr) {
			if (unlikely((i & 0x7) == 0))
				prefetch(entries + i + 8);
			continue;
		}

		if (delete) {
#ifndef F2DFS_KEEP_ORDER

			int last = n - 1;
			if (likely(i != last))
				entries[i] = entries[last];

			memset(&entries[last], 0, sizeof(struct fp_entry));
			bucket->valid_count = last;
#else

			memmove(&entries[i], &entries[i + 1],
				(n - i - 1) * sizeof(struct fp_entry));
			bucket->valid_count = n - 1;
#endif

			if (bucket->valid_count == 0)
				return FP_BUFFER_SEARCH_DUPL;

			raw_bucket = f2fs_kvmalloc(
				sbi, sizeof(struct f2dfs_fp_bucket_in_disk),
				GFP_NOFS);
			if (unlikely(!raw_bucket)) {
				print_err("Failed to allocate raw bucket");
				return -ENOMEM;
			}
			copy_bucket_to_raw_bucket(raw_bucket, bucket, true);
			if (unlikely(f2dfs_write_meta_page(sbi, raw_bucket,
							   bucket->blkaddr) <
				     0)) {
				print_err(
					"Failed to write meta page for bucket");
				kvfree(raw_bucket);
				return -EIO;
			}
			kvfree(raw_bucket);
		} else {
			print_info(
				PRINT_BASIC_INFO_ENABLED,
				"Found fingerprint in bucket, but not deleting");
		}
		return FP_BUFFER_SEARCH_DUPL;
	}
	return -FP_BUFFER_SEARCH_UNIQUE;
}

static int f2dfs_buckets_free_empty_bucket(struct f2fs_sb_info *sbi,
					   int bucket_index)
{
	int i;
	struct f2dfs_fp_bucket *bucket;
	f2fs_bug_on(sbi,
		    bucket_index < 0 ||
			    bucket_index >= sbi->s_fp_bucket->current_number);
	bucket = sbi->s_fp_bucket->pointers[bucket_index];
	f2fs_bug_on(sbi, !bucket);
	if (bucket->valid_count > 0) {
		print_err("Cannot free non-empty bucket at index %d",
			  bucket_index);
		return -EINVAL;
	}

	f2dfs_free_block(sbi->dm_info->fp_blkaddr, bucket->blkaddr,
			 sbi->dm_info->fp_bitmap);

	kmem_cache_free(sbi->s_fp_bucket->bucket_cache, bucket);

	for (i = bucket_index; i < sbi->s_fp_bucket->current_number - 1; i++) {
		sbi->s_fp_bucket->pointers[i] =
			sbi->s_fp_bucket->pointers[i + 1];
	}
	sbi->s_fp_bucket->pointers[sbi->s_fp_bucket->current_number - 1] = NULL;
	sbi->s_fp_bucket->current_number--;
	return 0;
}

int delete_fp_in_buckets(struct f2fs_sb_info *sbi, virtual_t vaddr,
			 block_t fp_page_addr, bool delete)
{
	int i, ret = -FP_BUFFER_SEARCH_UNIQUE;

	f2fs_bug_on(sbi, !rwsem_is_locked(&sbi->s_fp_bucket_lock));

	if (likely(fp_page_addr != NULL_ADDR)) {
		for (i = 0; i < sbi->s_fp_bucket->current_number; i++) {
			struct f2dfs_fp_bucket *bucket =
				sbi->s_fp_bucket->pointers[i];
			f2fs_bug_on(sbi, !bucket);
			if (bucket->blkaddr != fp_page_addr)
				continue;

			prefetch(bucket);
			prefetch(bucket->entries);
			ret = delete_fp_in_bucket(sbi, bucket, vaddr, delete);
			if (ret == FP_BUFFER_SEARCH_DUPL) {
				if (bucket->valid_count == 0) {
					f2dfs_buckets_free_empty_bucket(sbi, i);
					return ret;
				}
				bucket->atime = jiffies;
				return ret;
			}

			print_err(
				"Fingerprint page address matches but not found in bucket, bucket.blkaddr: %u, bucket.valid_count: %u",
				bucket->blkaddr, bucket->valid_count);
			return -FP_PAGE_ADDR_MATCH_BUT_NOT_FOUND;
		}

		return -FP_BUFFER_SEARCH_UNIQUE;
	}

	for (i = sbi->s_fp_bucket->current_number - 1; i >= 0; i--) {
		struct f2dfs_fp_bucket *bucket = sbi->s_fp_bucket->pointers[i];
		f2fs_bug_on(sbi, !bucket);

		prefetch(bucket);
		prefetch(bucket->entries);
		ret = delete_fp_in_bucket(sbi, bucket, vaddr, delete);
		if (ret == FP_BUFFER_SEARCH_DUPL) {
			print_info(
				PRINT_BASIC_INFO_ENABLED,
				"Found fingerprint in bucket, blkaddr: %u, valid_count: %u",
				bucket->blkaddr, bucket->valid_count);
			if (bucket->valid_count == 0) {
				f2dfs_buckets_free_empty_bucket(sbi, i);
				return ret;
			}
			bucket->atime = jiffies;
			return ret;
		}

		if (unlikely(GIVE_UP_CPU_ENABLE &&
			     ((sbi->s_fp_bucket->current_number - 1 - i) &
			      FP_SCAN_RESCHED_MASK) == 0) &&
		    need_resched())
			cond_resched();
	}
	return -FP_BUFFER_SEARCH_UNIQUE;
}

static inline int f2dfs_delete_fingerprint_in_raw_bucket_and_wb(
	struct f2fs_sb_info *sbi, struct f2dfs_fp_bucket_in_disk *raw_bucket,
	block_t raw_blkaddr, virtual_t vaddr, bool delete)
{
	int i, j;
	f2fs_bug_on(sbi, !is_fp_raw_bucket(raw_bucket));
	if (is_raw_bucket_empty(raw_bucket)) {
		return -RAW_BUCKET_EMPTY;
	}

	for (i = 0, j = 0; j < raw_bucket->valid_count; i++) {
		if (!test_bit_le(i, raw_bucket->invalidmap)) {
			if (raw_bucket->entries[i].vaddr == vaddr) {
				if (delete) {
					set_bit_le(i, raw_bucket->invalidmap);
					raw_bucket->valid_count--;
					if (raw_bucket->valid_count > 0) {
						f2dfs_write_meta_page(
							sbi, raw_bucket,
							raw_blkaddr);
					} else {
						print_info(
							PRINT_IMPORTANT_INFO_ENABLED,
							"raw bucket blkaddr: %x:%u is empty, freeing it",
							raw_blkaddr,
							raw_blkaddr);
						f2dfs_free_block(
							sbi->dm_info->fp_blkaddr,
							raw_blkaddr,
							sbi->dm_info->fp_bitmap);
					}
				} else {
					print_info(
						PRINT_BASIC_INFO_ENABLED,
						"Found fingerprint in raw bucket, but not deleting");
				}
				return FP_BUFFER_SEARCH_DUPL;
			} else {
				j++;
			}
		}
	}
	return -FP_BUFFER_SEARCH_UNIQUE;
}

int delete_fp_in_disk_protected(struct f2fs_sb_info *sbi, virtual_t vaddr,
				bool delete)
{
	block_t start				   = sbi->dm_info->fp_blkaddr;
	block_t count				   = sbi->dm_info->fp_blks;
	block_t fp_buckets_num			   = 0;
	block_t *fp_buckets			   = NULL;
	int ret					   = -FP_BUFFER_SEARCH_UNIQUE;
	struct f2dfs_fp_bucket_in_disk *raw_buffer = NULL;
	unsigned long i;

	raw_buffer =
		kmalloc(sizeof(struct f2dfs_fp_bucket_in_disk), GFP_KERNEL);
	if (!raw_buffer) {
		print_err("Failed to allocate memory for raw buffer");
		return -ENOMEM;
	}

	down_read(&sbi->fp_buffer_lock);
	down_read(&sbi->s_fp_bucket_lock);

	{
		block_t need =
			(sbi->s_fp_bucket ? sbi->s_fp_bucket->current_number :
					    0) +
			(sbi->fp_buffer ? 1 : 0);
		fp_buckets = kvmalloc_array(max_t(block_t, need, 1),
					    sizeof(block_t), GFP_KERNEL);
		if (!fp_buckets) {
			up_read(&sbi->s_fp_bucket_lock);
			up_read(&sbi->fp_buffer_lock);
			kvfree(raw_buffer);
			print_err("Failed to allocate memory for fp_buckets");
			return -ENOMEM;
		}
	}

	if (sbi->fp_buffer)
		fp_buckets[fp_buckets_num++] = sbi->fp_buffer->blkaddr;

	if (sbi->s_fp_bucket) {
		int k;
		for (k = 0; k < sbi->s_fp_bucket->current_number; k++) {
			struct f2dfs_fp_bucket *mem_bucket =
				sbi->s_fp_bucket->pointers[k];
			f2fs_bug_on(sbi, !mem_bucket);
			fp_buckets[fp_buckets_num++] = mem_bucket->blkaddr;
		}
	}

	up_read(&sbi->s_fp_bucket_lock);
	up_read(&sbi->fp_buffer_lock);

	if (fp_buckets_num > 1)
		sort(fp_buckets, fp_buckets_num, sizeof(block_t), cmp_block_t,
		     NULL);

	for (i = find_next_bit_le((unsigned long *)sbi->dm_info->fp_bitmap,
				  count, 0);
	     i < count;
	     i = find_next_bit_le((unsigned long *)sbi->dm_info->fp_bitmap,
				  count, i + 1)) {
		block_t raw_buffer_blkaddr = start + i;

		if (fp_buckets_num) {
			block_t *found = bsearch(&raw_buffer_blkaddr,
						 fp_buckets, fp_buckets_num,
						 sizeof(block_t), cmp_block_t);
			if (found)
				continue;
		}

		ret = f2dfs_read_meta_page(sbi, raw_buffer, raw_buffer_blkaddr);
		if (ret < 0)
			continue;

		if (unlikely(!is_fp_raw_bucket(raw_buffer))) {
			f2fs_bug_on(sbi, !is_raw_bucket_empty(raw_buffer));
			continue;
		}

		ret = f2dfs_delete_fingerprint_in_raw_bucket_and_wb(
			sbi, raw_buffer, raw_buffer_blkaddr, vaddr, delete);

		if (ret == FP_BUFFER_SEARCH_DUPL) {
			if (raw_buffer->valid_count == 0) {
				print_info(
					PRINT_IMPORTANT_INFO_ENABLED,
					"bucket blkaddr: %x:%u is empty, freeing it",
					raw_buffer_blkaddr, raw_buffer_blkaddr);
				spin_lock(&sbi->dm_info->fp_lock);
				f2dfs_free_block(sbi->dm_info->fp_blkaddr,
						 raw_buffer_blkaddr,
						 sbi->dm_info->fp_bitmap);
				spin_unlock(&sbi->dm_info->fp_lock);
			}

			kvfree(raw_buffer);
			kvfree(fp_buckets);
			if (delete)
				print_info(
					PRINT_BASIC_INFO_ENABLED,
					"delete fingerprint in disk, vaddr: %x:%u, fp_page_addr: %x:%u, count:%u",
					vaddr, vaddr, raw_buffer_blkaddr,
					raw_buffer_blkaddr,
					raw_buffer->valid_count);
			return ret;
		}

		if (unlikely(GIVE_UP_CPU_ENABLE &&
			     (i & FP_SCAN_RESCHED_MASK) == 0) &&
		    need_resched())
			cond_resched();
	}

	kvfree(raw_buffer);
	kvfree(fp_buckets);
	print_info(PRINT_BASIC_INFO_ENABLED, "Fingerprint is unique");
	return -FP_BUFFER_SEARCH_UNIQUE;
}

int f2dfs_invalid_fp_entry(struct f2fs_sb_info *sbi, virtual_t vaddr,
			   block_t fp_page_addr, struct node_info ni)
{
	struct f2dfs_fp_bucket_in_disk *raw_bucket;
	int ret;
	f2fs_bug_on(sbi, ni.ino != INO_MAGIC);
	f2fs_bug_on(sbi, !(fp_page_addr >= sbi->dm_info->fp_blkaddr &&
			   fp_page_addr < sbi->dm_info->rc_base_blkaddr));

	down_read(&sbi->fp_buffer_lock);
	ret = delete_fp_in_buffer(sbi, vaddr, fp_page_addr, true);
	if (ret >= 0) {
		print_info(
			PRINT_BASIC_INFO_ENABLED,
			"delete fingerprint in buffer, vaddr: %x:%u, ni.blkaddr: %x:%u, fp_page_addr: %x:%u, count: %u",
			vaddr, vaddr, ni.blk_addr, ni.blk_addr, fp_page_addr,
			fp_page_addr, sbi->fp_buffer->valid_count);
		up_read(&sbi->fp_buffer_lock);
		return 0;
	} else if (fp_page_addr == sbi->fp_buffer->blkaddr) {
		print_err(
			"vaddr(ni.nid): %x:%u should be found in buffer but not found, ni.blkaddr: %x:%u, fp_page_addr: %x:%u, count: %u",
			vaddr, vaddr, ni.blk_addr, ni.blk_addr, fp_page_addr,
			fp_page_addr, sbi->fp_buffer->valid_count);
		up_read(&sbi->fp_buffer_lock);
		return -FP_PAGE_ADDR_MATCH_BUT_NOT_FOUND;
	}
	up_read(&sbi->fp_buffer_lock);

	down_read(&sbi->s_fp_bucket_lock);
	ret = delete_fp_in_buckets(sbi, vaddr, fp_page_addr, true);
	if (ret >= 0) {
		up_read(&sbi->s_fp_bucket_lock);
		return 0;
	} else if (ret == -FP_PAGE_ADDR_MATCH_BUT_NOT_FOUND) {
		up_read(&sbi->s_fp_bucket_lock);
		print_err(
			"vaddr(ni.nid): %x:%u should be found in buckets but not found, ni.blkaddr: %x:%u, fp_page_addr: %x:%u",
			vaddr, vaddr, ni.blk_addr, ni.blk_addr, fp_page_addr,
			fp_page_addr);
		return -FP_PAGE_ADDR_MATCH_BUT_NOT_FOUND;
	}
	up_read(&sbi->s_fp_bucket_lock);

	if (fp_page_addr == NULL_ADDR) {
		if (delete_fp_in_disk_protected(sbi, vaddr, true) >= 0) {
			return 0;
		} else {
			f2fs_bug_on(sbi, vaddr != ni.nid);
			print_err(
				"vaddr(ni.nid): %x:%u not found in disk, ni.blkaddr: %x:%u, fp_page_addr: %x:%u",
				vaddr, vaddr, ni.blk_addr, ni.blk_addr,
				fp_page_addr, fp_page_addr);
			return -FP_BUFFER_SEARCH_UNIQUE;
		}
	}

	if (!f2dfs_is_block_set(sbi->dm_info->fp_blkaddr, fp_page_addr,
				sbi->dm_info->fp_bitmap)) {
		print_err(
			"fp_page_addr: %x:%u is not set in fp_bitmap, vaddr: %x:%u, ni.blkaddr: %x:%u",
			fp_page_addr, fp_page_addr, vaddr, vaddr, ni.blk_addr,
			ni.blk_addr);
		return -FP_BUFFER_SEARCH_UNIQUE;
	}
	raw_bucket =
		kmalloc(sizeof(struct f2dfs_fp_bucket_in_disk), GFP_KERNEL);
	if (!raw_bucket) {
		print_err("Failed to allocate memory for raw buffer");
		return -ENOMEM;
	}
	if (f2dfs_read_meta_page(sbi, raw_bucket, fp_page_addr) < 0) {
		print_err("Failed to read meta page at %x:%u", fp_page_addr,
			  fp_page_addr);
		kvfree(raw_bucket);
		return -EIO;
	}

	ret = f2dfs_delete_fingerprint_in_raw_bucket_and_wb(
		sbi, raw_bucket, fp_page_addr, vaddr, true);
	if (ret >= 0) {
		print_info(
			PRINT_BASIC_INFO_ENABLED,
			"delete fingerprint in disk, vaddr: %x:%u, ni.blkaddr: %x:%u, fp_page_addr: %x:%u, count: %u",
			vaddr, vaddr, ni.blk_addr, ni.blk_addr, fp_page_addr,
			fp_page_addr, raw_bucket->valid_count);
		kvfree(raw_bucket);
		return 0;
	} else if (ret == -RAW_BUCKET_EMPTY) {
		print_err(
			"vaddr(ni.nid): %x:%u should be found in disk but disk is empty (means bitmap is setted incorrect), ni.blkaddr: %x:%u, fp_page_addr: %x:%u",
			vaddr, vaddr, ni.blk_addr, ni.blk_addr, fp_page_addr,
			fp_page_addr);
		kvfree(raw_bucket);
		return -FP_BUFFER_SEARCH_UNIQUE;
	} else {
		f2fs_bug_on(sbi, vaddr != ni.nid);
		print_err(
			"vaddr(ni.nid): %x:%u should be found in disk but not found, ni.blkaddr: %x:%u, fp_page_addr: %x:%u, count: %u",
			vaddr, vaddr, ni.blk_addr, ni.blk_addr, fp_page_addr,
			fp_page_addr, raw_bucket->valid_count);
		kvfree(raw_bucket);
		return -FP_BUFFER_SEARCH_UNIQUE;
	}
}

static int add_or_merge_base_entry_optimized(
	struct f2fs_sb_info *sbi, struct hlist_head *rc_hash, int hash_bits,
	struct rc_base_entry *all_base, int *base_index,
	struct rc_base_entry *entry, int total_entries, int *duplicate_count)
{
	struct rc_merge_hash_entry *existing_entry;
	struct rc_merge_hash_entry *hash_entry;
	unsigned int hash_bucket = hash_min(entry->vaddr, hash_bits);

	hlist_for_each_entry (existing_entry, &rc_hash[hash_bucket], hnode) {
		if (existing_entry->vaddr == entry->vaddr) {
			(*duplicate_count)++;

			print_err(
				"Found duplicate base entry for vaddr: %x:%u, merging rc: %d + %d = %d",
				entry->vaddr, entry->vaddr,
				existing_entry->base_entry->rc, entry->rc,
				existing_entry->base_entry->rc + entry->rc);

			if (rc_overflow(existing_entry->base_entry->rc,
					entry->rc)) {
				print_err(
					"RC overflow detected when merging duplicate base entries, "
					"vaddr: %x:%u, existing_rc: %d, new_rc: %d",
					entry->vaddr, entry->vaddr,
					existing_entry->base_entry->rc,
					entry->rc);
				return -EOVERFLOW;
			}

			existing_entry->base_entry->rc += entry->rc;

			if (existing_entry->base_entry->fp_page_addr !=
			    entry->fp_page_addr) {
				print_err(
					"Duplicate base entries have different fp_page_addr: "
					"vaddr: %x:%u, existing: %x:%u, new: %x:%u",
					entry->vaddr, entry->vaddr,
					existing_entry->base_entry->fp_page_addr,
					existing_entry->base_entry->fp_page_addr,
					entry->fp_page_addr,
					entry->fp_page_addr);
			}

			return 0;
		}
	}

	if (*base_index >= total_entries) {
		print_err("Base index overflow: %d >= %d", *base_index,
			  total_entries);
		return -ENOSPC;
	}

	all_base[*base_index] = *entry;
	hash_entry	      = kmalloc(sizeof(*hash_entry), GFP_KERNEL);
	if (!hash_entry) {
		print_err("Failed to allocate hash entry for vaddr: %x:%u",
			  entry->vaddr, entry->vaddr);
		return -ENOMEM;
	}

	hash_entry->vaddr      = entry->vaddr;
	hash_entry->base_entry = &all_base[*base_index];
	hlist_add_head(&hash_entry->hnode, &rc_hash[hash_bucket]);

	(*base_index)++;
	return 0;
}

inline int f2dfs_send_nvme_admin_command(struct f2fs_sb_info *sbi, __u8 opcode,
					 __u32 cdw10)
{
	print_err(
		"NVME_REQUEST: device=%s opcode=0x%02X cdw10=%u timestamp=%lu",
		sbi->sb->s_bdev->bd_disk->disk_name, opcode, cdw10, jiffies);

	return 0;
}

int f2dfs_merge_rc_delta_to_base(struct f2fs_sb_info *sbi, bool exit)
{
	block_t i, base_blks, delta_blks;
	int j, ret = 0, base_total = 0, delta_total = 0;
	int hash_bits;
	int total_entries;
	int base_index;
	int written;
	int count = 0;
	block_t blkaddr;
	struct f2dfs_rc_base_buffer *base_buf	= NULL;
	struct f2dfs_rc_delta_buffer *delta_buf = NULL;
	struct rc_merge_hash_entry *hash_entry;
	struct hlist_node *tmp;
	struct hlist_head *rc_hash     = NULL;
	struct rc_base_entry *all_base = NULL;
	int fp_counter_zero = 0, fp_counter_unique = 0, fp_counter_dupl = 0;

	print_info(
		PRINT_IMPORTANT_INFO_ENABLED,
		"===========================f2dfs_merge_rc_delta_to_base: start merging================================");
	if (exit) {
		spin_lock(&sbi->rcb_buffer_lock);
		spin_lock(&sbi->dm_info->rc_base_lock);
		if (f2dfs_insert_rcb_buffer_into_storage(sbi) ==
		    -RC_BUFFER_INTO_STORAGE_FAILURE) {
			print_err(
				"Failed to insert fingerprint base buffer into storage");
		}
		spin_unlock(&sbi->dm_info->rc_base_lock);
		spin_unlock(&sbi->rcb_buffer_lock);
		spin_lock(&sbi->rcd_buffer_lock);
		if (f2dfs_insert_rc_delta_buffer_into_storage(sbi) ==
		    -RC_BUFFER_INTO_STORAGE_FAILURE) {
			print_err(
				"Failed to insert fingerprint delta buffer into storage");
		}

		spin_unlock(&sbi->rcd_buffer_lock);
	}

	spin_lock(&sbi->dm_info->rc_base_lock);
	spin_lock(&sbi->dm_info->rc_delta_lock);
	base_blks  = sbi->dm_info->rc_base_blks;
	delta_blks = sbi->dm_info->rc_delta_blks;
	base_buf   = kmalloc(sizeof(*base_buf), GFP_KERNEL);
	delta_buf  = kmalloc(sizeof(*delta_buf), GFP_KERNEL);
	if (!base_buf || !delta_buf) {
		print_err("Failed to allocate memory for base or delta buffer");
		goto out_free;
	}

	if (!exit)
		f2dfs_load_dm_bitmap(sbi, false, false, true, true);

	for (i = 0; i < base_blks; i++) {
		if (!test_bit_le(i, sbi->dm_info->rc_base_bitmap))
			continue;
		base_total++;
	}
	for (i = 0; i < delta_blks; i++) {
		if (!test_bit_le(i, sbi->dm_info->rc_delta_bitmap))
			continue;
		delta_total++;
	}

	if (delta_total > 1) {
		print_info(
			PRINT_IMPORTANT_INFO_ENABLED,
			"SSD background merging not finished, triggered background GC");

		ret = f2dfs_send_nvme_admin_command(
			sbi, 0xEF, FEMU_TRIGGER_RC_DELTA_MERGE);
		if (ret < 0) {
			print_err(
				"Failed to send NVMe background merge command");
		}

		kvfree(base_buf);
		kvfree(delta_buf);
		spin_unlock(&sbi->dm_info->rc_delta_lock);
		spin_unlock(&sbi->dm_info->rc_base_lock);
		return RCD_EMPTY_SKIP_MERGE;
	}

	if (exit) {
		sbi->dm_info->unfull_rc_base_blkaddr  = NULL_ADDR;
		sbi->dm_info->unfull_rc_delta_blkaddr = NULL_ADDR;
	}

	total_entries = (base_total)*RC_BASE_ENTRIES_PER_PAGE_MAX;
	if (!exit) {
		total_entries += sbi->rcb_buffer->valid_count;
	}
	hash_bits = 10;
	while ((FEMU_TRIGGER_RC_DELTA_MERGE << hash_bits) < total_entries)
		hash_bits++;
	print_info(PRINT_IMPORTANT_INFO_ENABLED,
		   "Total base entries: %d, delta entries: %d, "
		   "hash bits: %d, total alloc entries: %d",
		   base_total * RC_BASE_ENTRIES_PER_PAGE_MAX,
		   delta_total * RC_DELTA_ENTRIES_PER_PAGE_MAX, hash_bits,
		   1 << hash_bits);
	rc_hash = kvmalloc((1 << hash_bits) * sizeof(struct hlist_head),
			   GFP_KERNEL);
	if (!rc_hash) {
		print_err("Failed to allocate memory for rc_hash");
		goto out_free;
	}
	for (i = 0; i < (1 << hash_bits); i++)
		INIT_HLIST_HEAD(&rc_hash[i]);

	all_base = kvmalloc(total_entries * sizeof(struct rc_base_entry),
			    GFP_KERNEL);
	if (!all_base) {
		print_err("Failed to allocate memory for all_base");
		goto out_free_hash;
	}
	base_index = 0;

	for (i = 0; i < base_blks; i++) {
		int original_entries = 0;
		int duplicate_count  = 0;
		if (!test_bit_le(i, sbi->dm_info->rc_base_bitmap))
			continue;
		if (f2dfs_read_meta_page_direct(sbi, base_buf,
						sbi->dm_info->rc_base_blkaddr +
							i) < 0) {
			print_err("Failed to read base buffer");
			continue;
		}

		__clear_bit_le(i, sbi->dm_info->rc_base_bitmap);
		original_entries = base_buf->valid_count;
		for (j = 0; j < base_buf->valid_count; j++) {
			int ret = add_or_merge_base_entry_optimized(
				sbi, rc_hash, hash_bits, all_base, &base_index,
				&base_buf->entries[j], total_entries,
				&duplicate_count);
			if (ret < 0) {
				if (ret == -ENOMEM)
					goto out_free_hash;

				print_err(
					"Failed to add/merge base entry %d from block %d: %d",
					j, i, ret);
			}
		}

		if (duplicate_count > 0) {
			print_info(
				PRINT_IMPORTANT_INFO_ENABLED,
				"Block %d deduplication: original %d entries, %d duplicates merged, %d final entries",
				i, original_entries, duplicate_count,
				original_entries - duplicate_count);
		}
	}

	spin_lock(&sbi->rcb_buffer_lock);
	if (sbi->rcb_buffer->valid_count > 0) {
		for (j = 0; j < sbi->rcb_buffer->valid_count; j++) {
			int ret = add_or_merge_base_entry_optimized(
				sbi, rc_hash, hash_bits, all_base, &base_index,
				&sbi->rcb_buffer->entries[j], total_entries,
				&count);
			if (ret < 0) {
				if (ret == -ENOMEM)
					goto out_free_hash;
				print_err(
					"Failed to add/merge base entry from rc buffer: %d",
					ret);
			}
		}
		sbi->rcb_buffer->valid_count = 0;
	}
	spin_unlock(&sbi->rcb_buffer_lock);

	for (i = 0; i < delta_blks; i++) {
		if (!test_bit_le(i, sbi->dm_info->rc_delta_bitmap))
			continue;
		if (f2dfs_read_meta_page_direct(sbi, delta_buf,
						sbi->dm_info->rc_delta_blkaddr +
							i) < 0) {
			print_err("Failed to read delta buffer");
			continue;
		}

		__clear_bit_le(i, sbi->dm_info->rc_delta_bitmap);
		for (j = 0; j < delta_buf->valid_count; j++) {
			virtual_t vaddr = delta_buf->entries[j].vaddr;
			int rc		= delta_buf->entries[j].rc;
			bool found	= false;
			hlist_for_each_entry (
				hash_entry,
				&rc_hash[hash_min(vaddr, hash_bits)], hnode) {
				if (hash_entry->vaddr == vaddr) {
					f2fs_bug_on(
						sbi,
						rc_overflow(
							hash_entry->base_entry
								->rc,
							rc));
					hash_entry->base_entry->rc += rc;
					found = true;
					break;
				}
			}

			f2fs_bug_on(sbi, !found);
		}
	}

	print_info(PRINT_IMPORTANT_INFO_ENABLED,
		   "fp buffer blkaddr: %u, valid_count: %u",
		   sbi->fp_buffer->blkaddr, sbi->fp_buffer->valid_count);
	for (i = 0; i < sbi->s_fp_bucket->current_number; i++) {
		struct f2dfs_fp_bucket *bucket;
		bucket = sbi->s_fp_bucket->pointers[i];
		f2fs_bug_on(sbi, !bucket);
		print_info(PRINT_IMPORTANT_INFO_ENABLED,
			   "fp bucket %d blkaddr: %u, valid_count: %u", i,
			   bucket->blkaddr, bucket->valid_count);
	}

	for (i = 0; i < base_index; i++) {
		if (all_base[i].rc <= FP_COUNTER_ZERO) {
			fp_counter_zero++;
			release_block(sbi, all_base[i].vaddr,
				      all_base[i].fp_page_addr);

			memmove(&all_base[i], &all_base[i + 1],
				(base_index - i - 1) *
					sizeof(struct rc_base_entry));
			base_index--;
			i--;
		} else if (all_base[i].rc == FP_COUNTER_UNIQUE) {
			fp_counter_unique++;
		} else if (all_base[i].rc >= FP_COUNTER_DUPL) {
			fp_counter_dupl++;
		} else {
			print_err(
				"Unexpected rc value: %d for vaddr: 0x%08llx ",
				all_base[i].rc,
				(unsigned long long)all_base[i].vaddr);
		}
	}

	spin_lock(&sbi->stat_lock);
	sbi->duplication_block_count_low = fp_counter_dupl;
	sbi->unique_block_count		 = fp_counter_unique;
	sbi->total_valid_block_count -= (block_t)fp_counter_zero;
	if ((sbi->reserved_blocks != (block_t)0) &&
	    ((unsigned int)sbi->current_reserved_blocks <
	     (unsigned int)sbi->reserved_blocks))
		sbi->current_reserved_blocks =
			min((block_t)sbi->reserved_blocks,
			    (block_t)(sbi->current_reserved_blocks +
				      (block_t)fp_counter_zero));
	spin_unlock(&sbi->stat_lock);

	base_buf = krealloc(base_buf, sizeof(*base_buf), GFP_KERNEL);
	written	 = 0;
	while (written < base_index) {
		count = min((int)RC_BASE_ENTRIES_PER_PAGE_MAX,
			    base_index - written);
		if (count < RC_BASE_ENTRIES_PER_PAGE_MAX) {
			spin_lock(&sbi->rcb_buffer_lock);
		keep_write:
			for (; sbi->rcb_buffer->valid_count <
				       RC_BASE_ENTRIES_PER_PAGE_MAX &&
			       written < base_index;
			     written++) {
				sbi->rcb_buffer
					->entries[sbi->rcb_buffer->valid_count] =
					all_base[written];
				sbi->rcb_buffer->valid_count++;
			}
			if (sbi->rcb_buffer->valid_count >=
			    RC_BASE_ENTRIES_PER_PAGE_MAX) {
				ret = f2dfs_insert_rcb_buffer_into_storage(sbi);
				if (ret < 0) {
					print_err(
						"Failed to insert rc base buffer into storage");
					spin_unlock(&sbi->rcb_buffer_lock);
					goto out_free_hash;
				}
			}
			if (written < base_index) {
				goto keep_write;
			}
			spin_unlock(&sbi->rcb_buffer_lock);
			break;
		}
		memset(base_buf, 0, sizeof(*base_buf));
		memcpy(base_buf->entries, &all_base[written],
		       count * sizeof(struct rc_base_entry));
		base_buf->valid_count = count;
		blkaddr		      = f2dfs_find_free_block(sbi,
							      sbi->dm_info->rc_base_blkaddr,
							      base_blks,
							      sbi->dm_info->rc_base_bitmap);
		if (blkaddr == NULL_ADDR)
			goto out_free_hash;
		ret = f2dfs_write_meta_page_direct(sbi, base_buf, blkaddr);
		if (ret < 0)
			goto out_free_hash;
		written += count;
	}

	f2dfs_store_dm_bitmap(sbi, false, true, true);

	spin_unlock(&sbi->dm_info->rc_delta_lock);
	spin_unlock(&sbi->dm_info->rc_base_lock);

	for (i = 0; i < (1 << hash_bits); i++) {
		hlist_for_each_entry_safe (hash_entry, tmp, &rc_hash[i],
					   hnode) {
			hlist_del(&hash_entry->hnode);
			kvfree(hash_entry);
		}
	}
	kvfree(rc_hash);
	kvfree(all_base);
	kvfree(base_buf);
	kvfree(delta_buf);
	return 0;

out_free_hash:
	if (rc_hash) {
		for (i = 0; i < (1 << hash_bits); i++) {
			hlist_for_each_entry_safe (hash_entry, tmp, &rc_hash[i],
						   hnode) {
				hlist_del(&hash_entry->hnode);
				kvfree(hash_entry);
			}
		}
		kvfree(rc_hash);
	}
out_free:
	spin_unlock(&sbi->dm_info->rc_base_lock);
	spin_unlock(&sbi->dm_info->rc_delta_lock);
	kvfree(all_base);
	kvfree(base_buf);
	kvfree(delta_buf);
	return -ENOMEM;
}