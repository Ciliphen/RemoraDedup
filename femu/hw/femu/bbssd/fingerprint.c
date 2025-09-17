#include "../nvme.h"
#include "dedup.h"
#include "ftl.h"

static int init_merge_thread(FemuCtrl *n);
static void *background_merge_thread(void *arg);
static int f2dfs_write_meta_page(FemuCtrl *n, const void *src,
				 uint64_t f2fs_blkaddr);
static int load_bitmap(FemuCtrl *n, block_t bitmap_blkaddr);

static int bb_internal_read(FemuCtrl *n, uint64_t f2fs_blkaddr, void *dest,
			    size_t size)
{
	const uint8_t lba_index =
		NVME_ID_NS_FLBAS_INDEX(n->namespaces->id_ns.flbas);
	const uint8_t data_shift = n->namespaces->id_ns.lbaf[lba_index].lbads;
	uint64_t offset = (f2fs_blkaddr * 4096 / 512 + 2048) << data_shift;

	if (!n || !dest || size == 0) {
		femu_err("ssd_internal_read invalid parameters\r\n");
		return -1;
	}

	if (!n || !n->mbe || !n->mbe->logical_space) {
		femu_err("ssd_internal_read invalid backend\r\n");
		return -1;
	}

	if (offset + size > n->mbe->size) {
		femu_err("ssd_internal_read out of range, offset=%" PRIu64
			 ", size=%zu, mbe_size=%zu\r\n",
			 offset, size, n->mbe->size);
		return -1;
	}

	memcpy(dest, (char *)n->mbe->logical_space + offset, size);
	return 0;
}

void f2dfs_free_block(block_t start_blk, block_t blkaddr, char *bitmap)
{
	unsigned int idx = blkaddr - start_blk;
	clear_bit(idx, (unsigned long *)bitmap);
}

void f2dfs_set_block(block_t start_blk, block_t blkaddr, char *bitmap)
{
	unsigned int idx = blkaddr - start_blk;
	set_bit(idx, (unsigned long *)bitmap);
}

static bool __attribute__((unused))
f2dfs_is_block_set(block_t start_blk, block_t blkaddr, char *bitmap)
{
	unsigned int idx = blkaddr - start_blk;
	return test_bit(idx, (unsigned long *)bitmap);
}

static int f2dfs_read_meta_page(FemuCtrl *n, void *dst, uint64_t f2fs_blkaddr)
{
	if (!n || !dst) {
		femu_err("ssd_internal_read_page invalid parameters\r\n");
		return -1;
	}

	bb_internal_read(n, f2fs_blkaddr, dst, PAGE_SIZE);
	return 0;
}

block_t f2dfs_find_free_block(block_t start_blk, block_t blks_num, char *bitmap)
{
	unsigned int i;

	for (i = 0; i < blks_num; i++) {
		if (!test_bit(i, (unsigned long *)bitmap)) {
			set_bit(i, (unsigned long *)bitmap);
			return start_blk + i;
		}
	}
	return NULL_ADDR;
}

void init_dm_info(FemuCtrl *n)
{
	struct f2dfs_dm_info *dm_info;

	dm_info = g_malloc0(sizeof(struct f2dfs_dm_info));

	dm_info->fp_bitmap_blkaddr = FP_META_BLKADDR;
	dm_info->rc_base_bitmap_blkaddr =
		dm_info->fp_bitmap_blkaddr + FP_BITMAP_PAGESIZE;
	dm_info->rc_delta_bitmap_blkaddr =
		dm_info->rc_base_bitmap_blkaddr + RC_BASE_BITMAP_PAGESIZE;

	dm_info->rc_base_blkaddr  = RC_BASE_BLKADDR;
	dm_info->rc_delta_blkaddr = RC_DELTA_BLKADDR;

	dm_info->rc_base_blks  = RC_BASE_BLKS;
	dm_info->rc_delta_blks = RC_DELTA_BLKS;

	dm_info->rc_base_bitmap =
		g_malloc0(DIV_ROUND_UP(dm_info->rc_base_blks, 8));
	dm_info->rc_delta_bitmap =
		g_malloc0(DIV_ROUND_UP(dm_info->rc_delta_blks, 8));

	dm_info->enable_dedup_merge = false;
	dm_info->enable_compress    = false;

	n->dm_info = dm_info;

	if (init_merge_thread(n) != 0) {
		femu_err("Failed to initialize RC Delta merge thread\r\n");

		femu_log("FEMU running without RC Delta merge\r\n");
	}

	if (init_compress_thread(n) != 0) {
		femu_err("Failed to initialize compression thread\r\n");

		femu_log("FEMU running without compression\r\n");
	}
}

void cleanup_dm_info(FemuCtrl *n)
{
	struct f2dfs_dm_info *dm_info = n->dm_info;

	if (!dm_info) {
		return;
	}

	stop_compress_thread(n);

	stop_merge_thread(n);

	g_free(dm_info->rc_base_bitmap);
	g_free(dm_info->rc_delta_bitmap);

	qemu_mutex_destroy(&dm_info->merge_mutex);
	qemu_cond_destroy(&dm_info->merge_cond);

	g_free(dm_info);
	n->dm_info = NULL;

	femu_log("DM info cleaned up\r\n");
}

static int load_bitmap(FemuCtrl *n, block_t bitmap_blkaddr)
{
	struct f2dfs_dm_info *dm_info = n->dm_info;
	struct f2dfs_bitmap_disk *disk_bitmap;
	char *bitmap;
	block_t page_num;
	size_t copy_bytes;
	size_t total_size;
	size_t per_page = sizeof(((struct f2dfs_bitmap_disk *)0)->bitmap);
	int i, ret;

	if (!dm_info || !dm_info->rc_base_bitmap || !dm_info->rc_delta_bitmap) {
		femu_err("DM info or fp bitmap is not initialized.\r\n");
		return -1;
	}

	if (!dm_info->enable_dedup_merge) {
		femu_err(
			"Deduplication merge is not enabled, cannot update fp bitmap.\r\n");
		return -1;
	}

	switch (bitmap_blkaddr) {
	case FP_META_BLKADDR:

		femu_err("FP bitmap is not supported in this version.\r\n");
		return -1;
	case (FP_META_BLKADDR + FP_BITMAP_PAGESIZE):
		bitmap	   = dm_info->rc_base_bitmap;
		total_size = RC_BASE_BITMAP_SIZE;
		page_num   = RC_BASE_BITMAP_PAGESIZE;

		break;
	case (FP_META_BLKADDR + FP_BITMAP_PAGESIZE + RC_BASE_BITMAP_PAGESIZE):
		bitmap	   = dm_info->rc_delta_bitmap;
		total_size = RC_DELTA_BITMAP_SIZE;
		page_num   = RC_DELTA_BITMAP_PAGESIZE;

		break;
	default:
		femu_err("Invalid bitmap block address: %" PRIu32 "\r\n",
			 bitmap_blkaddr);
		return -1;
	}

	disk_bitmap = g_malloc0(sizeof(struct f2dfs_bitmap_disk));

	for (i = 0; i < page_num; i++) {
		ret = f2dfs_read_meta_page(n, disk_bitmap, bitmap_blkaddr + i);
		if (ret < 0) {
			g_free(disk_bitmap);
			femu_err("Failed to read fp bitmap page %d\r\n", i);
			return ret;
		}
		copy_bytes = MIN(per_page, total_size - i * per_page);
		memcpy(bitmap + i * per_page, disk_bitmap->bitmap, copy_bytes);
	}
	g_free(disk_bitmap);
	return 0;
}

static int store_bitmap(FemuCtrl *n, block_t bitmap_blkaddr)
{
	struct f2dfs_dm_info *dm_info = n->dm_info;
	struct f2dfs_bitmap_disk disk_bitmap;
	char *bitmap;
	block_t page_num;
	size_t copy_bytes;
	size_t total_size;
	size_t per_page = sizeof(disk_bitmap.bitmap);
	int i, ret;

	if (!dm_info || !dm_info->rc_base_bitmap || !dm_info->rc_delta_bitmap) {
		femu_err("DM info or bitmaps are not initialized.\r\n");
		return -1;
	}

	switch (bitmap_blkaddr) {
	case FP_META_BLKADDR:
		femu_err("FP bitmap is not supported in this version.\r\n");
		return -1;
	case (FP_META_BLKADDR + FP_BITMAP_PAGESIZE):
		bitmap	   = dm_info->rc_base_bitmap;
		total_size = RC_BASE_BITMAP_SIZE;
		page_num   = RC_BASE_BITMAP_PAGESIZE;

		break;
	case (FP_META_BLKADDR + FP_BITMAP_PAGESIZE + RC_BASE_BITMAP_PAGESIZE):
		bitmap	   = dm_info->rc_delta_bitmap;
		total_size = RC_DELTA_BITMAP_SIZE;
		page_num   = RC_DELTA_BITMAP_PAGESIZE;

		break;
	default:
		femu_err("Invalid bitmap block address: %" PRIu32 "\r\n",
			 bitmap_blkaddr);
		return -1;
	}

	memset(&disk_bitmap, 0, sizeof(disk_bitmap));

	for (i = 0; i < page_num; i++) {
		copy_bytes = MIN(per_page, total_size - i * per_page);
		memcpy(disk_bitmap.bitmap, bitmap + i * per_page, copy_bytes);
		ret = f2dfs_write_meta_page(n, &disk_bitmap,
					    bitmap_blkaddr + i);
		if (ret < 0) {
			femu_err("Failed to write bitmap page %d\r\n", i);
			return ret;
		}
	}
	return 0;
}

static int bb_internal_write(FemuCtrl *n, uint64_t f2fs_blkaddr,
			     const void *data, size_t size)
{
	const uint8_t lba_index =
		NVME_ID_NS_FLBAS_INDEX(n->namespaces->id_ns.flbas);
	const uint8_t data_shift = n->namespaces->id_ns.lbaf[lba_index].lbads;
	uint64_t offset = (f2fs_blkaddr * 4096 / 512 + 2048) << data_shift;

	if (!n || !data || size == 0) {
		femu_err("ssd_internal_write invalid parameters\r\n");
		return -1;
	}

	if (!n || !n->mbe || !n->mbe->logical_space) {
		femu_err("ssd_internal_write invalid backend\r\n");
		return -1;
	}

	if (offset + size > n->mbe->size) {
		femu_err("ssd_internal_write out of range, offset=%" PRIu64
			 ", size=%zu, mbe_size=%zu\r\n",
			 offset, size, n->mbe->size);
		return -1;
	}

	memcpy((char *)n->mbe->logical_space + offset, data, size);
	return 0;
}

static int f2dfs_write_meta_page(FemuCtrl *n, const void *src,
				 uint64_t f2fs_blkaddr)
{
	if (!n || !src) {
		femu_err("ssd_internal_write_page invalid parameters\r\n");
		return -1;
	}

	bb_internal_write(n, f2fs_blkaddr, src, PAGE_SIZE);
	return 0;
}

void bb_read_data_print(FemuCtrl *n, uint64_t f2fs_blkaddr, size_t size)
{
	char *data;
	size_t i;

	if (!n || !n->mbe || !n->mbe->logical_space) {
		femu_err("bb_read_data invalid backend\r\n");
		return;
	}

	data = g_malloc0(size);
	if (bb_internal_read(n, f2fs_blkaddr, data, size) != 0) {
		femu_err("bb_internal_read failed\r\n");
		g_free(data);
		return;
	}

	printf("Data at blkaddr %" PRIu64 ":\r\n", f2fs_blkaddr);
	for (i = 0; i < size; i++) {
		printf("%02x ", (unsigned char)data[i]);
		if ((i + 1) % 16 == 0) {
			printf("\r\n");
		}
	}
	printf("\r\n");

	g_free(data);
}

static int calculate_valid_blks(void *bitmap, block_t nblks)
{
	int valid_blks = 0;
	for (block_t blkaddr = 0; blkaddr < nblks; blkaddr++) {
		if (test_bit(blkaddr, (unsigned long *)bitmap)) {
			valid_blks++;
		}
	}
	return valid_blks;
}

static int perform_rc_delta_merge(FemuCtrl *n)
{
	struct f2dfs_dm_info *dm_info = n->dm_info;

	int base_dirty_npage  = 0;
	int delta_dirty_npage = 0;

	struct f2dfs_rc_base_buffer *base_buf	= NULL;
	struct f2dfs_rc_delta_buffer *delta_buf = NULL;

	GHashTable *rc_hash_table	    = NULL;
	struct rc_base_entry *all_base	    = NULL;
	struct rc_delta_entry *remain_delta = NULL;

	int total_base_entry  = 0;
	int total_delta_entry = 0;
	int base_index	      = 0;
	int delta_index	      = 0;

	int written = 0;
	int count   = 0;
	int blkaddr = 0;

	if (!dm_info->enable_dedup_merge) {
		return 0;
	}

	load_bitmap(n, dm_info->rc_delta_bitmap_blkaddr);
	delta_dirty_npage = calculate_valid_blks(dm_info->rc_delta_bitmap,
						 dm_info->rc_delta_blks);

	if (delta_dirty_npage <= 1) {
		return 0;
	}

	load_bitmap(n, dm_info->rc_base_bitmap_blkaddr);
	base_dirty_npage = calculate_valid_blks(dm_info->rc_base_bitmap,
						dm_info->rc_base_blks);

	base_buf = g_malloc(sizeof(*base_buf));
	if (!base_buf) {
		femu_err("Failed to allocate memory for base_buf\r\n");
		return -1;
	}
	delta_buf = g_malloc(sizeof(*delta_buf));
	if (!delta_buf) {
		femu_err("Failed to allocate memory for delta_buf\r\n");
		g_free(base_buf);
		return -1;
	}

	total_base_entry = base_dirty_npage * RC_BASE_ENTRIES_PER_PAGE;
	all_base = g_malloc(sizeof(struct rc_base_entry) * total_base_entry);
	if (!all_base) {
		femu_err("Failed to allocate memory for all_base entries\r\n");
		g_free(base_buf);
		g_free(delta_buf);
		return -1;
	}

	rc_hash_table =
		g_hash_table_new_full(g_bytes_hash, g_bytes_equal,
				      (GDestroyNotify)g_bytes_unref, g_free);
	if (!rc_hash_table) {
		femu_err("Failed to create hash table for RC Base entries\r\n");
		g_free(base_buf);
		g_free(delta_buf);
		g_free(all_base);
		return -1;
	}

	for (int i = 0; i < dm_info->rc_base_blks; i++) {
		if (!test_bit(i, (unsigned long *)dm_info->rc_base_bitmap)) {
			continue;
		}

		if (f2dfs_read_meta_page(n, base_buf,
					 dm_info->rc_base_blkaddr + i) < 0) {
			femu_err(
				"Failed to read RC Base page at blkaddr %" PRIu32
				"\r\n",
				dm_info->rc_base_blkaddr + i);
			goto clean_up_err;
		}

		clear_bit(i, (unsigned long *)dm_info->rc_base_bitmap);

		for (int j = 0; j < base_buf->valid_count; j++) {
			struct rc_base_entry *entry = &base_buf->entries[j];

			GBytes *vaddr_key = g_bytes_new(&entry->vaddr,
							sizeof(entry->vaddr));

			int *existing_index = (int *)g_hash_table_lookup(
				rc_hash_table, vaddr_key);

			if (existing_index) {
				if (all_base[*existing_index].fp_page_addr !=
				    entry->fp_page_addr) {
					femu_err(
						"Found duplicate vaddr with different fp_page_addr: "
						"vaddr=%" PRIx32
						", existing_fp_page_addr=%" PRIu32
						", new_fp_page_addr=%" PRIu32
						"\r\n",
						entry->vaddr,
						all_base[*existing_index]
							.fp_page_addr,
						entry->fp_page_addr);
				}

				all_base[*existing_index].rc += entry->rc;
				g_bytes_unref(vaddr_key);
			} else {
				if (base_index >= total_base_entry) {
					femu_err(
						"Base entries overflow, should not happen\r\n");
					g_bytes_unref(vaddr_key);
					goto clean_up_err;
				}

				all_base[base_index] = *entry;

				int *index_ptr = g_malloc(sizeof(int));
				*index_ptr     = base_index;
				g_hash_table_insert(rc_hash_table, vaddr_key,
						    index_ptr);

				base_index++;
			}
		}
	}

	total_delta_entry = RC_BASE_ENTRIES_PER_PAGE;
	remain_delta =
		g_malloc0(sizeof(struct rc_delta_entry) * total_delta_entry);
	if (!remain_delta) {
		femu_err(
			"Failed to allocate memory for delta_not_found entries\r\n");
		goto clean_up_err;
	}

	for (int i = 0; i < dm_info->rc_delta_blks; i++) {
		if (!test_bit(i, (unsigned long *)dm_info->rc_delta_bitmap)) {
			continue;
		}

		if (f2dfs_read_meta_page(n, delta_buf,
					 dm_info->rc_delta_blkaddr + i) < 0) {
			femu_err(
				"Failed to read RC Delta page at blkaddr %" PRIu32
				"\r\n",
				dm_info->rc_delta_blkaddr + i);
			goto clean_up_err_delta;
		}

		clear_bit(i, (unsigned long *)dm_info->rc_delta_bitmap);

		for (int j = 0; j < delta_buf->valid_count; j++) {
			struct rc_delta_entry *entry = &delta_buf->entries[j];

			GBytes *vaddr_key = g_bytes_new(&entry->vaddr,
							sizeof(entry->vaddr));

			int *existing_index = (int *)g_hash_table_lookup(
				rc_hash_table, vaddr_key);

			if (existing_index) {
				all_base[*existing_index].rc += entry->rc;
				g_bytes_unref(vaddr_key);
			} else {
				g_bytes_unref(vaddr_key);

				if (delta_index >= total_delta_entry) {
					femu_err(
						"Delta not found list is full, it should not "
						"happen\r\n");
					goto clean_up_err_delta;
				}
				remain_delta[delta_index] = *entry;
				delta_index++;
			}
		}
	}

	written = 0;
	while (written < base_index) {
		count = MIN(RC_BASE_ENTRIES_PER_PAGE, base_index - written);

		memset(base_buf, 0, sizeof(*base_buf));
		memcpy(base_buf->entries, &all_base[written],
		       count * sizeof(struct rc_base_entry));
		base_buf->valid_count = count;

		blkaddr = f2dfs_find_free_block(dm_info->rc_base_blkaddr,
						dm_info->rc_base_blks,
						dm_info->rc_base_bitmap);
		if (blkaddr == NULL_ADDR) {
			femu_err("No free block found for RC Base entries\r\n");
			goto clean_up_err_delta;
		}

		if (f2dfs_write_meta_page(n, base_buf, blkaddr) < 0) {
			femu_err(
				"Failed to write RC Base page at blkaddr %" PRIu32
				"\r\n",
				blkaddr);
			goto clean_up_err_delta;
		}
		written += count;
	}

	written = 0;
	while (written < delta_index) {
		count = MIN(RC_DELTA_ENTRIES_PER_PAGE, delta_index - written);

		memset(delta_buf, 0, sizeof(*delta_buf));
		memcpy(delta_buf->entries, &remain_delta[written],
		       count * sizeof(struct rc_delta_entry));
		delta_buf->valid_count = count;

		blkaddr = f2dfs_find_free_block(dm_info->rc_delta_blkaddr,
						dm_info->rc_delta_blks,
						dm_info->rc_delta_bitmap);
		if (blkaddr == NULL_ADDR) {
			femu_err(
				"No free block found for RC Delta entries\r\n");
			goto clean_up_err_delta;
		}

		if (f2dfs_write_meta_page(n, delta_buf, blkaddr) < 0) {
			femu_err(
				"Failed to write RC Delta page at blkaddr %" PRIu32
				"\r\n",
				blkaddr);
			goto clean_up_err_delta;
		}
		written += count;
	}

	if (store_bitmap(n, dm_info->rc_base_bitmap_blkaddr) < 0) {
		femu_err("Failed to store RC Base bitmap\r\n");
		goto clean_up_err_delta;
	}

	if (store_bitmap(n, dm_info->rc_delta_bitmap_blkaddr) < 0) {
		femu_err("Failed to store RC Delta bitmap\r\n");
		goto clean_up_err_delta;
	}

	g_free(remain_delta);
	g_free(base_buf);
	g_free(delta_buf);
	g_free(all_base);
	g_hash_table_destroy(rc_hash_table);
	return 0;

clean_up_err_delta:
	g_free(remain_delta);
clean_up_err:
	g_free(base_buf);
	g_free(delta_buf);
	g_free(all_base);
	g_hash_table_destroy(rc_hash_table);
	return -1;
}

static void *background_merge_thread(void *arg)
{
	FemuCtrl *n		      = (FemuCtrl *)arg;
	struct f2dfs_dm_info *dm_info = n->dm_info;

	femu_log("RC Delta merge thread started (manual trigger only)\r\n");

	while (!dm_info->merge_thread_stop) {
		qemu_mutex_lock(&dm_info->merge_mutex);

		while (!dm_info->trigger_rc_delta_merge &&
		       !dm_info->merge_thread_stop) {
			qemu_cond_wait(&dm_info->merge_cond,
				       &dm_info->merge_mutex);
		}

		if (dm_info->merge_thread_stop) {
			qemu_mutex_unlock(&dm_info->merge_mutex);
			break;
		}

		if (!dm_info->enable_dedup_merge) {
			dm_info->trigger_rc_delta_merge = false;
			qemu_mutex_unlock(&dm_info->merge_mutex);
			continue;
		}

		dm_info->trigger_rc_delta_merge = false;
		qemu_mutex_unlock(&dm_info->merge_mutex);

		perform_rc_delta_merge(n);
	}

	femu_log("RC Delta merge thread stopped\r\n");
	return NULL;
}

void trigger_rc_delta_merge(FemuCtrl *n)
{
	struct f2dfs_dm_info *dm_info = n->dm_info;

	if (!dm_info || !dm_info->merge_thread_running) {
		femu_err("Merge thread is not initialized\r\n");
		return;
	}

	qemu_mutex_lock(&dm_info->merge_mutex);
	dm_info->trigger_rc_delta_merge = true;
	qemu_cond_signal(&dm_info->merge_cond);
	qemu_mutex_unlock(&dm_info->merge_mutex);
}

static int init_merge_thread(FemuCtrl *n)
{
	struct f2dfs_dm_info *dm_info = n->dm_info;

	dm_info->merge_thread_running = false;
	dm_info->merge_thread_stop    = false;

	qemu_mutex_init(&dm_info->merge_mutex);
	qemu_cond_init(&dm_info->merge_cond);

	qemu_thread_create(&dm_info->merge_thread, "FEMU-RC-Merge",
			   background_merge_thread, n, QEMU_THREAD_JOINABLE);

	dm_info->merge_thread_running = true;
	femu_log("RC Delta merge thread initialized successfully\r\n");

	return 0;
}

void stop_merge_thread(FemuCtrl *n)
{
	struct f2dfs_dm_info *dm_info = n->dm_info;

	if (!dm_info || !dm_info->merge_thread_running) {
		return;
	}

	femu_log("Stopping RC Delta merge thread...\r\n");

	qemu_mutex_lock(&dm_info->merge_mutex);
	dm_info->merge_thread_stop = true;
	qemu_cond_signal(&dm_info->merge_cond);
	qemu_mutex_unlock(&dm_info->merge_mutex);

	qemu_thread_join(&dm_info->merge_thread);
	dm_info->merge_thread_running = false;

	femu_log("RC Delta merge thread stopped\r\n");
}

void enable_dedup_merge(FemuCtrl *n, bool enable)
{
	struct f2dfs_dm_info *dm_info = n->dm_info;

	if (!dm_info) {
		femu_err("Merge thread is not initialized\r\n");
		return;
	}

	qemu_mutex_lock(&dm_info->merge_mutex);
	if (dm_info->enable_dedup_merge != enable) {
		dm_info->enable_dedup_merge = enable;
		if (enable) {
			femu_log("Deduplication merge enabled\r\n");
			qemu_cond_signal(&dm_info->merge_cond);
		} else {
			femu_log("Deduplication merge disabled\r\n");
		}
	}
	qemu_mutex_unlock(&dm_info->merge_mutex);
}

bool is_dedup_merge_enabled(FemuCtrl *n)
{
	struct f2dfs_dm_info *dm_info = n->dm_info;
	bool enabled;

	if (!dm_info) {
		return false;
	}

	qemu_mutex_lock(&dm_info->merge_mutex);
	enabled = dm_info->enable_dedup_merge;
	qemu_mutex_unlock(&dm_info->merge_mutex);

	return enabled;
}