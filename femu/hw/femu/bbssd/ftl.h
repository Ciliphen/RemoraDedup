#ifndef __FEMU_FTL_H
#define __FEMU_FTL_H

#include "../nvme.h"
#include "dedup.h"

#define INVALID_PPA  (~(0ULL))
#define INVALID_LPN  (~(0ULL))
#define UNUSED_LPN   (~(0ULL))
#define UNMAPPED_PPA (~(0ULL))

enum {
	NAND_READ  = 0,
	NAND_WRITE = 1,
	NAND_ERASE = 2,

	NAND_READ_LATENCY  = 40000,
	NAND_PROG_LATENCY  = 200000,
	NAND_ERASE_LATENCY = 2000000,
};

enum {
	USER_IO	    = 0,
	GC_IO	    = 1,
	COMPRESS_IO = 2,
};

enum {
	SEC_FREE    = 0,
	SEC_INVALID = 1,
	SEC_VALID   = 2,

	PG_FREE	   = 0,
	PG_INVALID = 1,
	PG_VALID   = 2
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

	FEMU_ENABLE_COMPRESSION_DELAY  = 12,
	FEMU_DISABLE_COMPRESSION_DELAY = 13,
	FEMU_ENABLE_COMPRESSION	       = 14,
	FEMU_DISABLE_COMPRESSION       = 15,
	FEMU_TRIGGER_COMPRESSION       = 16,

	FEMU_PRINT_SSD_STATS = 17,
};

#define BLK_BITS (16)
#define PG_BITS	 (16)
#define SEC_BITS (8)
#define PL_BITS	 (8)
#define LUN_BITS (8)
#define CH_BITS	 (7)

struct ppa {
	union {
		struct {
			uint64_t blk : BLK_BITS;
			uint64_t pg : PG_BITS;
			uint64_t sec : SEC_BITS;
			uint64_t pl : PL_BITS;
			uint64_t lun : LUN_BITS;
			uint64_t ch : CH_BITS;
			uint64_t rsv : 1;
		} g;

		uint64_t ppa;
	};
#ifdef DEDUP_COMPRESSION_ENABLED
	bool is_compressed;
	uint64_t access_time;
#endif
};

typedef int nand_sec_status_t;

struct nand_page {
	nand_sec_status_t *sec;
	int nsecs;
	int status;
};

struct nand_block {
	struct nand_page *pg;
	int npgs;
	int ipc;
	int vpc;
	int erase_cnt;
	int wp;
};

struct nand_plane {
	struct nand_block *blk;
	int nblks;
};

struct nand_lun {
	struct nand_plane *pl;
	int npls;
	uint64_t next_lun_avail_time;
	bool busy;
	uint64_t gc_endtime;
};

struct ssd_channel {
	struct nand_lun *lun;
	int nluns;
	uint64_t next_ch_avail_time;
	bool busy;
	uint64_t gc_endtime;
};

struct ssdparams {
	int secsz;
	int secs_per_pg;
	int pgs_per_blk;
	int blks_per_pl;
	int pls_per_lun;
	int luns_per_ch;
	int nchs;

	int pg_rd_lat;
	int pg_wr_lat;
	int blk_er_lat;
	int ch_xfer_lat;

	double gc_thres_pcent;
	int gc_thres_lines;
	double gc_thres_pcent_high;
	int gc_thres_lines_high;
	bool enable_gc_delay;

	int secs_per_blk;
	int secs_per_pl;
	int secs_per_lun;
	int secs_per_ch;
	int tt_secs;

	int pgs_per_pl;
	int pgs_per_lun;
	int pgs_per_ch;
	int tt_pgs;

	int blks_per_lun;
	int blks_per_ch;
	int tt_blks;

	int secs_per_line;
	int pgs_per_line;
	int blks_per_line;
	int tt_lines;

	int pls_per_ch;
	int tt_pls;

	int tt_luns;

#ifdef DEDUP_COMPRESSION_ENABLED
	int tt_phy_pgs;
	int main_area_pgs;
	bool enable_cmprs_delay;
	uint64_t cold_page_threshold_ns;
	int compress_hit_cnt;
	int compress_miss_cnt;
	int cmprs_line;
	int compress_lat;
	int decompress_lat;
#endif
};

typedef struct line {
	int id;
	int ipc;
	int vpc;
	QTAILQ_ENTRY(line) entry;

	size_t pos;
#ifdef DEDUP_COMPRESSION_ENABLED
	bool is_compress_line;
#endif
} line;

struct write_pointer {
	struct line *curline;
	int ch;
	int lun;
	int pg;
	int blk;
	int pl;
};

struct line_mgmt {
	struct line *lines;

	QTAILQ_HEAD(free_line_list, line) free_line_list;

	QTAILQ_HEAD(free_compress_line_list, line) free_compress_line_list;

	pqueue_t *victim_line_pq;

	QTAILQ_HEAD(full_line_list, line) full_line_list;

	int tt_lines;
	int free_line_cnt;
	int victim_line_cnt;
	int full_line_cnt;

	int free_compress_line_cnt;
};

struct nand_cmd {
	int type;
	int cmd;
	int64_t stime;
};

#ifdef DEDUP_COMPRESSION_ENABLED

struct cmprs_rinfo {
	uint64_t lpn[COMPRESS_PAGE_MAX_NUM];
	uint8_t ref_cnt;
	bool is_compressed;
};
#endif

struct ssd_stats {
	uint64_t total_pages_written;
	uint64_t total_pages_read;
	uint64_t total_blocks_erased;
	uint64_t valid_pages_count;
	uint64_t migrated_pages_count;
	uint64_t gc_count;
	uint64_t compressed_pages_count[5];
};

struct ssd {
	char *ssdname;
	struct ssdparams sp;
	struct ssd_channel *ch;
	struct ppa *maptbl;
#ifdef DEDUP_COMPRESSION_ENABLED
	struct cmprs_rinfo *rmap;
	struct write_pointer cmprs_wp;
#else
	uint64_t *rmap;
#endif
	struct write_pointer wp;
	struct line_mgmt lm;
	struct ssd_stats stats;

	struct rte_ring **to_ftl;
	struct rte_ring **to_poller;
	bool *dataplane_started_ptr;
	QemuThread ftl_thread;
};

void ssd_init(FemuCtrl *n);

#ifdef FEMU_DEBUG_FTL
#define ftl_debug(fmt, ...)                                                    \
	do {                                                                   \
		printf("[FEMU] FTL-Dbg: " fmt, ##__VA_ARGS__);                 \
	} while (0)
#else
#define ftl_debug(fmt, ...)                                                    \
	do {                                                                   \
	} while (0)
#endif

#define ftl_err(fmt, ...)                                                      \
	do {                                                                   \
		fprintf(stderr, "[FEMU] FTL-Err: " fmt, ##__VA_ARGS__);        \
	} while (0)

#define ftl_log(fmt, ...)                                                      \
	do {                                                                   \
		printf("[FEMU] FTL-Log: " fmt, ##__VA_ARGS__);                 \
	} while (0)

#ifdef FEMU_DEBUG_FTL
#define ftl_assert(expression) assert(expression)
#else
#define ftl_assert(expression)
#endif

#ifdef DEDUP_COMPRESSION_ENABLED
static inline struct ppa get_maptbl_ent(struct ssd *ssd, uint64_t lpn)
{
	return ssd->maptbl[lpn];
}

static inline void set_maptbl_ent(struct ssd *ssd, uint64_t lpn,
				  struct ppa *ppa)
{
	ftl_assert(lpn < ssd->sp.tt_pgs);

	ssd->maptbl[lpn] = *ppa;
}

static uint64_t ppa2pgidx(struct ssd *ssd, struct ppa *ppa)
{
	struct ssdparams *spp = &ssd->sp;

	uint64_t pgidx;

	pgidx = ppa->g.ch * spp->pgs_per_ch + ppa->g.lun * spp->pgs_per_lun +
		ppa->g.pl * spp->pgs_per_pl + ppa->g.blk * spp->pgs_per_blk +
		ppa->g.pg;

	if (pgidx >= spp->tt_phy_pgs) {
		ftl_err("%" PRIu64
			"= %d * %d +\r\n                           %d * %d "
			"+\r\n                           %d * %d +\r\n          "
			"                 %d * %d + %d\r\n",
			pgidx, ppa->g.ch, spp->pgs_per_ch, ppa->g.lun,
			spp->pgs_per_lun, ppa->g.pl, spp->pgs_per_pl,
			ppa->g.blk, spp->pgs_per_blk, ppa->g.pg);
		ftl_err("Invalid PPA %" PRIx64 "\r\n", ppa->ppa);
		ftl_err("spp->tt_phy_pgs = %d\r\n", spp->tt_phy_pgs);
	}
	ftl_assert(pgidx < spp->tt_phy_pgs);

	return pgidx;
}

static inline struct cmprs_rinfo *get_rmap_ent_pointer(struct ssd *ssd,
						       struct ppa *ppa)
{
	uint64_t pgidx = ppa2pgidx(ssd, ppa);

	return &ssd->rmap[pgidx];
}

static inline void set_rmap_ent(struct ssd *ssd, uint64_t lpn,
				bool is_compressed, uint8_t ref_cnt,
				struct ppa *ppa,
				uint64_t lpn_tbl[COMPRESS_PAGE_MAX_NUM])
{
	uint64_t pgidx = ppa2pgidx(ssd, ppa);

	ssd->rmap[pgidx].is_compressed = is_compressed;
	ssd->rmap[pgidx].ref_cnt       = ref_cnt;
	if (is_compressed) {
		ftl_assert(lpn_tbl != NULL);
		ftl_assert(lpn == UNUSED_LPN);
		for (int i = 0; i < COMPRESS_PAGE_MAX_NUM; i++) {
			ssd->rmap[pgidx].lpn[i] = lpn_tbl[i];
		}
	} else {
		ftl_assert(lpn_tbl == NULL);
		ssd->rmap[pgidx].lpn[0] = lpn;
		for (int i = 1; i < COMPRESS_PAGE_MAX_NUM; i++) {
			ssd->rmap[pgidx].lpn[i] = INVALID_LPN;
		}
	}
}

static inline bool valid_ppa(struct ssd *ssd, struct ppa *ppa)
{
	struct ssdparams *spp = &ssd->sp;
	int ch		      = ppa->g.ch;
	int lun		      = ppa->g.lun;
	int pl		      = ppa->g.pl;
	int blk		      = ppa->g.blk;
	int pg		      = ppa->g.pg;
	int sec		      = ppa->g.sec;

	if (ch >= 0 && ch < spp->nchs && lun >= 0 && lun < spp->luns_per_ch &&
	    pl >= 0 && pl < spp->pls_per_lun && blk >= 0 &&
	    blk < spp->blks_per_pl && pg >= 0 && pg < spp->pgs_per_blk &&
	    sec >= 0 && sec < spp->secs_per_pg)
		return true;

	return false;
}

static inline bool valid_lpn(struct ssd *ssd, uint64_t lpn)
{
	return (lpn < ssd->sp.tt_pgs);
}

static inline bool mapped_ppa(struct ppa *ppa)
{
	return !(ppa->ppa == UNMAPPED_PPA);
}

static inline bool should_compress(struct ssd *ssd)
{
	double used_percent =
		(double)(ssd->stats.valid_pages_count) / ssd->sp.tt_phy_pgs;
	uint64_t compress_pages_count = ssd->stats.compressed_pages_count[1] +
					ssd->stats.compressed_pages_count[2] +
					ssd->stats.compressed_pages_count[3] +
					ssd->stats.compressed_pages_count[4];
	double compress_used_percent =
		(double)(compress_pages_count) /
		(ssd->sp.cmprs_line * ssd->sp.pgs_per_line);

	if (used_percent < 0.15 || used_percent > 0.85)
		return false;

	double allowed_compress_percent = (used_percent - 0.15) / 0.7;

	return (compress_used_percent < allowed_compress_percent &&
		ssd->lm.free_compress_line_cnt > 0);
}
#endif
#endif
