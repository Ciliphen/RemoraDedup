#include "dedup.h"
#include "ftl.h"
#include <execinfo.h>

void print_stacktrace(void)
{
	void *buffer[32];
	int nptrs      = backtrace(buffer, 32);
	char **symbols = backtrace_symbols(buffer, nptrs);
	if (symbols) {
		fprintf(stderr, "=== Stack trace ===\r\n");
		for (int i = 0; i < nptrs; i++) {
			fprintf(stderr, "%s\r\n", symbols[i]);
		}
		free(symbols);
	}
}

static void cmprs_read_page(struct ssd *ssd, struct ppa *ppa)
{
	if (ssd->sp.enable_cmprs_delay) {
		struct nand_cmd gcr;
		gcr.type  = COMPRESS_IO;
		gcr.cmd	  = NAND_READ;
		gcr.stime = 0;
		ssd_advance_status(ssd, ppa, &gcr);
	}
}

static inline void update_threshold_pid(struct ssdparams *spp,
					bool compress_success)
{
	static double integral	 = 0.0;
	static double last_error = 0.0;

	const double kp = 0.5;
	const double ki = 0.1;
	const double kd = 0.2;

	double target_success_rate = 0.8;
	double current_success_rate =
		(double)spp->compress_hit_cnt /
		(spp->compress_hit_cnt + spp->compress_miss_cnt + 1);
	double error = target_success_rate - current_success_rate;

	integral += error;
	double derivative = error - last_error;
	double output	  = kp * error + ki * integral + kd * derivative;

	int64_t adjustment = (int64_t)(output * COLD_PAGE_THRESHOLD_STEP);
	spp->cold_page_threshold_ns =
		MAX(MIN(spp->cold_page_threshold_ns + adjustment,
			COLD_PAGE_THRESHOLD_NS_MAX),
		    COLD_PAGE_THRESHOLD_NS_MIN);

	last_error = error;
}

static inline void update_threshold_ema(struct ssdparams *spp,
					bool compress_success)
{
	static double success_rate_ema = 0.5;
	const double alpha	       = 0.1;

	success_rate_ema = alpha * (compress_success ? 1.0 : 0.0) +
			   (1 - alpha) * success_rate_ema;

	double target_rate = 0.75;
	if (success_rate_ema < target_rate - 0.1) {
		spp->cold_page_threshold_ns =
			MAX(spp->cold_page_threshold_ns -
				    COLD_PAGE_THRESHOLD_STEP * 2,
			    COLD_PAGE_THRESHOLD_NS_MIN);
	} else if (success_rate_ema > target_rate + 0.1) {
		spp->cold_page_threshold_ns = MIN(
			spp->cold_page_threshold_ns + COLD_PAGE_THRESHOLD_STEP,
			COLD_PAGE_THRESHOLD_NS_MAX);
	}
}

static inline void update_threshold_adaptive(struct ssdparams *spp,
					     bool compress_success)
{
	static int consecutive_same = 0;
	static bool last_result	    = false;
	static uint64_t base_step   = COLD_PAGE_THRESHOLD_STEP;

	if (compress_success == last_result) {
		consecutive_same++;

		if (consecutive_same > 3) {
			base_step = MIN(base_step * 2,
					COLD_PAGE_THRESHOLD_STEP * 8);
		}
	} else {
		consecutive_same = 0;

		base_step = COLD_PAGE_THRESHOLD_STEP;
	}

	if (compress_success) {
		spp->cold_page_threshold_ns =
			MIN(spp->cold_page_threshold_ns + base_step,
			    COLD_PAGE_THRESHOLD_NS_MAX);
	} else {
		spp->cold_page_threshold_ns =
			MAX(spp->cold_page_threshold_ns - base_step,
			    COLD_PAGE_THRESHOLD_NS_MIN);
	}

	last_result = compress_success;
}

typedef struct {
	uint64_t threshold;
	double success_rate;
	uint64_t timestamp;
} threshold_history_t;

static inline void update_threshold_history_aware(struct ssdparams *spp,
						  bool compress_success)
{
	static threshold_history_t history[16];
	static int history_idx	       = 0;
	static int history_count       = 0;
	static uint64_t total_attempts = 0;
	static uint64_t success_count  = 0;

	total_attempts++;
	if (compress_success)
		success_count++;

	if (total_attempts % 64 == 0) {
		double current_rate = (double)success_count / total_attempts;

		history[history_idx] = (threshold_history_t){
			.threshold    = spp->cold_page_threshold_ns,
			.success_rate = current_rate,
			.timestamp    = qemu_clock_get_ns(QEMU_CLOCK_REALTIME)
		};

		history_idx = (history_idx + 1) % 16;
		if (history_count < 16)
			history_count++;

		double best_rate	= 0;
		uint64_t best_threshold = spp->cold_page_threshold_ns;

		for (int i = 0; i < history_count; i++) {
			if (history[i].success_rate > best_rate) {
				best_rate      = history[i].success_rate;
				best_threshold = history[i].threshold;
			}
		}

		if (current_rate < 0.6 && best_rate > 0.7) {
			int64_t diff =
				best_threshold - spp->cold_page_threshold_ns;
			spp->cold_page_threshold_ns += diff / 4;
		}

		total_attempts = 0;
		success_count  = 0;
	}

	spp->cold_page_threshold_ns = MAX(MIN(spp->cold_page_threshold_ns,
					      COLD_PAGE_THRESHOLD_NS_MAX),
					  COLD_PAGE_THRESHOLD_NS_MIN);
}

static inline void update_compression_threshold(struct ssdparams *spp,
						bool compress_success)
{
	switch (0) {
	case 0:
		if (compress_success) {
			spp->compress_hit_cnt++;
			spp->compress_miss_cnt = 0;
			if (spp->compress_hit_cnt > 5) {
				spp->cold_page_threshold_ns +=
					COLD_PAGE_THRESHOLD_STEP * 5;
				spp->compress_hit_cnt = 0;
			} else {
				spp->cold_page_threshold_ns +=
					COLD_PAGE_THRESHOLD_STEP;
			}
		} else {
			spp->compress_miss_cnt++;
			spp->compress_hit_cnt = 0;
			if (spp->compress_miss_cnt > 5) {
				spp->cold_page_threshold_ns = MAX(
					spp->cold_page_threshold_ns -
						COLD_PAGE_THRESHOLD_STEP * 5,
					COLD_PAGE_THRESHOLD_NS_MIN);
				spp->compress_miss_cnt = 0;
			} else {
				spp->cold_page_threshold_ns =
					MAX(spp->cold_page_threshold_ns -
						    COLD_PAGE_THRESHOLD_STEP,
					    COLD_PAGE_THRESHOLD_NS_MIN);
			}
		}
		break;

	case 1:
		update_threshold_pid(spp, compress_success);
		break;

	case 2:
		update_threshold_ema(spp, compress_success);
		break;

	case 3:
		update_threshold_adaptive(spp, compress_success);
		break;

	case 4:
		update_threshold_history_aware(spp, compress_success);
		break;

	default:
		update_threshold_ema(spp, compress_success);
	}
}

static void perform_compression(FemuCtrl *n)
{
	struct ssd *ssd	      = n->ssd;
	struct ssdparams *spp = &ssd->sp;

	static struct {
		uint64_t lpn;
		struct ppa ppa;
		uint64_t access_time;
	} cold_pages[COMPRESS_PAGE_MAX_NUM];

	for (int i = 0; i < COMPRESS_PAGE_MAX_NUM; i++) {
		cold_pages[i].access_time = UINT64_MAX;
		cold_pages[i].lpn	  = INVALID_LPN;
	}

	uint64_t now = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);

	uint64_t max_cold_time = 0;
	int filled_count       = 0;

	for (uint64_t lpn = spp->tt_pgs - spp->main_area_pgs + 1;
	     lpn < spp->tt_pgs && filled_count < COMPRESS_PAGE_MAX_NUM * 2;
	     lpn++) {
		struct ppa ppa = get_maptbl_ent(ssd, lpn);
		if (!mapped_ppa(&ppa) || !valid_ppa(ssd, &ppa))
			continue;

		struct cmprs_rinfo *rinfo = get_rmap_ent_pointer(ssd, &ppa);
		if (rinfo->is_compressed || rinfo->ref_cnt == 0)
			continue;

		if (filled_count >= COMPRESS_PAGE_MAX_NUM &&
		    ppa.access_time >= max_cold_time) {
#ifdef TRACE_REPLAY
			break;
#else
			continue;
#endif
		}

		int insert_pos = -1;
		if (filled_count < COMPRESS_PAGE_MAX_NUM) {
			for (int i = 0; i < filled_count; i++) {
				if (ppa.access_time <
				    cold_pages[i].access_time) {
					insert_pos = i;
					break;
				}
			}
			if (insert_pos == -1) {
				insert_pos = filled_count;
			}
			filled_count++;
		} else {
			for (int i = 0; i < COMPRESS_PAGE_MAX_NUM; i++) {
				if (ppa.access_time <
				    cold_pages[i].access_time) {
					insert_pos = i;
					break;
				}
			}
		}

		if (insert_pos != -1) {
			int move_count =
				(filled_count <= COMPRESS_PAGE_MAX_NUM ?
					 filled_count - 1 :
					 COMPRESS_PAGE_MAX_NUM - 1) -
				insert_pos;
			if (move_count > 0) {
				memmove(&cold_pages[insert_pos + 1],
					&cold_pages[insert_pos],
					move_count * sizeof(cold_pages[0]));
			}

			cold_pages[insert_pos].lpn	   = lpn;
			cold_pages[insert_pos].ppa	   = ppa;
			cold_pages[insert_pos].access_time = ppa.access_time;

			if (filled_count >= COMPRESS_PAGE_MAX_NUM) {
				max_cold_time =
					cold_pages[COMPRESS_PAGE_MAX_NUM - 1]
						.access_time;
			}
		}
	}

	if (filled_count < COMPRESS_PAGE_MAX_NUM ||
	    cold_pages[COMPRESS_PAGE_MAX_NUM - 1].lpn == INVALID_LPN) {
		update_compression_threshold(spp, false);
		return;
	}

	bool all_cold	   = true;
	uint64_t threshold = spp->cold_page_threshold_ns;
	for (int i = 0; i < COMPRESS_PAGE_MAX_NUM; i++) {
		if (now - cold_pages[i].access_time < threshold) {
#ifndef TRACE_REPLAY
			all_cold = false;
#endif
			break;
		}
	}

	if (!all_cold) {
		update_compression_threshold(spp, false);
		return;
	}

	update_compression_threshold(spp, true);

	uint64_t lpn_tbl[COMPRESS_PAGE_MAX_NUM];

	for (int i = 0; i < COMPRESS_PAGE_MAX_NUM; i++) {
		lpn_tbl[i] = cold_pages[i].lpn;
		cmprs_read_page(ssd, &cold_pages[i].ppa);
		mark_page_invalid(ssd, &cold_pages[i].ppa);
		set_rmap_ent(ssd, INVALID_LPN, false, 0, &cold_pages[i].ppa,
			     NULL);
	}

	struct ppa new_ppa = get_new_page(ssd, true, now);

	for (int i = 0; i < COMPRESS_PAGE_MAX_NUM; i++) {
		set_maptbl_ent(ssd, cold_pages[i].lpn, &new_ppa);
	}

	set_rmap_ent(ssd, UNUSED_LPN, true, COMPRESS_PAGE_MAX_NUM, &new_ppa,
		     lpn_tbl);
	mark_page_valid(ssd, &new_ppa);
	ssd->stats.migrated_pages_count++;

	ssd->stats.compressed_pages_count[4]++;
	ssd_advance_write_pointer(ssd, true);

	if (ssd->sp.enable_cmprs_delay) {
		struct nand_cmd gcw = { .type  = COMPRESS_IO,
					.cmd   = NAND_WRITE,
					.stime = 0 };
		ssd_advance_status(ssd, &new_ppa, &gcw);
	}
}

static void *background_compress_thread(void *arg)
{
	FemuCtrl *n		      = (FemuCtrl *)arg;
	struct ssd *ssd		      = n->ssd;
	struct f2dfs_dm_info *dm_info = n->dm_info;

	femu_log("Compression thread started\r\n");

	while (!dm_info->compress_thread_stop) {
		if (dm_info->compress_thread_stop) {
			break;
		}

		bool manual_trigger	  = dm_info->trigger_compress;
		dm_info->trigger_compress = false;

		if ((dm_info->enable_compress && should_compress(ssd)) ||
		    manual_trigger) {
			perform_compression(n);
		}
	}

	femu_log("Compression thread stopped\r\n");
	return NULL;
}

void trigger_compression(FemuCtrl *n)
{
	struct f2dfs_dm_info *dm_info = n->dm_info;
	dm_info->trigger_compress     = true;
}

int init_compress_thread(FemuCtrl *n)
{
	struct f2dfs_dm_info *dm_info = n->dm_info;

	dm_info->compress_thread_running = true;
	dm_info->compress_thread_stop	 = false;

	qemu_thread_create(&dm_info->compress_thread, "compress_thread",
			   background_compress_thread, n, QEMU_THREAD_JOINABLE);

	dm_info->compress_thread_running = true;
	femu_log("Compression thread initialized successfully\r\n");
	return 0;
}

void stop_compress_thread(FemuCtrl *n)
{
	struct f2dfs_dm_info *dm_info = n->dm_info;

	if (!dm_info || !dm_info->compress_thread_running) {
		return;
	}

	dm_info->compress_thread_stop = true;

	qemu_thread_join(&dm_info->compress_thread);
	dm_info->compress_thread_running = false;

	femu_log("Compression thread stopped\r\n");
}

void enable_compression(FemuCtrl *n, bool enable)
{
	struct f2dfs_dm_info *dm_info = n->dm_info;

	if (!dm_info) {
		femu_err("DM info is not initialized\r\n");
		return;
	}

	if (dm_info->enable_compress != enable) {
		dm_info->enable_compress = enable;
		if (enable) {
			femu_log("Compression enabled\r\n");
		} else {
			femu_log("Compression disabled\r\n");
		}
	}
}
