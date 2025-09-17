#include "../nvme.h"
#include "./dedup.h"
#include "./ftl.h"

static void bb_init_ctrl_str(FemuCtrl *n)
{
	static int fsid_vbb = 0;

	const char *vbbssd_mn = "FEMU BlackBox-SSD Controller";

	const char *vbbssd_sn = "vSSD";

	nvme_set_ctrl_name(n, vbbssd_mn, vbbssd_sn, &fsid_vbb);
}

static void bb_init(FemuCtrl *n, Error **errp)
{
	struct ssd *ssd = n->ssd = g_malloc0(sizeof(struct ssd));

	bb_init_ctrl_str(n);

	ssd->dataplane_started_ptr = &n->dataplane_started;
	ssd->ssdname		   = (char *)n->devname;
	femu_debug("Starting FEMU in Blackbox-SSD mode ...\r\n");
	ssd_init(n);
	init_dm_info(n);
}

static void bb_exit(FemuCtrl *n)
{
	femu_debug("Exiting FEMU in Blackbox-SSD mode ...\r\n");

	cleanup_dm_info(n);
}

static void bb_flip(FemuCtrl *n, NvmeCmd *cmd)
{
	struct ssd *ssd = n->ssd;

	int64_t cdw10  = le64_to_cpu(cmd->cdw10);
	uint64_t cdw11 = le64_to_cpu(cmd->cdw11);
	uint64_t cdw12 = le64_to_cpu(cmd->cdw12);

	switch (cdw10) {
	case FEMU_ENABLE_GC_DELAY:

		ssd->sp.enable_gc_delay = true;

		femu_log("%s,FEMU GC Delay Emulation [Enabled]!\r\n",
			 n->devname);
		break;

	case FEMU_DISABLE_GC_DELAY:

		ssd->sp.enable_gc_delay = false;

		femu_log("%s,FEMU GC Delay Emulation [Disabled]!\r\n",
			 n->devname);
		break;

	case FEMU_ENABLE_DELAY_EMU:

		ssd->sp.pg_rd_lat = n->bb_params.pg_rd_lat;

		ssd->sp.pg_wr_lat = n->bb_params.pg_wr_lat;

		ssd->sp.blk_er_lat = n->bb_params.blk_er_lat;

		ssd->sp.ch_xfer_lat = n->bb_params.ch_xfer_lat;

		femu_log("%s,FEMU Delay Emulation [Enabled]!\r\n", n->devname);
		break;

	case FEMU_DISABLE_DELAY_EMU:

		ssd->sp.pg_rd_lat = 0;

		ssd->sp.pg_wr_lat = 0;

		ssd->sp.blk_er_lat = 0;

		ssd->sp.ch_xfer_lat = 0;

		femu_log("%s,FEMU Delay Emulation [Disabled]!\r\n", n->devname);
		break;

	case FEMU_RESET_ACCT:

		n->nr_tt_ios = 0;

		n->nr_tt_late_ios = 0;

		femu_log("%s,Reset tt_late_ios/tt_ios,%lu/%lu\r\n", n->devname,
			 n->nr_tt_late_ios, n->nr_tt_ios);
		break;

	case FEMU_ENABLE_LOG:

		n->print_log = true;

		femu_log("%s,Log print [Enabled]!\r\n", n->devname);
		break;

	case FEMU_DISABLE_LOG:

		n->print_log = false;

		femu_log("%s,Log print [Disabled]!\r\n", n->devname);
		break;
	case FEMU_PRINT_DATA:
		bb_read_data_print(n, cdw11, cdw12);
		break;
	case FEMU_ENABLE_DEDUP_MERGE:
		enable_dedup_merge(n, true);

		femu_log("%s,FEMU Deduplication Merge [Enabled]!\r\n",
			 n->devname);
		break;
	case FEMU_DISABLE_DEDUP_MERGE:
		enable_dedup_merge(n, false);

		femu_log("%s,FEMU Deduplication Merge [Disabled]!\r\n",
			 n->devname);
		break;
	case FEMU_TRIGGER_RC_DELTA_MERGE:

		trigger_rc_delta_merge(n);

		femu_log("%s,FEMU RC Delta Merge Triggered!\r\n", n->devname);
		break;
#ifdef DEDUP_COMPRESSION_ENABLED
	case FEMU_ENABLE_COMPRESSION_DELAY:
		ssd->sp.enable_cmprs_delay = true;
		ssd->sp.compress_lat	   = COMPRESS_LATENCY;
		ssd->sp.decompress_lat	   = DECOMPRESS_LATENCY;

		femu_log("%s,FEMU Compression Delay Emulation [Enabled]!\r\n",
			 n->devname);
		break;
	case FEMU_DISABLE_COMPRESSION_DELAY:
		ssd->sp.enable_cmprs_delay = false;
		ssd->sp.compress_lat	   = 0;
		ssd->sp.decompress_lat	   = 0;

		femu_log("%s,FEMU Compression Delay Emulation [Disabled]!\r\n",
			 n->devname);
		break;
#endif
	case FEMU_ENABLE_COMPRESSION:

		enable_compression(n, true);

		femu_log("%s,FEMU Compression [Enabled]!\r\n", n->devname);
		break;
	case FEMU_DISABLE_COMPRESSION:

		enable_compression(n, false);

		femu_log("%s,FEMU Compression [Disabled]!\r\n", n->devname);
		break;
	case FEMU_TRIGGER_COMPRESSION:
		do {
			double used_percent =
				(double)(ssd->stats.valid_pages_count) /
				ssd->sp.tt_phy_pgs;
			uint64_t compress_pages_count =
				ssd->stats.compressed_pages_count[1] +
				ssd->stats.compressed_pages_count[2] +
				ssd->stats.compressed_pages_count[3] +
				ssd->stats.compressed_pages_count[4];
			double compress_used_percent =
				(double)(compress_pages_count) /
				(ssd->sp.cmprs_line * ssd->sp.pgs_per_line);
			femu_log(
				"%s,Used Percent: %.2f, Compress Used Percent: %.2f\r\n",
				n->devname, used_percent,
				compress_used_percent);
		} while (0);
		trigger_compression(n);

		femu_log("%s,FEMU Compression Triggered!\r\n", n->devname);
		break;
	case FEMU_PRINT_SSD_STATS:

		femu_log("SSD Stats:\r\n");
		femu_log("Total Pages Written: %lu\r\n",
			 ssd->stats.total_pages_written);
		femu_log("Total Pages Read: %lu\r\n",
			 ssd->stats.total_pages_read);
		femu_log("Total Blocks Erased: %lu\r\n",
			 ssd->stats.total_blocks_erased);
		femu_log("Valid Pages Count: %lu\r\n",
			 ssd->stats.valid_pages_count);
		femu_log("Migrated Pages Count: %lu\r\n",
			 ssd->stats.migrated_pages_count);
		femu_log("GC Count: %lu\r\n", ssd->stats.gc_count);
		for (int i = 1; i < 5; i++) {
			femu_log("Compressed Pages Count [%d]: %lu\r\n", i,
				 ssd->stats.compressed_pages_count[i]);
		}
		break;

	default:

		femu_log("FEMU:%s,Not implemented flip cmd (%lu)\r\n",
			 n->devname, cdw10);
	}
}

static uint16_t bb_nvme_rw(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
			   NvmeRequest *req)
{
	return nvme_rw(n, ns, cmd, req);
}

static uint16_t bb_io_cmd(FemuCtrl *n, NvmeNamespace *ns, NvmeCmd *cmd,
			  NvmeRequest *req)
{
	switch (cmd->opcode) {
	case NVME_CMD_READ:

	case NVME_CMD_WRITE:

		return bb_nvme_rw(n, ns, cmd, req);

	default:

		return NVME_INVALID_OPCODE | NVME_DNR;
	}
}

static uint16_t bb_admin_cmd(FemuCtrl *n, NvmeCmd *cmd)
{
	switch (cmd->opcode) {
	case NVME_ADM_CMD_FEMU_FLIP:

		bb_flip(n, cmd);

		return NVME_SUCCESS;

	default:

		return NVME_INVALID_OPCODE | NVME_DNR;
	}
}

int nvme_register_bbssd(FemuCtrl *n)
{
	n->ext_ops = (FemuExtCtrlOps){

		.state = NULL,

		.init = bb_init,

		.exit = bb_exit,

		.rw_check_req = NULL,

		.admin_cmd = bb_admin_cmd,

		.io_cmd = bb_io_cmd,

		.get_log = NULL,
	};

	return 0;
}
