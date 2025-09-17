#include "ftl.h"
#ifndef DEDUP_COMPRESSION_ENABLED

static void *ftl_thread(void *arg);

static inline bool should_gc(struct ssd *ssd)
{
	return (ssd->lm.free_line_cnt <= ssd->sp.gc_thres_lines);
}

static inline bool should_gc_high(struct ssd *ssd)
{
	return (ssd->lm.free_line_cnt <= ssd->sp.gc_thres_lines_high);
}

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

	ftl_assert(pgidx < spp->tt_pgs);

	return pgidx;
}

static inline uint64_t get_rmap_ent(struct ssd *ssd, struct ppa *ppa)
{
	uint64_t pgidx = ppa2pgidx(ssd, ppa);

	return ssd->rmap[pgidx];
}

static inline void set_rmap_ent(struct ssd *ssd, uint64_t lpn, struct ppa *ppa)
{
	uint64_t pgidx = ppa2pgidx(ssd, ppa);

	ssd->rmap[pgidx] = lpn;
}

static inline int victim_line_cmp_pri(pqueue_pri_t next, pqueue_pri_t curr)
{
	return (next > curr);
}

static inline pqueue_pri_t victim_line_get_pri(void *a)
{
	return ((struct line *)a)->vpc;
}

static inline void victim_line_set_pri(void *a, pqueue_pri_t pri)
{
	((struct line *)a)->vpc = pri;
}

static inline size_t victim_line_get_pos(void *a)
{
	return ((struct line *)a)->pos;
}

static inline void victim_line_set_pos(void *a, size_t pos)
{
	((struct line *)a)->pos = pos;
}

static void ssd_init_lines(struct ssd *ssd)
{
	struct ssdparams *spp = &ssd->sp;
	struct line_mgmt *lm  = &ssd->lm;
	struct line *line;

	lm->tt_lines = spp->blks_per_pl;
	ftl_assert(lm->tt_lines == spp->tt_lines);
	lm->lines = g_malloc0(sizeof(struct line) * lm->tt_lines);

	QTAILQ_INIT(&lm->free_line_list);
	lm->victim_line_pq =
		pqueue_init(spp->tt_lines, victim_line_cmp_pri,
			    victim_line_get_pri, victim_line_set_pri,
			    victim_line_get_pos, victim_line_set_pos);
	QTAILQ_INIT(&lm->full_line_list);

	lm->free_line_cnt = 0;
	for (int i = 0; i < lm->tt_lines; i++) {
		line	  = &lm->lines[i];
		line->id  = i;
		line->ipc = 0;
		line->vpc = 0;
		line->pos = 0;

		QTAILQ_INSERT_TAIL(&lm->free_line_list, line, entry);
		lm->free_line_cnt++;
	}

	ftl_assert(lm->free_line_cnt == lm->tt_lines);
	lm->victim_line_cnt = 0;
	lm->full_line_cnt   = 0;
}

static void ssd_init_write_pointer(struct ssd *ssd)
{
	struct write_pointer *wpp = &ssd->wp;
	struct line_mgmt *lm	  = &ssd->lm;
	struct line *curline	  = NULL;

	curline = QTAILQ_FIRST(&lm->free_line_list);
	QTAILQ_REMOVE(&lm->free_line_list, curline, entry);
	lm->free_line_cnt--;

	wpp->curline = curline;
	wpp->ch	     = 0;
	wpp->lun     = 0;
	wpp->pg	     = 0;
	wpp->blk     = 0;
	wpp->pl	     = 0;
}

static inline void check_addr(int a, int max)
{
	ftl_assert(a >= 0 && a < max);
}

static struct line *get_next_free_line(struct ssd *ssd)
{
	struct line_mgmt *lm = &ssd->lm;
	struct line *curline = NULL;

	curline = QTAILQ_FIRST(&lm->free_line_list);
	if (!curline) {
		ftl_err("No free lines left in [%s] !!!!\r\n", ssd->ssdname);
		return NULL;
	}

	QTAILQ_REMOVE(&lm->free_line_list, curline, entry);
	lm->free_line_cnt--;
	return curline;
}

static void ssd_advance_write_pointer(struct ssd *ssd)
{
	struct ssdparams *spp = &ssd->sp;

	struct write_pointer *wpp = &ssd->wp;

	struct line_mgmt *lm = &ssd->lm;

	check_addr(wpp->ch, spp->nchs);

	wpp->ch++;

	if (wpp->ch == spp->nchs) {
		wpp->ch = 0;

		check_addr(wpp->lun, spp->luns_per_ch);

		wpp->lun++;

		if (wpp->lun == spp->luns_per_ch) {
			wpp->lun = 0;

			check_addr(wpp->pg, spp->pgs_per_blk);

			wpp->pg++;

			if (wpp->pg == spp->pgs_per_blk) {
				wpp->pg = 0;

				if (wpp->curline->vpc == spp->pgs_per_line) {
					ftl_assert(wpp->curline->ipc == 0);

					QTAILQ_INSERT_TAIL(&lm->full_line_list,
							   wpp->curline, entry);

					lm->full_line_cnt++;
				} else {
					ftl_assert(wpp->curline->vpc >= 0 &&
						   wpp->curline->vpc <
							   spp->pgs_per_line);

					ftl_assert(wpp->curline->ipc > 0);

					pqueue_insert(lm->victim_line_pq,
						      wpp->curline);

					lm->victim_line_cnt++;
				}

				check_addr(wpp->blk, spp->blks_per_pl);

				wpp->curline = NULL;

				wpp->curline = get_next_free_line(ssd);

				if (!wpp->curline) {
					abort();
				}

				wpp->blk = wpp->curline->id;

				check_addr(wpp->blk, spp->blks_per_pl);

				ftl_assert(wpp->pg == 0);

				ftl_assert(wpp->lun == 0);

				ftl_assert(wpp->ch == 0);

				ftl_assert(wpp->pl == 0);
			}
		}
	}
}

static struct ppa get_new_page(struct ssd *ssd)
{
	struct write_pointer *wpp = &ssd->wp;

	struct ppa ppa;

	ppa.ppa = 0;

	ppa.g.ch = wpp->ch;

	ppa.g.lun = wpp->lun;

	ppa.g.pg = wpp->pg;

	ppa.g.blk = wpp->blk;

	ppa.g.pl = wpp->pl;

	ftl_assert(ppa.g.pl == 0);

	return ppa;
}

static void check_params(struct ssdparams *spp)
{
}

static void ssd_init_params(struct ssdparams *spp, FemuCtrl *n)
{
	spp->secsz	 = n->bb_params.secsz;
	spp->secs_per_pg = n->bb_params.secs_per_pg;
	spp->pgs_per_blk = n->bb_params.pgs_per_blk;
	spp->blks_per_pl = n->bb_params.blks_per_pl;
	spp->pls_per_lun = n->bb_params.pls_per_lun;
	spp->luns_per_ch = n->bb_params.luns_per_ch;
	spp->nchs	 = n->bb_params.nchs;

	spp->pg_rd_lat	 = n->bb_params.pg_rd_lat;
	spp->pg_wr_lat	 = n->bb_params.pg_wr_lat;
	spp->blk_er_lat	 = n->bb_params.blk_er_lat;
	spp->ch_xfer_lat = n->bb_params.ch_xfer_lat;

	spp->secs_per_blk = spp->secs_per_pg * spp->pgs_per_blk;
	spp->secs_per_pl  = spp->secs_per_blk * spp->blks_per_pl;
	spp->secs_per_lun = spp->secs_per_pl * spp->pls_per_lun;
	spp->secs_per_ch  = spp->secs_per_lun * spp->luns_per_ch;
	spp->tt_secs	  = spp->secs_per_ch * spp->nchs;

	spp->pgs_per_pl	 = spp->pgs_per_blk * spp->blks_per_pl;
	spp->pgs_per_lun = spp->pgs_per_pl * spp->pls_per_lun;
	spp->pgs_per_ch	 = spp->pgs_per_lun * spp->luns_per_ch;
	spp->tt_pgs	 = spp->pgs_per_ch * spp->nchs;

	spp->blks_per_lun = spp->blks_per_pl * spp->pls_per_lun;
	spp->blks_per_ch  = spp->blks_per_lun * spp->luns_per_ch;
	spp->tt_blks	  = spp->blks_per_ch * spp->nchs;

	spp->pls_per_ch = spp->pls_per_lun * spp->luns_per_ch;
	spp->tt_pls	= spp->pls_per_ch * spp->nchs;

	spp->tt_luns = spp->luns_per_ch * spp->nchs;

	spp->blks_per_line = spp->tt_luns;
	spp->pgs_per_line  = spp->blks_per_line * spp->pgs_per_blk;
	spp->secs_per_line = spp->pgs_per_line * spp->secs_per_pg;
	spp->tt_lines	   = spp->blks_per_lun;

	spp->gc_thres_pcent = n->bb_params.gc_thres_pcent / 100.0;
	spp->gc_thres_lines = (int)((1 - spp->gc_thres_pcent) * spp->tt_lines);
	spp->gc_thres_pcent_high = n->bb_params.gc_thres_pcent_high / 100.0;
	spp->gc_thres_lines_high =
		(int)((1 - spp->gc_thres_pcent_high) * spp->tt_lines);
	spp->enable_gc_delay = true;

	check_params(spp);
}

static void ssd_init_nand_page(struct nand_page *pg, struct ssdparams *spp)
{
	pg->nsecs = spp->secs_per_pg;
	pg->sec	  = g_malloc0(sizeof(nand_sec_status_t) * pg->nsecs);
	for (int i = 0; i < pg->nsecs; i++) {
		pg->sec[i] = SEC_FREE;
	}
	pg->status = PG_FREE;
}

static void ssd_init_nand_blk(struct nand_block *blk, struct ssdparams *spp)
{
	blk->npgs = spp->pgs_per_blk;
	blk->pg	  = g_malloc0(sizeof(struct nand_page) * blk->npgs);
	for (int i = 0; i < blk->npgs; i++) {
		ssd_init_nand_page(&blk->pg[i], spp);
	}
	blk->ipc       = 0;
	blk->vpc       = 0;
	blk->erase_cnt = 0;
	blk->wp	       = 0;
}

static void ssd_init_nand_plane(struct nand_plane *pl, struct ssdparams *spp)
{
	pl->nblks = spp->blks_per_pl;
	pl->blk	  = g_malloc0(sizeof(struct nand_block) * pl->nblks);
	for (int i = 0; i < pl->nblks; i++) {
		ssd_init_nand_blk(&pl->blk[i], spp);
	}
}

static void ssd_init_nand_lun(struct nand_lun *lun, struct ssdparams *spp)
{
	lun->npls = spp->pls_per_lun;
	lun->pl	  = g_malloc0(sizeof(struct nand_plane) * lun->npls);
	for (int i = 0; i < lun->npls; i++) {
		ssd_init_nand_plane(&lun->pl[i], spp);
	}
	lun->next_lun_avail_time = 0;
	lun->busy		 = false;
}

static void ssd_init_ch(struct ssd_channel *ch, struct ssdparams *spp)
{
	ch->nluns = spp->luns_per_ch;
	ch->lun	  = g_malloc0(sizeof(struct nand_lun) * ch->nluns);
	for (int i = 0; i < ch->nluns; i++) {
		ssd_init_nand_lun(&ch->lun[i], spp);
	}
	ch->next_ch_avail_time = 0;
	ch->busy	       = 0;
}

static void ssd_init_maptbl(struct ssd *ssd)
{
	struct ssdparams *spp = &ssd->sp;

	ssd->maptbl = g_malloc0(sizeof(struct ppa) * spp->tt_pgs);

	for (int i = 0; i < spp->tt_pgs; i++) {
		ssd->maptbl[i].ppa = UNMAPPED_PPA;
	}
}

static void ssd_init_rmap(struct ssd *ssd)
{
	struct ssdparams *spp = &ssd->sp;

	ssd->rmap = g_malloc0(sizeof(uint64_t) * spp->tt_pgs);

	for (int i = 0; i < spp->tt_pgs; i++) {
		ssd->rmap[i] = INVALID_LPN;
	}
}

void ssd_init(FemuCtrl *n)
{
	struct ssd *ssd = n->ssd;

	struct ssdparams *spp = &ssd->sp;

	ftl_assert(ssd);

	ssd_init_params(spp, n);

	ssd->ch = g_malloc0(sizeof(struct ssd_channel) * spp->nchs);

	for (int i = 0; i < spp->nchs; i++) {
		ssd_init_ch(&ssd->ch[i], spp);
	}

	ssd_init_maptbl(ssd);

	ssd_init_rmap(ssd);

	ssd_init_lines(ssd);

	ssd_init_write_pointer(ssd);

	qemu_thread_create(&ssd->ftl_thread, "FEMU-FTL-Thread", ftl_thread, n,
			   QEMU_THREAD_JOINABLE);
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

static inline struct ssd_channel *get_ch(struct ssd *ssd, struct ppa *ppa)
{
	return &(ssd->ch[ppa->g.ch]);
}

static inline struct nand_lun *get_lun(struct ssd *ssd, struct ppa *ppa)
{
	struct ssd_channel *ch = get_ch(ssd, ppa);
	return &(ch->lun[ppa->g.lun]);
}

static inline struct nand_plane *get_pl(struct ssd *ssd, struct ppa *ppa)
{
	struct nand_lun *lun = get_lun(ssd, ppa);
	return &(lun->pl[ppa->g.pl]);
}

static inline struct nand_block *get_blk(struct ssd *ssd, struct ppa *ppa)
{
	struct nand_plane *pl = get_pl(ssd, ppa);
	return &(pl->blk[ppa->g.blk]);
}

static inline struct line *get_line(struct ssd *ssd, struct ppa *ppa)
{
	return &(ssd->lm.lines[ppa->g.blk]);
}

static inline struct nand_page *get_pg(struct ssd *ssd, struct ppa *ppa)
{
	struct nand_block *blk = get_blk(ssd, ppa);
	return &(blk->pg[ppa->g.pg]);
}

static uint64_t ssd_advance_status(struct ssd *ssd, struct ppa *ppa,
				   struct nand_cmd *ncmd)
{
	int c = ncmd->cmd;

	uint64_t cmd_stime = (ncmd->stime == 0) ?
				     qemu_clock_get_ns(QEMU_CLOCK_REALTIME) :
				     ncmd->stime;

	uint64_t nand_stime;

	struct ssdparams *spp = &ssd->sp;

	struct nand_lun *lun = get_lun(ssd, ppa);

	uint64_t lat = 0;

	switch (c) {
	case NAND_READ:

		nand_stime = (lun->next_lun_avail_time < cmd_stime) ?
				     cmd_stime :
				     lun->next_lun_avail_time;

		lun->next_lun_avail_time = nand_stime + spp->pg_rd_lat;

		lat = lun->next_lun_avail_time - cmd_stime;
#if 0
        lun->next_lun_avail_time = nand_stime + spp->pg_rd_lat;

        
        chnl_stime = (ch->next_ch_avail_time < lun->next_lun_avail_time) ? \
            lun->next_lun_avail_time : ch->next_ch_avail_time;
        ch->next_ch_avail_time = chnl_stime + spp->ch_xfer_lat;

        lat = ch->next_ch_avail_time - cmd_stime;
#endif
		break;

	case NAND_WRITE:

		nand_stime = (lun->next_lun_avail_time < cmd_stime) ?
				     cmd_stime :
				     lun->next_lun_avail_time;

		if (ncmd->type == USER_IO) {
			lun->next_lun_avail_time = nand_stime + spp->pg_wr_lat;
		} else {
			lun->next_lun_avail_time = nand_stime + spp->pg_wr_lat;
		}

		lat = lun->next_lun_avail_time - cmd_stime;

#if 0
        chnl_stime = (ch->next_ch_avail_time < cmd_stime) ? cmd_stime : \
                     ch->next_ch_avail_time;
        ch->next_ch_avail_time = chnl_stime + spp->ch_xfer_lat;

        
        nand_stime = (lun->next_lun_avail_time < ch->next_ch_avail_time) ? \
            ch->next_ch_avail_time : lun->next_lun_avail_time;
        lun->next_lun_avail_time = nand_stime + spp->pg_wr_lat;

        lat = lun->next_lun_avail_time - cmd_stime;
#endif
		break;

	case NAND_ERASE:

		nand_stime = (lun->next_lun_avail_time < cmd_stime) ?
				     cmd_stime :
				     lun->next_lun_avail_time;

		lun->next_lun_avail_time = nand_stime + spp->blk_er_lat;

		lat = lun->next_lun_avail_time - cmd_stime;
		break;

	default:

		ftl_err("Unsupported NAND command: 0x%x\r\n", c);
	}

	return lat;
}

static void mark_page_invalid(struct ssd *ssd, struct ppa *ppa)
{
	struct line_mgmt *lm = &ssd->lm;

	struct ssdparams *spp = &ssd->sp;

	struct nand_block *blk = NULL;

	struct nand_page *pg = NULL;

	bool was_full_line = false;

	struct line *line;

	pg = get_pg(ssd, ppa);

	ftl_assert(pg->status == PG_VALID);

	pg->status = PG_INVALID;

	blk = get_blk(ssd, ppa);

	ftl_assert(blk->ipc >= 0 && blk->ipc < spp->pgs_per_blk);

	blk->ipc++;

	ftl_assert(blk->vpc > 0 && blk->vpc <= spp->pgs_per_blk);

	blk->vpc--;

	line = get_line(ssd, ppa);

	ftl_assert(line->ipc >= 0 && line->ipc < spp->pgs_per_line);

	if (line->vpc == spp->pgs_per_line) {
		ftl_assert(line->ipc == 0);

		was_full_line = true;
	}

	line->ipc++;

	ftl_assert(line->vpc > 0 && line->vpc <= spp->pgs_per_line);

	if (line->pos) {
		pqueue_change_priority(lm->victim_line_pq, line->vpc - 1, line);
	} else {
		line->vpc--;
	}

	if (was_full_line) {
		QTAILQ_REMOVE(&lm->full_line_list, line, entry);

		lm->full_line_cnt--;

		pqueue_insert(lm->victim_line_pq, line);

		lm->victim_line_cnt++;
	}
}

static void mark_page_valid(struct ssd *ssd, struct ppa *ppa)
{
	struct nand_block *blk = NULL;
	struct nand_page *pg   = NULL;
	struct line *line;

	pg = get_pg(ssd, ppa);
	ftl_assert(pg->status == PG_FREE);
	pg->status = PG_VALID;

	blk = get_blk(ssd, ppa);
	ftl_assert(blk->vpc >= 0 && blk->vpc < ssd->sp.pgs_per_blk);
	blk->vpc++;

	line = get_line(ssd, ppa);
	ftl_assert(line->vpc >= 0 && line->vpc < ssd->sp.pgs_per_line);
	line->vpc++;
}

static void mark_block_free(struct ssd *ssd, struct ppa *ppa)
{
	struct ssdparams *spp  = &ssd->sp;
	struct nand_block *blk = get_blk(ssd, ppa);
	struct nand_page *pg   = NULL;

	for (int i = 0; i < spp->pgs_per_blk; i++) {
		pg = &blk->pg[i];
		ftl_assert(pg->nsecs == spp->secs_per_pg);
		pg->status = PG_FREE;
	}

	ftl_assert(blk->npgs == spp->pgs_per_blk);
	blk->ipc = 0;
	blk->vpc = 0;
	blk->erase_cnt++;
}

static void gc_read_page(struct ssd *ssd, struct ppa *ppa)
{
	if (ssd->sp.enable_gc_delay) {
		struct nand_cmd gcr;
		gcr.type  = GC_IO;
		gcr.cmd	  = NAND_READ;
		gcr.stime = 0;
		ssd_advance_status(ssd, ppa, &gcr);
	}
}

static uint64_t gc_write_page(struct ssd *ssd, struct ppa *old_ppa)
{
	struct ppa new_ppa;
	struct nand_lun *new_lun;
	uint64_t lpn = get_rmap_ent(ssd, old_ppa);

	ftl_assert(valid_lpn(ssd, lpn));
	new_ppa = get_new_page(ssd);

	set_maptbl_ent(ssd, lpn, &new_ppa);

	set_rmap_ent(ssd, lpn, &new_ppa);

	mark_page_valid(ssd, &new_ppa);

	ssd_advance_write_pointer(ssd);

	if (ssd->sp.enable_gc_delay) {
		struct nand_cmd gcw;
		gcw.type  = GC_IO;
		gcw.cmd	  = NAND_WRITE;
		gcw.stime = 0;
		ssd_advance_status(ssd, &new_ppa, &gcw);
	}

#if 0
    new_ch = get_ch(ssd, &new_ppa);
    new_ch->gc_endtime = new_ch->next_ch_avail_time;
#endif

	new_lun		    = get_lun(ssd, &new_ppa);
	new_lun->gc_endtime = new_lun->next_lun_avail_time;

	return 0;
}

static struct line *select_victim_line(struct ssd *ssd, bool force)
{
	struct line_mgmt *lm	 = &ssd->lm;
	struct line *victim_line = NULL;

	victim_line = pqueue_peek(lm->victim_line_pq);
	if (!victim_line) {
		return NULL;
	}

	if (!force && victim_line->ipc < ssd->sp.pgs_per_line / 8) {
		return NULL;
	}

	pqueue_pop(lm->victim_line_pq);
	victim_line->pos = 0;
	lm->victim_line_cnt--;

	return victim_line;
}

static void clean_one_block(struct ssd *ssd, struct ppa *ppa)
{
	struct ssdparams *spp	  = &ssd->sp;
	struct nand_page *pg_iter = NULL;
	int cnt			  = 0;

	for (int pg = 0; pg < spp->pgs_per_blk; pg++) {
		ppa->g.pg = pg;
		pg_iter	  = get_pg(ssd, ppa);

		ftl_assert(pg_iter->status != PG_FREE);
		if (pg_iter->status == PG_VALID) {
			gc_read_page(ssd, ppa);

			gc_write_page(ssd, ppa);
			cnt++;
		}
	}

	ftl_assert(get_blk(ssd, ppa)->vpc == cnt);
}

static void mark_line_free(struct ssd *ssd, struct ppa *ppa)
{
	struct line_mgmt *lm = &ssd->lm;
	struct line *line    = get_line(ssd, ppa);
	line->ipc	     = 0;
	line->vpc	     = 0;

	QTAILQ_INSERT_TAIL(&lm->free_line_list, line, entry);
	lm->free_line_cnt++;
}

static int do_gc(struct ssd *ssd, bool force)
{
	struct line *victim_line = NULL;

	struct ssdparams *spp = &ssd->sp;

	struct nand_lun *lunp;

	struct ppa ppa;

	int ch;

	int lun;

	victim_line = select_victim_line(ssd, force);

	if (!victim_line) {
		return -1;
	}

	ppa.g.blk = victim_line->id;

	ftl_debug("GC-ing line:%d,ipc=%d,victim=%d,full=%d,free=%d\r\n",
		  ppa.g.blk, victim_line->ipc, ssd->lm.victim_line_cnt,
		  ssd->lm.full_line_cnt, ssd->lm.free_line_cnt);

	for (ch = 0; ch < spp->nchs; ch++) {
		for (lun = 0; lun < spp->luns_per_ch; lun++) {
			ppa.g.ch = ch;

			ppa.g.lun = lun;

			ppa.g.pl = 0;

			lunp = get_lun(ssd, &ppa);

			clean_one_block(ssd, &ppa);

			mark_block_free(ssd, &ppa);

			if (spp->enable_gc_delay) {
				struct nand_cmd gce;

				gce.type = GC_IO;

				gce.cmd = NAND_ERASE;

				gce.stime = 0;

				ssd_advance_status(ssd, &ppa, &gce);
			}

			lunp->gc_endtime = lunp->next_lun_avail_time;
		}
	}

	mark_line_free(ssd, &ppa);

	return 0;
}

static uint64_t ssd_read(struct ssd *ssd, NvmeRequest *req)
{
	struct ssdparams *spp = &ssd->sp;

	uint64_t lba = req->slba;

	int nsecs = req->nlb;

	struct ppa ppa;

	uint64_t start_lpn = lba / spp->secs_per_pg;

	uint64_t end_lpn = (lba + nsecs - 1) / spp->secs_per_pg;

	uint64_t lpn;

	uint64_t sublat;

	uint64_t maxlat = 0;

	if (end_lpn >= spp->tt_pgs) {
		ftl_err("start_lpn=%" PRIu64 ",tt_pgs=%d\r\n", start_lpn,
			ssd->sp.tt_pgs);
	}

	for (lpn = start_lpn; lpn <= end_lpn; lpn++) {
		ppa = get_maptbl_ent(ssd, lpn);

		if (!mapped_ppa(&ppa) || !valid_ppa(ssd, &ppa)) {
			continue;
		}

		struct nand_cmd srd;

		srd.type = USER_IO;

		srd.cmd = NAND_READ;

		srd.stime = req->stime;

		sublat = ssd_advance_status(ssd, &ppa, &srd);

		maxlat = (sublat > maxlat) ? sublat : maxlat;
	}

	return maxlat;
}

static uint64_t ssd_write(struct ssd *ssd, NvmeRequest *req)
{
	uint64_t lba = req->slba;

	struct ssdparams *spp = &ssd->sp;

	int len = req->nlb;

	uint64_t start_lpn = lba / spp->secs_per_pg;

	uint64_t end_lpn = (lba + len - 1) / spp->secs_per_pg;

	struct ppa ppa;

	uint64_t lpn;

	uint64_t curlat = 0;

	uint64_t maxlat = 0;

	int r;

	if (end_lpn >= spp->tt_pgs) {
		ftl_err("start_lpn=%" PRIu64 ",tt_pgs=%d\r\n", start_lpn,
			ssd->sp.tt_pgs);
	}

	while (should_gc_high(ssd)) {
		r = do_gc(ssd, true);

		if (r == -1)
			break;
	}

	for (lpn = start_lpn; lpn <= end_lpn; lpn++) {
		ppa = get_maptbl_ent(ssd, lpn);

		if (mapped_ppa(&ppa)) {
			mark_page_invalid(ssd, &ppa);

			set_rmap_ent(ssd, INVALID_LPN, &ppa);
		}

		ppa = get_new_page(ssd);

		set_maptbl_ent(ssd, lpn, &ppa);

		set_rmap_ent(ssd, lpn, &ppa);

		mark_page_valid(ssd, &ppa);

		ssd_advance_write_pointer(ssd);

		struct nand_cmd swr;

		swr.type = USER_IO;

		swr.cmd = NAND_WRITE;

		swr.stime = req->stime;

		curlat = ssd_advance_status(ssd, &ppa, &swr);

		maxlat = (curlat > maxlat) ? curlat : maxlat;
	}

	return maxlat;
}

static void *ftl_thread(void *arg)
{
	FemuCtrl *n = (FemuCtrl *)arg;

	struct ssd *ssd = n->ssd;

	NvmeRequest *req = NULL;

	uint64_t lat = 0;

	int rc;

	int i;

	while (!*(ssd->dataplane_started_ptr)) {
		usleep(100000);
	}

	ssd->to_ftl    = n->to_ftl;
	ssd->to_poller = n->to_poller;

	while (1) {
		for (i = 1; i <= n->nr_pollers; i++) {
			if (!ssd->to_ftl[i] || !femu_ring_count(ssd->to_ftl[i]))
				continue;

			rc = femu_ring_dequeue(ssd->to_ftl[i], (void *)&req, 1);
			if (rc != 1) {
				printf("FEMU: FTL to_ftl dequeue failed\r\n");
			}

			ftl_assert(req);

			switch (req->cmd.opcode) {
			case NVME_CMD_WRITE:

				lat = ssd_write(ssd, req);
				break;
			case NVME_CMD_READ:

				lat = ssd_read(ssd, req);
				break;
			case NVME_CMD_DSM:

				lat = 0;
				break;
			default:

				;
			}

			req->reqlat = lat;

			req->expire_time += lat;

			rc = femu_ring_enqueue(ssd->to_poller[i], (void *)&req,
					       1);
			if (rc != 1) {
				ftl_err("FTL to_poller enqueue failed\r\n");
			}

			if (should_gc(ssd)) {
				do_gc(ssd, false);
			}
		}
	}

	return NULL;
}

#endif