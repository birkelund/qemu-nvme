#include "qemu/osdep.h"
#include "hw/block/block.h"
#include "hw/hw.h"
#include "hw/pci/pci.h"
#include "sysemu/block-backend.h"
#include "sysemu/sysemu.h"
#include "qapi/error.h"
#include "trace.h"

#include "nvme.h"
#include "ocssd.h"

#include "block/ocssd.h"

#define OCSSD_LBA_FORMAT_TEMPLATE \
    "lba 0xffffffffffffffff group 255 punit 255 chunk 65535 sectr 4294967295"

static int _lba_str(char *buf, OcssdCtrl *o, OcssdNamespace *ons, uint64_t lba)
{
    OcssdAddrF *addrf = &ons->addrf;

    uint8_t pugrp, punit;
    uint16_t chunk;
    uint32_t sectr;

    pugrp = _group(addrf, lba);
    punit = _punit(addrf, lba);
    chunk = _chunk(addrf, lba);
    sectr = _sectr(addrf, lba);

    return sprintf(buf, "lba 0x%016"PRIx64" group %"PRIu8" punit %"PRIu8
        " chunk %"PRIu16" sectr %"PRIu32, lba, pugrp, punit, chunk, sectr);
}

static void _trace_ocssd_rw(OcssdCtrl *o, NvmeRequest *req)
{
    OcssdNamespace *ons = &o->namespaces[req->ns->id - 1];
    char *buf = g_malloc_n(req->nlb, sizeof(OCSSD_LBA_FORMAT_TEMPLATE) + 3 + 1);
    char *bufp = buf;
    for (uint16_t i = 0; i < req->nlb; i++) {
        bufp += sprintf(bufp, "\n  ");
        bufp += _lba_str(bufp, o, ons, _vlba(req, i));
    }

    trace_ocssd_rw(req->cqe.cid, req->cmd_opcode, req->nlb, buf);
    g_free(buf);
}

static OcssdChunkDescriptor *_get_chunk(OcssdCtrl *o, OcssdNamespace *ons,
    uint64_t lba)
{
    if (!_valid(o, ons, lba)) {
        return NULL;
    }

    return &ons->chunk_info[_chk_idx(o, ons, lba)];
}

static int _parse_string(const char *s, const char *k, char **v)
{
    char *p = strstr(s, k);
    if (!p) {
        return 0;
    }

    return sscanf(p + strlen(k), "%ms", v);
}

static int _parse_uint8(const char *s, const char *k, uint8_t *v)
{
    char *p = strstr(s, k);
    if (!p) {
        return 0;
    }

    return sscanf(p + strlen(k), "0x%"SCNx8, v) ||
        sscanf(p + strlen(k), "%"SCNu8, v);
}

static int _parse_uint16(const char *s, const char *k, uint16_t *v)
{
    char *p = strstr(s, k);
    if (!p) {
        return 0;
    }

    return sscanf(p + strlen(k), "0x%"SCNx16, v) ||
        sscanf(p + strlen(k), "%"SCNu16, v);
}

static int _parse_uint32(const char *s, const char *k, uint32_t *v)
{
    char *p = strstr(s, k);
    if (!p) {
        return 0;
    }

    return sscanf(p + strlen(k), "0x%"SCNx32, v) ||
        sscanf(p + strlen(k), "%"SCNu32, v);
}

static int _parse_uint64(const char *s, const char *k, uint64_t *v)
{
    char *p = strstr(s, k);
    if (!p) {
        return 0;
    }

    return sscanf(p + strlen(k), "0x%"SCNx64, v) ||
        sscanf(p + strlen(k), "%"SCNu64, v);
}

static int _parse_wildcard(const char *s, const char *prefix)
{
    char *v;
    int rc = 0;
    if (!_parse_string(s, prefix, &v)) {
        return 0;
    }

    if (strcmp(v, "*") == 0) {
        rc = 1;
    }

    free(v);

    return rc;
}

static int _parse_lba_part_uint16(const char *s, const char *prefix,
    uint16_t *bgn, uint16_t *end, uint16_t end_defval)
{
    if (!bgn || !end) {
        return 1;
    }

    if (_parse_wildcard(s, prefix)) {
        *bgn = 0;
        *end = end_defval;

        return 1;
    }

    if (!_parse_uint16(s, prefix, bgn)) {
        return 0;
    }

    *end = *bgn + 1;

    return 1;
}

static int _parse_lba_part_uint32(const char *s, const char *prefix,
    uint32_t *bgn, uint32_t *end, uint32_t end_defval)
{
    if (!bgn || !end) {
        return 1;
    }

    if (_parse_wildcard(s, prefix)) {
        *bgn = 0;
        *end = end_defval;

        return 1;
    }

    if (!_parse_uint32(s, prefix, bgn)) {
        return 0;
    }

    *end = *bgn + 1;

    return 1;
}

static int _parse_lba_parts(OcssdIdGeo *geo, const char *s,
    uint16_t *grp_bgn, uint16_t *grp_end, uint16_t *pu_bgn,
    uint16_t *pu_end, uint32_t *chk_bgn, uint32_t *chk_end,
    uint32_t *sec_bgn, uint32_t *sec_end, Error **errp)
{
    if (!_parse_lba_part_uint16(s, "group=", grp_bgn, grp_end, geo->num_grp)) {
        error_setg(errp, "could not parse group");
        return 0;
    }

    if (!_parse_lba_part_uint16(s, "punit=", pu_bgn, pu_end, geo->num_pu)) {
        error_setg(errp, "could not parse punit");
        return 0;
    }

    if (!_parse_lba_part_uint32(s, "chunk=", chk_bgn, chk_end, geo->num_chk)) {
        error_setg(errp, "could not parse chunk");
        return 0;
    }

    if (!_parse_lba_part_uint32(s, "sectr=", sec_bgn, sec_end, geo->clba)) {
        error_setg(errp, "could not parse sectr");
        return 0;
    }

    return 1;
}

static inline int _str_to_chunk_state(char *s)
{
    if (!strcmp(s, "FREE")) {
        return OCSSD_CHUNK_FREE;
    }

    if (!strcmp(s, "OFFLINE")) {
        return OCSSD_CHUNK_OFFLINE;
    }

    if (!strcmp(s, "OPEN")) {
        return OCSSD_CHUNK_OPEN;
    }

    if (!strcmp(s, "CLOSED")) {
        return OCSSD_CHUNK_CLOSED;
    }

    return -1;
}

static inline int _str_to_chunk_type(char *s)
{
    if (!strcmp(s, "SEQ") || !strcmp(s, "SEQUENTIAL")) {
        return OCSSD_CHUNK_TYPE_SEQUENTIAL;
    }

    if (!strcmp(s, "RAN") || !strcmp(s, "RANDOM")) {
        return OCSSD_CHUNK_TYPE_RANDOM;
    }

    return -1;
}

static int _parse_and_update_reset_err_injection(OcssdCtrl *o, const char *s,
    Error **errp)
{
    OcssdNamespace *ons;
    OcssdIdGeo *geo;
    uint16_t group, group_end, punit, punit_end;
    uint32_t nsid, chunk, chunk_end;
    uint64_t idx;
    uint8_t prob;
    Error *local_err = NULL;

    size_t slen = strlen(s);
    if (slen == 1 || (slen > 1 && s[0] == '#')) {
        return 0;
    }

    if (!_parse_uint32(s, "ns=", &nsid)) {
        error_setg(errp, "could not parse namespace id");
        return 1;
    }

    ons = &o->namespaces[nsid - 1];
    geo = &ons->id.geo;

    if (!_parse_lba_parts(geo, s, &group, &group_end, &punit, &punit_end,
        &chunk, &chunk_end, NULL, NULL, &local_err)) {
        error_propagate_prepend(errp, local_err, "could not parse chunk slba");
        return 1;
    }

    if (!_parse_uint8(s, "prob=", &prob)) {
        error_setg(errp, "could not parse probability");
        return 1;
    }

    if (prob > 100) {
        error_setg(errp, "invalid probability");
        return 1;
    }

    for (uint16_t g = group; g < group_end; g++) {
        for (uint16_t p = punit; p < punit_end; p++) {
            for (uint32_t c = chunk; c < chunk_end; c++) {
                idx = _chk_idx(o, ons, _make_lba(&ons->addrf, g, p, c, 0));
                ons->resetfail[idx] = prob;
            }
        }
    }

    return 0;
}

static int _parse_and_update_write_err_injection(OcssdCtrl *o, const char *s,
    Error **errp)
{
    OcssdNamespace *ons;
    OcssdIdGeo *geo;
    uint16_t group, group_end, punit, punit_end;
    uint32_t nsid, chunk, chunk_end, sectr, sectr_end;
    uint64_t idx;
    uint8_t prob;
    Error *local_err = NULL;

    size_t slen = strlen(s);
    if (slen == 1 || (slen > 1 && s[0] == '#')) {
        return 0;
    }

    if (!_parse_uint32(s, "ns=", &nsid)) {
        error_setg(errp, "could not parse namespace id");
        return 1;
    }

    ons = &o->namespaces[nsid - 1];
    geo = &ons->id.geo;

    if (!_parse_lba_parts(geo, s, &group, &group_end, &punit, &punit_end,
        &chunk, &chunk_end, &sectr, &sectr_end, &local_err)) {
        error_propagate_prepend(errp, local_err, "could not parse lba");
        return 1;
    }

    if (!_parse_uint8(s, "prob=", &prob)) {
        error_setg(errp, "could not parse probability");
        return 1;
    }

    if (prob > 100) {
        error_setg(errp, "invalid probability");
        return 1;
    }

    for (uint16_t g = group; g < group_end; g++) {
        for (uint16_t p = punit; p < punit_end; p++) {
            for (uint32_t c = chunk; c < chunk_end; c++) {
                for (uint32_t s = sectr; s < sectr_end; c++) {
                    idx = _idx(o, ons, _make_lba(&ons->addrf, g, p, c, s));
                    ons->writefail[idx] = prob;
                }
            }
        }
    }

    return 0;
}

static int _parse_and_update_chunk_state(OcssdCtrl *o, const char *s,
    Error **errp)
{
    char *v;
    OcssdChunkDescriptor *chk;
    OcssdNamespace *ons;
    OcssdIdGeo *geo;
    uint8_t wi;
    uint16_t group, group_end, punit, punit_end;
    uint32_t nsid, chunk, chunk_end;
    uint64_t cnlb, wp, slba;
    int state = 0, type = 0;
    bool cnlb_parsed = false, wp_parsed = false, wi_parsed = false;
    bool state_parsed = false, type_parsed = false;
    Error *local_err = NULL;

    size_t slen = strlen(s);
    if (slen == 1 || (slen > 1 && s[0] == '#')) {
        return 0;
    }

    if (!_parse_uint32(s, "ns=", &nsid)) {
        error_setg(errp, "could not parse namespace id");
        return 1;
    }

    ons = &o->namespaces[nsid - 1];
    geo = &ons->id.geo;

    if (!_parse_lba_parts(geo, s, &group, &group_end, &punit, &punit_end,
        &chunk, &chunk_end, NULL, NULL, &local_err)) {
        error_propagate_prepend(errp, local_err, "could not parse chunk slba");
        return 1;
    }

    if (_parse_string(s, "state=", &v)) {
        state_parsed = true;
        state = _str_to_chunk_state(v);
        free(v);

        if (state < 0) {
            error_setg(errp, "invalid chunk state");
            return 1;
        }
    }

    if (_parse_string(s, "type=", &v)) {
        type_parsed = true;
        type = _str_to_chunk_type(v);
        free(v);

        if (type < 0) {
            error_setg(errp, "invalid chunk type");
            return 1;
        }
    }

    if (_parse_uint64(s, "cnlb=", &cnlb)) {
        cnlb_parsed = true;
    }

    if (_parse_uint64(s, "wp=", &wp)) {
        wp_parsed = true;
    }

    if (_parse_uint8(s, "wi=", &wi)) {
        wi_parsed = true;
    }

    if (state_parsed) {
        if (state == OCSSD_CHUNK_OFFLINE && wp_parsed) {
            error_setg(errp, "invalid wp; offline chunk");
            return 1;
        }
    }

    if (type_parsed) {
        if (type == OCSSD_CHUNK_TYPE_RANDOM && wp_parsed) {
            error_setg(errp, "invalid wp; random chunk");
            return 1;
        }
    }

    for (uint16_t g = group; g < group_end; g++) {
        for (uint16_t p = punit; p < punit_end; p++) {
            for (uint32_t c = chunk; c < chunk_end; c++) {
                slba = _make_lba(&ons->addrf, g, p, c, 0);
                chk = _get_chunk(o, ons, slba);
                if (!chk) {
                    error_setg(errp, "invalid lba");
                    return 1;
                }

                if (type_parsed) {
                    chk->type = type;
                    if (chk->type == OCSSD_CHUNK_TYPE_RANDOM) {
                        chk->wp = 0;
                    }
                }

                if (state_parsed) {
                    chk->state = state;
                    if (chk->state == OCSSD_CHUNK_OFFLINE) {
                        chk->wp = UINT64_MAX;
                    }
                }

                if (cnlb_parsed) {
                    chk->cnlb = cnlb;
                    if (chk->cnlb > ons->id.geo.clba) {
                        error_setg(errp, "invalid chunk cnlb");
                        return 1;
                    }

                    if (chk->cnlb != ons->id.geo.clba) {
                        chk->type |= OCSSD_CHUNK_TYPE_SHRINKED;
                    }
                }

                if (wp_parsed) {
                    chk->wp = wp;
                    if (chk->wp > chk->cnlb) {
                        error_setg(errp, "invalid chunk wp");
                        return 1;
                    }
                }

                if (wi_parsed) {
                    chk->wear_index = wi;
                }
            }
        }
    }

    return 0;
}

static int ocssd_load_write_err_injection_from_file(OcssdCtrl *o,
    const char *fname, Error **errp)
{
    ssize_t n;
    size_t len = 0;
    int line_num = 0;
    char *line;
    Error *local_err = NULL;
    FILE *fp;

    fp = fopen(fname, "r");
    if (!fp) {
        error_setg_errno(errp, errno,
            "could not open write error injection file (%s): ", fname);
        return 1;
    }

    while ((n = getline(&line, &len, fp)) != -1) {
        line_num++;
        if (_parse_and_update_write_err_injection(o, line, &local_err)) {
            error_propagate_prepend(errp, local_err,
                "could not parse write error injection (line %d): ", line_num);
            return 1;
        }
    }

    fclose(fp);

    return 0;
}

static int ocssd_load_reset_err_injection_from_file(OcssdCtrl *o,
    const char *fname, Error **errp)
{
    ssize_t n;
    size_t len = 0;
    int line_num = 0;
    char *line;
    Error *local_err = NULL;
    FILE *fp;

    fp = fopen(fname, "r");
    if (!fp) {
        error_setg_errno(errp, errno,
            "could not open reset error injection file (%s): ", fname);
        return 1;
    }

    while ((n = getline(&line, &len, fp)) != -1) {
        line_num++;
        if (_parse_and_update_reset_err_injection(o, line, &local_err)) {
            error_propagate_prepend(errp, local_err,
                "could not parse reset error injection (line %d): ", line_num);
            return 1;
        }
    }

    fclose(fp);

    return 0;
}

static int ocssd_load_chunk_info_from_file(OcssdCtrl *o, const char *fname,
    Error **errp)
{
    ssize_t n;
    size_t len = 0;
    int line_num = 0;
    char *line;
    Error *local_err = NULL;
    FILE *fp;

    fp = fopen(fname, "r");
    if (!fp) {
        error_setg_errno(errp, errno, "could not open chunk info file");
        return 1;
    }

    while ((n = getline(&line, &len, fp)) != -1) {
        line_num++;
        if (_parse_and_update_chunk_state(o, line, &local_err)) {
            error_propagate_prepend(errp, local_err,
                "could not parse chunk state (line %d): ", line_num);
            return 1;
        }
    }

    fclose(fp);

    return 0;
}

static void ocssd_ns_commit_chunk_state(OcssdCtrl *o, OcssdNamespace *ons,
    NvmeRequest *req, OcssdChunkDescriptor *chk)
{
    NvmeCtrl *n = &o->nvme;
    NvmeBlockBackendRequest *blk_req = g_malloc0(sizeof(*blk_req));
    blk_req->req = req;

    qemu_iovec_init(&blk_req->iov, 1);
    qemu_iovec_add(&blk_req->iov, chk, sizeof(OcssdChunkDescriptor));

    blk_req->blk_offset = ons->blk.chunk_info +
        _chk_idx(o, ons, chk->slba) * sizeof(OcssdChunkDescriptor);

    QTAILQ_INSERT_TAIL(&req->blk_req_tailq_head, blk_req, blk_req_tailq);

    block_acct_start(blk_get_stats(n->conf.blk), &blk_req->acct,
        blk_req->iov.size, BLOCK_ACCT_WRITE);

    blk_req->aiocb = blk_aio_pwritev(n->conf.blk, blk_req->blk_offset,
        &blk_req->iov, 0, nvme_rw_cb, blk_req);
}

static int ocssd_ns_commit_chunk_info(OcssdCtrl *o, OcssdNamespace *ons)
{
    BlockBackend *blk = o->nvme.conf.blk;
    uint64_t nbytes = ons->chunkinfo_size;
    return blk_pwrite(blk, ons->blk.chunk_info, ons->chunk_info, nbytes, 0);
}

static int ocssd_commit_chunk_info(OcssdCtrl *o)
{
    int ret;
    for (int i = 0; i < o->hdr.num_namespaces; i++) {
        ret = ocssd_ns_commit_chunk_info(o, &o->namespaces[i]);
        if (ret < 0) {
            return ret;
        }
    }

    return 0;
}

static int ocssd_ns_load_chunk_info(OcssdCtrl *o, OcssdNamespace *ons)
{
    BlockBackend *blk = o->nvme.conf.blk;
    return blk_pread(blk, ons->blk.chunk_info, ons->chunk_info,
        ons->chunkinfo_size);
}

static uint16_t ocssd_do_chunk_info(OcssdCtrl *o, NvmeCmd *cmd,
    uint32_t buf_len, uint64_t off, NvmeRequest *req)
{
    OcssdNamespace *ons;

    uint8_t *log_page;
    uint32_t log_len, trans_len, nsid;
    uint16_t ret;

    nsid = le32_to_cpu(cmd->nsid);
    if (unlikely(nsid == 0 || nsid > o->nvme.params.num_namespaces)) {
        return NVME_INVALID_NSID | NVME_DNR;
    }

    ons = &o->namespaces[nsid - 1];

    log_len = ons->chks_total * sizeof(OcssdChunkDescriptor);
    trans_len = MIN(log_len, buf_len);

    log_page = (uint8_t *) ons->chunk_info + off;

    if (cmd->opcode == NVME_ADM_CMD_GET_LOG_PAGE) {
        return nvme_dma_read(&o->nvme, log_page, trans_len, cmd, req);
    }

    ret = nvme_dma_write(&o->nvme, log_page, trans_len, cmd, req);
    if (ret) {
        return ret;
    }

    if (ocssd_ns_commit_chunk_info(o, ons) < 0) {
        return NVME_INTERNAL_DEV_ERROR | NVME_DNR;
    }

    return NVME_SUCCESS;
}

static uint16_t ocssd_rw_check_chunk_write(OcssdCtrl *o, NvmeCmd *cmd,
    uint64_t lba, uint32_t ws, NvmeRequest *req)
{
    OcssdChunkDescriptor *chk;
    NvmeCtrl *n = &o->nvme;
    NvmeNamespace *ns = req->ns;
    OcssdNamespace *ons = &o->namespaces[ns->id - 1];
    OcssdParams *params = &o->params;
    OcssdRwCmd *orw = (OcssdRwCmd *) cmd;

    chk = _get_chunk(o, ons, lba);
    if (!chk) {
        trace_ocssd_err_invalid_chunk(req->cqe.cid,
            lba & ~ons->addrf.sec_mask);
        return NVME_WRITE_FAULT | NVME_DNR;
    }

    uint32_t start_sectr = lba & ons->addrf.sec_mask;
    uint32_t end_sectr = start_sectr + ws;

    /* check if we are at all allowed to write to the chunk */
    if (chk->state == OCSSD_CHUNK_OFFLINE || chk->state == OCSSD_CHUNK_CLOSED) {
        trace_ocssd_err_invalid_chunk_state(req->cqe.cid,
            lba & ~(ons->addrf.sec_mask), chk->state);
        return NVME_WRITE_FAULT | NVME_DNR;
    }

    if (end_sectr > chk->cnlb) {
        trace_ocssd_err_out_of_bounds(req->cqe.cid, end_sectr, chk->cnlb);
        return NVME_WRITE_FAULT | NVME_DNR;
    }


    if (chk->type == OCSSD_CHUNK_TYPE_RANDOM) {
        /*
         * For OCSSD_CHUNK_TYPE_RANDOM, we skip the additional constraint
         * checks and only check that the chunk is OPEN.
         */
        if (chk->state != OCSSD_CHUNK_OPEN) {
            trace_ocssd_err_invalid_chunk_state(req->cqe.cid,
                lba & ~(ons->addrf.sec_mask), chk->state);
            return NVME_WRITE_FAULT | NVME_DNR;
        }

        return NVME_SUCCESS;
    }

    if (ws < params->ws_min || (ws % params->ws_min) != 0) {
        trace_ocssd_err_write_constraints(req->cqe.cid, ws, params->ws_min);
        nvme_set_error_page(n, req->sq->sqid, req->cqe.cid,
            NVME_INVALID_FIELD, offsetof(OcssdRwCmd, lbal),
            orw->lbal + req->nlb, req->ns->id);
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    /* check that the write begins at the current wp */
    if (start_sectr != chk->wp) {
        trace_ocssd_err_out_of_order(req->cqe.cid, start_sectr, chk->wp);
        return OCSSD_OUT_OF_ORDER_WRITE | NVME_DNR;
    }

    return NVME_SUCCESS;
}

static uint16_t ocssd_rw_check_vector_write_req(OcssdCtrl *o, NvmeCmd *cmd,
    NvmeRequest *req)
{
    NvmeNamespace *ns = req->ns;
    OcssdNamespace *ons = &o->namespaces[ns->id - 1];
    OcssdAddrF *addrf = &ons->addrf;

    uint64_t lba = _vlba(req, 0);
    uint64_t cidx = _chk_idx(o, ons, lba);
    uint32_t sectr = _sectr(addrf, lba);
    uint16_t ws = 1;

    for (uint16_t i = 1; i < req->nlb; i++) {
        uint64_t next_cidx;
        uint64_t next_lba = ((uint64_t *) req->slba)[i];

        /*
         * We assumed that LBAs for different chunks are laid out contiguously
         * and sorted with increasing addresses.
         */
        next_cidx = _chk_idx(o, ons, next_lba);
        if (cidx != next_cidx) {
            uint16_t err = ocssd_rw_check_chunk_write(o, cmd, lba, ws, req);
            if (err) {
                return err;
            }

            lba = next_lba;
            cidx = next_cidx;
            sectr = _sectr(addrf, lba);
            ws = 1;

            continue;
        }

        if (++sectr != _sectr(addrf, next_lba)) {
            return OCSSD_OUT_OF_ORDER_WRITE | NVME_DNR;
        }

        ws++;
    }

    return ocssd_rw_check_chunk_write(o, cmd, lba, ws, req);
}

static uint16_t ocssd_rw_check_chunk_read(OcssdCtrl *o, NvmeCmd *cmd,
    NvmeRequest *req, uint64_t lba)
{
    NvmeNamespace *ns = req->ns;
    OcssdNamespace *ons = &o->namespaces[ns->id - 1];
    OcssdAddrF *addrf = &ons->addrf;
    OcssdParams *params = &o->params;

    OcssdChunkDescriptor *chk;
    uint64_t sectr, mw_cunits, wp;
    uint8_t state;

    chk = _get_chunk(o, ons, lba);
    if (!chk) {
        trace_ocssd_err_invalid_chunk(req->cqe.cid,
            lba & ~ons->addrf.sec_mask);
        return NVME_DULB;
    }

    sectr = _sectr(addrf, lba);
    mw_cunits = params->mw_cunits;
    wp = chk->wp;
    state = chk->state;

    if (chk->type == OCSSD_CHUNK_TYPE_RANDOM) {
        /*
         * For OCSSD_CHUNK_TYPE_RANDOM it is sufficient to ensure that the
         * chunk is OPEN and that we are reading a valid address.
         */
        if (state != OCSSD_CHUNK_OPEN || sectr >= chk->cnlb) {
            trace_ocssd_err_invalid_chunk_state(req->cqe.cid,
                lba & ~(ons->addrf.sec_mask), chk->state);
            return NVME_DULB;
        }

        return NVME_SUCCESS;
    }

    if (state == OCSSD_CHUNK_CLOSED && sectr < wp) {
        return NVME_SUCCESS;
    }

    if (state == OCSSD_CHUNK_OPEN) {
        if (wp < mw_cunits) {
            return NVME_DULB;
        }

        if (sectr < (wp - mw_cunits)) {
            return NVME_SUCCESS;
        }
    }

    fprintf(stderr, "DULB\n");
    return NVME_DULB;
}

static uint16_t ocssd_rw_check_vector_read_req(OcssdCtrl *o, NvmeCmd *cmd,
    NvmeRequest *req)
{
    req->predef = 0;
    for (int i = 0; i < req->nlb; i++) {
        uint16_t err = ocssd_rw_check_chunk_read(o, cmd, req, _vlba(req, i));

        if (err) {
            if (nvme_is_error(err, NVME_DULB)) {
                req->predef |= (1 << i);
                continue;
            }

            return err;
        }
    }

    return NVME_SUCCESS;
}

static uint16_t ocssd_rw_check_scalar_req(OcssdCtrl *o, NvmeCmd *cmd,
    NvmeRequest *req)
{
    NvmeCtrl *n = &o->nvme;
    int err;

    err = nvme_rw_check_req(n, cmd, req);
    if (err) {
        return err;
    }

    if (nvme_rw_is_write(req)) {
        return ocssd_rw_check_chunk_write(o, cmd, req->slba, req->nlb, req);
    }

    for (uint16_t i = 0; i < req->nlb; i++) {
        err = ocssd_rw_check_chunk_read(o, cmd, req, req->slba + i);
        if (err && nvme_is_error(err, NVME_DULB)) {
            req->predef = req->slba + i;
            if (NVME_ERR_REC_DULBE(n->features.err_rec)) {
                return NVME_DULB | NVME_DNR;
            }

            break;
        }

        return err;
    }

    return NVME_SUCCESS;
}

static uint16_t ocssd_rw_check_vector_req(OcssdCtrl *o, NvmeCmd *cmd,
    NvmeRequest *req)
{
    NvmeCtrl *n = &o->nvme;
    int err = nvme_rw_check_req(n, cmd, req);
    if (err) {
        return err;
    }

    if (ocssd_rw_is_write(req)) {
        return ocssd_rw_check_vector_write_req(o, cmd, req);
    }

    return ocssd_rw_check_vector_read_req(o, cmd, req);
}

/*
 * ocssd_blk_setup maps the requests represented as qsq to a list of
 * independent contiguous block backend requests.
 */
static uint16_t ocssd_blk_setup(NvmeCtrl *n, NvmeNamespace *ns,
    QEMUSGList *qsg, uint64_t blk_offset, uint32_t unit_len, NvmeAddrFn addrfn,
    NvmeRequest *req)
{
    OcssdCtrl *o = OCSSD(n);
    OcssdNamespace *ons = &o->namespaces[ns->id - 1];

    NvmeBlockBackendRequest *blk_req = NULL;
    size_t curr_byte = 0;
    uint64_t slba, last_lba;
    int curr_sge = 0;

    for (uint16_t i = 0; i < req->nlb; i++) {
        slba = _vlba(req, i);
        if (!req->is_write && req->predef & (1 << i)) {
            /* skip block request if dlfeat is 0x00 */
            if (ns->id_ns.dlfeat) {
                blk_req = nvme_blk_req_new(n, req);
                if (!blk_req) {
                    return NVME_INTERNAL_DEV_ERROR;
                }

                blk_req->blk_offset = ns->blk.predef;
                blk_req->slba = slba;

                QTAILQ_INSERT_TAIL(&req->blk_req_tailq_head, blk_req,
                    blk_req_tailq);
            } else {
                blk_req = NULL;
            }
        } else {
            /* Add a new block backend request if non-contiguous. */
            if (!blk_req || (i > 0 && last_lba + 1 != slba)) {
                uint64_t offset = blk_offset + _idx(o, ons, slba) * unit_len;

                blk_req = nvme_blk_req_new(n, req);
                if (!blk_req) {
                    return NVME_INTERNAL_DEV_ERROR;
                }

                blk_req->blk_offset = offset;
                blk_req->slba = slba;

                QTAILQ_INSERT_TAIL(&req->blk_req_tailq_head, blk_req,
                    blk_req_tailq);
            }
        }

        if (blk_req) {
            last_lba = blk_req->slba + blk_req->nlb;

            blk_req->nlb++;
        }

        qemu_sglist_yank(qsg, blk_req ? &blk_req->qsg : NULL, &curr_sge,
            &curr_byte, unit_len);
    }

    return NVME_SUCCESS;
}

static uint16_t ocssd_do_chunk_reset(OcssdCtrl *o, OcssdNamespace *ons,
    uint64_t lba, hwaddr mptr, NvmeRequest *req)
{
    NvmeCtrl *n = &o->nvme;
    OcssdChunkDescriptor *chk;
    uint8_t p;

    chk = _get_chunk(o, ons, lba);
    if (!chk) {
        trace_ocssd_err_invalid_chunk(req->cqe.cid,
            lba & ~ons->addrf.sec_mask);
        return OCSSD_INVALID_RESET | NVME_DNR;
    }

    if (chk->state & OCSSD_CHUNK_RESETABLE) {
        switch (chk->state) {
        case OCSSD_CHUNK_FREE:
            trace_ocssd_double_reset(req->cqe.cid, lba);

            if (!(ons->id.mccap & OCSSD_IDENTITY_MCCAP_MULTIPLE_RESETS)) {
                return OCSSD_INVALID_RESET | NVME_DNR;
            }

            break;

        case OCSSD_CHUNK_OPEN:
            trace_ocssd_early_reset(req->cqe.cid, lba, chk->wp);
            if (!(ons->id.mccap & OCSSD_IDENTITY_MCCAP_EARLY_RESET)) {
                return OCSSD_INVALID_RESET | NVME_DNR;
            }

            break;
        }

        if (ons->resetfail) {
            p = ons->resetfail[_chk_idx(o, ons, lba)];

            if (p == 100 || (rand() % 100) < p) {
                chk->state = OCSSD_CHUNK_OFFLINE;
                chk->wp = UINT64_MAX;
                trace_ocssd_inject_reset_err(req->cqe.cid, p, lba);
                return OCSSD_INVALID_RESET | NVME_DNR;
            }
        }

        chk->state = OCSSD_CHUNK_FREE;
        chk->wear_index++;
        chk->wp = 0;

        if (mptr) {
            nvme_addr_write(n, mptr, chk, sizeof(*chk));
        }

        if (ocssd_ns_commit_chunk_info(o, ons) < 0) {
            return NVME_INTERNAL_DEV_ERROR | NVME_DNR;
        }

        return NVME_SUCCESS;
    }

    trace_ocssd_err_offline_chunk(req->cqe.cid, lba);

    return OCSSD_OFFLINE_CHUNK | NVME_DNR;
}

static void ocssd_reset_cb(void *opaque, int ret)
{
    NvmeBlockBackendRequest *blk_req = opaque;
    NvmeRequest *req = blk_req->req;
    NvmeSQueue *sq = req->sq;
    NvmeCtrl *n = sq->ctrl;
    NvmeCQueue *cq = n->cq[sq->cqid];
    NvmeNamespace *ns = req->ns;

    OcssdCtrl *o = OCSSD(n);
    OcssdNamespace *ons = &o->namespaces[ns->id - 1];

    QTAILQ_REMOVE(&req->blk_req_tailq_head, blk_req, blk_req_tailq);

    if (!ret) {
        int err;
        err = ocssd_do_chunk_reset(o, ons, blk_req->slba, req->mptr, req);
        if (err) {
            req->status = err;
            goto out;
        }

        if (req->mptr) {
            req->mptr += sizeof(OcssdChunkDescriptor);
        }

    } else {
        req->status = NVME_INTERNAL_DEV_ERROR;
    }

out:
    if (QTAILQ_EMPTY(&req->blk_req_tailq_head)) {
        nvme_enqueue_req_completion(cq, req);
    }

    nvme_blk_req_destroy(blk_req);
}


static uint16_t ocssd_reset(OcssdCtrl *o, NvmeCmd *cmd, NvmeRequest *req)
{
    NvmeCtrl *n = &o->nvme;
    OcssdRwCmd *dm = (OcssdRwCmd *) cmd;
    OcssdNamespace *ons = &o->namespaces[req->ns->id - 1];
    uint64_t lbal = le64_to_cpu(dm->lbal);
    uint32_t nlb = le16_to_cpu(dm->nlb) + 1;
    uint8_t lbads = NVME_ID_NS_LBADS(req->ns);
    uint16_t err;

    req->nlb = nlb;
    req->mptr = le64_to_cpu(cmd->mptr);

    if (nlb > 1) {
        req->slba = (uint64_t) g_malloc_n(nlb, sizeof(uint64_t));
        nvme_addr_read(n, lbal, (void *) req->slba, nlb * sizeof(void *));
    } else {
        req->slba = lbal;
    }

    for (int i = 0; i < nlb; i++) {
        OcssdChunkDescriptor *chk;
        NvmeBlockBackendRequest *blk_req = nvme_blk_req_new(n, req);
        blk_req->slba = _vlba(req, i);

        chk = _get_chunk(o, ons, blk_req->slba);
        if (!chk) {
            trace_ocssd_err_invalid_chunk(req->cqe.cid,
                blk_req->slba & ~ons->addrf.sec_mask);
            err = OCSSD_INVALID_RESET;
            goto out;
        }

        QTAILQ_INSERT_TAIL(&req->blk_req_tailq_head, blk_req,
            blk_req_tailq);

        blk_req->aiocb = blk_aio_pdiscard(n->conf.blk,
            req->ns->blk.data + (_idx(o, ons, blk_req->slba) << lbads),
            chk->cnlb << lbads, ocssd_reset_cb, blk_req);
    }

    return NVME_NO_COMPLETE;

out:
    if (req->nlb > 1) {
        g_free((void *) req->slba);
    }

    return err;
}

static uint16_t ocssd_advance_wp(OcssdCtrl *o, OcssdNamespace *ons,
    uint64_t lba, uint16_t nlb, NvmeRequest *req)
{
    OcssdChunkDescriptor *chk = _get_chunk(o, ons, lba);
    if (!chk) {
        trace_ocssd_err_invalid_chunk(req->cqe.cid,
            lba & ~ons->addrf.sec_mask);
        return NVME_INTERNAL_DEV_ERROR | NVME_DNR;
    }

    if (chk->type == OCSSD_CHUNK_TYPE_RANDOM) {
        /* do not modify the chunk state or write pointer for random chunks */
        return NVME_SUCCESS;
    }

    trace_ocssd_advance_wp(req->cqe.cid, lba, nlb);

    if (chk->state == OCSSD_CHUNK_FREE) {
        chk->state = OCSSD_CHUNK_OPEN;
    }

    if (chk->state != OCSSD_CHUNK_OPEN) {
        trace_ocssd_err_invalid_chunk_state(req->cqe.cid, lba,
            chk->state);
        return NVME_INTERNAL_DEV_ERROR | NVME_DNR;
    }

    chk->wp += nlb;
    if (chk->wp == chk->cnlb) {
        chk->state = OCSSD_CHUNK_CLOSED;
    }

    ocssd_ns_commit_chunk_state(o, ons, req, chk);

    return NVME_SUCCESS;
}

static uint16_t ocssd_rw_maybe_write_error_inject(OcssdCtrl *o,
    NvmeBlockBackendRequest *blk_req)
{
    NvmeRequest *req = blk_req->req;
    NvmeNamespace *ns = req->ns;
    OcssdNamespace *ons = &o->namespaces[ns->id - 1];
    OcssdChunkDescriptor *chk;
    uint8_t p;
    uint64_t cidx, lba = blk_req->slba;

    if (!ons->writefail || !req->is_write) {
        return NVME_SUCCESS;
    }

    for (uint16_t i = 0; i < blk_req->nlb; i++) {
        p = ons->writefail[_idx(o, ons, lba + i)];

        if (p && (p == 100 || (rand() % 100) < p)) {
            trace_ocssd_inject_write_err(req->cqe.cid, p, lba + i);

            chk = _get_chunk(o, ons, lba);
            if (!chk) {
                trace_ocssd_err_invalid_chunk(req->cqe.cid,
                    lba & ~ons->addrf.sec_mask);
                return NVME_INTERNAL_DEV_ERROR | NVME_DNR;
            }

            cidx = _chk_idx(o, ons, lba + i);
            chk->state = OCSSD_CHUNK_CLOSED;


            ocssd_ns_commit_chunk_state(o, ons, req, chk);
            ons->resetfail[cidx] = 100;

            for (uint16_t j = 0; j < req->nlb; j++) {
                if (cidx == _chk_idx(o, ons, _vlba(req, i))) {
                    bitmap_set(&req->cqe.res64, i, 1);
                }
            }

            return OCSSD_CHUNK_EARLY_CLOSE | NVME_DNR;
        }
    }

    return NVME_SUCCESS;
}

static void ocssd_rw_cb(void *opaque, int ret)
{
    NvmeBlockBackendRequest *blk_req = opaque;
    NvmeRequest *req = blk_req->req;
    NvmeSQueue *sq = req->sq;
    NvmeCtrl *n = sq->ctrl;
    NvmeCQueue *cq = n->cq[sq->cqid];
    NvmeNamespace *ns = req->ns;

    OcssdCtrl *o = OCSSD(n);
    OcssdNamespace *ons = &o->namespaces[ns->id - 1];

    int err;

    trace_nvme_rw_cb(req->cqe.cid);

    QTAILQ_REMOVE(&req->blk_req_tailq_head, blk_req, blk_req_tailq);

    if (!ret) {
        block_acct_done(blk_get_stats(n->conf.blk), &blk_req->acct);

        if (req->is_write && blk_req->blk_offset >= ns->blk.data &&
            blk_req->blk_offset < ns->blk.meta) {

            /*
             * We know that each NvmeBlockBackendRequest corresponds to a write
             * to at most one chunk (one contiguous write). This way, we can
             * allow a write to a single chunk to fail (while leaving the write
             * pointer intact), but allow writes to other chunks to proceed.
             */
            err = ocssd_rw_maybe_write_error_inject(o, blk_req);
            if (!err) {
                err = ocssd_advance_wp(o, ons, blk_req->slba, blk_req->nlb,
                    req);
            }

            /*
             * An internal device error trumps all other errors, but there is
             * no way of triaging other errors, so only set an error if one has
             * not already been set.
             */
            if (nvme_is_error(err, NVME_INTERNAL_DEV_ERROR) ||
                (err && !req->status)) {
                req->status = err;
            }
        }
    } else {
        block_acct_failed(blk_get_stats(n->conf.blk), &blk_req->acct);
        req->status = NVME_INTERNAL_DEV_ERROR | NVME_DNR;
    }

    if (QTAILQ_EMPTY(&req->blk_req_tailq_head)) {
        if (req->status != NVME_SUCCESS) {
            nvme_set_error_page(n, sq->sqid, req->cqe.cid, req->status,
                offsetof(NvmeRwCmd, slba), blk_req->blk_offset, ns->id);
        }

        nvme_enqueue_req_completion(cq, req);
    }

    nvme_blk_req_destroy(blk_req);
}

static uint16_t ocssd_rw(OcssdCtrl *o, NvmeCmd *cmd, NvmeRequest *req)
{
    NvmeCtrl *n = &o->nvme;
    OcssdRwCmd *orw = (OcssdRwCmd *) cmd;
    OcssdParams *params = &o->params;

    uint64_t lbal = le64_to_cpu(orw->lbal);
    uint16_t err;

    if (req->nlb > OCSSD_CMD_MAX_LBAS) {
        trace_ocssd_err(req->cqe.cid, "OCSSD_CMD_MAX_LBAS exceeded",
            NVME_INVALID_FIELD | NVME_DNR);
        nvme_set_error_page(n, req->sq->sqid, req->cqe.cid, NVME_INVALID_FIELD,
            offsetof(OcssdRwCmd, lbal), 0, req->ns->id);
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    if (ocssd_rw_is_write(req)) {
        req->is_write = 1;
    }

    if (req->nlb > 1) {
        req->slba = (uint64_t) g_malloc_n(req->nlb, sizeof(uint64_t));
        uint32_t len = req->nlb * sizeof(uint64_t);

        if (cmd->psdt && params->sgl_lbal) {
            NvmeSglDescriptor sgl;

            nvme_addr_read(n, lbal, &sgl, sizeof(NvmeSglDescriptor));

            err = nvme_dma_read_sgl(n, (uint8_t *) req->slba, len, sgl, cmd,
                req);
            if (err) {
                if (nvme_is_error(err, NVME_DATA_SGL_LENGTH_INVALID)) {
                    err = OCSSD_LBAL_SGL_LENGTH_INVALID | NVME_DNR;
                }

                nvme_set_error_page(n, req->sq->sqid, req->cqe.cid, err,
                    offsetof(OcssdRwCmd, lbal), 0, req->ns->id);

                return err;
            }
        } else {
            nvme_addr_read(n, lbal, (void *) req->slba, len);
        }
    } else {
        req->slba = lbal;
    }

    if (trace_event_get_state_backends(TRACE_OCSSD_RW)) {
        _trace_ocssd_rw(o, req);
    }

    err = ocssd_rw_check_vector_req(o, cmd, req);
    if (err) {
        trace_ocssd_err(req->cqe.cid, "ocssd_rw_check_vector_req", err);
        return err;
    }

    for (uint32_t i = 0; i < req->nlb; i++) {
        if ((req->predef & (1 << i)) && !req->is_write &&
            NVME_ERR_REC_DULBE(n->features.err_rec)) {
            return NVME_DULB | NVME_DNR;
        }
    }

    err = nvme_blk_map(n, cmd, req, _addrfn, ocssd_blk_setup);
    if (err) {
        trace_ocssd_err(req->cqe.cid, "nvme_blk_map", err);
        return err;
    }

    return nvme_blk_submit_io(n, req, ocssd_rw_cb);
}

static uint16_t ocssd_set_log(OcssdCtrl *o, NvmeCmd *cmd, NvmeRequest *req)
{
    uint32_t dw10 = le32_to_cpu(cmd->cdw10);
    uint32_t dw11 = le32_to_cpu(cmd->cdw11);
    uint32_t dw12 = le32_to_cpu(cmd->cdw12);
    uint32_t dw13 = le32_to_cpu(cmd->cdw13);
    uint16_t lid = dw10 & 0xff;
    uint32_t numdl, numdu, len;
    uint64_t off, lpol, lpou;

    numdl = (dw10 >> 16);
    numdu = (dw11 & 0xffff);
    lpol = dw12;
    lpou = dw13;

    len = (((numdu << 16) | numdl) + 1) << 2;
    off = (lpou << 32ULL) | lpol;

    switch (lid) {
    case OCSSD_CHUNK_INFO:
        return ocssd_do_chunk_info(o, cmd, len, off, req);
    default:
        return NVME_INVALID_LOG_ID | NVME_DNR;
    }
}

static uint16_t ocssd_geometry(OcssdCtrl *o, NvmeCmd *cmd, NvmeRequest *req)
{
    OcssdNamespace *ons;

    uint32_t nsid = le32_to_cpu(cmd->nsid);
    if (unlikely(nsid == 0 || nsid > o->nvme.params.num_namespaces)) {
        return NVME_INVALID_NSID | NVME_DNR;
    }

    ons = &o->namespaces[nsid - 1];

    return nvme_dma_read(&o->nvme, (uint8_t *) &ons->id, sizeof(OcssdIdentity),
        cmd, req);
}

static uint16_t ocssd_get_log(OcssdCtrl *o, NvmeCmd *cmd, NvmeRequest *req)
{
    uint32_t dw10 = le32_to_cpu(cmd->cdw10);
    uint32_t dw11 = le32_to_cpu(cmd->cdw11);
    uint32_t dw12 = le32_to_cpu(cmd->cdw12);
    uint32_t dw13 = le32_to_cpu(cmd->cdw13);
    uint16_t lid = dw10 & 0xff;
    uint32_t numdl, numdu, len;
    uint64_t off, lpol, lpou;

    numdl = (dw10 >> 16);
    numdu = (dw11 & 0xffff);
    lpol = dw12;
    lpou = dw13;

    len = (((numdu << 16) | numdl) + 1) << 2;
    off = (lpou << 32ULL) | lpol;

    switch (lid) {
    case OCSSD_CHUNK_INFO:
        return ocssd_do_chunk_info(o, cmd, len, off, req);
    default:
        return NVME_INVALID_LOG_ID | NVME_DNR;
    }
}

static uint16_t ocssd_admin_cmd(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    OcssdCtrl *o = OCSSD(n);
    uint16_t status;

    switch (cmd->opcode) {
    case OCSSD_ADM_CMD_GEOMETRY:
        return ocssd_geometry(o, cmd, req);
    case OCSSD_ADM_CMD_SET_LOG_PAGE:
        return ocssd_set_log(o, cmd, req);
    case NVME_ADM_CMD_GET_LOG_PAGE:
        status = ocssd_get_log(o, cmd, req);
        if (status == NVME_INVALID_LOG_ID) {
            return nvme_admin_cmd(n, cmd, req);
        }

        return status;
    default:
        return nvme_admin_cmd(n, cmd, req);
    }
}

static uint16_t ocssd_io_cmd(NvmeCtrl *n, NvmeCmd *cmd, NvmeRequest *req)
{
    OcssdCtrl *o = OCSSD(n);
    NvmeRwCmd *rw;
    int err;

    uint32_t nsid = le32_to_cpu(cmd->nsid);

    if (unlikely(nsid == 0 || nsid > n->params.num_namespaces)) {
        trace_nvme_err_invalid_ns(nsid, n->params.num_namespaces);
        return NVME_INVALID_NSID | NVME_DNR;
    }

    trace_ocssd_io_cmd(req->cqe.cid, nsid, cmd->opcode);

    req->ns = &n->namespaces[nsid - 1];

    switch (cmd->opcode) {
    case NVME_CMD_READ:
    case NVME_CMD_WRITE:
        rw = (NvmeRwCmd *)cmd;

        req->nlb  = le16_to_cpu(rw->nlb) + 1;
        req->slba = le64_to_cpu(rw->slba);

        if (ocssd_rw_is_write(req)) {
            req->is_write = 1;
        }

        trace_nvme_rw(req->cqe.cid, cmd->opcode, req->nlb, req->slba);
        OcssdNamespace *ons = &o->namespaces[nsid - 1];
        OcssdAddrF *addrf = &ons->addrf;
        fprintf(stderr, "group=%ld punit=%ld chunk=%ld sectr=%ld\n", _group(addrf, req->slba), _punit(addrf, req->slba), _chunk(addrf, req->slba), _sectr(addrf, req->slba));

        err = ocssd_rw_check_scalar_req(o, cmd, req);
        if (err) {
            fprintf(stderr, "DULB returned\n");
            return err;
        }

        int err = nvme_blk_map(n, cmd, req, _addrfn, nvme_blk_setup);
        if (err) {
            return err;
        }

        return nvme_blk_submit_io(n, req, ocssd_rw_cb);

    case OCSSD_CMD_VECT_READ:
    case OCSSD_CMD_VECT_WRITE:
        rw = (NvmeRwCmd *)cmd;

        req->nlb = le16_to_cpu(rw->nlb) + 1;

        if (ocssd_rw_is_write(req)) {
            req->is_write = 1;
        }

        return ocssd_rw(o, cmd, req);
    case OCSSD_CMD_VECT_RESET:
        return ocssd_reset(o, cmd, req);
    default:
        return nvme_io_cmd(n, cmd, req);
    }
}

static int ocssd_init_namespace(OcssdCtrl *o, OcssdNamespace *ons,
    Error **errp)
{
    NvmeCtrl *n = &o->nvme;
    NvmeNamespace *ns = ons->ns;
    NvmeIdNs *id_ns = &ons->ns->id_ns;
    OcssdParams *params = &o->params;
    BlockBackend *blk = n->conf.blk;
    OcssdIdentity *id = &ons->id;
    OcssdIdGeo *geo = &ons->id.geo;
    OcssdAddrF *addrf = &ons->addrf;

    int ret;

    nvme_ns_init_identify(n, id_ns);

    ret = blk_pread(blk, ns->blk.begin, id, sizeof(OcssdIdentity));
    if (ret < 0) {
        error_setg_errno(errp, -ret,
            "could not read namespace identity structure");
        return 1;
    }

    if (params->mccap) {
        id->mccap = cpu_to_le32(params->mccap);
    }

    if (params->early_reset) {
        id->mccap |= OCSSD_IDENTITY_MCCAP_EARLY_RESET;
    }

    if (params->ws_min) {
        id->wrt.ws_min = cpu_to_le32(params->ws_min);
    }

    if (params->ws_opt) {
        id->wrt.ws_opt = cpu_to_le32(params->ws_opt);
    }

    if (params->mw_cunits) {
        id->wrt.mw_cunits = cpu_to_le32(params->mw_cunits);
    }

    id_ns->lbaf[0].lbads = 63 - clz64(o->hdr.sector_size);
    id_ns->lbaf[0].ms = o->hdr.md_size;
    id_ns->nlbaf = 0;
    id_ns->flbas = 0;

    uint64_t chks_total = geo->num_grp * geo->num_pu * geo->num_chk;
    ons->chunkinfo_size =
        QEMU_ALIGN_UP(chks_total * sizeof(OcssdChunkDescriptor),
            o->hdr.sector_size);
    ons->chunk_info = g_malloc0(ons->chunkinfo_size);

    ons->blk.chunk_info = ns->blk.begin + sizeof(OcssdIdentity);

    ns->ns_blks = nvme_ns_calc_blks(n, ns) -
        (2 + ons->chunkinfo_size / NVME_ID_NS_LBADS_BYTES(ns));

    ns->blk.predef = ons->blk.chunk_info + ons->chunkinfo_size;
    ns->blk.data = ns->blk.predef + NVME_ID_NS_LBADS_BYTES(ns);
    ns->blk.meta = ns->blk.data + NVME_ID_NS_LBADS_BYTES(ns) * ns->ns_blks;

    nvme_ns_init_predef(n, ns);

    ons->chks_per_grp = geo->num_chk * geo->num_pu;
    ons->chks_total   = ons->chks_per_grp * geo->num_grp;
    ons->secs_per_chk = geo->clba;
    ons->secs_per_pu  = ons->secs_per_chk * geo->num_chk;
    ons->secs_per_grp = ons->secs_per_pu  * geo->num_pu;
    ons->secs_total   = ons->secs_per_grp * geo->clba;

    addrf->sec_offset = 0;
    addrf->chk_offset = id->lbaf.sec_len;
    addrf->pu_offset = id->lbaf.sec_len + id->lbaf.chk_len;
    addrf->grp_offset = id->lbaf.sec_len +
                            id->lbaf.chk_len +
                            id->lbaf.pu_len;

    addrf->grp_mask = ((1 << id->lbaf.grp_len) - 1) << addrf->grp_offset;
    addrf->pu_mask  = ((1 << id->lbaf.pu_len) - 1)  << addrf->pu_offset;
    addrf->chk_mask = ((1 << id->lbaf.chk_len) - 1) << addrf->chk_offset;
    addrf->sec_mask = ((1 << id->lbaf.sec_len) - 1) << addrf->sec_offset;

    /*
     * Size of device is the entire address space (though some space is not
     * usable).
     */
    id_ns->nuse = id_ns->ncap = id_ns->nsze =
        1ULL << (id->lbaf.sec_len + id->lbaf.chk_len +
            id->lbaf.pu_len + id->lbaf.grp_len);

    ret = ocssd_ns_load_chunk_info(o, ons);
    if (ret < 0) {
        error_setg_errno(errp, -ret, "could not load chunk info");
        return 1;
    }

    if (params->chunkinfo_fname) {
        if (ocssd_load_chunk_info_from_file(o, params->chunkinfo_fname,
            errp)) {
            return 1;
        }

        ret = ocssd_commit_chunk_info(o);
        if (ret < 0) {
            error_setg_errno(errp, -ret, "could not commit chunk info");
            return 1;
        }
    }

    ons->resetfail = NULL;
    if (params->resetfail_fname) {
        ons->resetfail = g_malloc0_n(ons->chks_total, sizeof(*ons->resetfail));
        if (!ons->resetfail) {
            error_setg_errno(errp, ENOMEM, "could not allocate memory");
            return 1;
        }

        if (ocssd_load_reset_err_injection_from_file(o, params->resetfail_fname,
            errp)) {
            return 1;
        }
    }

    ons->writefail = NULL;
    if (params->writefail_fname) {
        ons->writefail = g_malloc0_n(ns->ns_blks, sizeof(*ons->writefail));
        if (!ons->writefail) {
            error_setg_errno(errp, ENOMEM, "could not allocate memory");
            return 1;
        }

        if (ocssd_load_write_err_injection_from_file(o,
            params->resetfail_fname, errp)) {
            return 1;
        }

        /*
         * We fail resets for a chunk after a write failure to it, so make sure
         * to allocate the resetfailure buffer if it has not been already.
         */
        if (!ons->resetfail) {
            ons->resetfail = g_malloc0_n(ons->chks_total,
                sizeof(*ons->resetfail));
        }
    }

    return 0;
}

static int ocssd_init_namespaces(OcssdCtrl *o, Error **errp)
{
    NvmeCtrl *n = &o->nvme;
    BlockBackend *blk = n->conf.blk;
    int ret;
    Error *local_err = NULL;

    ret = blk_pread(blk, 0, &o->hdr, sizeof(OcssdFormatHeader));
    if (ret < 0) {
        error_setg(errp, "could not read block format header");
        return ret;
    }

    n->namespaces = g_new0(NvmeNamespace, o->hdr.num_namespaces);
    o->namespaces = g_new0(OcssdNamespace, o->hdr.num_namespaces);
    for (int i = 0; i < o->hdr.num_namespaces; i++) {
        OcssdNamespace *ons = &o->namespaces[i];
        NvmeNamespace *ns = ons->ns = &n->namespaces[i];
        ns->id = i + 1;
        ns->blk.begin = o->hdr.sector_size + i * o->hdr.ns_size;

        if (ocssd_init_namespace(o, ons, &local_err)) {
            error_propagate_prepend(errp, local_err,
                "init namespaces failed: ");
            return 1;
        }
    }

    return 0;
}

static void ocssd_realize(PCIDevice *pci_dev, Error **errp)
{
    OcssdCtrl *o = OCSSD(pci_dev);
    NvmeCtrl *n = &o->nvme;

    n->namespaces = NULL;
    n->admin_cmd = ocssd_admin_cmd;
    n->io_cmd = ocssd_io_cmd;

    nvme_init_state(n, errp);
    nvme_init_pci(n, pci_dev);

    pci_config_set_vendor_id(pci_dev->config, PCI_VENDOR_ID_CNEX);
    pci_config_set_device_id(pci_dev->config, 0x1f1f);

    nvme_init_ctrl(n);

    ocssd_init_namespaces(o, errp);
}

static void ocssd_exit(PCIDevice *pci_dev)
{

}

static Property ocssd_props[] = {
    DEFINE_BLOCK_PROPERTIES(OcssdCtrl, nvme.conf),
    DEFINE_NVME_PROPERTIES(OcssdCtrl, nvme.params),
    DEFINE_OCSSD_PROPERTIES(OcssdCtrl, params),
    DEFINE_PROP_END_OF_LIST(),
};

static const VMStateDescription ocssd_vmstate = {
    .name = "ocssd",
    .unmigratable = 1,
};

static void ocssd_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    PCIDeviceClass *pc = PCI_DEVICE_CLASS(oc);

    pc->realize = ocssd_realize;
    pc->exit = ocssd_exit;
    pc->class_id = PCI_CLASS_STORAGE_EXPRESS;
    pc->vendor_id = PCI_VENDOR_ID_CNEX;
    pc->device_id = 0x1f1f;
    pc->revision = 2;

    set_bit(DEVICE_CATEGORY_STORAGE, dc->categories);
    dc->desc = "Non-Volatile Memory Express";
    dc->props = ocssd_props;
    dc->vmsd = &ocssd_vmstate;
}

static void ocssd_instance_init(Object *obj)
{
    OcssdCtrl *s = OCSSD(obj);

    device_add_bootindex_property(obj, &s->nvme.conf.bootindex,
                                  "bootindex", "/namespace@1,0",
                                  DEVICE(obj), &error_abort);
}

static const TypeInfo ocssd_info = {
    .name          = TYPE_OCSSD,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(OcssdCtrl),
    .class_init    = ocssd_class_init,
    .instance_init = ocssd_instance_init,
    .interfaces = (InterfaceInfo[]) {
        { INTERFACE_PCIE_DEVICE },
        { }
    },
};

static void ocssd_register_types(void)
{
    type_register_static(&ocssd_info);
}

type_init(ocssd_register_types)
