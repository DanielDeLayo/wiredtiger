/*-
 * Copyright (c) 2014-present MongoDB, Inc.
 * Copyright (c) 2008-2014 WiredTiger, Inc.
 *	All rights reserved.
 *
 * See the file LICENSE for redistribution information.
 */

#pragma once

#ifdef HAVE_ANALYZE_CACHE

/*
 * How far past the configured cache size the miss-ratio curve should reach. The point of the curve
 * is to say whether more cache would help, so it has to extend well beyond the size actually in
 * use. This is a ceiling rather than a reservation: the curve costs 8 bytes per block of the living
 * set actually touched, and stops growing there.
 */
#define WT_IAF_CACHE_HEADROOM 4

/*
 * The main curve is WT_IAF_PARTITIONS independent samples, each of one address in
 * 2^WT_IAF_SAMPLING_LOG2. They are disjoint, so together they sample 1 in 4: the work IAF does per
 * access and the memory the curves need are what a single 1-in-4 sample would cost, and their
 * spread gives the curve an error bar. The cache-size axis is scaled back up when each curve is
 * emitted, so the reported sizes stay in real blocks.
 */
#define WT_IAF_SAMPLING_LOG2 4 /* 1 in 16 each */
#define WT_IAF_PARTITIONS 4

/*
 * The internal-page curve samples 1 in 4 addresses. Internal pages are about half of all page
 * accesses but few distinct pages, and the root and upper levels take most of those accesses, so at
 * this rate the curve misses the steep drop they cause at the smallest sizes; above the provable
 * floor it matches the unsampled curve. It has its own lock, so it does not contend with the main
 * curve.
 */
#define WT_IAF_INTERNAL_SAMPLING_LOG2 2

/*
 * Placeholder bound. conn->iaf has to be created at the top of wiredtiger_open, before the cache
 * size is known, but __wt_analyze_cache_bound() replaces this from __wt_cache_create() -- still
 * ahead of the first metadata read -- so no request is ever recorded under it.
 */
#define WT_IAF_DEFAULT_MAX_BLOCKS (1000000)

/*
 * __wt_analyze_cache_bound --
 *     Re-bound the miss-ratio curve to cover the configured cache size, with headroom. Called once
 *     the cache size is known, and again on reconfigure if it changes.
 */
static WT_INLINE void
__wt_analyze_cache_bound(WT_SESSION_IMPL *session)
{
    WT_CONNECTION_IMPL *conn;

    conn = S2C(session);

    /*
     * A shared cache reports a size of zero here and is sized by the pool instead; leave the
     * previous bound in place rather than collapsing the curve to nothing.
     */
    if (conn->iaf == NULL || conn->cache_size == 0)
        return;

    Iaf_set_max_cache_blocks(
      conn->iaf, (size_t)(conn->cache_size / IAF_BLOCK_SIZE) * WT_IAF_CACHE_HEADROOM);
    Iaf_set_max_cache_blocks(
      conn->iaf_intl, (size_t)(conn->cache_size / IAF_BLOCK_SIZE) * WT_IAF_CACHE_HEADROOM);
}

/*
 * __wt_analyze_cache_log --
 *     Dump an IAF miss-ratio curve, prefixed with the cache size the curve should be read at and
 *     the hit rate WiredTiger actually achieved there. The predicted and the observed numbers are
 *     emitted in a single message so a reader can validate one against the other without having to
 *     correlate separate log lines. The internal curve covers internal pages only, and its observed
 *     numbers are restricted to internal pages to match.
 */
static WT_INLINE void
__wt_analyze_cache_log(WT_SESSION_IMPL *session, bool internal)
{
    WT_CONNECTION_IMPL *conn;
    Iaf iaf;
    Iaf_size_stats sizes;
    double cache_eps, hit_rate;
    uint64_t cache_blocks, curve_blocks, floor_blocks, floor1, floor5, floor25, floor50, floor100;
    uint64_t floor200;
    int64_t bytes_inuse, reads, requests;
    size_t nparts, part;
    char *iaf_str;

    conn = S2C(session);
    iaf = internal ? conn->iaf_intl : conn->iaf;
    if (iaf == NULL)
        return;

    /*
     * Pages requested is every lookup that found a page in cache or read one in; pages read is the
     * subset that missed. Both stay zero unless the connection enabled statistics, hence the guard
     * on the division.
     */
    requests = WT_STAT_CONN_READ(conn->stats, cache_pages_requested_internal);
    reads = WT_STAT_CONN_READ(conn->stats, cache_read_internal);
    if (internal)
        bytes_inuse = WT_STAT_CONN_READ(conn->stats, cache_bytes_internal);
    else {
        requests += WT_STAT_CONN_READ(conn->stats, cache_pages_requested_leaf);
        reads += WT_STAT_CONN_READ(conn->stats, cache_read_leaf);
        bytes_inuse = WT_STAT_CONN_READ(conn->stats, cache_bytes_inuse);
    }
    hit_rate = requests > 0 ? 100.0 * (double)(requests - reads) / (double)requests : 0.0;

    /*
     * The curve's cache-size axis is denominated in IAF_BLOCK_SIZE units, so report the configured
     * cache size in those units as well as in bytes -- that value is the x coordinate at which the
     * curve should predict the hit rate reported here. If it lies beyond the largest cache size the
     * curve can represent then the two numbers cannot be compared at all, so say so rather than
     * leaving a reader to infer it from the curve's last row.
     */
    cache_blocks = (uint64_t)conn->cache_size / IAF_BLOCK_SIZE;
    curve_blocks = Iaf_max_cache_blocks(iaf);

    /*
     * How much rounding page sizes up to whole blocks distorts the curve, and the smallest cache
     * sizes at which sampling is provably accurate to within 1%, 5%, 10%, 25%, 50%, 100% and 200%.
     */
    Iaf_get_size_stats(iaf, &sizes);
    floor_blocks = Iaf_provable_floor_blocks(iaf);
    floor1 = Iaf_provable_floor_blocks_at(iaf, 0.01);
    floor5 = Iaf_provable_floor_blocks_at(iaf, 0.05);
    floor25 = Iaf_provable_floor_blocks_at(iaf, 0.25);
    floor50 = Iaf_provable_floor_blocks_at(iaf, 0.5);
    floor100 = Iaf_provable_floor_blocks_at(iaf, 1.0);
    floor200 = Iaf_provable_floor_blocks_at(iaf, 2.0);
    /* And how far the curve can be trusted at the configured cache size itself. */
    cache_eps = Iaf_provable_eps_at(iaf, cache_blocks);

    /* One record per partition: every curve in one record could pass mongod's log size limit. */
    nparts = Iaf_partitions(iaf);
    for (part = 0; part < nparts; ++part) {
        if ((iaf_str = Iaf_stringify_partition(iaf, part)) == NULL)
            continue;
        __wt_verbose_info(session, WT_VERB_EVICTION,
          "IAF-SUMMARY curve=%s,partition=%" WT_SIZET_FMT ",partitions=%" WT_SIZET_FMT
          ",block_bytes=%d,grid_ratio=%.2f,sampling_log2=%d,cache_bytes=%" PRIu64
          ",cache_blocks=%" PRIu64 ",curve_max_blocks=%" PRIu64 ",provable_floor_blocks=%" PRIu64
          ",provable_floor_blocks_by_pct=1:%" PRIu64 "|5:%" PRIu64 "|10:%" PRIu64 "|25:%" PRIu64
          "|50:%" PRIu64 "|100:%" PRIu64 "|200:%" PRIu64
          ",provable_eps_at_cache=%.4f"
          ",curve_covers_cache=%s,bytes_inuse=%" PRId64 ",pages_requested=%" PRId64
          ",pages_read=%" PRId64 ",hit_rate_pct=%.4f,stats_enabled=%s,sampled_accesses=%" PRIu64
          ",small_accesses=%" PRIu64 ",sampled_bytes=%" PRIu64 ",rounded_bytes=%" PRIu64 "\n%s",
          internal ? "internal" : "all", part, nparts, IAF_BLOCK_SIZE, IAF_GRID_RATIO,
          internal ? WT_IAF_INTERNAL_SAMPLING_LOG2 : WT_IAF_SAMPLING_LOG2, conn->cache_size,
          cache_blocks, curve_blocks, floor_blocks, floor1, floor5, floor_blocks, floor25, floor50,
          floor100, floor200, cache_eps, cache_blocks <= curve_blocks ? "true" : "false",
          bytes_inuse, requests, reads, hit_rate, WT_STAT_ENABLED(session) ? "true" : "false",
          sizes.accesses, sizes.small_accesses, sizes.bytes, sizes.rounded_bytes, iaf_str);
        Iaf_free_string(iaf_str);
    }
}

#endif /* HAVE_ANALYZE_CACHE */
