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
 * use; the cost is roughly 8 bytes of hits vector per block covered, doubled transiently whenever
 * the curve is stringified.
 */
#define WT_IAF_CACHE_HEADROOM 4

/*
 * Bound used until the cache configuration has been parsed. conn->iaf is created at the very top of
 * wiredtiger_open, before the cache size is known, so this only has to cover the handful of
 * accesses made before __wt_analyze_cache_bound() runs.
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
}

/*
 * __wt_analyze_cache_log --
 *     Dump the IAF miss-ratio curve, prefixed with the cache size the curve should be read at and
 *     the hit rate WiredTiger actually achieved there. The predicted and the observed numbers are
 *     emitted in a single message so a reader can validate one against the other without having to
 *     correlate separate log lines.
 */
static WT_INLINE void
__wt_analyze_cache_log(WT_SESSION_IMPL *session)
{
    WT_CONNECTION_IMPL *conn;
    double hit_rate;
    uint64_t cache_blocks, curve_blocks;
    int64_t bytes_inuse, reads, requests;
    char *iaf_str;

    conn = S2C(session);
    if (conn->iaf == NULL)
        return;

    /*
     * Pages requested is every lookup that found a page in cache or read one in; pages read is the
     * subset that missed. Both counters are zero unless statistics are enabled on the connection,
     * in which case we report a hit rate of zero rather than dividing by it.
     */
    requests = WT_STAT_CONN_READ(conn->stats, cache_pages_requested_internal) +
      WT_STAT_CONN_READ(conn->stats, cache_pages_requested_leaf);
    reads = WT_STAT_CONN_READ(conn->stats, cache_read_internal) +
      WT_STAT_CONN_READ(conn->stats, cache_read_leaf);
    bytes_inuse = WT_STAT_CONN_READ(conn->stats, cache_bytes_inuse);
    hit_rate = requests > 0 ? 100.0 * (double)(requests - reads) / (double)requests : 0.0;

    iaf_str = Iaf_stringify(conn->iaf);
    if (iaf_str == NULL)
        return;

    /*
     * The curve's cache-size axis is denominated in IAF_BLOCK_SIZE units, so report the configured
     * cache size in those units as well as in bytes -- that value is the x coordinate at which the
     * curve should predict the hit rate reported here. If it lies beyond the largest cache size the
     * curve can represent then the two numbers cannot be compared at all, so say so rather than
     * leaving a reader to infer it from the curve's last row.
     */
    cache_blocks = (uint64_t)conn->cache_size / IAF_BLOCK_SIZE;
    curve_blocks = Iaf_max_cache_blocks(conn->iaf);

    __wt_verbose_info(session, WT_VERB_EVICTION,
      "IAF-SUMMARY cache_bytes=%" PRIu64 ",cache_blocks=%" PRIu64 ",curve_max_blocks=%" PRIu64
      ",curve_covers_cache=%s,bytes_inuse=%" PRId64 ",pages_requested=%" PRId64
      ",pages_read=%" PRId64 ",hit_rate_pct=%.4f,stats_enabled=%s\n%s",
      conn->cache_size, cache_blocks, curve_blocks, cache_blocks <= curve_blocks ? "true" : "false",
      bytes_inuse, requests, reads, hit_rate, WT_STAT_ENABLED(session) ? "true" : "false", iaf_str);

    Iaf_free_string(iaf_str);
}

#endif /* HAVE_ANALYZE_CACHE */
