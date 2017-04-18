# mirror\_run()を追う

drive\_mirror QMPから呼ばれるコルーチンmirror\_run()の中身。

最終的には書き出すときにThin Provisioning対応しているかを知りたい。

## 概要

最終的に、dirty bitmapを見ながらループする。おおまかなループの流れはこんな感じ。

- mirror\_run()
- mirror\_iteration()
- mirror\_do\_read()
- bdrv\_aio\_read() @block/io.c
  - bdrv\_co\_aio\_rw\_vector @io.c
- mirror\_read\_complete()
- bdrv\_aio\_writev() @block/io.c
  - bdrv\_co\_aio\_rw\_vector @io.c
- mirror\_write\_complete()
- mirror\_iteration\_done()
- qemu\_coroutine\_enter()

# 詳細

- mirror\_interation() @block/mirror.c

```c
static uint64_t coroutine_fn mirror_iteration(MirrorBlockJob *s)
{
    BlockDriverState *source = s->common.bs;
    int64_t sector_num, first_chunk;
    uint64_t delay_ns = 0;
    /* At least the first dirty chunk is mirrored in one iteration. */
    int nb_chunks = 1;
    int64_t end = s->bdev_length / BDRV_SECTOR_SIZE;
    int sectors_per_chunk = s->granularity >> BDRV_SECTOR_BITS;

(snip)

    /* Clear dirty bits before querying the block status, because
     * calling bdrv_get_block_status_above could yield - if some blocks are
     * marked dirty in this window, we need to know.
     */
    bdrv_reset_dirty_bitmap(s->dirty_bitmap, sector_num,
                            nb_chunks * sectors_per_chunk);
    bitmap_set(s->in_flight_bitmap, sector_num / sectors_per_chunk, nb_chunks);
    while (nb_chunks > 0 && sector_num < end) {
        int ret;
        int io_sectors;
        BlockDriverState *file;
        enum MirrorMethod {
            MIRROR_METHOD_COPY,
            MIRROR_METHOD_ZERO,
            MIRROR_METHOD_DISCARD
        } mirror_method = MIRROR_METHOD_COPY;

(snip)

        ret = bdrv_get_block_status_above(source, NULL, sector_num,
                                          nb_chunks * sectors_per_chunk,
                                          &io_sectors, &file);

(snip)

        io_sectors -= io_sectors % sectors_per_chunk;
        if (io_sectors < sectors_per_chunk) {
            io_sectors = sectors_per_chunk;
        } else if (ret >= 0 && !(ret & BDRV_BLOCK_DATA)) {
            int64_t target_sector_num;
            int target_nb_sectors;
            bdrv_round_to_clusters(s->target, sector_num, io_sectors,
                                   &target_sector_num, &target_nb_sectors);
            if (target_sector_num == sector_num &&
                target_nb_sectors == io_sectors) {
                mirror_method = ret & BDRV_BLOCK_ZERO ?
                                    MIRROR_METHOD_ZERO :
                                    MIRROR_METHOD_DISCARD;
            }
        }

(snip)

        switch (mirror_method) {
        case MIRROR_METHOD_COPY:
            io_sectors = mirror_do_read(s, sector_num, io_sectors);
            break;
        case MIRROR_METHOD_ZERO:
            mirror_do_zero_or_discard(s, sector_num, io_sectors, false);
            break;
        case MIRROR_METHOD_DISCARD:
            mirror_do_zero_or_discard(s, sector_num, io_sectors, true);
            break;
        default:
            abort();
        }

(snip)

        delay_ns += ratelimit_calculate_delay(&s->limit, io_sectors);
    }
    return delay_ns;
}

```

bdrv\_get\_block\_status\_above()の戻り値を見て、次に何を呼ぶかを変えているっぽい。

- bdrv\_get\_block\_status\_above() @block/io.c

```c
/*
 * Synchronous wrapper around bdrv_co_get_block_status_above().
 *
 * See bdrv_co_get_block_status_above() for details.
 */
int64_t bdrv_get_block_status_above(BlockDriverState *bs,
                                    BlockDriverState *base,
                                    int64_t sector_num,
                                    int nb_sectors, int *pnum,
                                    BlockDriverState **file)
{
    Coroutine *co;
    BdrvCoGetBlockStatusData data = {
        .bs = bs,
        .base = base,
        .file = file,
        .sector_num = sector_num,
        .nb_sectors = nb_sectors,
        .pnum = pnum,
        .done = false,
    };

    if (qemu_in_coroutine()) {
        /* Fast-path if already in coroutine context */
        bdrv_get_block_status_above_co_entry(&data);
    } else {
        AioContext *aio_context = bdrv_get_aio_context(bs);

        co = qemu_coroutine_create(bdrv_get_block_status_above_co_entry);
        qemu_coroutine_enter(co, &data);
        while (!data.done) {
            aio_poll(aio_context, true);
        }
    }
    return data.ret;
}

```

コルーチン bdrv\_get\_block\_status\_above\_co\_entry() を作成。

- bdrv\_get\_block\_status\_above\_co\_entry() @block/io.c

```c
/* Coroutine wrapper for bdrv_get_block_status_above() */
static void coroutine_fn bdrv_get_block_status_above_co_entry(void *opaque)
{
    BdrvCoGetBlockStatusData *data = opaque;

    data->ret = bdrv_co_get_block_status_above(data->bs, data->base,
                                               data->sector_num,
                                               data->nb_sectors,
                                               data->pnum,
                                               data->file);
    data->done = true;
}
```

さらにbdrv\_co\_get\_block\_status\_above()を呼ぶ。

- bdrv\_co\_get\_block\_status\_above() @block/io.c

```c
static int64_t coroutine_fn bdrv_co_get_block_status_above(BlockDriverState *bs,
        BlockDriverState *base,
        int64_t sector_num,
        int nb_sectors,
        int *pnum,
        BlockDriverState **file)
{
    BlockDriverState *p;
    int64_t ret = 0;

    assert(bs != base);
    for (p = bs; p != base; p = backing_bs(p)) {
        ret = bdrv_co_get_block_status(p, sector_num, nb_sectors, pnum, file);
        if (ret < 0 || ret & BDRV_BLOCK_ALLOCATED) {
            break;
        }
        /* [sector_num, pnum] unallocated on this layer, which could be only
         * the first part of [sector_num, nb_sectors].  */
        nb_sectors = MIN(nb_sectors, *pnum);
    }
    return ret;
}
```

- bdrv\_co\_get\_block\_status() @block/io.c

```c
/*
 * Returns the allocation status of the specified sectors.
 * Drivers not implementing the functionality are assumed to not support
 * backing files, hence all their sectors are reported as allocated.
 *
 * If 'sector_num' is beyond the end of the disk image the return value is 0
 * and 'pnum' is set to 0.
 *
 * 'pnum' is set to the number of sectors (including and immediately following
 * the specified sector) that are known to be in the same
 * allocated/unallocated state.
 *
 * 'nb_sectors' is the max value 'pnum' should be set to.  If nb_sectors goes
 * beyond the end of the disk image it will be clamped.
 *
 * If returned value is positive and BDRV_BLOCK_OFFSET_VALID bit is set, 'file'
 * points to the BDS which the sector range is allocated in.
 */
static int64_t coroutine_fn bdrv_co_get_block_status(BlockDriverState *bs,
                                                     int64_t sector_num,
                                                     int nb_sectors, int *pnum,
                                                     BlockDriverState **file)
{
    int64_t total_sectors;
    int64_t n;
    int64_t ret, ret2;

    total_sectors = bdrv_nb_sectors(bs);
    if (total_sectors < 0) {
        return total_sectors;
    }

    if (sector_num >= total_sectors) {
        *pnum = 0;
        return 0;
    }

    n = total_sectors - sector_num;
    if (n < nb_sectors) {
        nb_sectors = n;
    }

    if (!bs->drv->bdrv_co_get_block_status) {
        *pnum = nb_sectors;
        ret = BDRV_BLOCK_DATA | BDRV_BLOCK_ALLOCATED;
        if (bs->drv->protocol_name) {
            ret |= BDRV_BLOCK_OFFSET_VALID | (sector_num * BDRV_SECTOR_SIZE);
        }
        return ret;
    }

    *file = NULL;
    ret = bs->drv->bdrv_co_get_block_status(bs, sector_num, nb_sectors, pnum,
                                            file);
    if (ret < 0) {
        *pnum = 0;
        return ret;
    }

    if (ret & BDRV_BLOCK_RAW) {
        assert(ret & BDRV_BLOCK_OFFSET_VALID);
        return bdrv_get_block_status(bs->file->bs, ret >> BDRV_SECTOR_BITS,
                                     *pnum, pnum, file);
    }

    if (ret & (BDRV_BLOCK_DATA | BDRV_BLOCK_ZERO)) {
        ret |= BDRV_BLOCK_ALLOCATED;
    } else {
        if (bdrv_unallocated_blocks_are_zero(bs)) {
            ret |= BDRV_BLOCK_ZERO;
        } else if (bs->backing) {
            BlockDriverState *bs2 = bs->backing->bs;
            int64_t nb_sectors2 = bdrv_nb_sectors(bs2);
            if (nb_sectors2 >= 0 && sector_num >= nb_sectors2) {
                ret |= BDRV_BLOCK_ZERO;
            }
        }
    }

    if (*file && *file != bs &&
        (ret & BDRV_BLOCK_DATA) && !(ret & BDRV_BLOCK_ZERO) &&
        (ret & BDRV_BLOCK_OFFSET_VALID)) {
        BlockDriverState *file2;
        int file_pnum;

        ret2 = bdrv_co_get_block_status(*file, ret >> BDRV_SECTOR_BITS,
                                        *pnum, &file_pnum, &file2);
        if (ret2 >= 0) {
            /* Ignore errors.  This is just providing extra information, it
             * is useful but not necessary.
             */
            if (!file_pnum) {
                /* !file_pnum indicates an offset at or beyond the EOF; it is
                 * perfectly valid for the format block driver to point to such
                 * offsets, so catch it and mark everything as zero */
                ret |= BDRV_BLOCK_ZERO;
            } else {
                /* Limit request to the range reported by the protocol driver */
                *pnum = file_pnum;
                ret |= (ret2 & BDRV_BLOCK_ZERO);
            }
        }
    }

    return ret;
}
```
