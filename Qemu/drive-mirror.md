# qemuのdrive-mirrorを追う

"drive-mirror" QMPを追う。

qemu-kvm-rhev-2.6.0-28.el7_3.6

# QMP (Qemu Machine Protocol) とは

qemuインスタンスを外から制御するためのjsonベースのプロトコル

## "drive-mirror" QMP

- qmp-commands.hx [qemu]

```
    {
        .name       = "drive-mirror",
        .args_type  = "sync:s,device:B,target:s,speed:i?,mode:s?,format:s?,"
                      "node-name:s?,replaces:s?,"
                      "on-source-error:s?,on-target-error:s?,"
                      "unmap:b?,"
                      "granularity:i?,buf-size:i?",
        .mhandler.cmd_new = qmp_marshal_drive_mirror,
    },
```

```
drive-mirror
------------

Start mirroring a block device's writes to a new destination. target
specifies the target of the new image. If the file exists, or if it is
a device, it will be used as the new destination for writes. If it does not
exist, a new file will be created. format specifies the format of the
mirror image, default is to probe if mode='existing', else the format
of the source.

Arguments:

- "device": device name to operate on (json-string)
- "target": name of new image file (json-string)
- "format": format of new image (json-string, optional)
- "node-name": the name of the new block driver state in the node graph
               (json-string, optional)
- "replaces": the block driver node name to replace when finished
              (json-string, optional)
- "mode": how an image file should be created into the target
  file/device (NewImageMode, optional, default 'absolute-paths')
- "speed": maximum speed of the streaming job, in bytes per second
  (json-int)
- "granularity": granularity of the dirty bitmap, in bytes (json-int, optional)
- "buf-size": maximum amount of data in flight from source to target, in bytes
  (json-int, default 10M)
- "sync": what parts of the disk image should be copied to the destination;
  possibilities include "full" for all the disk, "top" for only the sectors
  allocated in the topmost image, or "none" to only replicate new I/O
  (MirrorSyncMode).
- "on-source-error": the action to take on an error on the source
  (BlockdevOnError, default 'report')
- "on-target-error": the action to take on an error on the target
  (BlockdevOnError, default 'report')
- "unmap": whether the target sectors should be discarded where source has only
  zeroes. (json-bool, optional, default true)

The default value of the granularity is the image cluster size clamped
between 4096 and 65536, if the image format defines one.  If the format
does not define a cluster size, the default value of the granularity
is 65536.


Example:

-> { "execute": "drive-mirror", "arguments": { "device": "ide-hd0",
                                               "target": "/some/place/my-image",
                                               "sync": "full",
                                               "format": "qcow2" } }
<- { "return": {} }

```

- qapi/block-core.json [qemu]

```
##
# @drive-mirror
#
# Start mirroring a block device's writes to a new destination.
#
# @device:  the name of the device whose writes should be mirrored.
#
# @target: the target of the new image. If the file exists, or if it
#          is a device, the existing file/device will be used as the new
#          destination.  If it does not exist, a new file will be created.
#
# @format: #optional the format of the new destination, default is to
#          probe if @mode is 'existing', else the format of the source
#
# @node-name: #optional the new block driver state node name in the graph
#             (Since 2.1)
#
# @replaces: #optional with sync=full graph node name to be replaced by the new
#            image when a whole image copy is done. This can be used to repair
#            broken Quorum files. (Since 2.1)
#
# @mode: #optional whether and how QEMU should create a new image, default is
#        'absolute-paths'.
#
# @speed:  #optional the maximum speed, in bytes per second
#
# @sync: what parts of the disk image should be copied to the destination
#        (all the disk, only the sectors allocated in the topmost image, or
#        only new I/O).
#
# @granularity: #optional granularity of the dirty bitmap, default is 64K
#               if the image format doesn't have clusters, 4K if the clusters
#               are smaller than that, else the cluster size.  Must be a
#               power of 2 between 512 and 64M (since 1.4).
#
# @buf-size: #optional maximum amount of data in flight from source to
#            target (since 1.4).
#
# @on-source-error: #optional the action to take on an error on the source,
#                   default 'report'.  'stop' and 'enospc' can only be used
#                   if the block device supports io-status (see BlockInfo).
#
# @on-target-error: #optional the action to take on an error on the target,
#                   default 'report' (no limitations, since this applies to
#                   a different block device than @device).
# @unmap: #optional Whether to try to unmap target sectors where source has
#         only zero. If true, and target unallocated sectors will read as zero,
#         target image sectors will be unmapped; otherwise, zeroes will be
#         written. Both will result in identical contents.
#         Default is true. (Since 2.4)
#
# Returns: nothing on success
#          If @device is not a valid block device, DeviceNotFound
#
# Since 1.3
##
{ 'command': 'drive-mirror',
  'data': { 'device': 'str', 'target': 'str', '*format': 'str',
            '*node-name': 'str', '*replaces': 'str',
            'sync': 'MirrorSyncMode', '*mode': 'NewImageMode',
            '*speed': 'int', '*granularity': 'uint32',
            '*buf-size': 'int', '*on-source-error': 'BlockdevOnError',
            '*on-target-error': 'BlockdevOnError',
            '*unmap': 'bool' } }
```

QMPを呼び出す方法のひとつに、Human Monitor Interfaceがある。drive\_mirrorのHMIはこちら。

- hmp.c [qemu]

```c
void hmp_drive_mirror(Monitor *mon, const QDict *qdict)
{
    const char *device = qdict_get_str(qdict, "device");
    const char *filename = qdict_get_str(qdict, "target");
    const char *format = qdict_get_try_str(qdict, "format");
    bool reuse = qdict_get_try_bool(qdict, "reuse", false);
    bool full = qdict_get_try_bool(qdict, "full", false);
    enum NewImageMode mode;
    Error *err = NULL;

    if (!filename) {
        error_setg(&err, QERR_MISSING_PARAMETER, "target");
        hmp_handle_error(mon, &err);
        return;
    }

    if (reuse) {
        mode = NEW_IMAGE_MODE_EXISTING;
    } else {
        mode = NEW_IMAGE_MODE_ABSOLUTE_PATHS;
    }

    qmp_drive_mirror(device, filename, !!format, format,
                     false, NULL, false, NULL,
                     full ? MIRROR_SYNC_MODE_FULL : MIRROR_SYNC_MODE_TOP,
                     true, mode, false, 0, false, 0, false, 0,
                     false, 0, false, 0, false, true, &err);
    hmp_handle_error(mon, &err);
}
```

"drive\_mirror" QMPの本体はqmp\_drive\_mirror()が起点になる。

qmp\_drive\_mirror()の定義とか、どこから呼び出されるかとかは、make時に作るファイルqmp-commands.h、qmp-marshal.c等に書かれる。scripts/qapi-commands.pyを使って、qapi/block-core.jsonから生成する。

- Makefile

```
qmp-commands.h qmp-marshal.c :\
$(qapi-modules) $(SRC_PATH)/scripts/qapi-commands.py $(qapi-py)
        $(call quiet-command,$(PYTHON) $(SRC_PATH)/scripts/qapi-commands.py \
                $(gen-out-type) -o "." -m $<, \
                "  GEN   $@")
```

- qmp-commands.h

```c
void qmp_drive_mirror(const char *device, const char *target, bool has_format, const char *format, bool has_node_name, const char *node_name, bool has_replaces, const char *replaces, MirrorSyncMode sync, bool has_mode, NewImageMode mode, bool has_speed, int64_t speed, bool has_granularity, uint32_t granularity, bool has_buf_size, int64_t buf_size, bool has_on_source_error, BlockdevOnError on_source_error, bool has_on_target_error, BlockdevOnError on_target_error, bool has_unmap, bool unmap, Error **errp);
void qmp_marshal_drive_mirror(QDict *args, QObject **ret, Error **errp);
```

- qmp-marshal.c

```c
void qmp_marshal_drive_mirror(QDict *args, QObject **ret, Error **errp)
{
    Error *err = NULL;
    QmpInputVisitor *qiv = qmp_input_visitor_new_strict(QOBJECT(args));
    QapiDeallocVisitor *qdv;
    Visitor *v;
    q_obj_drive_mirror_arg arg = {0};

    v = qmp_input_get_visitor(qiv);
    visit_type_q_obj_drive_mirror_arg_members(v, &arg, &err);
    if (err) {
        goto out;
    }

    qmp_drive_mirror(arg.device, arg.target, arg.has_format, arg.format, arg.has_node_name, arg.node_name, arg.has_replaces, arg.replaces, arg.sync, arg.has_mode, arg.mode, arg.has_speed, arg.speed, arg.has_granularity, arg.granularity, arg.has_buf_size, arg.buf_size, arg.has_on_source_error, arg.on_source_error, arg.has_on_target_error, arg.on_target_error, arg.has_unmap, arg.unmap, &err);

out:
    error_propagate(errp, err);
    qmp_input_visitor_cleanup(qiv);
    qdv = qapi_dealloc_visitor_new();
    v = qapi_dealloc_get_visitor(qdv);
    visit_type_q_obj_drive_mirror_arg_members(v, &arg, NULL);
    qapi_dealloc_visitor_cleanup(qdv);
}
```

というわけで、"drive\_mirror" QMPの本体であるqmp\_drive\_mirror()がこれ。


- blockdev.c [qemu]

```c
void qmp_drive_mirror(const char *device, const char *target,
                      bool has_format, const char *format,
                      bool has_node_name, const char *node_name,
                      bool has_replaces, const char *replaces,
                      enum MirrorSyncMode sync,
                      bool has_mode, enum NewImageMode mode,
                      bool has_speed, int64_t speed,
                      bool has_granularity, uint32_t granularity,
                      bool has_buf_size, int64_t buf_size,
                      bool has_on_source_error, BlockdevOnError on_source_error,
                      bool has_on_target_error, BlockdevOnError on_target_error,
                      bool has_unmap, bool unmap,
                      Error **errp)
{
    BlockDriverState *bs;
    BlockBackend *blk;
    BlockDriverState *source, *target_bs;
    AioContext *aio_context;
    Error *local_err = NULL;
    QDict *options = NULL;
    int flags;
    int64_t size;
    int ret;

    blk = blk_by_name(device);
    if (!blk) {
        error_set(errp, ERROR_CLASS_DEVICE_NOT_FOUND,
                  "Device '%s' not found", device);
        return;
    }

    aio_context = blk_get_aio_context(blk);
    aio_context_acquire(aio_context);

    if (!blk_is_available(blk)) {
        error_setg(errp, QERR_DEVICE_HAS_NO_MEDIUM, device);
        goto out;
    }
    bs = blk_bs(blk);
    if (!has_mode) {
        mode = NEW_IMAGE_MODE_ABSOLUTE_PATHS;
    }

    if (!has_format) {
        format = mode == NEW_IMAGE_MODE_EXISTING ? NULL : bs->drv->format_name;
    }

    flags = bs->open_flags | BDRV_O_RDWR;
    source = backing_bs(bs);
    if (!source && sync == MIRROR_SYNC_MODE_TOP) {
        sync = MIRROR_SYNC_MODE_FULL;
    }
    if (sync == MIRROR_SYNC_MODE_NONE) {
        source = bs;
    }

    size = bdrv_getlength(bs);
    if (size < 0) {
        error_setg_errno(errp, -size, "bdrv_getlength failed");
        goto out;
    }

    if (has_replaces) {
        BlockDriverState *to_replace_bs;
        AioContext *replace_aio_context;
        int64_t replace_size;

        if (!has_node_name) {
            error_setg(errp, "a node-name must be provided when replacing a"
                             " named node of the graph");
            goto out;
        }

        to_replace_bs = check_to_replace_node(bs, replaces, &local_err);

        if (!to_replace_bs) {
            error_propagate(errp, local_err);
            goto out;
        }

        replace_aio_context = bdrv_get_aio_context(to_replace_bs);
        aio_context_acquire(replace_aio_context);
        replace_size = bdrv_getlength(to_replace_bs);
        aio_context_release(replace_aio_context);

        if (size != replace_size) {
            error_setg(errp, "cannot replace image with a mirror image of "
                             "different size");
            goto out;
        }
    }

    if ((sync == MIRROR_SYNC_MODE_FULL || !source)
        && mode != NEW_IMAGE_MODE_EXISTING)
    {
        /* create new image w/o backing file */
        assert(format);
        bdrv_img_create(target, format,
                        NULL, NULL, NULL, size, flags, &local_err, false);
    } else {
        switch (mode) {
        case NEW_IMAGE_MODE_EXISTING:
            break;
        case NEW_IMAGE_MODE_ABSOLUTE_PATHS:
            /* create new image with backing file */
            bdrv_img_create(target, format,
                            source->filename,
                            source->drv->format_name,
                            NULL, size, flags, &local_err, false);
            break;
        default:
            abort();
        }
    }

    if (local_err) {
        error_propagate(errp, local_err);
        goto out;
    }

    options = qdict_new();
    if (has_node_name) {
        qdict_put(options, "node-name", qstring_from_str(node_name));
    }
    if (format) {
        qdict_put(options, "driver", qstring_from_str(format));
    }

    /* Mirroring takes care of copy-on-write using the source's backing
     * file.
     */
    target_bs = NULL;
    ret = bdrv_open(&target_bs, target, NULL, options,
                    flags | BDRV_O_NO_BACKING, &local_err);
    if (ret < 0) {
        error_propagate(errp, local_err);
        goto out;
    }

    bdrv_set_aio_context(target_bs, aio_context);

    blockdev_mirror_common(bs, target_bs,                                   /* XXX */
                           has_replaces, replaces, sync,
                           has_speed, speed,
                           has_granularity, granularity,
                           has_buf_size, buf_size,
                           has_on_source_error, on_source_error,
                           has_on_target_error, on_target_error,
                           has_unmap, unmap,
                           &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        bdrv_unref(target_bs);
    }
out:
    aio_context_release(aio_context);
}
```

blockdev\_mirror\_common()を呼ぶ。

- blockdev.c [qemu]

```c
/* Parameter check and block job starting for drive mirroring.
 * Caller should hold @device and @target's aio context (must be the same).
 **/
static void blockdev_mirror_common(BlockDriverState *bs,
                                   BlockDriverState *target,
                                   bool has_replaces, const char *replaces,
                                   enum MirrorSyncMode sync,
                                   bool has_speed, int64_t speed,
                                   bool has_granularity, uint32_t granularity,
                                   bool has_buf_size, int64_t buf_size,
                                   bool has_on_source_error,
                                   BlockdevOnError on_source_error,
                                   bool has_on_target_error,
                                   BlockdevOnError on_target_error,
                                   bool has_unmap, bool unmap,
                                   Error **errp)
{

    if (!has_speed) {
        speed = 0;
    }
    if (!has_on_source_error) {
        on_source_error = BLOCKDEV_ON_ERROR_REPORT;
    }
    if (!has_on_target_error) {
        on_target_error = BLOCKDEV_ON_ERROR_REPORT;
    }
    if (!has_granularity) {
        granularity = 0;
    }
    if (!has_buf_size) {
        buf_size = 0;
    }
    if (!has_unmap) {
        unmap = true;
    }

    if (granularity != 0 && (granularity < 512 || granularity > 1048576 * 64)) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE, "granularity",
                   "a value in range [512B, 64MB]");
        return;
    }
    if (granularity & (granularity - 1)) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE, "granularity",
                   "power of 2");
        return;
    }

    if (bdrv_op_is_blocked(bs, BLOCK_OP_TYPE_MIRROR_SOURCE, errp)) {
        return;
    }
    if (bdrv_op_is_blocked(target, BLOCK_OP_TYPE_MIRROR_TARGET, errp)) {
        return;
    }
    if (target->blk) {
        error_setg(errp, "Cannot mirror to an attached block device");
        return;
    }

    if (!bs->backing && sync == MIRROR_SYNC_MODE_TOP) {
        sync = MIRROR_SYNC_MODE_FULL;
    }

    /* pass the node name to replace to mirror start since it's loose coupling
     * and will allow to check whether the node still exist at mirror completion
     */
    mirror_start(bs, target,                                                       /* XXX */
                 has_replaces ? replaces : NULL,
                 speed, granularity, buf_size, sync,
                 on_source_error, on_target_error, unmap,
                 block_job_cb, bs, errp);
}
```

mirror_start()を呼ぶ。

- block/mirror.c [qemu]

```c
void mirror_start(BlockDriverState *bs, BlockDriverState *target,
                  const char *replaces,
                  int64_t speed, uint32_t granularity, int64_t buf_size,
                  MirrorSyncMode mode, BlockdevOnError on_source_error,
                  BlockdevOnError on_target_error,
                  bool unmap,
                  BlockCompletionFunc *cb,
                  void *opaque, Error **errp)
{
    bool is_none_mode;
    BlockDriverState *base;

    if (mode == MIRROR_SYNC_MODE_INCREMENTAL) {
        error_setg(errp, "Sync mode 'incremental' not supported");
        return;
    }
    is_none_mode = mode == MIRROR_SYNC_MODE_NONE;
    base = mode == MIRROR_SYNC_MODE_TOP ? backing_bs(bs) : NULL;
    mirror_start_job(bs, target, replaces,                                      /* XXX */
                     speed, granularity, buf_size,
                     on_source_error, on_target_error, unmap, cb, opaque, errp,
                     &mirror_job_driver, is_none_mode, base);
}
```

さらにmirror\_start\_job()を呼ぶ。

```c
static void mirror_start_job(BlockDriverState *bs, BlockDriverState *target,
                             const char *replaces,
                             int64_t speed, uint32_t granularity,
                             int64_t buf_size,
                             BlockdevOnError on_source_error,
                             BlockdevOnError on_target_error,
                             bool unmap,
                             BlockCompletionFunc *cb,
                             void *opaque, Error **errp,
                             const BlockJobDriver *driver,
                             bool is_none_mode, BlockDriverState *base)
{
    MirrorBlockJob *s;
    BlockDriverState *replaced_bs;

    if (granularity == 0) {
        granularity = bdrv_get_default_bitmap_granularity(target);
    }

    assert ((granularity & (granularity - 1)) == 0);

    if ((on_source_error == BLOCKDEV_ON_ERROR_STOP ||
         on_source_error == BLOCKDEV_ON_ERROR_ENOSPC) &&
        (!bs->blk || !blk_iostatus_is_enabled(bs->blk))) {
        error_setg(errp, QERR_INVALID_PARAMETER, "on-source-error");
        return;
    }

    if (buf_size < 0) {
        error_setg(errp, "Invalid parameter 'buf-size'");
        return;
    }

    if (buf_size == 0) {
        buf_size = DEFAULT_MIRROR_BUF_SIZE;
    }

    /* We can't support this case as long as the block layer can't handle
     * multiple BlockBackends per BlockDriverState. */
    if (replaces) {
        replaced_bs = bdrv_lookup_bs(replaces, replaces, errp);
        if (replaced_bs == NULL) {
            return;
        }
    } else {
        replaced_bs = bs;
    }
    if (replaced_bs->blk && target->blk) {
        error_setg(errp, "Can't create node with two BlockBackends");
        return;
    }

    s = block_job_create(driver, bs, speed, cb, opaque, errp);
    if (!s) {
        return;
    }

    s->replaces = g_strdup(replaces);
    s->on_source_error = on_source_error;
    s->on_target_error = on_target_error;
    s->target = target;
    s->is_none_mode = is_none_mode;
    s->base = base;
    s->granularity = granularity;
    s->buf_size = ROUND_UP(buf_size, granularity);
    s->unmap = unmap;

    s->dirty_bitmap = bdrv_create_dirty_bitmap(bs, granularity, NULL, errp);
    if (!s->dirty_bitmap) {
        g_free(s->replaces);
        block_job_unref(&s->common);
        return;
    }

    bdrv_op_block_all(s->target, s->common.blocker);

    if (s->target->blk) {
        blk_set_on_error(s->target->blk, on_target_error, on_target_error);
        blk_iostatus_enable(s->target->blk);
    }
    s->common.co = qemu_coroutine_create(mirror_run);                              /* XXX */
    trace_mirror_start(bs, s, s->common.co, opaque);
    qemu_coroutine_enter(s->common.co, s);
}
```

mirror\_run()をコルーチンとして呼び出す。実際にミラーする処理はここが本体。

- block/mirror.c [qemu]

```c
static void coroutine_fn mirror_run(void *opaque)
{
    MirrorBlockJob *s = opaque;
    MirrorExitData *data;
    BlockDriverState *bs = s->common.bs;
    int64_t sector_num, end, length;
    uint64_t last_pause_ns;
    BlockDriverInfo bdi;
    char backing_filename[2]; /* we only need 2 characters because we are only
                                 checking for a NULL string */
    int ret = 0;
    int n;
    int target_cluster_size = BDRV_SECTOR_SIZE;

    if (block_job_is_cancelled(&s->common)) {
        goto immediate_exit;
    }

    s->bdev_length = bdrv_getlength(bs);
    if (s->bdev_length < 0) {
        ret = s->bdev_length;
        goto immediate_exit;
    } else if (s->bdev_length == 0) {
        /* Report BLOCK_JOB_READY and wait for complete. */
        block_job_event_ready(&s->common);
        s->synced = true;
        while (!block_job_is_cancelled(&s->common) && !s->should_complete) {
            block_job_yield(&s->common);
        }
        s->common.cancelled = false;
        goto immediate_exit;
    }

    length = DIV_ROUND_UP(s->bdev_length, s->granularity);
    s->in_flight_bitmap = bitmap_new(length);

    /* If we have no backing file yet in the destination, we cannot let
     * the destination do COW.  Instead, we copy sectors around the
     * dirty data if needed.  We need a bitmap to do that.
     */
    bdrv_get_backing_filename(s->target, backing_filename,
                              sizeof(backing_filename));
    if (!bdrv_get_info(s->target, &bdi) && bdi.cluster_size) {
        target_cluster_size = bdi.cluster_size;
    }
    if (backing_filename[0] && !s->target->backing
        && s->granularity < target_cluster_size) {
        s->buf_size = MAX(s->buf_size, target_cluster_size);
        s->cow_bitmap = bitmap_new(length);
    }
    s->target_cluster_sectors = target_cluster_size >> BDRV_SECTOR_BITS;
    s->max_iov = MIN(s->common.bs->bl.max_iov, s->target->bl.max_iov);

    end = s->bdev_length / BDRV_SECTOR_SIZE;
    s->buf = qemu_try_blockalign(bs, s->buf_size);
    if (s->buf == NULL) {
        ret = -ENOMEM;
        goto immediate_exit;
    }

    mirror_free_init(s);

    last_pause_ns = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    if (!s->is_none_mode) {
        /* First part, loop on the sectors and initialize the dirty bitmap.  */
        BlockDriverState *base = s->base;
        bool mark_all_dirty = s->base == NULL && !bdrv_has_zero_init(s->target);

        for (sector_num = 0; sector_num < end; ) {
            /* Just to make sure we are not exceeding int limit. */
            int nb_sectors = MIN(INT_MAX >> BDRV_SECTOR_BITS,
                                 end - sector_num);
            int64_t now = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);

            if (now - last_pause_ns > SLICE_TIME) {
                last_pause_ns = now;
                block_job_sleep_ns(&s->common, QEMU_CLOCK_REALTIME, 0);
            } else {
                block_job_pause_point(&s->common);
            }

            if (block_job_is_cancelled(&s->common)) {
                goto immediate_exit;
            }

            ret = bdrv_is_allocated_above(bs, base, sector_num, nb_sectors, &n);

            if (ret < 0) {
                goto immediate_exit;
            }

            assert(n > 0);
            if (ret == 1 || mark_all_dirty) {
                bdrv_set_dirty_bitmap(s->dirty_bitmap, sector_num, n);
            }
            sector_num += n;
        }
    }

    bdrv_dirty_iter_init(s->dirty_bitmap, &s->hbi);
    for (;;) {
        uint64_t delay_ns = 0;
        int64_t cnt;
        bool should_complete;

        if (s->ret < 0) {
            ret = s->ret;
            goto immediate_exit;
        }

        block_job_pause_point(&s->common);

        cnt = bdrv_get_dirty_count(s->dirty_bitmap);
        /* s->common.offset contains the number of bytes already processed so
         * far, cnt is the number of dirty sectors remaining and
         * s->sectors_in_flight is the number of sectors currently being
         * processed; together those are the current total operation length */
        s->common.len = s->common.offset +
                        (cnt + s->sectors_in_flight) * BDRV_SECTOR_SIZE;

        /* Note that even when no rate limit is applied we need to yield
         * periodically with no pending I/O so that bdrv_drain_all() returns.
         * We do so every SLICE_TIME nanoseconds, or when there is an error,
         * or when the source is clean, whichever comes first.
         */
        if (qemu_clock_get_ns(QEMU_CLOCK_REALTIME) - last_pause_ns < SLICE_TIME &&
            s->common.iostatus == BLOCK_DEVICE_IO_STATUS_OK) {
            if (s->in_flight == MAX_IN_FLIGHT || s->buf_free_count == 0 ||
                (cnt == 0 && s->in_flight > 0)) {
                trace_mirror_yield(s, s->in_flight, s->buf_free_count, cnt);
                mirror_wait_for_io(s);
                continue;
            } else if (cnt != 0) {
                delay_ns = mirror_iteration(s);
            }
        }

        should_complete = false;
        if (s->in_flight == 0 && cnt == 0) {
            trace_mirror_before_flush(s);
            ret = bdrv_flush(s->target);
            if (ret < 0) {
                if (mirror_error_action(s, false, -ret) ==
                    BLOCK_ERROR_ACTION_REPORT) {
                    goto immediate_exit;
                }
            } else {
                /* We're out of the streaming phase.  From now on, if the job
                 * is cancelled we will actually complete all pending I/O and
                 * report completion.  This way, block-job-cancel will leave
                 * the target in a consistent state.
                 */
                if (!s->synced) {
                    block_job_event_ready(&s->common);
                    s->synced = true;
                }

                should_complete = s->should_complete ||
                    block_job_is_cancelled(&s->common);
                cnt = bdrv_get_dirty_count(s->dirty_bitmap);
            }
        }

        if (cnt == 0 && should_complete) {
            /* The dirty bitmap is not updated while operations are pending.
             * If we're about to exit, wait for pending operations before
             * calling bdrv_get_dirty_count(bs), or we may exit while the
             * source has dirty data to copy!
             *
             * Note that I/O can be submitted by the guest while
             * mirror_populate runs.
             */
            trace_mirror_before_drain(s, cnt);
            bdrv_co_drain(bs);
            cnt = bdrv_get_dirty_count(s->dirty_bitmap);
        }

        ret = 0;
        trace_mirror_before_sleep(s, cnt, s->synced, delay_ns);
        if (!s->synced) {
            block_job_sleep_ns(&s->common, QEMU_CLOCK_REALTIME, delay_ns);
            if (block_job_is_cancelled(&s->common)) {
                break;
            }
        } else if (!should_complete) {
            delay_ns = (s->in_flight == 0 && cnt == 0 ? SLICE_TIME : 0);
            block_job_sleep_ns(&s->common, QEMU_CLOCK_REALTIME, delay_ns);
        } else if (cnt == 0) {
            /* The two disks are in sync.  Exit and report successful
             * completion.
             */
            assert(QLIST_EMPTY(&bs->tracked_requests));
            s->common.cancelled = false;
            break;
        }
        last_pause_ns = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    }

immediate_exit:
    if (s->in_flight > 0) {
        /* We get here only if something went wrong.  Either the job failed,
         * or it was cancelled prematurely so that we do not guarantee that
         * the target is a copy of the source.
         */
        assert(ret < 0 || (!s->synced && block_job_is_cancelled(&s->common)));
        mirror_drain(s);
    }

    assert(s->in_flight == 0);
    qemu_vfree(s->buf);
    g_free(s->cow_bitmap);
    g_free(s->in_flight_bitmap);
    bdrv_release_dirty_bitmap(bs, s->dirty_bitmap);
    if (s->target->blk) {
        blk_iostatus_disable(s->target->blk);
    }

    data = g_malloc(sizeof(*data));
    data->ret = ret;
    /* Before we switch to target in mirror_exit, make sure data doesn't
     * change. */
    bdrv_drained_begin(s->common.bs);
    if (qemu_get_aio_context() == bdrv_get_aio_context(bs)) {
        /* FIXME: virtio host notifiers run on iohandler_ctx, therefore the
         * above bdrv_drained_end isn't enough to quiesce it. This is ugly, we
         * need a block layer API change to achieve this. */
        aio_disable_external(iohandler_get_aio_context());
    }
    block_job_defer_to_main_loop(&s->common, mirror_exit, data);
}
```
