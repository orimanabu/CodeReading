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

- hmp.c [qemu]

このファイルには、Human Monitor Interfaceが実装されている。

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

    blockdev_mirror_common(bs, target_bs,
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

- block.c [qemu]

```c
void bdrv_img_create(const char *filename, const char *fmt,
                     const char *base_filename, const char *base_fmt,
                     char *options, uint64_t img_size, int flags,
                     Error **errp, bool quiet)
{
    QemuOptsList *create_opts = NULL;
    QemuOpts *opts = NULL;
    const char *backing_fmt, *backing_file;
    int64_t size;
    BlockDriver *drv, *proto_drv;
    Error *local_err = NULL;
    int ret = 0;

    /* Find driver and parse its options */
    drv = bdrv_find_format(fmt);
    if (!drv) {
        error_setg(errp, "Unknown file format '%s'", fmt);
        return;
    }

    proto_drv = bdrv_find_protocol(filename, true, errp);
    if (!proto_drv) {
        return;
    }

    if (!drv->create_opts) {
        error_setg(errp, "Format driver '%s' does not support image creation",
                   drv->format_name);
        return;
    }

    if (!proto_drv->create_opts) {
        error_setg(errp, "Protocol driver '%s' does not support image creation",
                   proto_drv->format_name);
        return;
    }

    create_opts = qemu_opts_append(create_opts, drv->create_opts);
    create_opts = qemu_opts_append(create_opts, proto_drv->create_opts);

    /* Create parameter list with default values */
    opts = qemu_opts_create(create_opts, NULL, 0, &error_abort);
    qemu_opt_set_number(opts, BLOCK_OPT_SIZE, img_size, &error_abort);

    /* Parse -o options */
    if (options) {
        qemu_opts_do_parse(opts, options, NULL, &local_err);
        if (local_err) {
            error_report_err(local_err);
            local_err = NULL;
            error_setg(errp, "Invalid options for file format '%s'", fmt);
            goto out;
        }
    }

    if (base_filename) {
        qemu_opt_set(opts, BLOCK_OPT_BACKING_FILE, base_filename, &local_err);
        if (local_err) {
            error_setg(errp, "Backing file not supported for file format '%s'",
                       fmt);
            goto out;
        }
    }

    if (base_fmt) {
        qemu_opt_set(opts, BLOCK_OPT_BACKING_FMT, base_fmt, &local_err);
        if (local_err) {
            error_setg(errp, "Backing file format not supported for file "
                             "format '%s'", fmt);
            goto out;
        }
    }

    backing_file = qemu_opt_get(opts, BLOCK_OPT_BACKING_FILE);
    if (backing_file) {
        if (!strcmp(filename, backing_file)) {
            error_setg(errp, "Error: Trying to create an image with the "
                             "same filename as the backing file");
            goto out;
        }
    }

    backing_fmt = qemu_opt_get(opts, BLOCK_OPT_BACKING_FMT);

    // The size for the image must always be specified, with one exception:
    // If we are using a backing file, we can obtain the size from there
    size = qemu_opt_get_size(opts, BLOCK_OPT_SIZE, 0);
    if (size == -1) {
        if (backing_file) {
            BlockDriverState *bs;
            char *full_backing = g_new0(char, PATH_MAX);
            int64_t size;
            int back_flags;
            QDict *backing_options = NULL;

            bdrv_get_full_backing_filename_from_filename(filename, backing_file,
                                                         full_backing, PATH_MAX,
                                                         &local_err);
            if (local_err) {
                g_free(full_backing);
                goto out;
            }

            /* backing files always opened read-only */
            back_flags = flags;
            back_flags &= ~(BDRV_O_RDWR | BDRV_O_SNAPSHOT | BDRV_O_NO_BACKING);

            if (backing_fmt) {
                backing_options = qdict_new();
                qdict_put(backing_options, "driver",
                          qstring_from_str(backing_fmt));
            }

            bs = NULL;
            ret = bdrv_open(&bs, full_backing, NULL, backing_options,
                            back_flags, &local_err);
            g_free(full_backing);
            if (ret < 0) {
                goto out;
            }
            size = bdrv_getlength(bs);
            if (size < 0) {
                error_setg_errno(errp, -size, "Could not get size of '%s'",
                                 backing_file);
                bdrv_unref(bs);
                goto out;
            }

            qemu_opt_set_number(opts, BLOCK_OPT_SIZE, size, &error_abort);

            bdrv_unref(bs);
        } else {
            error_setg(errp, "Image creation needs a size parameter");
            goto out;
        }
    }

    if (!quiet) {
        printf("Formatting '%s', fmt=%s ", filename, fmt);
        qemu_opts_print(opts, " ");
        puts("");
    }

    ret = bdrv_create(drv, filename, opts, &local_err);

    if (ret == -EFBIG) {
        /* This is generally a better message than whatever the driver would
         * deliver (especially because of the cluster_size_hint), since that
         * is most probably not much different from "image too large". */
        const char *cluster_size_hint = "";
        if (qemu_opt_get_size(opts, BLOCK_OPT_CLUSTER_SIZE, 0)) {
            cluster_size_hint = " (try using a larger cluster size)";
        }
        error_setg(errp, "The image size is too large for file format '%s'"
                   "%s", fmt, cluster_size_hint);
        error_free(local_err);
        local_err = NULL;
    }

out:
    qemu_opts_del(opts);
    qemu_opts_free(create_opts);
    if (local_err) {
        error_propagate(errp, local_err);
    }
}
```

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
    mirror_start(bs, target,
                 has_replaces ? replaces : NULL,
                 speed, granularity, buf_size, sync,
                 on_source_error, on_target_error, unmap,
                 block_job_cb, bs, errp);
}
```

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
    mirror_start_job(bs, target, replaces,
                     speed, granularity, buf_size,
                     on_source_error, on_target_error, unmap, cb, opaque, errp,
                     &mirror_job_driver, is_none_mode, base);
}
```

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
    s->common.co = qemu_coroutine_create(mirror_run);
    trace_mirror_start(bs, s, s->common.co, opaque);
    qemu_coroutine_enter(s->common.co, s);
}
```

- blockjob.c [qemu]

```c
void *block_job_create(const BlockJobDriver *driver, BlockDriverState *bs,
                       int64_t speed, BlockCompletionFunc *cb,
                       void *opaque, Error **errp)
{
    BlockJob *job;

    if (bs->job) {
        error_setg(errp, QERR_DEVICE_IN_USE, bdrv_get_device_name(bs));
        return NULL;
    }
    bdrv_ref(bs);
    job = g_malloc0(driver->instance_size);
    error_setg(&job->blocker, "block device is in use by block job: %s",
               BlockJobType_lookup[driver->job_type]);
    bdrv_op_block_all(bs, job->blocker);
    bdrv_op_unblock(bs, BLOCK_OP_TYPE_DATAPLANE, job->blocker);

    job->driver        = driver;
    job->id            = g_strdup(bdrv_get_device_name(bs));
    job->bs            = bs;
    job->cb            = cb;
    job->opaque        = opaque;
    job->busy          = true;
    job->refcnt        = 1;
    bs->job = job;

    bdrv_add_aio_context_notifier(bs, block_job_attached_aio_context,
                                  block_job_detach_aio_context, job);

    /* Only set speed when necessary to avoid NotSupported error */
    if (speed != 0) {
        Error *local_err = NULL;

        block_job_set_speed(job, speed, &local_err);
        if (local_err) {
            block_job_unref(job);
            error_propagate(errp, local_err);
            return NULL;
        }
    }
    return job;
}
```

- block/dirty-bitmap.c [qemu]

```c
BdrvDirtyBitmap *bdrv_create_dirty_bitmap(BlockDriverState *bs,
                                          uint32_t granularity,
                                          const char *name,
                                          Error **errp)
{
    int64_t bitmap_size;
    BdrvDirtyBitmap *bitmap;
    uint32_t sector_granularity;

    assert((granularity & (granularity - 1)) == 0);

    if (name && bdrv_find_dirty_bitmap(bs, name)) {
        error_setg(errp, "Bitmap already exists: %s", name);
        return NULL;
    }
    sector_granularity = granularity >> BDRV_SECTOR_BITS;
    assert(sector_granularity);
    bitmap_size = bdrv_nb_sectors(bs);
    if (bitmap_size < 0) {
        error_setg_errno(errp, -bitmap_size, "could not get length of device");
        errno = -bitmap_size;
        return NULL;
    }
    bitmap = g_new0(BdrvDirtyBitmap, 1);
    bitmap->bitmap = hbitmap_alloc(bitmap_size, ctz32(sector_granularity));
    bitmap->size = bitmap_size;
    bitmap->name = g_strdup(name);
    bitmap->disabled = false;
    QLIST_INSERT_HEAD(&bs->dirty_bitmaps, bitmap, list);
    return bitmap;
}
```

- block.c [qemu]

```c
void bdrv_op_block_all(BlockDriverState *bs, Error *reason)
{
    int i;
    for (i = 0; i < BLOCK_OP_TYPE_MAX; i++) {
        bdrv_op_block(bs, i, reason);
    }
}
```

- block/block-backend.c

```c
void blk_iostatus_enable(BlockBackend *blk)
{
    blk->iostatus_enabled = true;
    blk->iostatus = BLOCK_DEVICE_IO_STATUS_OK;
}
```

- util/qemu-coroutine.c [qemu]

```c
Coroutine *qemu_coroutine_create(CoroutineEntry *entry)
{
    Coroutine *co = NULL;

    if (CONFIG_COROUTINE_POOL) {
        co = QSLIST_FIRST(&alloc_pool);
        if (!co) {
            if (release_pool_size > POOL_BATCH_SIZE) {
                /* Slow path; a good place to register the destructor, too.  */
                if (!coroutine_pool_cleanup_notifier.notify) {
                    coroutine_pool_cleanup_notifier.notify = coroutine_pool_cleanup;
                    qemu_thread_atexit_add(&coroutine_pool_cleanup_notifier);
                }

                /* This is not exact; there could be a little skew between
                 * release_pool_size and the actual size of release_pool.  But
                 * it is just a heuristic, it does not need to be perfect.
                 */
                alloc_pool_size = atomic_xchg(&release_pool_size, 0);
                QSLIST_MOVE_ATOMIC(&alloc_pool, &release_pool);
                co = QSLIST_FIRST(&alloc_pool);
            }
        }
        if (co) {
            QSLIST_REMOVE_HEAD(&alloc_pool, pool_next);
            alloc_pool_size--;
        }
    }

    if (!co) {
        co = qemu_coroutine_new();
    }

    co->entry = entry;
    QTAILQ_INIT(&co->co_queue_wakeup);
    return co;
}
```

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
