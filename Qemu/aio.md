# QemuのローレベルI/Oを追う

# 豆知識

[libvirt-aio-mode](https://blueprints.launchpad.net/nova/+spec/libvirt-aio-mode)のblueprintで、バックエンドに応じてlibvirtのaioモードを自動的に変えるようになっている。具体的には、

- バックエンドがCinderボリューム(FC/iSCSI/NFS)の場合はnative ([gerrit review](https://review.openstack.org/#/c/251829/))
- バックエンドがイメージな場合は、下記の場合にnative ([gerrit review](https://review.openstack.org/#/c/247396/))

  - Preallocated QCOW2
  - Preallocated RAW
  - Non-sparse LVM

(gerrit topicは[こちら](https://blueprints.launchpad.net/nova/+spec/libvirt-aio-mode))

# AIOについて

[Boost application performance using asynchronous I/O] (https://www.ibm.com/developerworks/library/l-async/)
[https://wiki.mikejung.biz/KVM_/_Xen](https://wiki.mikejung.biz/KVM_/_Xen)

```xml
<disk type='file' device='disk'>
  <driver name='qemu' type='qcow2' cache='none' io='native'/>
  <source file='/home/psuriset/xfs/vm2-native-ssd.qcow2'/>
  <target dev='vdb' bus='virtio'/>
  <address type='pci' domain='0x0000' bus='0x00' slot='0x06' function='0x0'/>
</disk>
```

```xml
<disk type='file' device='disk'>
  <driver name='qemu' type='raw' cache='directsync'/>
  <source dev='/dev/vg/lv' aio='native'/>
  <target dev='vdb' bus='virtio'/>
  <address type='pci' domain='0x0000' bus='0x00' slot='0x06' function='0x0'/>
</disk>
```

'driver' elementの 'io' attributeの説明: [libvirtのドキュメント](https://libvirt.org/formatdomain.html)から抜粋

```
The optional io attribute controls specific policies on I/O; qemu guests support "threads" and "native". Since 0.8.8
```

qemu起動、"aio='...'" がオプションとして渡る

libvirt的にはこの辺り

  - [commit 91ef4e05eac546f8ffdb18979cd21e4aee3dcbfd](https://libvirt.org/git/?p=libvirt.git;a=commitdiff;h=91ef4e05eac546f8ffdb18979cd21e4aee3dcbfd)
  - [commit f19357ce3779c47bac5638c24179a34e12fac8e4](https://libvirt.org/git/?p=libvirt.git;a=commitdiff;h=f19357ce3779c47bac5638c24179a34e12fac8e4)
  - [commit 819269c4f0aa8a3117d30cd12d01eb401bdf585a](https://libvirt.org/git/?p=libvirt.git;a=commitdiff;h=819269c4f0aa8a3117d30cd12d01eb401bdf585a)

# とっかかり

native, threadsでgrepしてみる

- blockdev.c

```c
        if ((aio = qemu_opt_get(opts, "aio")) != NULL) {
            if (!strcmp(aio, "native")) {
                *bdrv_flags |= BDRV_O_NATIVE_AIO;
            } else if (!strcmp(aio, "threads")) {
                /* this is the default */
            } else {
               error_setg(errp, "invalid aio option");
               return;
            }

```

aio=nativeならbdrv\_flagsにBDRV\_O\_NATIVE\_AIOをセットしている。

オプションの意味はこちら。

- qapi/block-core.json

```
##
# @BlockdevAioOptions
#
# Selects the AIO backend to handle I/O requests
#
# @threads:     Use qemu's thread pool
# @native:      Use native AIO backend (only Linux and Windows)
#
# Since: 1.7
##
{ 'enum': 'BlockdevAioOptions',
  'data': [ 'threads', 'native' ] }
```

# BDRV\_O\_NATIVE\_AIO

BDRV\_O\_NATIVE\_AIOでgrepすると、見るべきファイルはこの辺りっぽい。

- block/raw-posix.c
- block.c
- blockdev.c

内容的には、raw-posix.cに集中すればいい。

```c
#ifdef CONFIG_LINUX_AIO
static int raw_set_aio(void **aio_ctx, int *use_aio, int bdrv_flags)
{
    int ret = -1;
    assert(aio_ctx != NULL);
    assert(use_aio != NULL);
    /*
     * Currently Linux do AIO only for files opened with O_DIRECT
     * specified so check NOCACHE flag too
     */
    if ((bdrv_flags & (BDRV_O_NOCACHE|BDRV_O_NATIVE_AIO)) ==
                      (BDRV_O_NOCACHE|BDRV_O_NATIVE_AIO)) {

        /* if non-NULL, laio_init() has already been run */
        if (*aio_ctx == NULL) {
            *aio_ctx = laio_init();
            if (!*aio_ctx) {
                goto error;
            }
        }
        *use_aio = 1;
    } else {
        *use_aio = 0;
    }

    ret = 0;

error:
    return ret;
}
#endif
```

```c
static int raw_open_common(BlockDriverState *bs, QDict *options,
                           int bdrv_flags, int open_flags, Error **errp)
{
    BDRVRawState *s = bs->opaque;
<snip>
#ifdef CONFIG_LINUX_AIO
    if (raw_set_aio(&s->aio_ctx, &s->use_aio, bdrv_flags)) {
        qemu_close(fd);
        ret = -errno;
        error_setg_errno(errp, -ret, "Could not set AIO state");
        goto fail;
    }
    if (!s->use_aio && (bdrv_flags & BDRV_O_NATIVE_AIO)) {
        error_setg(errp, "aio=native was specified, but it requires "
                         "cache.direct=on, which was not specified.");
        ret = -EINVAL;
        goto fail;
    }
#else
    if (bdrv_flags & BDRV_O_NATIVE_AIO) {
        error_setg(errp, "aio=native was specified, but is not supported "
                         "in this build.");
        ret = -EINVAL;
        goto fail;
    }
#endif /* !defined(CONFIG_LINUX_AIO) */
<snip>
}
```

raw\_set\_aio.c()では、

  - O\_DIRECT(NOCACHEフラグ)つきであればlaio\_init()してaio_ctxを埋める
  - s->use_aio = 1 (s = bs->opaque)

をしている。

```c
typedef struct BDRVRawState {
    int fd;
    int type;
    int open_flags;
    size_t buf_align;

#ifdef CONFIG_LINUX_AIO
    int use_aio;
    void *aio_ctx;
#endif
#ifdef CONFIG_XFS
    bool is_xfs:1;
#endif
    bool has_discard:1;
    bool has_write_zeroes:1;
    bool discard_zeroes:1;
    bool has_fallocate;
    bool needs_alignment;
} BDRVRawState;

```

- linux-aio.c

```c
void *laio_init(void)
{
    struct qemu_laio_state *s;

    s = g_malloc0(sizeof(*s));
    if (event_notifier_init(&s->e, false) < 0) {
        goto out_free_state;
    }

    if (io_setup(MAX_EVENTS, &s->ctx) != 0) {
        goto out_close_efd;
    }

    ioq_init(&s->io_q);

    return s;

out_close_efd:
    event_notifier_cleanup(&s->e);
out_free_state:
    g_free(s);
    return NULL;
}
```

```c
struct qemu_laiocb {
    BlockAIOCB common;
    struct qemu_laio_state *ctx;
    struct iocb iocb;
    ssize_t ret;
    size_t nbytes;
    QEMUIOVector *qiov;
    bool is_read;
    QSIMPLEQ_ENTRY(qemu_laiocb) next;
};

typedef struct {
    int plugged;
    unsigned int n;
    bool blocked;
    QSIMPLEQ_HEAD(, qemu_laiocb) pending;
} LaioQueue;

struct qemu_laio_state {
    io_context_t ctx;
    EventNotifier e;

    /* io queue for submit at batch */
    LaioQueue io_q;

    /* I/O completion processing */
    QEMUBH *completion_bh;
    struct io_event events[MAX_EVENTS];
    int event_idx;
    int event_max;
};
```

# use_aioをトリガーに見てみる

```c
static void raw_detach_aio_context(BlockDriverState *bs)
{
#ifdef CONFIG_LINUX_AIO
    BDRVRawState *s = bs->opaque;

    if (s->use_aio) {
        laio_detach_aio_context(s->aio_ctx, bdrv_get_aio_context(bs));
    }
#endif
}

static void raw_attach_aio_context(BlockDriverState *bs,
                                   AioContext *new_context)
{
#ifdef CONFIG_LINUX_AIO
    BDRVRawState *s = bs->opaque;

    if (s->use_aio) {
        laio_attach_aio_context(s->aio_ctx, new_context);
    }
#endif
}
```

```c
static BlockAIOCB *raw_aio_submit(BlockDriverState *bs,
        int64_t sector_num, QEMUIOVector *qiov, int nb_sectors,
        BlockCompletionFunc *cb, void *opaque, int type)
{
    BDRVRawState *s = bs->opaque;

    if (fd_open(bs) < 0)
        return NULL;

    /*
     * Check if the underlying device requires requests to be aligned,
     * and if the request we are trying to submit is aligned or not.
     * If this is the case tell the low-level driver that it needs
     * to copy the buffer.
     */
    if (s->needs_alignment) {
        if (!bdrv_qiov_is_aligned(bs, qiov)) {
            type |= QEMU_AIO_MISALIGNED;
#ifdef CONFIG_LINUX_AIO
        } else if (s->use_aio) {
            return laio_submit(bs, s->aio_ctx, s->fd, sector_num, qiov,
                               nb_sectors, cb, opaque, type);
#endif
        }
    }

    return paio_submit(bs, s->fd, sector_num, qiov, nb_sectors,
                       cb, opaque, type);
}
```

```c
static void raw_aio_plug(BlockDriverState *bs)
{
#ifdef CONFIG_LINUX_AIO
    BDRVRawState *s = bs->opaque;
    if (s->use_aio) {
        laio_io_plug(bs, s->aio_ctx);
    }
#endif
}

static void raw_aio_unplug(BlockDriverState *bs)
{
#ifdef CONFIG_LINUX_AIO
    BDRVRawState *s = bs->opaque;
    if (s->use_aio) {
        laio_io_unplug(bs, s->aio_ctx, true);
    }
#endif
}

static void raw_aio_flush_io_queue(BlockDriverState *bs)
{
#ifdef CONFIG_LINUX_AIO
    BDRVRawState *s = bs->opaque;
    if (s->use_aio) {
        laio_io_unplug(bs, s->aio_ctx, false);
    }
#endif
```

```c
static void raw_close(BlockDriverState *bs)
{
    BDRVRawState *s = bs->opaque;

    raw_detach_aio_context(bs);

#ifdef CONFIG_LINUX_AIO
    if (s->use_aio) {
        laio_cleanup(s->aio_ctx);
    }
#endif
    if (s->fd >= 0) {
        qemu_close(s->fd);
        s->fd = -1;
    }
}
```


他に

- raw\_reopen\_prepare
- raw\_reopen\_commit

# raw\_aio\_submit()

- linux-aio.c

```c
BlockAIOCB *laio_submit(BlockDriverState *bs, void *aio_ctx, int fd,
        int64_t sector_num, QEMUIOVector *qiov, int nb_sectors,
        BlockCompletionFunc *cb, void *opaque, int type)
{
    struct qemu_laio_state *s = aio_ctx;
    struct qemu_laiocb *laiocb;
    struct iocb *iocbs;
    off_t offset = sector_num * 512;

    laiocb = qemu_aio_get(&laio_aiocb_info, bs, cb, opaque);
    laiocb->nbytes = nb_sectors * 512;
    laiocb->ctx = s;
    laiocb->ret = -EINPROGRESS;
    laiocb->is_read = (type == QEMU_AIO_READ);
    laiocb->qiov = qiov;

    iocbs = &laiocb->iocb;

    switch (type) {
    case QEMU_AIO_WRITE:
        io_prep_pwritev(iocbs, fd, qiov->iov, qiov->niov, offset);
	break;
    case QEMU_AIO_READ:
        io_prep_preadv(iocbs, fd, qiov->iov, qiov->niov, offset);
	break;
    /* Currently Linux kernel does not support other operations */
    default:
        fprintf(stderr, "%s: invalid AIO request type 0x%x.\n",
                        __func__, type);
        goto out_free_aiocb;
    }
    io_set_eventfd(&laiocb->iocb, event_notifier_get_fd(&s->e));

    QSIMPLEQ_INSERT_TAIL(&s->io_q.pending, laiocb, next);
    s->io_q.n++;
    if (!s->io_q.blocked &&
        (!s->io_q.plugged || s->io_q.n >= MAX_QUEUED_IO)) {
        ioq_submit(s);
    }
    return &laiocb->common;

out_free_aiocb:
    qemu_aio_unref(laiocb);
    return NULL;
}
```

- /usr/include/libaio.h

```c
static inline void io_prep_preadv(struct iocb *iocb, int fd, const struct iovec *iov, int iovcnt, long long offset)
{
        memset(iocb, 0, sizeof(*iocb));
        iocb->aio_fildes = fd;
        iocb->aio_lio_opcode = IO_CMD_PREADV;
        iocb->aio_reqprio = 0;
        iocb->u.c.buf = (void *)iov;
        iocb->u.c.nbytes = iovcnt;
        iocb->u.c.offset = offset;
}

static inline void io_prep_pwritev(struct iocb *iocb, int fd, const struct iovec *iov, int iovcnt, long long offset)
{
        memset(iocb, 0, sizeof(*iocb));
        iocb->aio_fildes = fd;
        iocb->aio_lio_opcode = IO_CMD_PWRITEV;
        iocb->aio_reqprio = 0;
        iocb->u.c.buf = (void *)iov;
        iocb->u.c.nbytes = iovcnt;
        iocb->u.c.offset = offset;
}
```

## raw_aio_submit()で呼んでいるもの

最終的にio_submit()に至る。

- linux-aio.c

```c
static void ioq_submit(struct qemu_laio_state *s)
{
    int ret, len;
    struct qemu_laiocb *aiocb;
    struct iocb *iocbs[MAX_QUEUED_IO];
    QSIMPLEQ_HEAD(, qemu_laiocb) completed;

    do {
        len = 0;
        QSIMPLEQ_FOREACH(aiocb, &s->io_q.pending, next) {
            iocbs[len++] = &aiocb->iocb;
            if (len == MAX_QUEUED_IO) {
                break;
            }
        }

        ret = io_submit(s->ctx, len, iocbs);
        if (ret == -EAGAIN) {
            break;
        }
        if (ret < 0) {
            /* Fail the first request, retry the rest */
            aiocb = QSIMPLEQ_FIRST(&s->io_q.pending);
            QSIMPLEQ_REMOVE_HEAD(&s->io_q.pending, next);
            s->io_q.n--;
            aiocb->ret = ret;
            qemu_laio_process_completion(s, aiocb);
            continue;
        }

        s->io_q.n -= ret;
        aiocb = container_of(iocbs[ret - 1], struct qemu_laiocb, iocb);
        QSIMPLEQ_SPLIT_AFTER(&s->io_q.pending, aiocb, next, &completed);
    } while (ret == len && !QSIMPLEQ_EMPTY(&s->io_q.pending));
    s->io_q.blocked = (s->io_q.n > 0);
}
```

## raw_aio_submit()を呼んでいるもの

- raw-posix.c

```c
static BlockAIOCB *raw_aio_readv(BlockDriverState *bs,
        int64_t sector_num, QEMUIOVector *qiov, int nb_sectors,
        BlockCompletionFunc *cb, void *opaque)
{
    return raw_aio_submit(bs, sector_num, qiov, nb_sectors,
                          cb, opaque, QEMU_AIO_READ);
}

static BlockAIOCB *raw_aio_writev(BlockDriverState *bs,
        int64_t sector_num, QEMUIOVector *qiov, int nb_sectors,
        BlockCompletionFunc *cb, void *opaque)
{
    return raw_aio_submit(bs, sector_num, qiov, nb_sectors,
                          cb, opaque, QEMU_AIO_WRITE);
}
```

```c
BlockDriver bdrv_file = {
    .format_name = "file",
    .protocol_name = "file",
    .instance_size = sizeof(BDRVRawState),
    .bdrv_needs_filename = true,
    .bdrv_probe = NULL, /* no probe for protocols */
    .bdrv_parse_filename = raw_parse_filename,
    .bdrv_file_open = raw_open,
    .bdrv_reopen_prepare = raw_reopen_prepare,
    .bdrv_reopen_commit = raw_reopen_commit,
    .bdrv_reopen_abort = raw_reopen_abort,
    .bdrv_close = raw_close,
    .bdrv_create = raw_create,
    .bdrv_has_zero_init = bdrv_has_zero_init_1,
    .bdrv_co_get_block_status = raw_co_get_block_status,
    .bdrv_co_write_zeroes = raw_co_write_zeroes,

    .bdrv_aio_readv = raw_aio_readv,
    .bdrv_aio_writev = raw_aio_writev,
    .bdrv_aio_flush = raw_aio_flush,
    .bdrv_aio_discard = raw_aio_discard,
    .bdrv_refresh_limits = raw_refresh_limits,
    .bdrv_io_plug = raw_aio_plug,
    .bdrv_io_unplug = raw_aio_unplug,
    .bdrv_flush_io_queue = raw_aio_flush_io_queue,

    .bdrv_truncate = raw_truncate,
    .bdrv_getlength = raw_getlength,
    .bdrv_get_info = raw_get_info,
    .bdrv_get_allocated_file_size
                        = raw_get_allocated_file_size,

    .bdrv_detach_aio_context = raw_detach_aio_context,
    .bdrv_attach_aio_context = raw_attach_aio_context,

    .create_opts = &raw_create_opts,
};
```

```c
static BlockDriver bdrv_host_device = {
    .format_name        = "host_device",
    .protocol_name        = "host_device",
    .instance_size      = sizeof(BDRVRawState),
    .bdrv_needs_filename = true,
    .bdrv_probe_device  = hdev_probe_device,
    .bdrv_parse_filename = hdev_parse_filename,
    .bdrv_file_open     = hdev_open,
    .bdrv_close         = raw_close,
    .bdrv_reopen_prepare = raw_reopen_prepare,
    .bdrv_reopen_commit  = raw_reopen_commit,
    .bdrv_reopen_abort   = raw_reopen_abort,
    .bdrv_create         = hdev_create,
    .create_opts         = &raw_create_opts,
    .bdrv_co_write_zeroes = hdev_co_write_zeroes,

    .bdrv_aio_readv	= raw_aio_readv,
    .bdrv_aio_writev	= raw_aio_writev,
    .bdrv_aio_flush	= raw_aio_flush,
    .bdrv_aio_discard   = hdev_aio_discard,
    .bdrv_refresh_limits = raw_refresh_limits,
    .bdrv_io_plug = raw_aio_plug,
    .bdrv_io_unplug = raw_aio_unplug,
    .bdrv_flush_io_queue = raw_aio_flush_io_queue,

    .bdrv_truncate      = raw_truncate,
    .bdrv_getlength	= raw_getlength,
    .bdrv_get_info = raw_get_info,
    .bdrv_get_allocated_file_size
                        = raw_get_allocated_file_size,
    .bdrv_probe_blocksizes = hdev_probe_blocksizes,
    .bdrv_probe_geometry = hdev_probe_geometry,

    .bdrv_detach_aio_context = raw_detach_aio_context,
    .bdrv_attach_aio_context = raw_attach_aio_context,

    /* generic scsi device */
#ifdef __linux__
    .bdrv_aio_ioctl     = hdev_aio_ioctl,
#endif
};
```

```c
static BlockDriver bdrv_host_cdrom = {
    .format_name        = "host_cdrom",
    .protocol_name      = "host_cdrom",
    .instance_size      = sizeof(BDRVRawState),
    .bdrv_needs_filename = true,
    .bdrv_probe_device	= cdrom_probe_device,
    .bdrv_parse_filename = cdrom_parse_filename,
    .bdrv_file_open     = cdrom_open,
    .bdrv_close         = raw_close,
    .bdrv_reopen_prepare = raw_reopen_prepare,
    .bdrv_reopen_commit  = raw_reopen_commit,
    .bdrv_reopen_abort   = raw_reopen_abort,
    .bdrv_create         = hdev_create,
    .create_opts         = &raw_create_opts,

    .bdrv_aio_readv     = raw_aio_readv,
    .bdrv_aio_writev    = raw_aio_writev,
    .bdrv_aio_flush	= raw_aio_flush,
    .bdrv_refresh_limits = raw_refresh_limits,
    .bdrv_io_plug = raw_aio_plug,
    .bdrv_io_unplug = raw_aio_unplug,
    .bdrv_flush_io_queue = raw_aio_flush_io_queue,

    .bdrv_truncate      = raw_truncate,
    .bdrv_getlength      = raw_getlength,
    .has_variable_length = true,
    .bdrv_get_allocated_file_size
                        = raw_get_allocated_file_size,

    .bdrv_detach_aio_context = raw_detach_aio_context,
    .bdrv_attach_aio_context = raw_attach_aio_context,

    /* removable device support */
    .bdrv_is_inserted   = cdrom_is_inserted,
    .bdrv_eject         = cdrom_eject,
    .bdrv_lock_medium   = cdrom_lock_medium,

    /* generic scsi device */
    .bdrv_aio_ioctl     = hdev_aio_ioctl,
};
```

この後はBlockDriver.bdrv_{readv,writev}をトリガーに見ていくのがよさそう。
