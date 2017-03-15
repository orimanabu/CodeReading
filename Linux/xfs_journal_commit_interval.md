# XFSのジャーナルログのコミット間隔

バージョン

- RHEL7.3
- kernel 3.10.0-514.6.1.el7.x86_64

## 動機

コンソールに出るエラーメッセージは以下のとおり。

```
[  335.780177] blk_update_request: I/O error, dev vda, sector 8208323
[  335.783178] blk_update_request: I/O error, dev vda, sector 8208323
[  335.786506] XFS (vda1): metadata I/O error: block 0x7d37c3 ("xlog_iodone") error 5 numblks 64
[  335.789187] XFS (vda1): xfs_do_force_shutdown(0x2) called from line 1203 of file fs/xfs/xfs_log.c.  Return address = 0xffffffffa0179b20
[  335.792898] XFS (vda1): Log I/O Error Detected.  Shutting down filesystem
[  335.795010] XFS (vda1): Please umount the filesystem and rectify the problem(s)
[  365.848319] XFS (vda1): xfs_log_force: error -5 returned.
[  395.928291] XFS (vda1): xfs_log_force: error -5 returned.
```

XFSのジャーナルログのコミット間隔を調べる。

## 種明かし

"xfs metadata interval" で検索するといきなりヒットするけどそれはそれとして。

http://serverfault.com/questions/646106/what-is-the-default-journal-commit-interval-of-xfs

## まずはエラーメッセージから

コンソールログに親切にも

```
xfs_do_force_shutdown(0x2) called from line 1203 of file fs/xfs/xfs_log.c.
```

と書いてくれている。

- xlog\_iodone() @fs/xfs/xfs\_log.c

```c
/*
 * Log function which is called when an io completes.
 *
 * The log manager needs its own routine, in order to control what
 * happens with the buffer after the write completes.
 */
void
xlog_iodone(xfs_buf_t *bp)
{
        struct xlog_in_core     *iclog = bp->b_fspriv;
        struct xlog             *l = iclog->ic_log;
        int                     aborted = 0;

        /*
         * Race to shutdown the filesystem if we see an error or the iclog is in
         * IOABORT state. The IOABORT state is only set in DEBUG mode to inject
         * CRC errors into log recovery.
         */
        if (XFS_TEST_ERROR(bp->b_error, l->l_mp, XFS_ERRTAG_IODONE_IOERR,
                           XFS_RANDOM_IODONE_IOERR) ||
            iclog->ic_state & XLOG_STATE_IOABORT) {
                if (iclog->ic_state & XLOG_STATE_IOABORT)
                        iclog->ic_state &= ~XLOG_STATE_IOABORT;

                xfs_buf_ioerror_alert(bp, __func__);
                xfs_buf_stale(bp);
                xfs_force_shutdown(l->l_mp, SHUTDOWN_LOG_IO_ERROR);
                /*
                 * This flag will be propagated to the trans-committed
                 * callback routines to let them know that the log-commit
                 * didn't succeed.
                 */
                aborted = XFS_LI_ABORTED;
        } else if (iclog->ic_state & XLOG_STATE_IOERROR) {
                aborted = XFS_LI_ABORTED;
        }

        /* log I/O is always issued ASYNC */
        ASSERT(XFS_BUF_ISASYNC(bp));
        xlog_state_done_syncing(iclog, aborted);

        /*
         * drop the buffer lock now that we are done. Nothing references
         * the buffer after this, so an unmount waiting on this lock can now
         * tear it down safely. As such, it is unsafe to reference the buffer
         * (bp) after the unlock as we could race with it being freed.
         */
        xfs_buf_unlock(bp);
}
```

1行上のログであるところの

```
metadata I/O error: block 0x7d37c3 ("xlog_iodone") error 5 numblks 64
```

のメッセージは xfs\_force\_shutdown() の2行上の xfs\_buf\_ioerror\_alert() で出している。

- xfs\_buf\_ioerror\_alert() @fs/xfs/xfs\_buf.c

```c
void
xfs_buf_ioerror_alert(
        struct xfs_buf          *bp,
        const char              *func)
{
        xfs_alert(bp->b_target->bt_mount,
"metadata I/O error: block 0x%llx (\"%s\") error %d numblks %d",
                (__uint64_t)XFS_BUF_ADDR(bp), func, -bp->b_error, bp->b_length);
}
```

xlog\_iodone() は xlog\_alloc\_log() から呼ばれる。

- xlog\_alloc\_log() @fs/xfs/xfs\_log.c

```c
/*
 * This routine initializes some of the log structure for a given mount point.
 * Its primary purpose is to fill in enough, so recovery can occur.  However,
 * some other stuff may be filled in too.
 */
STATIC struct xlog *
xlog_alloc_log(
        struct xfs_mount        *mp,
        struct xfs_buftarg      *log_target,
        xfs_daddr_t             blk_offset,
        int                     num_bblks)
{

(snip)

        /*
         * Use a NULL block for the extra log buffer used during splits so that
         * it will trigger errors if we ever try to do IO on it without first
         * having set it up properly.
         */
        error = -ENOMEM;
        bp = xfs_buf_alloc(mp->m_logdev_targp, XFS_BUF_DADDR_NULL,
                           BTOBB(log->l_iclog_size), XBF_NO_IOACCT);

(snip)

        /* use high priority wq for log I/O completion */
        bp->b_ioend_wq = mp->m_log_workqueue;
        bp->b_iodone = xlog_iodone;
        log->l_xbuf = bp;

        spin_lock_init(&log->l_icloglock);
        init_waitqueue_head(&log->l_flush_wait);

(snip)
```

xlog\_alloc\_log() は xfs\_log\_mount() から呼ばれる。

- xfs\_log\_mount() @fs/xfs/xfs\_log.c

```c
/*
 * Mount a log filesystem
 *
 * mp           - ubiquitous xfs mount point structure
 * log_target   - buftarg of on-disk log device
 * blk_offset   - Start block # where block size is 512 bytes (BBSIZE)
 * num_bblocks  - Number of BBSIZE blocks in on-disk log
 *
 * Return error or zero.
 */
int
xfs_log_mount(
        xfs_mount_t     *mp,
        xfs_buftarg_t   *log_target,
        xfs_daddr_t     blk_offset,
        int             num_bblks)
{

(snip)

        mp->m_log = xlog_alloc_log(mp, log_target, blk_offset, num_bblks);

(snip)
```

xfs\_log\_mount() は xfs\_mountfs() から呼ばれる。

- xfs\_mountfs() @fs/xfs/xfs\_mount.c

```c
/*
 * This function does the following on an initial mount of a file system:
 *      - reads the superblock from disk and init the mount struct
 *      - if we're a 32-bit kernel, do a size check on the superblock
 *              so we don't mount terabyte filesystems
 *      - init mount struct realtime fields
 *      - allocate inode hash table for fs
 *      - init directory manager
 *      - perform recovery and init the log manager
 */
int
xfs_mountfs(
        struct xfs_mount        *mp)
{

(snip)

        /*
         * Log's mount-time initialization. The first part of recovery can place
         * some items on the AIL, to be handled when recovery is finished or
         * cancelled.
         */
        error = xfs_log_mount(mp, mp->m_logdev_targp,
                              XFS_FSB_TO_DADDR(mp, sbp->sb_logstart),
                              XFS_FSB_TO_BB(mp, sbp->sb_logblocks));

(snip)

```

ここで、ログ初期化ルーチンであるところの xlog\_alloc\_log() を再掲する。

- xlog\_alloc\_log() @fs/xfs/xfs\_log.c

```c
/*
 * This routine initializes some of the log structure for a given mount point.
 * Its primary purpose is to fill in enough, so recovery can occur.  However,
 * some other stuff may be filled in too.
 */
STATIC struct xlog *
xlog_alloc_log(
        struct xfs_mount        *mp,
        struct xfs_buftarg      *log_target,
        xfs_daddr_t             blk_offset,
        int                     num_bblks)
{
        struct xlog             *log;
        xlog_rec_header_t       *head;
        xlog_in_core_t          **iclogp;
        xlog_in_core_t          *iclog, *prev_iclog=NULL;
        xfs_buf_t               *bp;
        int                     i;
        int                     error = -ENOMEM;
        uint                    log2_size = 0;

        log = kmem_zalloc(sizeof(struct xlog), KM_MAYFAIL);
        if (!log) {
                xfs_warn(mp, "Log allocation failed: No memory!");
                goto out;
        }

        log->l_mp          = mp;
        log->l_targ        = log_target;
        log->l_logsize     = BBTOB(num_bblks);
        log->l_logBBstart  = blk_offset;
        log->l_logBBsize   = num_bblks;
        log->l_covered_state = XLOG_STATE_COVER_IDLE;
        log->l_flags       |= XLOG_ACTIVE_RECOVERY;
        INIT_DELAYED_WORK(&log->l_work, xfs_log_worker);

(snip)
```

冒頭で struct xlog 用のメモリを確保し、INIT\_DELAYED\_WORK() で xfs\_log\_worker() を登録している。

- xfs\_log\_worker() @fs/xfs/xfs\_log.c

```c
/*
 * Every sync period we need to unpin all items in the AIL and push them to
 * disk. If there is nothing dirty, then we might need to cover the log to
 * indicate that the filesystem is idle.
 */
void
xfs_log_worker(
        struct work_struct      *work)
{
        struct xlog             *log = container_of(to_delayed_work(work),
                                                struct xlog, l_work);
        struct xfs_mount        *mp = log->l_mp;

        /* dgc: errors ignored - not fatal and nowhere to report them */
        if (xfs_log_need_covered(mp)) {
                /*
                 * Dump a transaction into the log that contains no real change.
                 * This is needed to stamp the current tail LSN into the log
                 * during the covering operation.
                 *
                 * We cannot use an inode here for this - that will push dirty
                 * state back up into the VFS and then periodic inode flushing
                 * will prevent log covering from making progress. Hence we
                 * synchronously log the superblock instead to ensure the
                 * superblock is immediately unpinned and can be written back.
                 */
                xfs_sync_sb(mp, true);
        } else
                xfs_log_force(mp, 0);

        /* start pushing all the metadata that is currently dirty */
        xfs_ail_push_all(mp->m_ail);

        /* queue us up again */
        xfs_log_work_queue(mp);
}
```

コメントから定期的にsyncしているっぽい匂いがする。
最後に呼んでいる xfs\_log\_work\_queue() を見てみる。

- xfs\_log\_work\_queue() @fs/xfs/xfs\_log.c

```c
void
xfs_log_work_queue(
        struct xfs_mount        *mp)
{
        queue_delayed_work(mp->m_log_workqueue, &mp->m_log->l_work,
                                msecs_to_jiffies(xfs_syncd_centisecs * 10));
}
```

queue\_delayed\_work() の引き数の "msecs\_to\_jiffies(xfs\_syncd\_centisecs * 10)" が怪しい。

- queue\_delayed\_work() @include/linux/workqueue.h

```c
/**
 * queue_delayed_work - queue work on a workqueue after delay
 * @wq: workqueue to use
 * @dwork: delayable work to queue
 * @delay: number of jiffies to wait before queueing
 *
 * Equivalent to queue_delayed_work_on() but tries to use the local CPU.
 */
static inline bool queue_delayed_work(struct workqueue_struct *wq,
                                      struct delayed_work *dwork,
                                      unsigned long delay)
{
        return queue_delayed_work_on(WORK_CPU_UNBOUND, wq, dwork, delay);
}
```

- fs/xfs/xfs_linux.h

```c
#define xfs_syncd_centisecs     xfs_params.syncd_timer.val
```

xfs_params は sysctl のパラメータっぽい。

```c
/*
 * Tunable XFS parameters.  xfs_params is required even when CONFIG_SYSCTL=n,
 * other XFS code uses these values.  Times are measured in centisecs (i.e.
 * 100ths of a second) with the exception of eofb_timer, which is measured in
 * seconds.
 */
xfs_param_t xfs_params = {
                          /*    MIN             DFLT            MAX     */
        .sgid_inherit   = {     0,              0,              1       },
        .symlink_mode   = {     0,              0,              1       },
        .panic_mask     = {     0,              0,              255     },
        .error_level    = {     0,              3,              11      },
        .syncd_timer    = {     1*100,          30*100,         7200*100},
        .stats_clear    = {     0,              0,              1       },
        .inherit_sync   = {     0,              1,              1       },
        .inherit_nodump = {     0,              1,              1       },
        .inherit_noatim = {     0,              1,              1       },
        .xfs_buf_timer  = {     100/2,          1*100,          30*100  },
        .xfs_buf_age    = {     1*100,          15*100,         7200*100},
        .inherit_nosym  = {     0,              0,              1       },
        .rotorstep      = {     1,              1,              255     },
        .inherit_nodfrg = {     0,              1,              1       },
        .fstrm_timer    = {     1,              30*100,         3600*100},
        .eofb_timer     = {     1,              300,            3600*24},
};
```

syncd_timer のデフォルト値は 30centisecs (30秒)。
コマンドでも確認してみる。

```
[root@osp10-ctrl01 nova]# sysctl fs.xfs.xfssyncd_centisecs
fs.xfs.xfssyncd_centisecs = 3000
```

後学のために他のパラメータも表示しておく。

```
[root@osp10-ctrl01 nova]# sysctl fs.xfs
fs.xfs.age_buffer_centisecs = 1500
fs.xfs.error_level = 3
fs.xfs.filestream_centisecs = 3000
fs.xfs.inherit_noatime = 1
fs.xfs.inherit_nodefrag = 1
fs.xfs.inherit_nodump = 1
fs.xfs.inherit_nosymlinks = 0
fs.xfs.inherit_sync = 1
fs.xfs.irix_sgid_inherit = 0
fs.xfs.irix_symlink_mode = 0
fs.xfs.panic_mask = 0
fs.xfs.rotorstep = 1
fs.xfs.speculative_prealloc_lifetime = 300
fs.xfs.stats_clear = 0
fs.xfs.xfsbufd_centisecs = 100
fs.xfs.xfssyncd_centisecs = 3000
[root@osp10-ctrl01 nova]#
```

```
[root@osp10-ctrl01 nova]# xfs_info /dev/vda3
meta-data=/dev/vda3              isize=512    agcount=47, agsize=336116 blks
         =                       sectsz=512   attr=2, projid32bit=1
         =                       crc=1        finobt=0 spinodes=0
data     =                       bsize=4096   blocks=15465924, imaxpct=25
         =                       sunit=0      swidth=0 blks
naming   =version 2              bsize=4096   ascii-ci=0 ftype=1
log      =internal               bsize=4096   blocks=2560, version=2
         =                       sectsz=512   sunit=0 blks, lazy-count=1
realtime =none                   extsz=4096   blocks=0, rtextents=0
[root@osp10-ctrl01 nova]#
```

