# qemuMonitorJSONCommandから実際にQMPコマンドを呼び出すまで

- src/qemu/qemu\_monitor.c

```c
/* Start a drive-mirror block job.  bandwidth is in bytes/sec.  */
int
qemuMonitorDriveMirror(qemuMonitorPtr mon,
                       const char *device, const char *file,
                       const char *format, unsigned long long bandwidth,
                       unsigned int granularity, unsigned long long buf_size,
                       unsigned int flags)
{
    VIR_DEBUG("device=%s, file=%s, format=%s, bandwidth=%lld, "
              "granularity=%#x, buf_size=%lld, flags=%x",
              device, file, NULLSTR(format), bandwidth, granularity,
              buf_size, flags);

    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONDriveMirror(mon, device, file, format, bandwidth, /* XXX */
                                      granularity, buf_size, flags);
}
```

さらにqemuMonitorJSONDriveMirror()を呼ぶ。

- src/qemu/qemu\_monitor\_json.c [libvirt]

```c
/* speed is in bytes/sec */
int
qemuMonitorJSONDriveMirror(qemuMonitorPtr mon,
                           const char *device, const char *file,
                           const char *format, unsigned long long speed,
                           unsigned int granularity,
                           unsigned long long buf_size,
                           unsigned int flags)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    bool shallow = (flags & VIR_DOMAIN_BLOCK_REBASE_SHALLOW) != 0;
    bool reuse = (flags & VIR_DOMAIN_BLOCK_REBASE_REUSE_EXT) != 0;

    cmd = qemuMonitorJSONMakeCommand("drive-mirror", /* XXX */
                                     "s:device", device,
                                     "s:target", file,
                                     "Y:speed", speed,
                                     "z:granularity", granularity,
                                     "P:buf-size", buf_size,
                                     "s:sync", shallow ? "top" : "full",
                                     "s:mode", reuse ? "existing" : "absolute-paths",
                                     "S:format", format,
                                     NULL);
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0) /* XXX */
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}
```

まず、qemuMonitorJSONMakeCommand()でJSON形式のコマンドを組み立てる。

- src/qemu/qemu\_monitor\_json.c [libvirt]

```c
#define qemuMonitorJSONMakeCommand(cmdname, ...) \
    qemuMonitorJSONMakeCommandRaw(false, cmdname, __VA_ARGS__)
```

```c
/* Top-level commands and nested transaction list elements share a
 * common structure for everything except the dictionary names.  */
static virJSONValuePtr ATTRIBUTE_SENTINEL
qemuMonitorJSONMakeCommandRaw(bool wrap, const char *cmdname, ...)
{
    virJSONValuePtr obj;
    virJSONValuePtr jargs = NULL;
    va_list args;

    va_start(args, cmdname);

    if (!(obj = virJSONValueNewObject()))
        goto error;

    if (virJSONValueObjectAppendString(obj, wrap ? "type" : "execute",
                                       cmdname) < 0)
        goto error;

    if (virJSONValueObjectCreateVArgs(&jargs, args) < 0)
        goto error;

    if (jargs &&
        virJSONValueObjectAppend(obj, wrap ? "data" : "arguments", jargs) < 0)
        goto error;

    va_end(args);

    return obj;

 error:
    virJSONValueFree(obj);
    virJSONValueFree(jargs);
    va_end(args);
    return NULL;
}
```

次に、qemuMonitorJSONCommand()でJSON形式のコマンドを投げる。

```c
static int
qemuMonitorJSONCommand(qemuMonitorPtr mon,
                       virJSONValuePtr cmd,
                       virJSONValuePtr *reply)
{
    return qemuMonitorJSONCommandWithFd(mon, cmd, -1, reply);
}
```

```c
static int
qemuMonitorJSONCommandWithFd(qemuMonitorPtr mon,
                             virJSONValuePtr cmd,
                             int scm_fd,
                             virJSONValuePtr *reply)
{
    int ret = -1;
    qemuMonitorMessage msg;
    char *cmdstr = NULL;
    char *id = NULL;

    *reply = NULL;

    memset(&msg, 0, sizeof(msg));

    if (virJSONValueObjectHasKey(cmd, "execute") == 1) {
        if (!(id = qemuMonitorNextCommandID(mon)))
            goto cleanup;
        if (virJSONValueObjectAppendString(cmd, "id", id) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unable to append command 'id' string"));
            goto cleanup;
        }
    }

    if (!(cmdstr = virJSONValueToString(cmd, false)))
        goto cleanup;
    if (virAsprintf(&msg.txBuffer, "%s\r\n", cmdstr) < 0)
        goto cleanup;
    msg.txLength = strlen(msg.txBuffer);
    msg.txFD = scm_fd;

    VIR_DEBUG("Send command '%s' for write with FD %d", cmdstr, scm_fd);

    ret = qemuMonitorSend(mon, &msg); /* XXX */

    VIR_DEBUG("Receive command reply ret=%d rxObject=%p",
              ret, msg.rxObject);


    if (ret == 0) {
        if (!msg.rxObject) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing monitor reply object"));
            ret = -1;
        } else {
            *reply = msg.rxObject;
        }
    }

 cleanup:
    VIR_FREE(id);
    VIR_FREE(cmdstr);
    VIR_FREE(msg.txBuffer);

    return ret;
}
```

```c
int
qemuMonitorSend(qemuMonitorPtr mon,
                qemuMonitorMessagePtr msg)
{
    int ret = -1;

    /* Check whether qemu quit unexpectedly */
    if (mon->lastError.code != VIR_ERR_OK) {
        VIR_DEBUG("Attempt to send command while error is set %s",
                  NULLSTR(mon->lastError.message));
        virSetError(&mon->lastError);
        return -1;
    }

    mon->msg = msg;
    qemuMonitorUpdateWatch(mon);

    PROBE(QEMU_MONITOR_SEND_MSG,
          "mon=%p msg=%s fd=%d",
          mon, mon->msg->txBuffer, mon->msg->txFD);

    while (!mon->msg->finished) {
        if (virCondWait(&mon->notify, &mon->parent.lock) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unable to wait on monitor condition"));
            goto cleanup;
        }
    }

    if (mon->lastError.code != VIR_ERR_OK) {
        VIR_DEBUG("Send command resulted in error %s",
                  NULLSTR(mon->lastError.message));
        virSetError(&mon->lastError);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    mon->msg = NULL;
    qemuMonitorUpdateWatch(mon);

    return ret;
}
```

