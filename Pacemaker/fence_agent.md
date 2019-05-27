# 動機

「Ubuntuで動いていた自作fence agentがRHELのPacemakerだと動かない」との問い合わせがあったので調査。

自作fence agentは、雰囲気としては [こんな](http://hg.linux-ha.org/lha-2.1/file/1d5b54f0a2e0/lib/plugins/stonith/external/ipmi) 感じの、$1にgetinfo-xmlがあるとメタデータを返す、的なシェルスクリプトだった。
以下では便宜上、この形式のfence agentを「Heatbeat形式の自作fence agentスクリプト」と呼ぶ。

結論としては、この手のagentは旧Heatbeatプロジェクトの外部コマンドをforkする形式の呼び出しで利用するfence agentであり、RHEL HA Add-onのPacemakerでは利用できない。

# 豆知識

Pacemakerは複雑な歴史をたどって今に至っている。とても乱暴にまとめると、

- 元々「Linux-HA」と「Red Hat Cluster Suite」の2つの派閥が併存していた。
- それぞれのプロジェクトは複数のコンポーネントから成るが、そのうちいくつかが統廃合されたり、そもそも主要開発者が移籍したり。
- しているうちに今のPacemakerになった。

という感じ、なのか？
[この資料](https://www.slideshare.net/ksk_ha/4linux-ha20110916-9349917)のp.19-p.21がとても参考になる。


検索するといろいろ情報が出てくるが、書かれた時代とどちらのプロジェクトの話かを念頭に置いて読む必要がある。最低限、

- Heatbeatという言葉が出てきたら、Linux-HAプロジェクト由来の話
- Andrew Beekhofは神
- Andrew Beekhofはいつの間にか (といっても大分昔ですが) SuSEからRed Hatに移籍していた

くらいを覚えておけばなんとかなる。

# 事象

Heatbeat形式の自作fence agentスクリプトのファイル名を仮りに `custom_stonith` とする。

これをRHEL上で `pcs stonith create` すると、

```
Error: Agent 'custom_stonith' is not installed or does not provide valid metadata: Metadata query for stonith:stonith-helper failed: Input/output error, use --force to override
```

というエラーになる。

また、`crm_resource --show-metadata=stonith'custom_stonith` を実行すると、何も表示されない。
期待される動きとしては(例えばUbuntu上だと)、リソースのメタデータがXML形式で標準出力に表示される。

# pcsコマンドの調査



# crm_resourceコマンドの調査

`crm_resource --show-metadata` すると、`lrmd_conn->cmds->get_metadata()` が呼び出される。

- [https://github.com/ClusterLabs/pacemaker/blob/1c4d8526de57cdcb0934a02e091bb8292130f9ce/tools/crm_resource.c#L547-L549](main() @tools/crm_resource.c)

```c
int
main(int argc, char **argv)
{

<snip>

                } else if (safe_str_eq("show-metadata", longname)) {

<snip>

                    if (rc == pcmk_ok) {
                        rc = lrmd_conn->cmds->get_metadata(lrmd_conn, standard,
                                                           provider, type,
                                                           &metadata, 0);

<snip>
```

stonith用の場合、`cmds->get_metadata()` は

- lrmd_api_get_metadata()
- lrmd_api_get_metadata_params()
- stonith_get_metadata()

の順で関数をたどる。

- [https://github.com/ClusterLabs/pacemaker/blob/1c4d8526de57cdcb0934a02e091bb8292130f9ce/lib/lrmd/lrmd_client.c#L1873](lrmd_api_new() @lib/lrmd/lrmd_client.c)

```c
lrmd_t *
lrmd_api_new(void)
{
    lrmd_t *new_lrmd = NULL;
    lrmd_private_t *pvt = NULL;

    new_lrmd = calloc(1, sizeof(lrmd_t));
    pvt = calloc(1, sizeof(lrmd_private_t));
    pvt->remote = calloc(1, sizeof(crm_remote_t));
    new_lrmd->cmds = calloc(1, sizeof(lrmd_api_operations_t));

    pvt->type = CRM_CLIENT_IPC;
    new_lrmd->private = pvt;

    new_lrmd->cmds->connect = lrmd_api_connect;
    new_lrmd->cmds->connect_async = lrmd_api_connect_async;
    new_lrmd->cmds->is_connected = lrmd_api_is_connected;
    new_lrmd->cmds->poke_connection = lrmd_api_poke_connection;
    new_lrmd->cmds->disconnect = lrmd_api_disconnect;
    new_lrmd->cmds->register_rsc = lrmd_api_register_rsc;
    new_lrmd->cmds->unregister_rsc = lrmd_api_unregister_rsc;
    new_lrmd->cmds->get_rsc_info = lrmd_api_get_rsc_info;
    new_lrmd->cmds->set_callback = lrmd_api_set_callback;
    new_lrmd->cmds->get_metadata = lrmd_api_get_metadata; // XXX HERE
    new_lrmd->cmds->exec = lrmd_api_exec;
    new_lrmd->cmds->cancel = lrmd_api_cancel;
    new_lrmd->cmds->list_agents = lrmd_api_list_agents;
    new_lrmd->cmds->list_ocf_providers = lrmd_api_list_ocf_providers;
    new_lrmd->cmds->list_standards = lrmd_api_list_standards;
    new_lrmd->cmds->exec_alert = lrmd_api_exec_alert;
    new_lrmd->cmds->get_metadata_params = lrmd_api_get_metadata_params; // XXX HERE

    return new_lrmd;
}
```

- [https://github.com/ClusterLabs/pacemaker/blob/1c4d8526de57cdcb0934a02e091bb8292130f9ce/lib/lrmd/lrmd_client.c#L1618](lrmd_api_get_metadata() @lib/lrmd/lrmd_client.c)

```c
static int
lrmd_api_get_metadata(lrmd_t *lrmd, const char *standard, const char *provider,
                      const char *type, char **output,
                      enum lrmd_call_options options)
{
    return lrmd->cmds->get_metadata_params(lrmd, standard, provider, type,
                                           output, options, NULL);
}
```

- [https://github.com/ClusterLabs/pacemaker/blob/1c4d8526de57cdcb0934a02e091bb8292130f9ce/lib/lrmd/lrmd_client.c#L1627](lrmd_api_get_metadata_params() @lib/lrmd/lrmd_client.c)

```c
static int
lrmd_api_get_metadata_params(lrmd_t *lrmd, const char *standard,
                             const char *provider, const char *type,
                             char **output, enum lrmd_call_options options,
                             lrmd_key_value_t *params)
{

<snip>

    if (safe_str_eq(standard, PCMK_RESOURCE_CLASS_STONITH)) {
        lrmd_key_value_freeall(params);
        return stonith_get_metadata(provider, type, output);
    }

<snip>
```

- [https://github.com/ClusterLabs/pacemaker/blob/1c4d8526de57cdcb0934a02e091bb8292130f9ce/lib/lrmd/lrmd_client.c#L1602](stonith_get_metadata() @lib/lrmd/lrmd_client.c)

```c
static int
stonith_get_metadata(const char *provider, const char *type, char **output)
{
    int rc = pcmk_ok;
    stonith_t *stonith_api = stonith_api_new();

    if(stonith_api) {
        stonith_api->cmds->metadata(stonith_api, st_opt_sync_call, type, provider, output, 0);
        stonith_api->cmds->free(stonith_api);
    }
    if (*output == NULL) {
        rc = -EIO;
    }
    return rc;
}
```

`stonith_api->cmds->metadata()` は stonith_api_device_metadata() @lib/fencing/st_client.c を呼び出す。

- [https://github.com/ClusterLabs/pacemaker/blob/1c4d8526de57cdcb0934a02e091bb8292130f9ce/lib/fencing/st_client.c#L2126](stonith_api_new() @lib/fencing/st_client.c)

```c
stonith_t *
stonith_api_new(void)
{

<snip>

    new_stonith->cmds->metadata     = stonith_api_device_metadata;
```

- [https://github.com/ClusterLabs/pacemaker/blob/1c4d8526de57cdcb0934a02e091bb8292130f9ce/lib/fencing/st_client.c#L1005-L1034](stonith_api_device_metadata() @lib/fencing/st_client.c)

```c
static int
stonith_api_device_metadata(stonith_t * stonith, int call_options, const char *agent,
                            const char *namespace, char **output, int timeout)
{
    /* By executing meta-data directly, we can get it from stonith_admin when
     * the cluster is not running, which is important for higher-level tools.
     */

    enum stonith_namespace ns = stonith_get_namespace(agent, namespace);

    crm_trace("Looking up metadata for %s agent %s",
              stonith_namespace2text(ns), agent);

    switch (ns) {
        case st_namespace_rhcs:
            return stonith__rhcs_metadata(agent, timeout, output);

#if HAVE_STONITH_STONITH_H
        case st_namespace_lha:
            return stonith__lha_metadata(agent, timeout, output);
#endif

        default:
            errno = EINVAL;
            crm_perror(LOG_ERR,
                       "Agent %s not found or does not support meta-data",
                       agent);
            break;
    }
    return -EINVAL;
}
```

このswitch-case文は怪しい。`rhcs` はRed Hat Cluster Suite、`lha` はLinux-HAを想起させる。しかもLinx-HAの方のコードブロックは、マクロ定義によってはifdef的にコンパイルされていない可能性がある。

- [https://github.com/ClusterLabs/pacemaker/blob/1c4d8526de57cdcb0934a02e091bb8292130f9ce/lib/fencing/st_lha.c#L152]()

```c
int
stonith__lha_metadata(const char *agent, int timeout, char **output)
{

<snip>

    if (need_init) {
        need_init = FALSE;
        st_new_fn = find_library_function(&lha_agents_lib, LHA_STONITH_LIBRARY,
                                          "stonith_new", FALSE);
        st_del_fn = find_library_function(&lha_agents_lib, LHA_STONITH_LIBRARY,
                                          "stonith_delete", FALSE);
        st_log_fn = find_library_function(&lha_agents_lib, LHA_STONITH_LIBRARY,
                                          "stonith_set_log", FALSE);
        st_info_fn = find_library_function(&lha_agents_lib, LHA_STONITH_LIBRARY,
                                           "stonith_get_info", FALSE);
    }

<snip>

```

find_library_function()はdlopen()してライブラリを読み込む系。

- [https://github.com/ClusterLabs/pacemaker/blob/1c4d8526de57cdcb0934a02e091bb8292130f9ce/lib/common/utils.c#L1244](find_library_function() @lib/common/utils.c)

```c
void *
find_library_function(void **handle, const char *lib, const char *fn, gboolean fatal)
{
    char *error;
    void *a_function;

    if (*handle == NULL) {
        *handle = dlopen(lib, RTLD_LAZY);
    }

    if (!(*handle)) {
        crm_err("%sCould not open %s: %s", fatal ? "Fatal: " : "", lib, dlerror());
        if (fatal) {
            crm_exit(DAEMON_RESPAWN_STOP);
        }
        return NULL;
    }

    a_function = dlsym(*handle, fn);
    if (a_function == NULL) {
        error = dlerror();
        crm_err("%sCould not find %s in %s: %s", fatal ? "Fatal: " : "", fn, lib, error);
        if (fatal) {
            crm_exit(DAEMON_RESPAWN_STOP);
        }
    }

    return a_function;
}
```

stonith_get_info()の実装は [https://github.com/ClusterLabs/cluster-glue](cluster-glue) プロジェクトにあった。

- [https://github.com/ClusterLabs/cluster-glue/blob/be86a9f22546e7d765b71ec0faebdabcc3a7c988/lib/stonith/stonith.c#L321](stonith_get_info() @lib/stonith/stonith.c)

```c
const char*
stonith_get_info(Stonith* s, int infotype)
{
        StonithPlugin*  sp = (StonithPlugin*)s;

        if (sp && sp->s_ops) {
                return sp->s_ops->get_info(sp, infotype);
        }
        return NULL;

}
```

s_ops->getinf0() の呼び出しは、Heatbeat用シェルスクリプトな形式なので、きっとこれ。

- [https://github.com/ClusterLabs/cluster-glue/blob/be86a9f22546e7d765b71ec0faebdabcc3a7c988/lib/plugins/stonith/external.c#L57](struct stonith_ops externalOps @lib/plugins/stonith/external.c)

```c
static struct stonith_ops externalOps ={
        external_new,                   /* Create new STONITH object      */
        external_destroy,               /* Destroy STONITH object         */
        external_getinfo,               /* Return STONITH info string     */
        external_get_confignames,       /* Return STONITH info string     */
        external_set_config,            /* Get configuration from NVpairs */
        external_status,                /* Return STONITH device status   */
        external_reset_req,             /* Request a reset                */
        external_hostlist,              /* Return list of supported hosts */
};
```

- [https://github.com/ClusterLabs/cluster-glue/blob/be86a9f22546e7d765b71ec0faebdabcc3a7c988/lib/plugins/stonith/external.c#L553](external_getinfo() @lib/plugins/stonith/external.c)

```c
/*
 * Return STONITH info string
 */
static const char *
external_getinfo(StonithPlugin * s, int reqtype)
{

<snip>

        switch (reqtype) {
                case ST_DEVICEID:
                        op = "getinfo-devid";
                        break;

                case ST_DEVICENAME:
                        op = "getinfo-devname";
                        break;

                case ST_DEVICEDESCR:
                        op = "getinfo-devdescr";
                        break;

                case ST_DEVICEURL:
                        op = "getinfo-devurl";
                        break;

                case ST_CONF_XML:
                        op = "getinfo-xml";
                        break;

                default:
                        return NULL;
        }

        rc = external_run_cmd(sd, op, &output);

<snip>
```

- [https://github.com/ClusterLabs/cluster-glue/blob/be86a9f22546e7d765b71ec0faebdabcc3a7c988/lib/plugins/stonith/external.c#L703](external_run_cmd() @lib/plugins/stonith/external.c)

```c
/* Run the command with op as command line argument(s) and return the exit
 * status + the output */
static int
external_run_cmd(struct pluginDevice *sd, const char *op, char **output)
{

<snip>

        strcat(cmd, " ");
        strcat(cmd, op);

<snip>

        file = popen(cmd, "r");

<snip>
```

xxx

- [https://github.com/ClusterLabs/pacemaker/blob/1c4d8526de57cdcb0934a02e091bb8292130f9ce/lib/fencing/st_rhcs.c#L77](stonith__rhcs_metadata() @lib/fencing/st_rhcs.c)

```c
/*!
 * \brief Execute RHCS-compatible agent's meta-data action
 *
 * \param[in]  agent    Agent to execute
 * \param[in]  timeout  Action timeout
 * \param[out] output   Where to store action output (or NULL to ignore)
 *
 * \todo timeout is currently ignored; shouldn't we use it?
 */
int
stonith__rhcs_metadata(const char *agent, int timeout, char **output)
{
    char *buffer = NULL;
    xmlNode *xml = NULL;
    xmlNode *actions = NULL;
    xmlXPathObject *xpathObj = NULL;
    stonith_action_t *action = stonith_action_create(agent, "metadata", NULL, 0,
                                                     5, NULL, NULL);
    int rc = stonith__execute(action);

<snip>
```

- [https://github.com/ClusterLabs/pacemaker/blob/1c4d8526de57cdcb0934a02e091bb8292130f9ce/lib/fencing/st_client.c#L716](stonith_action_create() @lib/fencing/st_client.c)

```c
#define FAILURE_MAX_RETRIES 2
stonith_action_t *
stonith_action_create(const char *agent,
                      const char *_action,
                      const char *victim,
                      uint32_t victim_nodeid,
                      int timeout, GHashTable * device_args, GHashTable * port_map)
{
    stonith_action_t *action;

    action = calloc(1, sizeof(stonith_action_t));
    action->args = make_args(agent, _action, victim, victim_nodeid, device_args, port_map);
    crm_debug("Preparing '%s' action for %s using agent %s",
              _action, (victim? victim : "no target"), agent);
    action->agent = strdup(agent);
    action->action = strdup(_action);
    if (victim) {
        action->victim = strdup(victim);
    }
    action->timeout = action->remaining_timeout = timeout;
    action->max_retries = FAILURE_MAX_RETRIES;

    if (device_args) {
        char buffer[512];
        const char *value = NULL;

        snprintf(buffer, sizeof(buffer), "pcmk_%s_retries", _action);
        value = g_hash_table_lookup(device_args, buffer);

        if (value) {
            action->max_retries = atoi(value);
        }
    }

    return action;
}
```

- [https://github.com/ClusterLabs/pacemaker/blob/1c4d8526de57cdcb0934a02e091bb8292130f9ce/lib/fencing/st_client.c#L963](stonith__execute() @lib/fencing/st_client.c)

```c
/*!
 * \internal
 * \brief Execute a stonith action
 *
 * \param[in,out] action  Action to execute
 *
 * \return pcmk_ok on success, -errno otherwise
 */
int
stonith__execute(stonith_action_t *action)
{
    int rc = pcmk_ok;

    CRM_CHECK(action != NULL, return -EINVAL);

    // Keep trying until success, max retries, or timeout
    do {
        rc = internal_stonith_action_execute(action);
    } while ((rc != pcmk_ok) && update_remaining_timeout(action));

    return rc;
}
```

- [https://github.com/ClusterLabs/pacemaker/blob/1c4d8526de57cdcb0934a02e091bb8292130f9ce/lib/fencing/st_client.c#L848](internal_stonith_action_execute() @lib/fencing/st_client.c)

```c
static int
internal_stonith_action_execute(stonith_action_t * action)
{

<snip>

    buffer = crm_strdup_printf(RH_STONITH_DIR "/%s", basename(action->agent));
    svc_action = services_action_create_generic(buffer, NULL);
    free(buffer);

<snip>

    if (action->async) {
        /* async */
        if(services_action_async_fork_notify(svc_action,
            &stonith_action_async_done,
            &stonith_action_async_forked) == FALSE) {
            services_action_free(svc_action);
            svc_action = NULL;
        } else {
            rc = 0;
        }

    } else {
        /* sync */
        if (services_action_sync(svc_action)) {
            rc = 0;
            action->rc = svc_action_to_errno(svc_action);
            action->output = svc_action->stdout_data;
            svc_action->stdout_data = NULL;
            action->error = svc_action->stderr_data;
            svc_action->stderr_data = NULL;
        } else {
            action->rc = -ECONNABORTED;
            rc = action->rc;
        }

        svc_action->params = NULL;
        services_action_free(svc_action);
    }

  fail:
    return rc;
}
```

- [https://github.com/ClusterLabs/pacemaker/blob/1c4d8526de57cdcb0934a02e091bb8292130f9ce/lib/services/services.c#L379](services_action_create_generic() @lib/services/services.c)

```c
svc_action_t *
services_action_create_generic(const char *exec, const char *args[])
{
    svc_action_t *op;
    unsigned int cur_arg;

    op = calloc(1, sizeof(*op));
    op->opaque = calloc(1, sizeof(svc_action_private_t));

    op->opaque->exec = strdup(exec);
    op->opaque->args[0] = strdup(exec);

    for (cur_arg = 1; args && args[cur_arg - 1]; cur_arg++) {
        op->opaque->args[cur_arg] = strdup(args[cur_arg - 1]);

        if (cur_arg == DIMOF(op->opaque->args) - 1) {
            crm_err("svc_action_t args list not long enough for '%s' execution request.", exec);
            break;
        }
    }

    return op;
}
```
- [https://github.com/ClusterLabs/pacemaker/blob/1c4d8526de57cdcb0934a02e091bb8292130f9ce/lib/services/services.c#L1308](services_action_sync() @lib/services/services.c)

```c
gboolean
services_action_sync(svc_action_t * op)
{
    gboolean rc = TRUE;

    if (op == NULL) {
        crm_trace("No operation to execute");
        return FALSE;
    }

    op->synchronous = true;

    if (safe_str_eq(op->action, "meta-data")) {
        /* Synchronous meta-data operations are handled specially. Since most
         * resource classes don't provide any meta-data, it has to be
         * synthesized from available information about the agent.
         *
         * services_action_async() doesn't treat meta-data actions specially, so
         * it will result in an error for classes that don't support the action.
         */
        rc = action_get_metadata(op);
    } else {
        rc = action_exec_helper(op);
    }
    crm_trace(" > %s_%s_%d: %s = %d",
              op->rsc, op->action, op->interval, op->opaque->exec, op->rc);
    if (op->stdout_data) {
        crm_trace(" >  stdout: %s", op->stdout_data);
    }
    if (op->stderr_data) {
        crm_trace(" >  stderr: %s", op->stderr_data);
    }
    return rc;
}
```
- [https://github.com/ClusterLabs/pacemaker/blob/1c4d8526de57cdcb0934a02e091bb8292130f9ce/lib/services/services.c#L1263](action_get_metadata() @lib/services/services.c)

```c
static gboolean
action_get_metadata(svc_action_t *op)
{
    const char *class = op->standard;

    if (op->agent == NULL) {
        crm_err("meta-data requested without specifying agent");
        return FALSE;
    }

    if (class == NULL) {
        crm_err("meta-data requested for agent %s without specifying class",
                op->agent);
        return FALSE;
    }

    if (!strcmp(class, PCMK_RESOURCE_CLASS_SERVICE)) {
        class = resources_find_service_class(op->agent);
    }

    if (class == NULL) {
        crm_err("meta-data requested for %s, but could not determine class",
                op->agent);
        return FALSE;
    }

    if (safe_str_eq(class, PCMK_RESOURCE_CLASS_LSB)) {
        return (lsb_get_metadata(op->agent, &op->stdout_data) >= 0);
    }

#if SUPPORT_NAGIOS
    if (safe_str_eq(class, PCMK_RESOURCE_CLASS_NAGIOS)) {
        return (nagios_get_metadata(op->agent, &op->stdout_data) >= 0);
    }
#endif

#if SUPPORT_HEARTBEAT
    if (safe_str_eq(class, PCMK_RESOURCE_CLASS_HB)) {
        return (heartbeat_get_metadata(op->agent, &op->stdout_data) >= 0);
    }
#endif

    return action_exec_helper(op);
}
```

- [https://github.com/ClusterLabs/pacemaker/blob/1c4d8526de57cdcb0934a02e091bb8292130f9ce/lib/services/services.c#L752](action_exec_helper() @lib/services/services.c)

最終的にここでfork(2)する。

```c
inline static gboolean
action_exec_helper(svc_action_t * op)
{
    /* Whether a/synchronous must be decided (op->synchronous) beforehand. */
    if (op->standard
        && (strcasecmp(op->standard, PCMK_RESOURCE_CLASS_UPSTART) == 0)) {
#if SUPPORT_UPSTART
        return upstart_job_exec(op);
#endif
    } else if (op->standard && strcasecmp(op->standard,
                                          PCMK_RESOURCE_CLASS_SYSTEMD) == 0) {
#if SUPPORT_SYSTEMD
        return systemd_unit_exec(op);
#endif
    } else {
        return services_os_action_execute(op);
    }
    /* The 'op' has probably been freed if the execution functions return TRUE
       for the asynchronous 'op'. */
    /* Avoid using the 'op' in here. */

    return FALSE;
}
```

- [https://github.com/ClusterLabs/pacemaker/blob/1c4d8526de57cdcb0934a02e091bb8292130f9ce/lib/services/services_linux.c#L684](services_os_action_execute() @lib/services/services_linux.c)

```c
/* For an asynchronous 'op', returns FALSE if 'op' should be free'd by the caller */
/* For a synchronous 'op', returns FALSE if 'op' fails */
gboolean
services_os_action_execute(svc_action_t * op)
{

<snip>

    op->pid = fork();
    switch (op->pid) {
        case -1:
            rc = errno;

            close(stdout_fd[0]);
            close(stdout_fd[1]);
            close(stderr_fd[0]);
            close(stderr_fd[1]);
            if (stdin_fd[0] >= 0) {
                close(stdin_fd[0]);
                close(stdin_fd[1]);
            }

            crm_err("Could not execute '%s': %s (%d)", op->opaque->exec, pcmk_strerror(rc), rc);
            services_handle_exec_error(op, rc);
            if (!op->synchronous) {
                return operation_finalize(op);
            }

            sigchld_cleanup();
            return FALSE;

        case 0:                /* Child */
            close(stdout_fd[0]);
            close(stderr_fd[0]);
            if (stdin_fd[1] >= 0) {
                close(stdin_fd[1]);
            }
            if (STDOUT_FILENO != stdout_fd[1]) {
                if (dup2(stdout_fd[1], STDOUT_FILENO) != STDOUT_FILENO) {
                    crm_err("dup2() failed (stdout)");
                }
                close(stdout_fd[1]);
            }
            if (STDERR_FILENO != stderr_fd[1]) {
                if (dup2(stderr_fd[1], STDERR_FILENO) != STDERR_FILENO) {
                    crm_err("dup2() failed (stderr)");
                }
                close(stderr_fd[1]);
            }
            if ((stdin_fd[0] >= 0) &&
                (STDIN_FILENO != stdin_fd[0])) {
                if (dup2(stdin_fd[0], STDIN_FILENO) != STDIN_FILENO) {
                    crm_err("dup2() failed (stdin)");
                }
                close(stdin_fd[0]);
            }

            if (op->synchronous) {
                sigchld_cleanup();
            }

            action_launch_child(op);
            CRM_ASSERT(0);  /* action_launch_child is effectively noreturn */
    }

<snip>
```

- []()

```c

```


