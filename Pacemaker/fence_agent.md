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

Heartbeat形式の自作fence agentスクリプトを使おうとした際、2つの事象が確認された。

## 事象1

Heatbeat形式の自作fence agentスクリプトのファイル名を仮りに `custom_stonith` とする。

これをRHEL上で `pcs stonith create` すると、

```
Error: Agent 'custom_stonith' is not installed or does not provide valid metadata: Metadata query for stonith:stonith-helper failed: Input/output error, use --force to override
```

というエラーになる。

## 事象2

`crm_resource --show-metadata=stonith:custom_stonith` を実行すると、何も表示されない。
期待される動きとしては(例えばUbuntu上だと)、リソースのメタデータがXML形式で標準出力に表示される。

# pcsコマンドの調査

まず事象1の調査。

- 該当エラーメッセージはどういう例外が発生したときに表示されるか
- `pcs stonith create` を実行してからその例外が発生するまで

の順に呼んでいく。

## エラーメッセージ

該当エラーメッセージは、`UnableToGetAgentMetadata` エラーがraiseされたときに表示される。

- [CODE_TO_MESSAGE_BUILDER_MAP @pcs/cli/common/console_report.py](https://github.com/ClusterLabs/pcs/blob/80a4d877e94354f7e23bef0b8729cac9a2e47364/pcs/cli/common/console_report.py#L1039)

```python
    codes.UNABLE_TO_GET_AGENT_METADATA: lambda info:
        (
            "Agent '{agent}' is not installed or does not provide valid"  # XXX HERE
            " metadata: {reason}"
        ).format(**info)
    ,
```

- [unable_to_get_agent_metadata() @pcs/lib/reports.py](https://github.com/ClusterLabs/pcs/blob/80a4d877e94354f7e23bef0b8729cac9a2e47364/pcs/lib/reports.py#L1948)

```python
def unable_to_get_agent_metadata(
    agent, reason, severity=ReportItemSeverity.ERROR, forceable=None
):
    """
    There were some issues trying to get metadata of agent

    string agent agent which metadata were unable to obtain
    string reason reason of failure
    """
    return ReportItem(
        report_codes.UNABLE_TO_GET_AGENT_METADATA,  # XXX HERE
        severity,
        info={
            "agent": agent,
            "reason": reason
        },
        forceable=forceable
    )
```

- [resource_agent_error_to_report_item() @pcs/lib/resource_agent.py](https://github.com/ClusterLabs/pcs/blob/80a4d877e94354f7e23bef0b8729cac9a2e47364/pcs/lib/resource_agent.py#L979)

```python
def resource_agent_error_to_report_item(
    e, severity=ReportItemSeverity.ERROR, forceable=False
):
    """
    Transform ResourceAgentError to ReportItem
    """
    force = None
    if e.__class__ == UnableToGetAgentMetadata:
        if severity == ReportItemSeverity.ERROR and forceable:
            force = report_codes.FORCE_METADATA_ISSUE
        return reports.unable_to_get_agent_metadata( # XXX HERE
            e.agent, e.message, severity, force
        )
    if e.__class__ == InvalidResourceAgentName:
        return reports.invalid_resource_agent_name(e.agent)
    if e.__class__ == InvalidStonithAgentName:
        return reports.invalid_stonith_agent_name(e.agent)
    raise e
```

## `pcs stonith create` から該当エラーメッセージが表示されるまで

`UnableToGetAgentMetadata` 例外が発生するまでのコールパス。

最終的に、`crm_resource --show-metadata` の呼び出しに失敗している。つまり、事象1は事象2と同じであることがわかる。

- [main() @pcs/app.py](https://github.com/ClusterLabs/pcs/blob/80a4d877e94354f7e23bef0b8729cac9a2e47364/pcs/app.py#L43)

```python
def main(argv=None):

### <snip>

    command = argv.pop(0)
    if (command == "-h" or command == "help"):
        usage.main()
        return
    cmd_map = {
        "resource": resource.resource_cmd,
        "cluster": cluster.cluster_cmd,
        "stonith": stonith.stonith_cmd, # XXX HERE

### <snip>

    }
    if command not in cmd_map:
        usage.main()
        sys.exit(1)
    # root can run everything directly, also help can be displayed,
    # working on a local file also do not need to run under root
    if (os.getuid() == 0) or (argv and argv[0] == "help") or usefile:
        cmd_map[command](argv) # XXX HERE
        return

### <snip>
```

- [stonith_cmd() @pcs/stonith.py](https://github.com/ClusterLabs/pcs/blob/80a4d877e94354f7e23bef0b8729cac9a2e47364/pcs/stonith.py#L29)

```python
def stonith_cmd(argv):
    if len(argv) < 1:
        sub_cmd, argv_next = "show", []
    else:
        sub_cmd, argv_next = argv[0], argv[1:]

    lib = utils.get_library_wrapper()
    modifiers = utils.get_modifiers()

    try:
        if sub_cmd == "help":
            usage.stonith([" ".join(argv_next)] if argv_next else [])
        elif sub_cmd == "list":
            stonith_list_available(lib, argv_next, modifiers)
        elif sub_cmd == "describe":
            stonith_list_options(lib, argv_next, modifiers)
        elif sub_cmd == "create":
            stonith_create(lib, argv_next, modifiers) # XXX HERE
### <snip>
```

- [stonith_create() @pcs/stonith.py](https://github.com/ClusterLabs/pcs/blob/80a4d877e94354f7e23bef0b8729cac9a2e47364/pcs/stonith.py#L156)

```python
def stonith_create(lib, argv, modifiers):

### <snip>

    if not modifiers["group"]:
        lib.stonith.create( # XXX HERE
            stonith_id, stonith_type, parts["op"],
            parts["meta"],
            parts["options"],
            **settings
        )

### <snip>
```

- [create() @pcs/lib/commands/stonith.py](https://github.com/ClusterLabs/pcs/blob/80a4d877e94354f7e23bef0b8729cac9a2e47364/pcs/lib/commands/stonith.py#L16)

```python
from pcs.lib.resource_agent import find_valid_stonith_agent_by_name as get_agent

### <snip>

def create(
    env, stonith_id, stonith_agent_name,
    operations, meta_attributes, instance_attributes,
    allow_absent_agent=False,
    allow_invalid_operation=False,
    allow_invalid_instance_attributes=False,
    use_default_operations=True,
    ensure_disabled=False,
    wait=False,
):
    """
    Create stonith as resource in a cib.

    LibraryEnvironment env provides all for communication with externals
    string stonith_id is an identifier of stonith resource
    string stonith_agent_name contains name for the identification of agent
    list of dict operations contains attributes for each entered operation
    dict meta_attributes contains attributes for primitive/meta_attributes
    dict instance_attributes contains attributes for
        primitive/instance_attributes
    bool allow_absent_agent is a flag for allowing agent that is not installed
        in a system
    bool allow_invalid_operation is a flag for allowing to use operations that
        are not listed in a stonith agent metadata
    bool allow_invalid_instance_attributes is a flag for allowing to use
        instance attributes that are not listed in a stonith agent metadata
        or for allowing to not use the instance_attributes that are required in
        stonith agent metadata
    bool use_default_operations is a flag for stopping stopping of adding
        default cib operations (specified in a stonith agent)
    bool ensure_disabled is flag that keeps resource in target-role "Stopped"
    mixed wait is flag for controlling waiting for pacemaker iddle mechanism
    """
    stonith_agent = get_agent( # XXX HERE
        env.report_processor,
        env.cmd_runner(),
        stonith_agent_name,
        allow_absent_agent,
    )

### <snip>
```

- [find_valid_stonith_agent_by_name() @pcs/lib/resource_agent.py](https://github.com/ClusterLabs/pcs/blob/80a4d877e94354f7e23bef0b8729cac9a2e47364/pcs/lib/resource_agent.py#L311)

```python
def find_valid_stonith_agent_by_name(
    report_processor, runner, name,
    allowed_absent=False, absent_agent_supported=True
):
    return _find_valid_agent_by_name( # XXX HERE
        report_processor,
        runner,
        name,
        StonithAgent,
        AbsentStonithAgent if allowed_absent else None,
        absent_agent_supported=absent_agent_supported,
    )
```

- [_find_valid_agent_by_name() @pcs/lib/resource_agent.py](https://github.com/ClusterLabs/pcs/blob/80a4d877e94354f7e23bef0b8729cac9a2e47364/pcs/lib/resource_agent.py#L324)

```python
def _find_valid_agent_by_name(
    report_processor, runner, name, PresentAgentClass, AbsentAgentClass,
    absent_agent_supported=True
):
    try:
        return PresentAgentClass(runner, name).validate_metadata() # XXX HERE
    except (InvalidResourceAgentName, InvalidStonithAgentName) as e:
        raise LibraryError(resource_agent_error_to_report_item(e))
    except UnableToGetAgentMetadata as e:
        if not absent_agent_supported:
            raise LibraryError(resource_agent_error_to_report_item(e))

        if not AbsentAgentClass:
            raise LibraryError(resource_agent_error_to_report_item(
                    e,
                    forceable=True
            ))

        report_processor.process(resource_agent_error_to_report_item(
            e,
            severity=ReportItemSeverity.WARNING,
        ))

        return AbsentAgentClass(runner, name)
```

- [CrmAgent.validate_metadata() @pcs/lib/resource_agent.py](https://github.com/ClusterLabs/pcs/blob/80a4d877e94354f7e23bef0b8729cac9a2e47364/pcs/lib/resource_agent.py#L725)

```python
class CrmAgent(Agent):
    #pylint:disable=abstract-method

### <snip>

    def validate_metadata(self):
        """
        Validate metadata by attepmt to retrieve it.
        """
        self._get_metadata() # XXX HERE
        return self
```

- [Agent._get_metadata() @pcs/lib/resource_agent.py](https://github.com/ClusterLabs/pcs/blob/80a4d877e94354f7e23bef0b8729cac9a2e47364/pcs/lib/resource_agent.py#L601)

```python
class Agent(object):
    """
    Base class for providing convinient access to an agent's metadata
    """

### <snip>

    def _get_metadata(self):
        """
        Return metadata DOM
        Raise UnableToGetAgentMetadata if agent doesn't exist or unable to get
            or parse its metadata
        """
        if self._metadata is None:
            self._metadata = self._parse_metadata(self._load_metadata()) # XXX HERE
        return self._metadata
```

- [CrmAgent._load_metadata() @pcs/lib/resource_agent.py](https://github.com/ClusterLabs/pcs/blob/80a4d877e94354f7e23bef0b8729cac9a2e47364/pcs/lib/resource_agent.py#L732)

```python
class CrmAgent(Agent):
    #pylint:disable=abstract-method

### <snip>

    def _load_metadata(self):
        env_path = ":".join([
            # otherwise pacemaker cannot run RHEL fence agents to get their
            # metadata
            settings.fence_agent_binaries,
            # otherwise heartbeat and cluster-glue agents don't work
            "/bin/",
            # otherwise heartbeat and cluster-glue agents don't work
            "/usr/bin/",
        ])
        stdout, stderr, retval = self._runner.run(
            [
                settings.crm_resource_binary, # XXX HERE
                "--show-metadata",
                self._get_full_name(),
            ],
            env_extend={
                "PATH": env_path,
            }
        )
        if retval != 0:
            raise UnableToGetAgentMetadata(self.get_name(), stderr.strip())
        return stdout.strip()
```

# crm_resourceコマンドの調査

事象2の調査。

`crm_resource --show-metadata` を実行すると、`lrmd_conn->cmds->get_metadata()` が呼び出される。

- [main() @tools/crm_resource.c](https://github.com/ClusterLabs/pacemaker/blob/1c4d8526de57cdcb0934a02e091bb8292130f9ce/tools/crm_resource.c#L547-L549)

```c
int
main(int argc, char **argv)
{

// <snip>

                } else if (safe_str_eq("show-metadata", longname)) {

// <snip>

                    if (rc == pcmk_ok) {
                        rc = lrmd_conn->cmds->get_metadata(lrmd_conn, standard, // XXX HERE
                                                           provider, type,
                                                           &metadata, 0);

// <snip>
```

stonith用の場合、`cmds->get_metadata()` は

- lrmd_api_get_metadata()
- lrmd_api_get_metadata_params()
- stonith_get_metadata()

の順で関数をたどる。

- [lrmd_api_new() @lib/lrmd/lrmd_client.c](https://github.com/ClusterLabs/pacemaker/blob/1c4d8526de57cdcb0934a02e091bb8292130f9ce/lib/lrmd/lrmd_client.c#L1873)

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

- [lrmd_api_get_metadata() @lib/lrmd/lrmd_client.c](https://github.com/ClusterLabs/pacemaker/blob/1c4d8526de57cdcb0934a02e091bb8292130f9ce/lib/lrmd/lrmd_client.c#L1618)

```c
static int
lrmd_api_get_metadata(lrmd_t *lrmd, const char *standard, const char *provider,
                      const char *type, char **output,
                      enum lrmd_call_options options)
{
    return lrmd->cmds->get_metadata_params(lrmd, standard, provider, type, // XXX HERE
                                           output, options, NULL);
}
```

- [lrmd_api_get_metadata_params() @lib/lrmd/lrmd_client.c](https://github.com/ClusterLabs/pacemaker/blob/1c4d8526de57cdcb0934a02e091bb8292130f9ce/lib/lrmd/lrmd_client.c#L1627)

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
        return stonith_get_metadata(provider, type, output); // XXX HERE
    }

<snip>
```

- [stonith_get_metadata() @lib/lrmd/lrmd_client.c](https://github.com/ClusterLabs/pacemaker/blob/1c4d8526de57cdcb0934a02e091bb8292130f9ce/lib/lrmd/lrmd_client.c#L1602)

```c
static int
stonith_get_metadata(const char *provider, const char *type, char **output)
{
    int rc = pcmk_ok;
    stonith_t *stonith_api = stonith_api_new();

    if(stonith_api) {
        stonith_api->cmds->metadata(stonith_api, st_opt_sync_call, type, provider, output, 0); // XXX HERE
        stonith_api->cmds->free(stonith_api);
    }
    if (*output == NULL) {
        rc = -EIO;
    }
    return rc;
}
```

`stonith_api->cmds->metadata()` は `stonith_api_device_metadata() @lib/fencing/st_client.c` を呼び出す。

- [stonith_api_new() @lib/fencing/st_client.c](https://github.com/ClusterLabs/pacemaker/blob/1c4d8526de57cdcb0934a02e091bb8292130f9ce/lib/fencing/st_client.c#L2126)

```c
stonith_t *
stonith_api_new(void)
{

<snip>

    new_stonith->cmds->metadata     = stonith_api_device_metadata; // XXX HERE
```

- [stonith_api_device_metadata() @lib/fencing/st_client.c](https://github.com/ClusterLabs/pacemaker/blob/1c4d8526de57cdcb0934a02e091bb8292130f9ce/lib/fencing/st_client.c#L1005-L1034)

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
            return stonith__rhcs_metadata(agent, timeout, output); // XXX HERE

#if HAVE_STONITH_STONITH_H
        case st_namespace_lha:
            return stonith__lha_metadata(agent, timeout, output); // XXX HERE
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

## `stonith__lha_metadata()`

まずLinux-HA形式のfence agent呼び出し部分を見る。

- [stonith__lha_metadata() @lib/fencing/st_lha.c](https://github.com/ClusterLabs/pacemaker/blob/1c4d8526de57cdcb0934a02e091bb8292130f9ce/lib/fencing/st_lha.c#L152)

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
        st_info_fn = find_library_function(&lha_agents_lib, LHA_STONITH_LIBRARY, // XXX HERE
                                           "stonith_get_info", FALSE);
    }

<snip>

```

`find_library_function()` はdlopen(3)してライブラリを読み込む系。

- [find_library_function() @lib/common/utils.c](https://github.com/ClusterLabs/pacemaker/blob/1c4d8526de57cdcb0934a02e091bb8292130f9ce/lib/common/utils.c#L1244)

```c
void *
find_library_function(void **handle, const char *lib, const char *fn, gboolean fatal)
{
    char *error;
    void *a_function;

    if (*handle == NULL) {
        *handle = dlopen(lib, RTLD_LAZY); // XXX HERE
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

`stonith_get_info()` の実装は [cluster-glue](https://github.com/ClusterLabs/cluster-glue) プロジェクトにあった。

- [stonith_get_info() @lib/stonith/stonith.c](https://github.com/ClusterLabs/cluster-glue/blob/be86a9f22546e7d765b71ec0faebdabcc3a7c988/lib/stonith/stonith.c#L321)

```c
const char*
stonith_get_info(Stonith* s, int infotype)
{
        StonithPlugin*  sp = (StonithPlugin*)s;

        if (sp && sp->s_ops) {
                return sp->s_ops->get_info(sp, infotype); // XXX HERE
        }
        return NULL;

}
```

`s_ops->getinf0()` の呼び出しは、Heatbeat用シェルスクリプトな形式なので、きっとこれ。

- [struct stonith_ops externalOps @lib/plugins/stonith/external.c](https://github.com/ClusterLabs/cluster-glue/blob/be86a9f22546e7d765b71ec0faebdabcc3a7c988/lib/plugins/stonith/external.c#L57)

```c
static struct stonith_ops externalOps ={
        external_new,                   /* Create new STONITH object      */
        external_destroy,               /* Destroy STONITH object         */
        external_getinfo,               /* Return STONITH info string     */ // XXX HERE
        external_get_confignames,       /* Return STONITH info string     */
        external_set_config,            /* Get configuration from NVpairs */
        external_status,                /* Return STONITH device status   */
        external_reset_req,             /* Request a reset                */
        external_hostlist,              /* Return list of supported hosts */
};
```

- [external_getinfo() @lib/plugins/stonith/external.c](https://github.com/ClusterLabs/cluster-glue/blob/be86a9f22546e7d765b71ec0faebdabcc3a7c988/lib/plugins/stonith/external.c#L553)

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
                        op = "getinfo-xml"; // XXX HERE
                        break;

                default:
                        return NULL;
        }

        rc = external_run_cmd(sd, op, &output);

<snip>
```

ここで `getinfo-xml` サブコマンドを呼んでいる。

- [external_run_cmd() @lib/plugins/stonith/external.c](https://github.com/ClusterLabs/cluster-glue/blob/be86a9f22546e7d765b71ec0faebdabcc3a7c988/lib/plugins/stonith/external.c#L703)

最終的に、popen(3)でforkする。

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

        file = popen(cmd, "r"); // XXX HERE

<snip>
```

## `stonith__rhcs_metadata()`

次にRed Hat Cluster Suite形式のfence agent呼び出し部分を見る。

- [stonith__rhcs_metadata() @lib/fencing/st_rhcs.c](https://github.com/ClusterLabs/pacemaker/blob/1c4d8526de57cdcb0934a02e091bb8292130f9ce/lib/fencing/st_rhcs.c#L77)

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
    stonith_action_t *action = stonith_action_create(agent, "metadata", NULL, 0, // XXX HERE
                                                     5, NULL, NULL);
    int rc = stonith__execute(action); // XXX HERE

<snip>
```

- [stonith_action_create() @lib/fencing/st_client.c](https://github.com/ClusterLabs/pacemaker/blob/1c4d8526de57cdcb0934a02e091bb8292130f9ce/lib/fencing/st_client.c#L716)

`stonith_action_t` の準備。`action->async` はゼロ初期化されたまま？

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

- [stonith__execute() @lib/fencing/st_client.c](https://github.com/ClusterLabs/pacemaker/blob/1c4d8526de57cdcb0934a02e091bb8292130f9ce/lib/fencing/st_client.c#L963)

`stonith_action_t` の実際の呼び出し。

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
        rc = internal_stonith_action_execute(action); // XXX HERE
    } while ((rc != pcmk_ok) && update_remaining_timeout(action));

    return rc;
}
```

- [internal_stonith_action_execute() @lib/fencing/st_client.c](https://github.com/ClusterLabs/pacemaker/blob/1c4d8526de57cdcb0934a02e091bb8292130f9ce/lib/fencing/st_client.c#L848)

`svc_action_t` を作って (syncモードで？) 呼び出す。

```c
static int
internal_stonith_action_execute(stonith_action_t * action)
{

<snip>

    buffer = crm_strdup_printf(RH_STONITH_DIR "/%s", basename(action->agent));
    svc_action = services_action_create_generic(buffer, NULL); // XXX HERE
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
        if (services_action_sync(svc_action)) { // XXX HERE
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

- [services_action_create_generic() @lib/services/services.c](https://github.com/ClusterLabs/pacemaker/blob/1c4d8526de57cdcb0934a02e091bb8292130f9ce/lib/services/services.c#L379)

`svc_action_t` の準備

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

`svc_action_t` の呼び出し

- [services_action_sync() @lib/services/services.c](https://github.com/ClusterLabs/pacemaker/blob/1c4d8526de57cdcb0934a02e091bb8292130f9ce/lib/services/services.c#L1308)

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
        rc = action_get_metadata(op); // XXX HERE
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
- [action_get_metadata() @lib/services/services.c](https://github.com/ClusterLabs/pacemaker/blob/1c4d8526de57cdcb0934a02e091bb8292130f9ce/lib/services/services.c#L1263)

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

    return action_exec_helper(op); // XXX HERE
}
```

- [action_exec_helper() @lib/services/services.c](https://github.com/ClusterLabs/pacemaker/blob/1c4d8526de57cdcb0934a02e091bb8292130f9ce/lib/services/services.c#L752)

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
        return services_os_action_execute(op); // XXX HERE
    }
    /* The 'op' has probably been freed if the execution functions return TRUE
       for the asynchronous 'op'. */
    /* Avoid using the 'op' in here. */

    return FALSE;
}
```

- [services_os_action_execute() @lib/services/services_linux.c](https://github.com/ClusterLabs/pacemaker/blob/1c4d8526de57cdcb0934a02e091bb8292130f9ce/lib/services/services_linux.c#L684)

ここでfence agentをfork(2)する。

```c
/* For an asynchronous 'op', returns FALSE if 'op' should be free'd by the caller */
/* For a synchronous 'op', returns FALSE if 'op' fails */
gboolean
services_os_action_execute(svc_action_t * op)
{

<snip>

    op->pid = fork(); // XXX HERE
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
