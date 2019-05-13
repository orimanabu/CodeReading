# 動機

Proxy設定をした環境でコンテナをビルドすると、コンテナイメージにProxy関連の環境変数設定が埋め込まれてしまい、このコンテナイメージを別の環境に持っていくとうまく動かない。

この動きの詳細を調査するためソースコードを追いかけた記録がこの文書です。

コンテナイメージに埋め込まれるProxy設定は `/etc/origin/master/master-config.yaml` の `admissionConfig.pluginConfig.BuildDefaults.configuration.env` 等の情報。

調査対象はgithubのOpenShift Originの[release-3.11](https://github.com/openshift/origin/tree/release-3.11)ブランチの先端 (commit id: [11bbf5df95](https://github.com/openshift/origin/tree/11bbf5df956be2a16a9c303427aac2055a6aa608))。

## (注)

- `XXX HERE` というコメントは、関数コール、注目したいところ、等の目印として私が記入したものです。
- 関連Bugzilla: [Bug 1708511 - \[RFE\] admissionConfig.pluginConfig.BuildDefaults should not embed ENV value to keep portability](https://bugzilla.redhat.com/show_bug.cgi?id=1708511)


# 結論

- `/etc/origin/master/master-config.yaml` の環境変数設定は、build PodのPod Specにmergesされる ([BuildDefaults.applyBuildDefaults() @pkg/build/controller/build/defaults/defaults.go](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/build/controller/build/defaults/defaults.go#L148))

  - `admissionConfig.pluginConfig.BuildDefaults.configuration.env` のmerge処理は[ここ](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/build/controller/build/defaults/defaults.go#L150-L157)
  - `admissionConfig.pluginConfig.BuildDefaults.configuration.{gitHTTPProxy,gitHTTPSProxy,gitNoProxy}` のmerge処理は[ここ](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/build/controller/build/defaults/defaults.go#L182-L204)

- mergeされた環境変数は、build Pod起動時にInit Containerとして起動される openshift-manage-dockerfile コマンドにより、FROM命令の直後に注入される ([insertEnvAfterFrom() @pkg/build/builder/docker.go](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/build/builder/docker.go#L475-L481))

がっつりハードコードされていて、簡単には直せなさそうに見えました。

# 準備

## Controller Managerの起動

Controller ManagerはPodとして起動している。

```
[ori@ocp311-master1 ~]$ oc -n kube-system get pod
NAME                                            READY     STATUS    RESTARTS   AGE
master-api-ocp311-master1.example.com           1/1       Running   1607       198d
master-controllers-ocp311-master1.example.com   1/1       Running   18         198d
master-etcd-ocp311-master1.example.com          1/1       Running   7          198d
```

`master-controllers-ocp311-master1.example.com` というPodがそれ。

Controller Managerの中で動いているプロセスを確認する。

```
[ori@ocp311-master1 ~]$ oc -n kube-system get pod master-controllers-ocp311-master1.example.com -o yaml
apiVersion: v1
kind: Pod

<snip>

spec:
  containers:
  - args:
    - |
      #!/bin/bash
      set -euo pipefail
      if [[ -f /etc/origin/master/master.env ]]; then
        set -o allexport
        source /etc/origin/master/master.env
      fi
      exec openshift start master controllers --config=/etc/origin/master/master-config.yaml --listen=https://0.0.0.0:8444 --loglevel=${DEBUG_LOGLEVEL:-2} # XXX HERE
    command:
    - /bin/bash
    - -c
    image: registry.redhat.io/openshift3/ose-control-plane:v3.11.16

<snip>
```

`openshift start master controllers --config=/etc/origin/master/master-config.yaml ...` というコマンドラインで起動している ( `hypershift` ではない)。

## master-config.yamlの設定

`/etc/origin/master/master-config.yaml` に入るProxy関連設定例:

```yaml
admissionConfig:
  pluginConfig:
    BuildDefaults:
      configuration:
        apiVersion: v1
        env:
        - name: HTTP_PROXY
          value: http://proxy.example.com:8080
        - name: HTTPS_PROXY
          value: http://proxy.example.com:8080
        - name: NO_PROXY
          value: '*,.cluster.local,.svc,169.254.169.254,172.30.0.1,192.168.0.101,192.168.0.249,192.168.0.95,infranode1.37b4.internal,infranode2.37b4.internal,loadbalancer.37b4.internal,master1.37b4.internal,master2.37b4.internal,master3.37b4.internal,node1.37b4.internal,node2.37b4.internal,node3.37b4.internal'
        - name: http_proxy
          value: http://proxy.example.com:8080
        - name: https_proxy
          value: http://proxy.example.com:8080
        - name: no_proxy
          value: '*,.cluster.local,.svc,169.254.169.254,172.30.0.1,192.168.0.101,192.168.0.249,192.168.0.95,infranode1.37b4.internal,infranode2.37b4.internal,loadbalancer.37b4.internal,master1.37b4.internal,master2.37b4.internal,master3.37b4.internal,node1.37b4.internal,node2.37b4.internal,node3.37b4.internal'
        gitHTTPProxy: http://proxy.example.com:8080
        gitHTTPSProxy: http://proxy.example.com:8080
        gitNoProxy: '*,.cluster.local,.svc,169.254.169.254,172.30.0.1,192.168.0.101,192.168.0.249,192.168.0.95,infranode1.37b4.internal,infranode2.37b4.internal,loadbalancer.37b4.internal,master1.37b4.internal,master2.37b4.internal,master3.37b4.internal,node1.37b4.internal,node2.37b4.internal,node3.37b4.internal'
```

`admissionConfig.pluginConfig.BuildDefaults.configuration.env` にenvが入る。


# master-config.yamlの設定をロードする

hypershiftコマンドから起動する場合と、openshfitコマンドから起動する場合の2通りがあるっぽい。
今回はopenshiftコマンドから起動しているので、そちらを見ていく。

関数呼び出しの流れは下記のようになる。

```
main() @cmd/openshift/openshift.go
└CommandFor() @pkg/cmd/openshift/openshift.go
  └NewCommandOpenShift() @pkg/cmd/openshift/openshift.go
    └NewCommandStart() @pkg/cmd/server/start/start.go
      └NewCommandStartMaster() @pkg/cmd/server/start/start_master.go
        └NewCommandStartMasterControllers() @pkg/cmd/server/start/start_controllers.go
          └MasterOptions.StartMaster() @pkg/cmd/server/start/start_master.go
            └MasterOptions.RunMaster() @pkg/cmd/server/start/start_master.go
              ├ReadAndResolveMasterConfig() @pkg/cmd/server/apis/config/latest/helpers.go
              └Master.Start() @pkg/cmd/server/start/start_master.go
                └ConvertMasterConfigToOpenshiftControllerConfig() @pkg/cmd/openshift-controller-manager/conversion.go
```

下記2段階にわけて読む。
- `--config` オプションの引数取得
- master-config.yamlの読み込み

## `--config` オプションの引数取得

`NewCommandStartMasterControllers()` で `--config` オプションの引数を解析する。

<details><summary>
詳細はこちら:
</summary><div>

- [main() @cmd/openshift/openshift.go](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/cmd/openshift/openshift.go#L26)

```go
func main() {
    logs.InitLogs()
    defer logs.FlushLogs()
    defer serviceability.BehaviorOnPanic(os.Getenv("OPENSHIFT_ON_PANIC"), version.Get())()
    defer serviceability.Profile(os.Getenv("OPENSHIFT_PROFILE")).Stop()

    legacy.InstallInternalLegacyAll(legacyscheme.Scheme)

    rand.Seed(time.Now().UTC().UnixNano())
    if len(os.Getenv("GOMAXPROCS")) == 0 {
        runtime.GOMAXPROCS(runtime.NumCPU())
    }

    basename := filepath.Base(os.Args[0])
    command := openshift.CommandFor(basename) // XXX HERE
    if err := command.Execute(); err != nil {
        os.Exit(1)
    }
}
```

- [CommandFor() @pkg/cmd/openshift/openshift.go](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/cmd/openshift/openshift.go#L36:6)

```go
// CommandFor returns the appropriate command for this base name,
// or the global OpenShift command
func CommandFor(basename string) *cobra.Command {
    var cmd *cobra.Command

    // Make case-insensitive and strip executable suffix if present
    if runtime.GOOS == "windows" {
        basename = strings.ToLower(basename)
        basename = strings.TrimSuffix(basename, ".exe")
    }

    switch basename {
    default:
        cmd = NewCommandOpenShift("openshift") // XXX HERE
    }

    if cmd.UsageFunc() == nil {
        templates.ActsAsRootCommand(cmd, []string{"options"})
    }
    flagtypes.GLog(cmd.PersistentFlags())

    return cmd
}
```

- [NewCommandOpenShift() @pkg/cmd/openshift/openshift.go](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/cmd/openshift/openshift.go#L59:6)

```go
// NewCommandOpenShift creates the standard OpenShift command
func NewCommandOpenShift(name string) *cobra.Command {
    out, errout := os.Stdout, os.Stderr

    root := &cobra.Command{
        Use:   name,
        Short: "Build, deploy, and manage your cloud applications",
        Long:  fmt.Sprintf(openshiftLong, name, cmdutil.GetPlatformName(name), cmdutil.GetDistributionName(name)),
        Run:   kcmdutil.DefaultSubCommandRun(out),
    }

    root.AddCommand(start.NewCommandStart(name, out, errout, wait.NeverStop)) // XXX HERE

    root.AddCommand(newCompletionCommand("completion", name+" completion"))
    root.AddCommand(cmdversion.NewCmdVersion(name, osversion.Get(), os.Stdout))
    root.AddCommand(newCmdOptions())

    // TODO: add groups
    templates.ActsAsRootCommand(root, []string{"options"})

    return root
}
```

- [NewCommandStart() @pkg/cmd/server/start/start.go](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/cmd/server/start/start.go#L15:6)

```go
// NewCommandStart provides a CLI handler for 'start' command
func NewCommandStart(basename string, out, errout io.Writer, stopCh <-chan struct{}) *cobra.Command {

    cmds := &cobra.Command{
        Use:   "start",
        Short: "Launch OpenShift components",
        Long: templates.LongDesc(`
            Start components of OpenShift

            This command launches components of OpenShift.

            `),
        Deprecated: "This command will be replaced by the hypershift and hyperkube binaries for starting individual components.",
    }

    startMaster, _ := NewCommandStartMaster(basename, out, errout) // XXX HERE
    startNodeNetwork, _ := NewCommandStartNetwork(basename, out, errout)
    startEtcdServer, _ := openshift_etcd.NewCommandStartEtcdServer(openshift_etcd.RecommendedStartEtcdServerName, basename, out, errout)
    cmds.AddCommand(startMaster)
    cmds.AddCommand(startNodeNetwork)
    cmds.AddCommand(startEtcdServer)

    return cmds
}
```

- [NewCommandStartMaster() @pkg/cmd/server/start/start_master.go](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/cmd/server/start/start_master.go#L75:6)

```go
// NewCommandStartMaster provides a CLI handler for 'start master' command
func NewCommandStartMaster(basename string, out, errout io.Writer) (*cobra.Command, *MasterOptions) {
    options := &MasterOptions{
        ExpireDays:       crypto.DefaultCertificateLifetimeInDays,
        SignerExpireDays: crypto.DefaultCACertificateLifetimeInDays,
        Output:           out,
    }
    options.DefaultsFromName(basename)

    cmd := &cobra.Command{
        Use:   "master",
        Short: "Launch a master",
        Long:  fmt.Sprintf(masterLong, basename),
        Run: func(c *cobra.Command, args []string) {

<snip>

            origin.StartProfiler()

            if err := options.StartMaster(); err != nil {
                if kerrors.IsInvalid(err) {
                    if details := err.(*kerrors.StatusError).ErrStatus.Details; details != nil {
                        fmt.Fprintf(errout, "Invalid %s %s\n", details.Kind, details.Name)
                        for _, cause := range details.Causes {
                            fmt.Fprintf(errout, "  %s: %s\n", cause.Field, cause.Message)
                        }
                        os.Exit(255)
                    }
                }
                glog.Fatal(err)
            }
        },
    }

<snip>

    startControllers, _ := NewCommandStartMasterControllers("controllers", basename, out, errout) // XXX HERE
    startAPI, _ := NewCommandStartMasterAPI("api", basename, out, errout)
    cmd.AddCommand(startAPI)
    cmd.AddCommand(startControllers)

    return cmd, options
}
```

- [NewCommandStartMasterControllers() @pkg/cmd/server/start/start_controllers.go](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/cmd/server/start/start_controllers.go#L31:6)

```go
// NewCommandStartMasterControllers starts only the controllers
func NewCommandStartMasterControllers(name, basename string, out, errout io.Writer) (*cobra.Command, *MasterOptions) {
    options := &MasterOptions{Output: out}
    options.DefaultsFromName(basename)

    cmd := &cobra.Command{
        Use:   "controllers",
        Short: "Launch master controllers",
        Long:  fmt.Sprintf(controllersLong, basename, name),
        Run: func(c *cobra.Command, args []string) {

<snip>

            origin.StartProfiler()

            if err := options.StartMaster(); err != nil { // XXX HERE
                if kerrors.IsInvalid(err) {
                    if details := err.(*kerrors.StatusError).ErrStatus.Details; details != nil {
                        fmt.Fprintf(errout, "Invalid %s %s\n", details.Kind, details.Name)
                        for _, cause := range details.Causes {
                            fmt.Fprintf(errout, "  %s: %s\n", cause.Field, cause.Message)
                        }
                        os.Exit(255)
                    }
                }
                glog.Fatal(err)
            }
        },
    }

<snip>

    flags := cmd.Flags()
    // This command only supports reading from config and the listen argument
    flags.StringVar(&options.ConfigFile, "config", "", "Location of the master configuration file to run from. Required") // XXX HERE
    cmd.MarkFlagFilename("config", "yaml", "yml")
    flags.StringVar(&lockServiceName, "lock-service-name", "", "Name of a service in the kube-system namespace to use as a lock, overrides config.")
    BindListenArg(listenArg, flags, "")

    return cmd, options
}
```

[`MasterOptions`](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/cmd/server/start/start_master.go#L44) structの `configFile` フィールドに `--config` オプションで指定したパス (`/etc/origin/master/master-config.yaml`) が入る。
</div>
</details>

## master-config.yamlの読み込み

まず、`ReadAndResolveMasterConfig()` でmaster-config.yamlを読み込む。
次に、`ConvertMasterConfigToOpenshiftControllerConfig()` でmaster-config.yamlのBuildDefaultsを読み込む。

<details><summary>
詳細はこちら:
</summary><div>

- [MasterOptions.StartMaster() @pkg/cmd/server/start/start_master.go](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/cmd/server/start/start_master.go#L202:24)

```go
// StartMaster calls RunMaster and then waits forever
func (o MasterOptions) StartMaster() error {
    if err := o.RunMaster(); err != nil { // XXX HERE
        return err
    }

    if o.IsWriteConfigOnly() {
        return nil
    }

    // TODO: this should be encapsulated by RunMaster, but StartAllInOne has no
    // way to communicate whether RunMaster should block.
    go daemon.SdNotify(false, "READY=1")
    select {}
}
```

- [MasterOptions.RunMaster() @pkg/cmd/server/start/start_master.go](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/cmd/server/start/start_master.go#L222:24)

```go
// RunMaster takes the options and:
// 1.  Creates certs if needed
// 2.  Reads fully specified master config OR builds a fully specified master config from the args
// 3.  Writes the fully specified master config and exits if needed
// 4.  Starts the master based on the fully specified config
func (o MasterOptions) RunMaster() error {
    startUsingConfigFile := !o.IsWriteConfigOnly() && o.IsRunFromConfig()

    if !startUsingConfigFile && o.CreateCertificates {
        glog.V(2).Infof("Generating master configuration")
        if err := o.CreateCerts(); err != nil {
            return err
        }
    }

    var masterConfig *configapi.MasterConfig
    var err error
    if startUsingConfigFile {
        masterConfig, err = configapilatest.ReadAndResolveMasterConfig(o.ConfigFile) // XXX HERE
    } else {
        masterConfig, err = o.MasterArgs.BuildSerializeableMasterConfig()
    }
    if err != nil {
        return err
    }

<snip>

    m := &Master{
        config:      masterConfig,
        api:         o.MasterArgs.StartAPI,
        controllers: o.MasterArgs.StartControllers,
    }
    return m.Start() // XXX HERE
}
```

`ReadAndResolveMasterConfig()` でmaster-config.yamlを読んで [`MasterConfig`](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/cmd/server/apis/config/types.go#L305) structを返す。
この [`MasterConfig`](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/cmd/server/start/start_master.go#L44) structを使って [`Master`](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/cmd/server/start/start_master.go#L341) structを作る。

- [Master.Start() @pkg/cmd/server/start/start_master.go](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/cmd/server/start/start_master.go#L358:18)

```go
// Start launches a master. It will error if possible, but some background processes may still
// be running and the process should exit after it finishes.
func (m *Master) Start() error {

<snip>

    controllersEnabled := m.controllers && len(m.config.ControllerConfig.Controllers) > 0
    if controllersEnabled {

<snip>

        openshiftControllerConfig := openshift_controller_manager.ConvertMasterConfigToOpenshiftControllerConfig(m.config) // XXX HERE
        // if we're starting the API, then this one isn't supposed to serve
        if m.api {
            openshiftControllerConfig.ServingInfo = nil
        }

        if err := openshift_controller_manager.RunOpenShiftControllerManager(openshiftControllerConfig, privilegedLoopbackConfig); err != nil {
            return err
        }

    }

    if m.api {

<snip>

    }

    return nil
}
```

[`Master`](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/cmd/server/start/start_master.go#L341) 構造体の `config` フィールド ([`MasterConfig`](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/cmd/server/apis/config/types.go#L305) 構造体) から [`OpenshiftControllerConfig`](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/cmd/server/apis/config/types.go#L1507) 構造体を作る。

- [ConvertMasterConfigToOpenshiftControllerConfig() @pkg/cmd/openshift-controller-manager/conversion.go](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/cmd/openshift-controller-manager/conversion.go#L22:6)

```go
func ConvertMasterConfigToOpenshiftControllerConfig(input *configapi.MasterConfig) *configapi.OpenshiftControllerConfig {
    // this is the old flag binding logic
    flagOptions, err := kcmoptions.NewKubeControllerManagerOptions()
    if err != nil {
        // coder error
        panic(err)
    }
    flagOptions.GenericComponent.LeaderElection.RetryPeriod = metav1.Duration{Duration: 3 * time.Second}
    flagFunc := cm.OriginControllerManagerAddFlags(flagOptions)
    errors := cmdflags.Resolve(input.KubernetesMasterConfig.ControllerArguments, flagFunc)
    if len(errors) > 0 {
        // this can't happen since we only run this on configs we have validated
        panic(errors)
    }

    // deep copy to make sure no linger references are shared
    in := input.DeepCopy()

    registryURLs := []string{}
    if len(in.ImagePolicyConfig.ExternalRegistryHostname) > 0 {
        registryURLs = append(registryURLs, in.ImagePolicyConfig.ExternalRegistryHostname)
    }
    if len(in.ImagePolicyConfig.InternalRegistryHostname) > 0 {
        registryURLs = append(registryURLs, in.ImagePolicyConfig.InternalRegistryHostname)
    }

    buildDefaults, err := getBuildDefaults(in.AdmissionConfig.PluginConfig) // XXX HERE
    if err != nil {
        // this should happen on scrubbed input
        panic(err)
    }
    buildOverrides, err := getBuildOverrides(in.AdmissionConfig.PluginConfig)
    if err != nil {
        // this should happen on scrubbed input
        panic(err)
    }

    ret := &configapi.OpenshiftControllerConfig{
        ClientConnectionOverrides: in.MasterClients.OpenShiftLoopbackClientConnectionOverrides,
        ServingInfo:               &in.ServingInfo,
        Controllers:               in.ControllerConfig.Controllers,
        LeaderElection: configapi.LeaderElectionConfig{
            RetryPeriod:   flagOptions.GenericComponent.LeaderElection.RetryPeriod,
            RenewDeadline: flagOptions.GenericComponent.LeaderElection.RenewDeadline,
            LeaseDuration: flagOptions.GenericComponent.LeaderElection.LeaseDuration,
        },
        ResourceQuota: configapi.ResourceQuotaControllerConfig{
            ConcurrentSyncs: flagOptions.ResourceQuotaController.ConcurrentResourceQuotaSyncs,
            SyncPeriod:      flagOptions.ResourceQuotaController.ResourceQuotaSyncPeriod,
            MinResyncPeriod: flagOptions.GenericComponent.MinResyncPeriod,
        },
        ServiceServingCert: in.ControllerConfig.ServiceServingCert,
        Deployer: configapi.DeployerControllerConfig{
            ImageTemplateFormat: in.ImageConfig,
        },
        Build: configapi.BuildControllerConfig{
            ImageTemplateFormat: in.ImageConfig,

            BuildDefaults:  buildDefaults,
            BuildOverrides: buildOverrides,
        },
        ServiceAccount: configapi.ServiceAccountControllerConfig{
            ManagedNames: in.ServiceAccountConfig.ManagedNames,
        },
        DockerPullSecret: configapi.DockerPullSecretControllerConfig{
            RegistryURLs: registryURLs,
        },
        Network: configapi.NetworkControllerConfig{
            ClusterNetworks:    in.NetworkConfig.ClusterNetworks,
            NetworkPluginName:  in.NetworkConfig.NetworkPluginName,
            ServiceNetworkCIDR: in.NetworkConfig.ServiceNetworkCIDR,
            VXLANPort:          in.NetworkConfig.VXLANPort,
        },
        Ingress: configapi.IngressControllerConfig{
            IngressIPNetworkCIDR: in.NetworkConfig.IngressIPNetworkCIDR,
        },
        SecurityAllocator: *in.ProjectConfig.SecurityAllocator,
        ImageImport: configapi.ImageImportControllerConfig{
            DisableScheduledImport:                     in.ImagePolicyConfig.DisableScheduledImport,
            MaxScheduledImageImportsPerMinute:          in.ImagePolicyConfig.MaxScheduledImageImportsPerMinute,
            ScheduledImageImportMinimumIntervalSeconds: in.ImagePolicyConfig.ScheduledImageImportMinimumIntervalSeconds,
        },
    }

    return ret
}
```

最終的に、master-config.yamlの `admissionConfig.pluginConfig.BuildDefaults` は、[`OpenShiftControllerConfig`](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/cmd/server/apis/config/types.go#L1507) structの `Build.BuildDefaults` フィールドに格納される。
</div>
</details>

# build Podの起動

Dockerビルドでbuild Podが起動するところまでを見る。

```
main() @cmd/openshift/openshift.go
└CommandFor() @pkg/cmd/openshift/openshift.go
  └NewCommandOpenShift() @pkg/cmd/openshift/openshift.go
    └NewCommandStart() @pkg/cmd/server/start/start.go
      └NewCommandStartMaster() @pkg/cmd/server/start/start_master.go
        └MasterOptions.StartMaster() @pkg/cmd/server/start/start_master.go
          └MasterOptions.RunMaster() @pkg/cmd/server/start/start_master.go
            └Master.Start() @pkg/cmd/server/start/start_master.go
              └RunOpenShiftControllerManager() @pkg/cmd/openshift-controller-manager/controller_manager.go
                ├NewControllerContext() @pkg/cmd/openshift-controller-manager/controller/interfaces.go
                └startControllers() @pkg/cmd/openshift-controller-manager/controller_manager.go
                  └ControllerInitializers @pkg/cmd/openshift-controller-manager/controller/config.go
                    └RunBuildController() @pkg/cmd/openshift-controller-manager/controller/build.go
                      ├NewBuildController() @pkg/build/controller/build/build_controller.go
                      └BuildController.Run() @pkg/build/controller/build/build_controller.go
                        └BuildController.buildWorker() @pkg/build/controller/build/build_controller.go
                          └BuildController.buildWork() @pkg/build/controller/build/build_controller.go
                            └BuildController.handleBuild() @pkg/build/controller/build/build_controller.go
                              └BuildController.handleNewBuild() @pkg/build/controller/build/build_controller.go
                                └BuildController.createBuildPod() @pkg/build/controller/build/build_controller.go
                                  └BuildController.createPodSpec() @pkg/build/controller/build/build_controller.go
                                    ├buildPodCreationStrategy.CreateBuildPod() @pkg/build/controller/build/defaults/defaults.go
                                    │└typeBasedFactoryStrategy.CreateBuildPod() @pkg/build/controller/build/defaults/defaults.go
                                    │  ├DockerBuildStrategy.CreateBuildPod() @pkg/build/controller/strategy/docker.go
                                    │  └SourceBuildStrategy.CreateBuildPod() @pkg/build/controller/strategy/docker.go
                                    └BuildDefaults.ApplyDefaults() @pkg/build/controller/build/defaults/defaults.go
                                      └BuildDefaults.applyBuildDefaults() @pkg/build/controller/build/defaults/defaults.go
                                        └addDefaultEnvVar() @pkg/build/controller/build/defaults/defaults.go
                                          └SetBuildEnv() @pkg/build/util/util.go
```

Controller Managerが起動してから `Master.start()` までは [master-config.yamlの設定をロードする](#master-configyaml%E3%81%AE%E8%A8%AD%E5%AE%9A%E3%82%92%E3%83%AD%E3%83%BC%E3%83%89%E3%81%99%E3%82%8B) と同じ。
`Master.start()` の後、`RunOpenShiftControllerManager()`に入る。

最終的に `BuildController.createPodSpec()` において、
- `buildPodCreationStrategy.CreateBuildPod()` でbuild PodのPod Specを作り、
- `BuildDefaults.ApplyDefaults()` でmaster-config.yamlに設定された環境変数を突っ込む
という流れになる。

以下、
- build Podの起動直前まで
- build PodのPod Spec作成
- BuildDefaultで設定したの環境変数の注入
の3段階にわけて見ていく。

## build Podの起動直前まで

<details><summary>
詳細はこちら:
</summary><div>

まずは `Master.Start() @pkg/cmd/server/start/start_master.go` を再掲。

- [Master.Start() @pkg/cmd/server/start/start_master.go](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/cmd/server/start/start_master.go#L358:18)

```go
// Start launches a master. It will error if possible, but some background processes may still
// be running and the process should exit after it finishes.
func (m *Master) Start() error {

<snip>

    controllersEnabled := m.controllers && len(m.config.ControllerConfig.Controllers) > 0
    if controllersEnabled {

<snip>

        openshiftControllerConfig := openshift_controller_manager.ConvertMasterConfigToOpenshiftControllerConfig(m.config)
        // if we're starting the API, then this one isn't supposed to serve
        if m.api {
            openshiftControllerConfig.ServingInfo = nil
        }

        if err := openshift_controller_manager.RunOpenShiftControllerManager(openshiftControllerConfig, privilegedLoopbackConfig); err != nil { // XXX HERE
            return err
        }

    }

    if m.api {

<snip>

    }

    return nil
}
```

以下、`RunOpenShiftControllerManager() @pkg/cmd/openshift-controller-manager/controller_manager.go` から辿る。

- [RunOpenShiftControllerManager() @pkg/cmd/openshift-controller-manager/controller_manager.go](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/cmd/openshift-controller-manager/controller_manager.go#L26:6)

```go
func RunOpenShiftControllerManager(config *configapi.OpenshiftControllerConfig, clientConfig *rest.Config) error {

<snip>

    originControllerManager := func(stopCh <-chan struct{}) {
        if err := waitForHealthyAPIServer(kubeClient.Discovery().RESTClient()); err != nil {
            glog.Fatal(err)
        }

        controllerContext, err := origincontrollers.NewControllerContext(*config, clientConfig, stopCh)
        if err != nil {
            glog.Fatal(err)
        }
        if err := startControllers(controllerContext); err != nil { // XXX HERE
            glog.Fatal(err)
        }
        controllerContext.StartInformers(stopCh)
    }

<snip>

    go leaderelection.RunOrDie(leaderelection.LeaderElectionConfig{
        Lock:          rl,
        LeaseDuration: config.LeaderElection.LeaseDuration.Duration,
        RenewDeadline: config.LeaderElection.RenewDeadline.Duration,
        RetryPeriod:   config.LeaderElection.RetryPeriod.Duration,
        Callbacks: leaderelection.LeaderCallbacks{
            OnStartedLeading: originControllerManager,
            OnStoppedLeading: func() {
                glog.Fatalf("leaderelection lost")
            },
        },
    })

    return nil
```

- [NewControllerContext() @pkg/cmd/openshift-controller-manager/controller/interfaces.go](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/cmd/openshift-controller-manager/controller/interfaces.go#L43:6)

```go
func NewControllerContext(
    config configapi.OpenshiftControllerConfig,
    inClientConfig *rest.Config,
    stopCh <-chan struct{},
) (*ControllerContext, error) {


<snip>

    openshiftControllerContext := &ControllerContext{
        OpenshiftControllerConfig: config,

        ClientBuilder: OpenshiftControllerClientBuilder{
            ControllerClientBuilder: controller.SAControllerClientBuilder{
                ClientConfig:         rest.AnonymousClientConfig(clientConfig),
                CoreClient:           kubeClient.CoreV1(),
                AuthenticationClient: kubeClient.AuthenticationV1(),
                Namespace:            bootstrappolicy.DefaultOpenShiftInfraNamespace,
            },
        },
        KubernetesInformers:       kexternalinformers.NewSharedInformerFactory(kubeClient, defaultInformerResyncPeriod),
        AppsInformers:             appsinformer.NewSharedInformerFactory(appsClient, defaultInformerResyncPeriod),
        BuildInformers:            buildinformer.NewSharedInformerFactory(buildClient, defaultInformerResyncPeriod),
        ImageInformers:            imageinformer.NewSharedInformerFactory(imageClient, defaultInformerResyncPeriod),
        NetworkInformers:          networkinformer.NewSharedInformerFactory(networkClient, defaultInformerResyncPeriod),
        InternalQuotaInformers:    quotainformer.NewSharedInformerFactory(quotaClient, defaultInformerResyncPeriod),
        InternalRouteInformers:    routeinformer.NewSharedInformerFactory(routerClient, defaultInformerResyncPeriod),
        InternalTemplateInformers: templateinformer.NewSharedInformerFactory(templateClient, defaultInformerResyncPeriod),
        Stop:             stopCh,
        InformersStarted: make(chan struct{}),
        RestMapper:       dynamicRestMapper,
    }
    openshiftControllerContext.GenericResourceInformer = openshiftControllerContext.ToGenericInformer()

    return openshiftControllerContext, nil
}
```

[`ControllerContext`](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/cmd/openshift-controller-manager/controller/interfaces.go#L157) structの `OpenshiftControllerConfig.Build.BuildDefaults` フィールドからBuildDefaultsにアクセスできる。

- [startControllers() @pkg/cmd/openshift-controller-manager/controller_manager.go](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/cmd/openshift-controller-manager/controller_manager.go#L131:6)

```go
// startControllers launches the controllers
// allocation controller is passed in because it wants direct etcd access.  Naughty.
func startControllers(controllerContext *origincontrollers.ControllerContext) error {
    for controllerName, initFn := range origincontrollers.ControllerInitializers {
        if !controllerContext.IsControllerEnabled(controllerName) {
            glog.Warningf("%q is disabled", controllerName)
            continue
        }

        glog.V(1).Infof("Starting %q", controllerName)
        started, err := initFn(controllerContext) // XXX HERE
        if err != nil {
            glog.Fatalf("Error starting %q (%v)", controllerName, err)
            return err
        }
        if !started {
            glog.Warningf("Skipping %q", controllerName)
            continue
        }
        glog.Infof("Started %q", controllerName)
    }

    glog.Infof("Started Origin Controllers")

    return nil
}
```

- [ControllerInitializers @pkg/cmd/openshift-controller-manager/controller/config.go](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/cmd/openshift-controller-manager/controller/config.go#L3)

```go
var ControllerInitializers = map[string]InitFunc{
    "openshift.io/serviceaccount": RunServiceAccountController,

    "openshift.io/namespace-security-allocation": RunNamespaceSecurityAllocationController,

    "openshift.io/default-rolebindings": RunDefaultRoleBindingController,

    "openshift.io/serviceaccount-pull-secrets": RunServiceAccountPullSecretsController,
    "openshift.io/origin-namespace":            RunOriginNamespaceController,
    "openshift.io/service-serving-cert":        RunServiceServingCertsController,

    "openshift.io/build":               RunBuildController, // XXX HERE
    "openshift.io/build-config-change": RunBuildConfigChangeController,

    "openshift.io/deployer":         RunDeployerController,
    "openshift.io/deploymentconfig": RunDeploymentConfigController,

    "openshift.io/image-trigger":          RunImageTriggerController,
    "openshift.io/image-import":           RunImageImportController,
    "openshift.io/image-signature-import": RunImageSignatureImportController,

    "openshift.io/templateinstance":          RunTemplateInstanceController,
    "openshift.io/templateinstancefinalizer": RunTemplateInstanceFinalizerController,

    "openshift.io/sdn":              RunSDNController,
    "openshift.io/unidling":         RunUnidlingController,
    "openshift.io/ingress-ip":       RunIngressIPController,
    "openshift.io/ingress-to-route": RunIngressToRouteController,

    "openshift.io/resourcequota":                RunResourceQuotaManager,
    "openshift.io/cluster-quota-reconciliation": RunClusterQuotaReconciliationController,
}
```

- [RunBuildController() @pkg/cmd/openshift-controller-manager/controller/build.go](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/cmd/openshift-controller-manager/controller/build.go#L14)

```go
// RunController starts the build sync loop for builds and buildConfig processing.
func RunBuildController(ctx *ControllerContext) (bool, error) {
    imageTemplate := variable.NewDefaultImageTemplate()
    imageTemplate.Format = ctx.OpenshiftControllerConfig.Build.ImageTemplateFormat.Format
    imageTemplate.Latest = ctx.OpenshiftControllerConfig.Build.ImageTemplateFormat.Latest

    buildClient := ctx.ClientBuilder.OpenshiftBuildClientOrDie(bootstrappolicy.InfraBuildControllerServiceAccountName)
    externalKubeClient := ctx.ClientBuilder.ClientOrDie(bootstrappolicy.InfraBuildControllerServiceAccountName)
    securityClient := ctx.ClientBuilder.OpenshiftSecurityClientOrDie(bootstrappolicy.InfraBuildControllerServiceAccountName)

    buildInformer := ctx.BuildInformers.Build().V1().Builds()
    buildConfigInformer := ctx.BuildInformers.Build().V1().BuildConfigs()
    imageStreamInformer := ctx.ImageInformers.Image().V1().ImageStreams()
    podInformer := ctx.KubernetesInformers.Core().V1().Pods()
    secretInformer := ctx.KubernetesInformers.Core().V1().Secrets()

    buildControllerParams := &buildcontroller.BuildControllerParams{
        BuildInformer:       buildInformer,
        BuildConfigInformer: buildConfigInformer,
        ImageStreamInformer: imageStreamInformer,
        PodInformer:         podInformer,
        SecretInformer:      secretInformer,
        KubeClient:          externalKubeClient,
        BuildClient:         buildClient,
        DockerBuildStrategy: &buildstrategy.DockerBuildStrategy{
            Image: imageTemplate.ExpandOrDie("docker-builder"),
        },
        SourceBuildStrategy: &buildstrategy.SourceBuildStrategy{
            Image:          imageTemplate.ExpandOrDie("docker-builder"),
            SecurityClient: securityClient.SecurityV1(),
        },
        CustomBuildStrategy: &buildstrategy.CustomBuildStrategy{},
        BuildDefaults:       builddefaults.BuildDefaults{Config: ctx.OpenshiftControllerConfig.Build.BuildDefaults},
        BuildOverrides:      buildoverrides.BuildOverrides{Config: ctx.OpenshiftControllerConfig.Build.BuildOverrides},
    }

    go buildcontroller.NewBuildController(buildControllerParams).Run(5, ctx.Stop) // XXX HERE
    return true, nil
}
```

- [NewBuildController() @pkg/build/controller/build/build_controller.go](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/build/controller/build/build_controller.go#L172:6)

```go
// NewBuildController creates a new BuildController.
func NewBuildController(params *BuildControllerParams) *BuildController {
    eventBroadcaster := record.NewBroadcaster()
    eventBroadcaster.StartRecordingToSink(&ktypedclient.EventSinkImpl{Interface: params.KubeClient.CoreV1().Events("")})

    buildClient := buildmanualclient.NewClientBuildClient(params.BuildClient)
    buildLister := params.BuildInformer.Lister()
    buildConfigGetter := params.BuildConfigInformer.Lister()
    c := &BuildController{
        buildPatcher:      buildClient,
        buildLister:       buildLister,
        buildConfigGetter: buildConfigGetter,
        buildDeleter:      buildClient,
        secretStore:       params.SecretInformer.Lister(),
        podClient:         params.KubeClient.CoreV1(),
        kubeClient:        params.KubeClient,
        podInformer:       params.PodInformer.Informer(),
        podStore:          params.PodInformer.Lister(),
        buildInformer:     params.BuildInformer.Informer(),
        buildStore:        params.BuildInformer.Lister(),
        imageStreamStore:  params.ImageStreamInformer.Lister(),
        createStrategy: &typeBasedFactoryStrategy{
            dockerBuildStrategy: params.DockerBuildStrategy,
            sourceBuildStrategy: params.SourceBuildStrategy,
            customBuildStrategy: params.CustomBuildStrategy,
        },
        buildDefaults:  params.BuildDefaults,
        buildOverrides: params.BuildOverrides,

        buildQueue:       workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
        imageStreamQueue: newResourceTriggerQueue(),
        buildConfigQueue: workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),

        recorder:    eventBroadcaster.NewRecorder(buildscheme.EncoderScheme, corev1.EventSource{Component: "build-controller"}),
        runPolicies: policy.GetAllRunPolicies(buildLister, buildClient),
    }

    c.podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
        UpdateFunc: c.podUpdated,
        DeleteFunc: c.podDeleted,
    })
    c.buildInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
        AddFunc:    c.buildAdded,
        UpdateFunc: c.buildUpdated,
        DeleteFunc: c.buildDeleted,
    })
    params.ImageStreamInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
        AddFunc:    c.imageStreamAdded,
        UpdateFunc: c.imageStreamUpdated,
    })

    c.buildStoreSynced = c.buildInformer.HasSynced
    c.podStoreSynced = c.podInformer.HasSynced
    c.secretStoreSynced = params.SecretInformer.Informer().HasSynced
    c.imageStreamStoreSynced = params.ImageStreamInformer.Informer().HasSynced

    return c
}
```

[`BuildController`](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/build/controller/build/build_controller.go#L121) structの `buildDefaults.Config.Env` フィールドが `admissionConfig.pluginConfig.BuildDefaults.configuration.env` に相当する。

- [BuildController.Run() @pkg/build/controller/build/build_controller.go](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/build/controller/build/build_controller.go#L231:28)

```go
// Run begins watching and syncing.
func (bc *BuildController) Run(workers int, stopCh <-chan struct{}) {
    defer utilruntime.HandleCrash()
    defer bc.buildQueue.ShutDown()
    defer bc.buildConfigQueue.ShutDown()

    // Wait for the controller stores to sync before starting any work in this controller.
    if !cache.WaitForCacheSync(stopCh, bc.buildStoreSynced, bc.podStoreSynced, bc.secretStoreSynced, bc.imageStreamStoreSynced) {
        utilruntime.HandleError(fmt.Errorf("timed out waiting for caches to sync"))
        return
    }

    glog.Infof("Starting build controller")

    for i := 0; i < workers; i++ {
        go wait.Until(bc.buildWorker, time.Second, stopCh) // XXX HERE
    }

    for i := 0; i < workers; i++ {
        go wait.Until(bc.buildConfigWorker, time.Second, stopCh)
    }

    metrics.IntializeMetricsCollector(bc.buildLister)

    <-stopCh
    glog.Infof("Shutting down build controller")
}
```

- [BuildController.buildWorker() @pkg/build/controller/build/build_controller.go](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/build/controller/build/build_controller.go#L258:28)

```go
func (bc *BuildController) buildWorker() {
    for {
        if quit := bc.buildWork(); quit { // XXX HERE
            return
        }
    }
}
```

- [BuildController.buildWork() @pkg/build/controller/build/build_controller.go](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/build/controller/build/build_controller.go#L267:28)

```go
// buildWork gets the next build from the buildQueue and invokes handleBuild on it
func (bc *BuildController) buildWork() bool {
    key, quit := bc.buildQueue.Get()
    if quit {
        return true
    }

    defer bc.buildQueue.Done(key)

    build, err := bc.getBuildByKey(key.(string))
    if err != nil {
        bc.handleBuildError(err, key)
        return false
    }
    if build == nil {
        return false
    }

    err = bc.handleBuild(build) // XXX HERE
    bc.handleBuildError(err, key)
    return false
}
```

- [BuildController.handleBuild() @pkg/build/controller/build/build_controller.go](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/build/controller/build/build_controller.go#L327:28)

```go
// handleBuild retrieves the build's corresponding pod and calls the appropriate
// handle function based on the build's current state. Each handler returns a buildUpdate
// object that includes any updates that need to be made on the build.
func (bc *BuildController) handleBuild(build *buildv1.Build) error {

<snip>

    pod, podErr := bc.podStore.Pods(build.Namespace).Get(buildapihelpers.GetBuildPodName(build))

    // Technically the only error that is returned from retrieving the pod is the
    // NotFound error so this check should not be needed, but leaving here in case
    // that changes in the future.
    if podErr != nil && !errors.IsNotFound(podErr) {
        return podErr
    }

    var update *buildUpdate
    var err, updateErr error

    switch {
    case shouldCancel(build):
        update, err = bc.cancelBuild(build)
    case build.Status.Phase == buildv1.BuildPhaseNew:
        update, err = bc.handleNewBuild(build, pod) // XXX HERE
    case build.Status.Phase == buildv1.BuildPhasePending,
        build.Status.Phase == buildv1.BuildPhaseRunning:
        update, err = bc.handleActiveBuild(build, pod)
    case buildutil.IsBuildComplete(build):
        update, err = bc.handleCompletedBuild(build, pod)
    }
    if update != nil && !update.isEmpty() {
        updateErr = bc.updateBuild(build, update, pod)
    }
    if err != nil {
        return err
    }
    if updateErr != nil {
        return updateErr
    }
    return nil
}
```

- [BuildController.handleNewBuild() @pkg/build/controller/build/build_controller.go](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/build/controller/build/build_controller.go#L434:28)

```go
// handleNewBuild will check whether policy allows running the new build and if so, creates a pod
// for the build and returns an update to move it to the Pending phase
func (bc *BuildController) handleNewBuild(build *buildv1.Build, pod *corev1.Pod) (*buildUpdate, error) {
    if pod != nil {
        // We're in phase New and a build pod already exists.  If the pod has an
        // owner reference to the build, we take that to mean that we created
        // the pod but failed to update the build object afterwards.  In
        // principle, we should re-run all the handleNewBuild/createBuildPod
        // logic in this case.  At the moment, however, we short-cut straight to
        // handleActiveBuild.  This is not ideal because we lose any updates we
        // meant to make to the build object (apart from advancing the phase).
        // On the other hand, as the code stands, re-running
        // handleNewBuild/createBuildPod is also problematic.  The build policy
        // code is not side-effect free, and the controller logic in general is
        // dependent on lots of state stored outside of the build object.  The
        // risk is that were we to re-run handleNewBuild/createBuildPod a second
        // time, we'd make different decisions to those taken previously.
        //
        // TODO: fix this.  One route might be to add an additional phase into
        // the build FSM: New -> X -> Pending -> Running, where all the pre-work
        // is done in the transition New->X, and nothing more than the build pod
        // creation is done in the transition X->Pending.
        if strategy.HasOwnerReference(pod, build) {
            return bc.handleActiveBuild(build, pod)
        }
        // If a pod was not created by the current build, move the build to
        // error.
        return transitionToPhase(buildv1.BuildPhaseError, buildv1.StatusReasonBuildPodExists, buildutil.StatusMessageBuildPodExists), nil
    }

    runPolicy := policy.ForBuild(build, bc.runPolicies)
    if runPolicy == nil {
        return nil, fmt.Errorf("unable to determine build policy for %s", buildDesc(build))
    }

    // The runPolicy decides whether to execute this build or not.
    if run, err := runPolicy.IsRunnable(build); err != nil || !run {
        return nil, err
    }

    return bc.createBuildPod(build) // XXX HERE
}
```

- [BuildController.createBuildPod() @pkg/build/controller/build/build_controller.go](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/build/controller/build/build_controller.go#L789:28)

```go
// createBuildPod creates a new pod to run a build
func (bc *BuildController) createBuildPod(build *buildv1.Build) (*buildUpdate, error) {
    update := &buildUpdate{}

<snip>

    // Create the build pod spec
    buildPod, err := bc.createPodSpec(build) // XXX HERE
    if err != nil {
        switch err.(type) {
        case common.ErrEnvVarResolver:
            update = transitionToPhase(buildv1.BuildPhaseError, buildv1.StatusReasonUnresolvableEnvironmentVariable, fmt.Sprintf("%v, %v",
                buildutil.StatusMessageUnresolvableEnvironmentVariable, err.Error()))
        default:
            update.setReason(buildv1.StatusReasonCannotCreateBuildPodSpec)
            update.setMessage(buildutil.StatusMessageCannotCreateBuildPodSpec)

        }
        // If an error occurred when creating the pod spec, it likely means
        // that the build is something we don't understand. For example, it could
        // have a strategy that we don't recognize. It will remain in New state
        // and be updated with the reason that it is still in New

        // The error will be logged, but will not be returned to the caller
        // to be retried. The reason is that there's really no external factor
        // that could cause the pod creation to fail; therefore no reason
        // to immediately retry processing the build.
        //
        // A scenario where this would happen is that we've introduced a
        // new build strategy in the master, but the old version of the controller
        // is still running. We don't want the old controller to move the
        // build to the error phase and we don't want it to keep actively retrying.
        utilruntime.HandleError(err)
        return update, nil
    }

<snip>
```

- [BuildController.createPodSpec() @pkg/build/controller/build/build_controller.go](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/build/controller/build/build_controller.go#L476:28)

```go
// createPodSpec creates a pod spec for the given build, with all references already resolved.
func (bc *BuildController) createPodSpec(build *buildv1.Build) (*corev1.Pod, error) {
    if build.Spec.Output.To != nil {
        build.Status.OutputDockerImageReference = build.Spec.Output.To.Name
    }

    // ensure the build object the pod sees starts with a clean set of reasons/messages,
    // rather than inheriting the potential "invalidoutputreference" message from the current
    // build state.  Otherwise when the pod attempts to update the build (e.g. with the git
    // revision information), it will re-assert the stale reason/message.
    build.Status.Reason = ""
    build.Status.Message = ""

    // Invoke the strategy to create a build pod.
    podSpec, err := bc.createStrategy.CreateBuildPod(build)
    if err != nil {
        if strategy.IsFatal(err) {
            return nil, &strategy.FatalError{Reason: fmt.Sprintf("failed to create a build pod spec for build %s/%s: %v", build.Namespace, build.Name, err)}
        }
        return nil, fmt.Errorf("failed to create a build pod spec for build %s/%s: %v", build.Namespace, build.Name, err)
    }
    if err := bc.buildDefaults.ApplyDefaults(podSpec); err != nil { // XXX HERE
        return nil, fmt.Errorf("failed to apply build defaults for build %s/%s: %v", build.Namespace, build.Name, err)
    }
    if err := bc.buildOverrides.ApplyOverrides(podSpec); err != nil {
        return nil, fmt.Errorf("failed to apply build overrides for build %s/%s: %v", build.Namespace, build.Name, err)
    }

    // Handle resolving ValueFrom references in build environment variables
    if err := common.ResolveValueFrom(podSpec, bc.kubeClient); err != nil {
        return nil, err
    }
    return podSpec, nil
}
```
</div>
</details>

## build PodのPod Spec作成

<details><summary>
詳細はこちら:
</summary><div>

- [buildPodCreationStrategy @pkg/build/controller/build/podcreationstrategy.go](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/build/controller/build/podcreationstrategy.go#L15:2)

```go
// buildPodCreationStrategy is used by the build controller to
// create a build pod based on a build strategy
type buildPodCreationStrategy interface {
    CreateBuildPod(build *buildv1.Build) (*corev1.Pod, error) // XXX HERE
}
```

- [typeBasedFactoryStrategy @pkg/build/controller/build/podcreationstrategy.go](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/build/controller/build/podcreationstrategy.go#L19)

```go
type typeBasedFactoryStrategy struct {
    dockerBuildStrategy buildPodCreationStrategy // XXX HERE
    sourceBuildStrategy buildPodCreationStrategy // XXX HERE
    customBuildStrategy buildPodCreationStrategy
}
```

- [typeBasedFactoryStrategy.CreateBuildPod() @pkg/build/controller/build/podcreationstrategy.go](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/build/controller/build/podcreationstrategy.go#L24)

```go
func (f *typeBasedFactoryStrategy) CreateBuildPod(build *buildv1.Build) (*corev1.Pod, error) {
    var pod *corev1.Pod
    var err error
    switch {
    case build.Spec.Strategy.DockerStrategy != nil:
        pod, err = f.dockerBuildStrategy.CreateBuildPod(build) // XXX HERE
    case build.Spec.Strategy.SourceStrategy != nil:
        pod, err = f.sourceBuildStrategy.CreateBuildPod(build) // XXX HERE
    case build.Spec.Strategy.CustomStrategy != nil:
        pod, err = f.customBuildStrategy.CreateBuildPod(build)
    case build.Spec.Strategy.JenkinsPipelineStrategy != nil:
        return nil, fmt.Errorf("creating a build pod for Build %s/%s with the JenkinsPipeline strategy is not supported", build.Namespace, build.Name)
    default:
        return nil, fmt.Errorf("no supported build strategy defined for Build %s/%s", build.Namespace, build.Name)
    }

    if pod != nil {
        if pod.Annotations == nil {
            pod.Annotations = map[string]string{}
        }
        pod.Annotations[buildutil.BuildAnnotation] = build.Name
    }
    return pod, err
}
```

### Dockerビルド

- [DockerBuildStrategy.CreateBuildPod() @pkg/build/controller/strategy/docker.go](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/build/controller/strategy/docker.go#L36)

```go
// CreateBuildPod creates the pod to be used for the Docker build
// TODO: Make the Pod definition configurable
func (bs *DockerBuildStrategy) CreateBuildPod(build *buildv1.Build) (*v1.Pod, error) {
    data, err := runtime.Encode(buildJSONCodec, build)
    if err != nil {
        return nil, fmt.Errorf("failed to encode the build: %v", err)
    }

<snip>

    pod := &v1.Pod{
        ObjectMeta: metav1.ObjectMeta{
            Name:      buildapihelpers.GetBuildPodName(build),
            Namespace: build.Namespace,
            Labels:    getPodLabels(build),
        },
        Spec: v1.PodSpec{
            ServiceAccountName: serviceAccount,
            Containers: []v1.Container{
                {
                    Name:    DockerBuild,
                    Image:   bs.Image,
                    Command: []string{"openshift-docker-build"}, // XXX HERE
                    Env:     copyEnvVarSlice(containerEnv),
                    // TODO: run unprivileged https://github.com/openshift/origin/issues/662
                    SecurityContext: &v1.SecurityContext{
                        Privileged: &privileged,
                    },
                    TerminationMessagePolicy: v1.TerminationMessageFallbackToLogsOnError,
                    VolumeMounts: []v1.VolumeMount{
                        {
                            Name:      "buildworkdir",
                            MountPath: buildutil.BuildWorkDirMount,
                        },
                    },
                    ImagePullPolicy: v1.PullIfNotPresent,
                    Resources:       build.Spec.Resources,
                },
            },
            Volumes: []v1.Volume{
                {
                    Name: "buildworkdir",
                    VolumeSource: v1.VolumeSource{
                        EmptyDir: &v1.EmptyDirVolumeSource{},
                    },
                },
            },
            RestartPolicy: v1.RestartPolicyNever,
            NodeSelector:  build.Spec.NodeSelector,
        },
    }

<snip>

    pod.Spec.InitContainers = append(pod.Spec.InitContainers,
        v1.Container{
            Name:    "manage-dockerfile",
            Image:   bs.Image,
            Command: []string{"openshift-manage-dockerfile"}, // XXX HERE
            Env:     copyEnvVarSlice(containerEnv),
            TerminationMessagePolicy: v1.TerminationMessageFallbackToLogsOnError,
            VolumeMounts: []v1.VolumeMount{
                {
                    Name:      "buildworkdir",
                    MountPath: buildutil.BuildWorkDirMount,
                },
            },
            ImagePullPolicy: v1.PullIfNotPresent,
            Resources:       build.Spec.Resources,
        },
    )

<snip>

    setOwnerReference(pod, build)
    setupDockerSocket(pod)
    setupCrioSocket(pod)
    setupDockerSecrets(pod, &pod.Spec.Containers[0], build.Spec.Output.PushSecret, strategy.PullSecret, build.Spec.Source.Images)
    // For any secrets the user wants to reference from their Assemble script or Dockerfile, mount those
    // secrets into the main container.  The main container includes logic to copy them from the mounted
    // location into the working directory.
    // TODO: consider moving this into the git-clone container and doing the secret copying there instead.
    setupInputSecrets(pod, &pod.Spec.Containers[0], build.Spec.Source.Secrets)
    setupInputConfigMaps(pod, &pod.Spec.Containers[0], build.Spec.Source.ConfigMaps)
    return pod, nil
}
```

### S2I ビルド

- [SourceBuildStrategy.CreateBuildPod() @pkg/build/controller/strategy/docker.go](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/build/controller/strategy/docker.go#L36)

```go
// CreateBuildPod creates a pod that will execute the STI build
// TODO: Make the Pod definition configurable
func (bs *SourceBuildStrategy) CreateBuildPod(build *buildv1.Build) (*corev1.Pod, error) {
    data, err := runtime.Encode(buildJSONCodec, build)
    if err != nil {
        return nil, fmt.Errorf("failed to encode the Build %s/%s: %v", build.Namespace, build.Name, err)
    }

<snip>

    privileged := true
    pod := &corev1.Pod{
        ObjectMeta: metav1.ObjectMeta{
            Name:      buildapihelpers.GetBuildPodName(build),
            Namespace: build.Namespace,
            Labels:    getPodLabels(build),
        },
        Spec: corev1.PodSpec{
            ServiceAccountName: serviceAccount,
            Containers: []corev1.Container{
                {
                    Name:    StiBuild,
                    Image:   bs.Image,
                    Command: []string{"openshift-sti-build"},
                    Env:     copyEnvVarSlice(containerEnv),
                    // TODO: run unprivileged https://github.com/openshift/origin/issues/662
                    SecurityContext: &corev1.SecurityContext{
                        Privileged: &privileged,
                    },
                    TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
                    VolumeMounts: []corev1.VolumeMount{
                        {
                            Name:      "buildworkdir",
                            MountPath: buildutil.BuildWorkDirMount,
                        },
                    },
                    ImagePullPolicy: corev1.PullIfNotPresent,
                    Resources:       build.Spec.Resources,
                },
            },
            Volumes: []corev1.Volume{
                {
                    Name: "buildworkdir",
                    VolumeSource: corev1.VolumeSource{
                        EmptyDir: &corev1.EmptyDirVolumeSource{},
                    },
                },
            },
            RestartPolicy: corev1.RestartPolicyNever,
            NodeSelector:  build.Spec.NodeSelector,
        },
    }

<snip>

    pod.Spec.InitContainers = append(pod.Spec.InitContainers,
        corev1.Container{
            Name:    "manage-dockerfile",
            Image:   bs.Image,
            Command: []string{"openshift-manage-dockerfile"},
            Env:     copyEnvVarSlice(containerEnv),
            TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
            VolumeMounts: []corev1.VolumeMount{
                {
                    Name:      "buildworkdir",
                    MountPath: buildutil.BuildWorkDirMount,
                },
            },
            ImagePullPolicy: corev1.PullIfNotPresent,
            Resources:       build.Spec.Resources,
        },
    )

<snip>

    setOwnerReference(pod, build)
    setupDockerSocket(pod)
    setupCrioSocket(pod)
    setupDockerSecrets(pod, &pod.Spec.Containers[0], build.Spec.Output.PushSecret, strategy.PullSecret, build.Spec.Source.Images)
    // For any secrets the user wants to reference from their Assemble script or Dockerfile, mount those
    // secrets into the main container.  The main container includes logic to copy them from the mounted
    // location into the working directory.
    // TODO: consider moving this into the git-clone container and doing the secret copying there instead.
    setupInputSecrets(pod, &pod.Spec.Containers[0], build.Spec.Source.Secrets)
    setupInputConfigMaps(pod, &pod.Spec.Containers[0], build.Spec.Source.ConfigMaps)
    return pod, nil
}
```

DockerビルドにしろS2Iビルドにしろ、build PodのInit Containerで `openshift-manage-dockerfile` コマンドを実行している。
</div>
</details>

## BuildDefaultで設定したの環境変数の注入

<details><summary>
詳細はこちら:
</summary><div>

- [BuildDefaults.ApplyDefaults() @pkg/build/controller/build/defaults/defaults.go](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/build/controller/build/defaults/defaults.go#L21)

```go
// ApplyDefaults applies configured build defaults to a build pod
func (b BuildDefaults) ApplyDefaults(pod *corev1.Pod) error {
    build, err := common.GetBuildFromPod(pod)
    if err != nil {
        return nil
    }

    if b.Config == nil {
        // even if there's no config for the defaulter, we need to set up the loglevel.
        return setPodLogLevelFromBuild(pod, build)
    }

    glog.V(4).Infof("Applying defaults to build %s/%s", build.Namespace, build.Name)
    b.applyBuildDefaults(build) // XXX HERE

    glog.V(4).Infof("Applying defaults to pod %s/%s", pod.Namespace, pod.Name)
    b.applyPodDefaults(pod, build.Spec.Strategy.CustomStrategy != nil)

    err = setPodLogLevelFromBuild(pod, build)
    if err != nil {
        return err
    }

    return common.SetBuildInPod(pod, build)
}
```

- [BuildDefaults.applyBuildDefaults() @pkg/build/controller/build/defaults/defaults.go](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/build/controller/build/defaults/defaults.go#L148:24)

```go
func (b BuildDefaults) applyBuildDefaults(build *buildv1.Build) {
    // Apply default env
    for _, envVar := range b.Config.Env {
        glog.V(5).Infof("Adding default environment variable %s=%s to build %s/%s", envVar.Name, envVar.Value, build.Namespace, build.Name)
        externalEnv := corev1.EnvVar{}
        if err := legacyscheme.Scheme.Convert(&envVar, &externalEnv, nil); err != nil {
            panic(err)
        }
        addDefaultEnvVar(build, externalEnv) // XXX HERE
    }

<snip>
```

- [addDefaultEnvVar() @pkg/build/controller/build/defaults/defaults.go](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/build/controller/build/defaults/defaults.go#L228:6)

```go
func addDefaultEnvVar(build *buildv1.Build, v corev1.EnvVar) {
    envVars := buildutil.GetBuildEnv(build)

    for i := range envVars {
        if envVars[i].Name == v.Name {
            return
        }
    }
    envVars = append(envVars, v)
    buildutil.SetBuildEnv(build, envVars) // XXX HERE
}
```

- [SetBuildEnv() @pkg/build/util/util.go](https://github.com/openshift/origin/blob/11bbf5df956be2a16a9c303427aac2055a6aa608/pkg/build/util/util.go#L207:6)

```go
// SetBuildEnv replaces the current build environment
func SetBuildEnv(build *buildv1.Build, env []corev1.EnvVar) {
    var oldEnv *[]corev1.EnvVar

    switch {
    case build.Spec.Strategy.SourceStrategy != nil:
        oldEnv = &build.Spec.Strategy.SourceStrategy.Env
    case build.Spec.Strategy.DockerStrategy != nil:
        oldEnv = &build.Spec.Strategy.DockerStrategy.Env
    case build.Spec.Strategy.CustomStrategy != nil:
        oldEnv = &build.Spec.Strategy.CustomStrategy.Env
    case build.Spec.Strategy.JenkinsPipelineStrategy != nil:
        oldEnv = &build.Spec.Strategy.JenkinsPipelineStrategy.Env
    default:
        return
    }
    *oldEnv = env
}
```
</div>
</details>

# openshift-manage-dockerfileコマンド

DockerビルドおよびS2Iビルドにおいて、build Pod起動時、Init Container内で `openshift-manage-dockerfile` コマンドを起動する。
このコマンドの中で、FROMの直後にENVを挿入している。
<details><summary>
詳細はこちら:
</summary><div>

```
main() @cmd/oc/oc.go
└CommandFor() @pkg/oc/cli/cli.go
  └NewCommandManageDockerfile() @pkg/cmd/infra/builder/builder.go
    └RunManageDockerfile() @pkg/build/builder/cmd/builder.go
      └ManageDockerfile() @@pkg/build/builder/source.go
        └addBuildParameters() @pkg/build/builder/common.go
          └insertEnvAfterFrom() @pkg/build/builder/docker.go
```

- main() @cmd/oc/oc.go

```go
func main() {
    logs.InitLogs()
    defer logs.FlushLogs()
    defer serviceability.BehaviorOnPanic(os.Getenv("OPENSHIFT_ON_PANIC"), version.Get())()
    defer serviceability.Profile(os.Getenv("OPENSHIFT_PROFILE")).Stop()

    rand.Seed(time.Now().UTC().UnixNano())
    if len(os.Getenv("GOMAXPROCS")) == 0 {
        runtime.GOMAXPROCS(runtime.NumCPU())
    }

    // the kubectl scheme expects to have all the recognizable external types it needs to consume.  Install those here.
    // We can't use the "normal" scheme because apply will use that to build stategic merge patches on CustomResources
    utilruntime.Must(apps.Install(scheme.Scheme))
    utilruntime.Must(authorization.Install(scheme.Scheme))
    utilruntime.Must(build.Install(scheme.Scheme))
    utilruntime.Must(image.Install(scheme.Scheme))
    utilruntime.Must(network.Install(scheme.Scheme))
    utilruntime.Must(oauth.Install(scheme.Scheme))
    utilruntime.Must(operator.Install(scheme.Scheme))
    utilruntime.Must(project.Install(scheme.Scheme))
    utilruntime.Must(quota.Install(scheme.Scheme))
    utilruntime.Must(route.Install(scheme.Scheme))
    utilruntime.Must(security.Install(scheme.Scheme))
    utilruntime.Must(template.Install(scheme.Scheme))
    utilruntime.Must(user.Install(scheme.Scheme))
    legacy.InstallExternalLegacyAll(scheme.Scheme)

    // the legacyscheme is used in kubectl and expects to have the internal types registered.  Explicitly wire our types here.
    // this does
    install.InstallInternalOpenShift(legacyscheme.Scheme)
    legacy.InstallInternalLegacyAll(scheme.Scheme)

    basename := filepath.Base(os.Args[0])
    command := cli.CommandFor(basename) // XXX HERE
    if err := command.Execute(); err != nil {
        os.Exit(1)
    }
}
```

- CommandFor() @pkg/oc/cli/cli.go

```go
// CommandFor returns the appropriate command for this base name,
// or the OpenShift CLI command.
func CommandFor(basename string) *cobra.Command {
    var cmd *cobra.Command

    in, out, errout := os.Stdin, os.Stdout, os.Stderr

    // Make case-insensitive and strip executable suffix if present
    if runtime.GOOS == "windows" {
        basename = strings.ToLower(basename)
        basename = strings.TrimSuffix(basename, ".exe")
    }

    switch basename {
    case "kubectl":
        kcmdutil.DefaultPrintingScheme = ocscheme.PrintingInternalScheme
        cmd = kubecmd.NewKubectlCommand(in, out, errout)
    case "openshift-deploy":
        cmd = deployer.NewCommandDeployer(basename)
    case "openshift-sti-build":
        cmd = builder.NewCommandS2IBuilder(basename)
    case "openshift-docker-build":
        cmd = builder.NewCommandDockerBuilder(basename)
    case "openshift-git-clone":
        cmd = builder.NewCommandGitClone(basename)
    case "openshift-manage-dockerfile":
        cmd = builder.NewCommandManageDockerfile(basename) // XXX HERE
    case "openshift-extract-image-content":
        cmd = builder.NewCommandExtractImageContent(basename)
    case "openshift-router":
        cmd = irouter.NewCommandTemplateRouter(basename)
    case "openshift-f5-router":
        cmd = irouter.NewCommandF5Router(basename)
    case "openshift-recycle":
        cmd = recycle.NewCommandRecycle(basename, out)
    default:
        kcmdutil.DefaultPrintingScheme = ocscheme.PrintingInternalScheme
        shimKubectlForOc()
        cmd = NewCommandCLI("oc", "oc", in, out, errout)
    }

    if cmd.UsageFunc() == nil {
        templates.ActsAsRootCommand(cmd, []string{"options"})
    }
    flagtypes.GLog(cmd.PersistentFlags())

    return cmd
}
```

- NewCommandManageDockerfile() @pkg/cmd/infra/builder/builder.go

```go
func NewCommandManageDockerfile(name string) *cobra.Command {
    cmd := &cobra.Command{
        Use:   name,
        Short: "Manage a dockerfile for a docker build",
        Long:  manageDockerfileLong,
        Run: func(c *cobra.Command, args []string) {
            err := cmd.RunManageDockerfile(c.OutOrStderr()) // XXX HERE
            kcmdutil.CheckErr(err)
        },
    }
    cmd.AddCommand(cmdversion.NewCmdVersion(name, version.Get(), os.Stdout))
    return cmd
}

func NewCommandExtractImageContent(name string) *cobra.Command {
    cmd := &cobra.Command{
        Use:   name,
        Short: "Extract build input content from existing images",
        Long:  extractImageContentLong,
        Run: func(c *cobra.Command, args []string) {
            err := cmd.RunExtractImageContent(c.OutOrStderr())
            kcmdutil.CheckErr(err)
        },
    }
    cmd.AddCommand(cmdversion.NewCmdVersion(name, version.Get(), os.Stdout))
    return cmd
}
```

- RunManageDockerfile() @pkg/build/builder/cmd/builder.go

```go
// RunManageDockerfile manipulates the dockerfile for docker builds.
// It will write the inline dockerfile to the working directory (possibly
// overwriting an existing dockerfile) and then update the dockerfile
// in the working directory (accounting for contextdir+dockerfilepath)
// with new FROM image information based on the imagestream/imagetrigger
// and also adds some env and label values to the dockerfile based on
// the build information.
func RunManageDockerfile(out io.Writer) error {
    cfg, err := newBuilderConfigFromEnvironment(out, false)
    if err != nil {
        return err
    }
    return bld.ManageDockerfile(buildutil.InputContentPath, cfg.build) // XXX HERE
}

// RunExtractImageContent extracts files from existing images
// into the build working directory.
func RunExtractImageContent(out io.Writer) error {
    cfg, err := newBuilderConfigFromEnvironment(out, true)
    if err != nil {
        return err
    }
    return cfg.extractImageContent()
}
```

- ManageDockerfile() @@pkg/build/builder/source.go

```go
// ManageDockerfile manipulates the dockerfile for docker builds.
// It will write the inline dockerfile to the working directory (possibly
// overwriting an existing dockerfile) and then update the dockerfile
// in the working directory (accounting for contextdir+dockerfilepath)
// with new FROM image information based on the imagestream/imagetrigger
// and also adds some env and label values to the dockerfile based on
// the build information.
func ManageDockerfile(dir string, build *buildapiv1.Build) error {
    os.MkdirAll(dir, 0777)
    glog.V(5).Infof("Checking for presence of a Dockerfile")
    // a Dockerfile has been specified, create or overwrite into the destination
    if dockerfileSource := build.Spec.Source.Dockerfile; dockerfileSource != nil {
        baseDir := dir
        if len(build.Spec.Source.ContextDir) != 0 {
            baseDir = filepath.Join(baseDir, build.Spec.Source.ContextDir)
        }
        if err := ioutil.WriteFile(filepath.Join(baseDir, "Dockerfile"), []byte(*dockerfileSource), 0660); err != nil {
            return err
        }
    }

    // We only mutate the dockerfile if this is a docker strategy build, otherwise
    // we leave it as it was provided.
    if build.Spec.Strategy.DockerStrategy != nil {
        sourceInfo, err := readSourceInfo()
        if err != nil {
            return fmt.Errorf("error reading git source info: %v", err)
        }
        return addBuildParameters(dir, build, sourceInfo) // XXX HERE
    }
    return nil
}
```

- addBuildParameters() @pkg/build/builder/common.go

```go
// addBuildParameters checks if a Image is set to replace the default base image.
// If that's the case then change the Dockerfile to make the build with the given image.
// Also append the environment variables and labels in the Dockerfile.
func addBuildParameters(dir string, build *buildapiv1.Build, sourceInfo *git.SourceInfo) error {
    dockerfilePath := getDockerfilePath(dir, build)

    in, err := ioutil.ReadFile(dockerfilePath)
    if err != nil {
        return err
    }
    node, err := imagebuilder.ParseDockerfile(bytes.NewBuffer(in))
    if err != nil {
        return err
    }

    // Update base image if build strategy specifies the From field.
    if build.Spec.Strategy.DockerStrategy != nil && build.Spec.Strategy.DockerStrategy.From != nil && build.Spec.Strategy.DockerStrategy.From.Kind == "DockerImage" {
        // Reduce the name to a minimal canonical form for the daemon
        name := build.Spec.Strategy.DockerStrategy.From.Name
        if ref, err := imagereference.Parse(name); err == nil {
            name = ref.DaemonMinimal().Exact()
        }
        err := replaceLastFrom(node, name)
        if err != nil {
            return err
        }
    }

    // Append build info as environment variables.
    if err := appendEnv(node, buildEnv(build, sourceInfo)); err != nil {
        return err
    }

    // Append build labels.
    if err := appendLabel(node, buildLabels(build, sourceInfo)); err != nil {
        return err
    }

    // Insert environment variables defined in the build strategy.
    if err := insertEnvAfterFrom(node, build.Spec.Strategy.DockerStrategy.Env); err != nil { // XXX HERE
        return err
    }

    replaceImagesFromSource(node, build.Spec.Source.Images)

    out := dockerfile.Write(node)
    glog.V(4).Infof("Replacing dockerfile\n%s\nwith:\n%s", string(in), string(out))
    return overwriteFile(dockerfilePath, out)
}
```

- insertEnvAfterFrom() @pkg/build/builder/docker.go

```go
// insertEnvAfterFrom inserts an ENV instruction with the environment variables
// from env after every FROM instruction in node.
func insertEnvAfterFrom(node *parser.Node, env []corev1.EnvVar) error {
    if node == nil || len(env) == 0 {
        return nil
    }

    // Build ENV instruction.
    var m []dockerfile.KeyValue
    for _, e := range env {
        m = append(m, dockerfile.KeyValue{Key: e.Name, Value: e.Value})
    }
    buildEnv, err := dockerfile.Env(m)
    if err != nil {
        return err
    }

    // Insert the buildEnv after every FROM instruction.
    // We iterate in reverse order, otherwise indices would have to be
    // recomputed after each step, because we're changing node in-place.
    indices := dockerfile.FindAll(node, dockercmd.From)
    for i := len(indices) - 1; i >= 0; i-- {
        err := dockerfile.InsertInstructions(node, indices[i]+1, buildEnv)
        if err != nil {
            return err
        }
    }

    return nil
}
```
</div>
</details>
