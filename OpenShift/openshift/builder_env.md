# xxx

## Controller Managerの起動

Controller Managerはコンテナとして起動している。

```
[ori@ocp311-master1 ~]$ oc -n kube-system get pod
NAME                                            READY     STATUS    RESTARTS   AGE
master-api-ocp311-master1.example.com           1/1       Running   1607       198d
master-controllers-ocp311-master1.example.com   1/1       Running   18         198d
master-etcd-ocp311-master1.example.com          1/1       Running   7          198d
```

`master-controllers-ocp311-master1.example.com` というPodがそれ。
中で動いているプロセスを確認する。

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
      exec openshift start master controllers --config=/etc/origin/master/master-config.yaml --listen=https://0.0.0.0:8444 --loglevel=${DEBUG_LOGLEVEL:-2}
    command:
    - /bin/bash
    - -c
    image: registry.redhat.io/openshift3/ose-control-plane:v3.11.16

<snip>
```

`openshift start master controllers --config=/etc/origin/master/master-config.yaml ...` というコマンドラインで起動している。覚えた。

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

`admissionConfig.pluginConfig.BuildDefaults.configuration.env` にenvが入る。覚えた。


# master-config.yamlの読み込み

hypershiftコマンドから起動する場合と、openshfitコマンドから起動する場合の2通りがあるようです。
今回はopenshiftコマンドから起動していますので、そちらを見ます。

## openshiftコマンドで起動する場合

### openshiftコマンドで起動してmaster-config.yamlを読み込むまで - 概要

- main() @cmd/openshift/openshift.go
- CommandFor() @pkg/cmd/openshift/openshift.go
- NewCommandOpenShift() @pkg/cmd/openshift/openshift.go
- NewCommandStart() @pkg/cmd/server/start/start.go
- NewCommandStartMaster() @pkg/cmd/server/start/start\_master.go
- MasterOptions.StartMaster() @pkg/cmd/server/start/start\_master.go
- MasterOptions.RunMaster() @pkg/cmd/server/start/start\_master.go
- Master.Start() @pkg/cmd/server/start/start_master.go
- ConvertMasterConfigToOpenshiftControllerConfig() @pkg/cmd/openshift-controller-manager/conversion.go

### openshiftコマンドで起動してmaster-config.yamlを読み込むまで - 詳細

- main() @cmd/openshift/openshift.go

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
    command := openshift.CommandFor(basename)
    if err := command.Execute(); err != nil {
        os.Exit(1)
    }
}
```

- CommandFor() @pkg/cmd/openshift/openshift.go

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
        cmd = NewCommandOpenShift("openshift")
    }

    if cmd.UsageFunc() == nil {
        templates.ActsAsRootCommand(cmd, []string{"options"})
    }
    flagtypes.GLog(cmd.PersistentFlags())

    return cmd
}
```

- NewCommandOpenShift() @pkg/cmd/openshift/openshift.go

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

    root.AddCommand(start.NewCommandStart(name, out, errout, wait.NeverStop))

    root.AddCommand(newCompletionCommand("completion", name+" completion"))
    root.AddCommand(cmdversion.NewCmdVersion(name, osversion.Get(), os.Stdout))
    root.AddCommand(newCmdOptions())

    // TODO: add groups
    templates.ActsAsRootCommand(root, []string{"options"})

    return root
}
```

- NewCommandStart() @pkg/cmd/server/start/start.go

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

    startMaster, _ := NewCommandStartMaster(basename, out, errout)
    startNodeNetwork, _ := NewCommandStartNetwork(basename, out, errout)
    startEtcdServer, _ := openshift_etcd.NewCommandStartEtcdServer(openshift_etcd.RecommendedStartEtcdServerName, basename, out, errout)
    cmds.AddCommand(startMaster)
    cmds.AddCommand(startNodeNetwork)
    cmds.AddCommand(startEtcdServer)

    return cmds
}
```

- NewCommandStartMaster() @pkg/cmd/server/start/start_master.go

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
            kcmdutil.CheckErr(options.Complete())

            if options.PrintIP {
                u, err := options.MasterArgs.GetMasterAddress()
                if err != nil {
                    glog.Fatal(err)
                }
                host, _, err := net.SplitHostPort(u.Host)
                if err != nil {
                    glog.Fatal(err)
                }
                fmt.Fprintf(out, "%s\n", host)
                return
            }
            kcmdutil.CheckErr(options.Validate(args))

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

    return cmd, options
}
```

- MasterOptions.StartMaster() @pkg/cmd/server/start/start_master.go

```go
// StartMaster calls RunMaster and then waits forever
func (o MasterOptions) StartMaster() error {
    if err := o.RunMaster(); err != nil {
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

- MasterOptions.RunMaster() @pkg/cmd/server/start/start_master.go

```go
// RunMaster takes the options and:
// 1.  Creates certs if needed
// 2.  Reads fully specified master config OR builds a fully specified master config from the args
// 3.  Writes the fully specified master config and exits if needed
// 4.  Starts the master based on the fully specified config
func (o MasterOptions) RunMaster() error {

<snip>

    m := &Master{
        config:      masterConfig,
        api:         o.MasterArgs.StartAPI,
        controllers: o.MasterArgs.StartControllers,
    }
    return m.Start()
}
```

- Master.Start() @pkg/cmd/server/start/start_master.go

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


## hypershiftコマンドで起動する場合

今回の調査とは直接関係はないですが、念のためざっと見ておきます。

### 関数呼び出しの流れ

- main() @cmd/hypershift/main.go
- NewHyperShiftCommand @cmd/hypershift/main.go
- NewOpenShiftControllerManagerCommand() @pkg/cmd/openshift-controller-manager/cmd.go
- OpenShiftControllerManager.StartControllerManager() @pkg/cmd/openshift-controller-manager/cmd.go
- OpenShiftControllerManager.RunControllerManager() @pkg/cmd/openshift-controller-manager/cmd.go
- ConvertMasterConfigToOpenshiftControllerConfig() @pkg/cmd/openshift-controller-manager/conversion.go

## xxx

- main() @cmd/hypershift/main.go

```go
func main() {
	rand.Seed(time.Now().UTC().UnixNano())

	pflag.CommandLine.SetNormalizeFunc(utilflag.WordSepNormalizeFunc)
	pflag.CommandLine.AddGoFlagSet(goflag.CommandLine)

	logs.InitLogs()
	defer logs.FlushLogs()
	defer serviceability.BehaviorOnPanic(os.Getenv("OPENSHIFT_ON_PANIC"), version.Get())()
	defer serviceability.Profile(os.Getenv("OPENSHIFT_PROFILE")).Stop()

	if len(os.Getenv("GOMAXPROCS")) == 0 {
		runtime.GOMAXPROCS(runtime.NumCPU())
	}

	command := NewHyperShiftCommand()
	if err := command.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
```

- NewHyperShiftCommand @cmd/hypershift/main.go

```go
func NewHyperShiftCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hypershift",
		Short: "Combined server command for OpenShift",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
			os.Exit(1)
		},
	}

	startEtcd, _ := openshift_etcd.NewCommandStartEtcdServer(openshift_etcd.RecommendedStartEtcdServerName, "hypershift", os.Stdout, os.Stderr)
	startEtcd.Deprecated = "will be removed in 3.10"
	startEtcd.Hidden = true
	cmd.AddCommand(startEtcd)

	startOpenShiftAPIServer := openshift_apiserver.NewOpenShiftAPIServerCommand(openshift_apiserver.RecommendedStartAPIServerName, "hypershift", os.Stdout, os.Stderr)
	cmd.AddCommand(startOpenShiftAPIServer)

	startOpenShiftKubeAPIServer := openshift_kube_apiserver.NewOpenShiftKubeAPIServerServerCommand(openshift_kube_apiserver.RecommendedStartAPIServerName, "hypershift", os.Stdout, os.Stderr)
	cmd.AddCommand(startOpenShiftKubeAPIServer)

	startOpenShiftControllerManager := openshift_controller_manager.NewOpenShiftControllerManagerCommand(openshift_controller_manager.RecommendedStartControllerManagerName, "hypershift", os.Stdout, os.Stderr)
	cmd.AddCommand(startOpenShiftControllerManager)

	experimental := openshift_experimental.NewExperimentalCommand(os.Stdout, os.Stderr)
	cmd.AddCommand(experimental)

	return cmd
}
```

- NewOpenShiftControllerManagerCommand() @pkg/cmd/openshift-controller-manager/cmd.go

```go
func NewOpenShiftControllerManagerCommand(name, basename string, out, errout io.Writer) *cobra.Command {
	options := &OpenShiftControllerManager{Output: out}

	cmd := &cobra.Command{
		Use:   name,
		Short: "Start the OpenShift controllers",
		Long:  longDescription,
		Run: func(c *cobra.Command, args []string) {
			kcmdutil.CheckErr(options.Validate())

			origin.StartProfiler()

			if err := options.StartControllerManager(); err != nil {
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

	flags := cmd.Flags()
	// This command only supports reading from config
	flags.StringVar(&options.ConfigFile, "config", options.ConfigFile, "Location of the master configuration file to run from.")
	cmd.MarkFlagFilename("config", "yaml", "yml")
	cmd.MarkFlagRequired("config")
	flags.StringVar(&options.KubeConfigFile, "kubeconfig", options.KubeConfigFile, "Location of the master configuration file to run from.")
	cmd.MarkFlagFilename("kubeconfig", "kubeconfig")

	return cmd
}
```

- OpenShiftControllerManager.StartControllerManager() @pkg/cmd/openshift-controller-manager/cmd.go

```go
// StartAPIServer calls RunAPIServer and then waits forever
func (o *OpenShiftControllerManager) StartControllerManager() error {
	if err := o.RunControllerManager(); err != nil {
		return err
	}

	go daemon.SdNotify(false, "READY=1")
	select {}
}
```

- OpenShiftControllerManager.RunControllerManager() @pkg/cmd/openshift-controller-manager/cmd.go

```go
// RunAPIServer takes the options and starts the etcd server
func (o *OpenShiftControllerManager) RunControllerManager() error {
	masterConfig, err := configapilatest.ReadAndResolveMasterConfig(o.ConfigFile)
	if err != nil {
		return err
	}

	validationResults := validation.ValidateMasterConfig(masterConfig, nil)
	if len(validationResults.Warnings) != 0 {
		for _, warning := range validationResults.Warnings {
			glog.Warningf("%v", warning)
		}
	}
	if len(validationResults.Errors) != 0 {
		return kerrors.NewInvalid(configapi.Kind("MasterConfig"), "master-config.yaml", validationResults.Errors)
	}

	config := ConvertMasterConfigToOpenshiftControllerConfig(masterConfig)
	clientConfig, err := configapi.GetKubeConfigOrInClusterConfig(o.KubeConfigFile, config.ClientConnectionOverrides)
	if err != nil {
		return err
	}

	return RunOpenShiftControllerManager(config, clientConfig)
}
```

- ConvertMasterConfigToOpenshiftControllerConfig() @pkg/cmd/openshift-controller-manager/conversion.go

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

	buildDefaults, err := getBuildDefaults(in.AdmissionConfig.PluginConfig)
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

# xxx

- OpenShiftControllerManager.RunControllerManager() @pkg/cmd/openshift-controller-manager/cmd.go

```go
// RunAPIServer takes the options and starts the etcd server
func (o *OpenShiftControllerManager) RunControllerManager() error {
	masterConfig, err := configapilatest.ReadAndResolveMasterConfig(o.ConfigFile)
	if err != nil {
		return err
	}

	validationResults := validation.ValidateMasterConfig(masterConfig, nil)
	if len(validationResults.Warnings) != 0 {
		for _, warning := range validationResults.Warnings {
			glog.Warningf("%v", warning)
		}
	}
	if len(validationResults.Errors) != 0 {
		return kerrors.NewInvalid(configapi.Kind("MasterConfig"), "master-config.yaml", validationResults.Errors)
	}

	config := ConvertMasterConfigToOpenshiftControllerConfig(masterConfig)
	clientConfig, err := configapi.GetKubeConfigOrInClusterConfig(o.KubeConfigFile, config.ClientConnectionOverrides)
	if err != nil {
		return err
	}

	return RunOpenShiftControllerManager(config, clientConfig)
}
```

- OpenShiftControllerManager.RunControllerManager() @pkg/cmd/openshift-controller-manager/controller_manager.go

```go
// RunAPIServer takes the options and starts the etcd server
func (o *OpenShiftControllerManager) RunControllerManager() error {
	masterConfig, err := configapilatest.ReadAndResolveMasterConfig(o.ConfigFile)
	if err != nil {
		return err
	}

	validationResults := validation.ValidateMasterConfig(masterConfig, nil)
	if len(validationResults.Warnings) != 0 {
		for _, warning := range validationResults.Warnings {
			glog.Warningf("%v", warning)
		}
	}
	if len(validationResults.Errors) != 0 {
		return kerrors.NewInvalid(configapi.Kind("MasterConfig"), "master-config.yaml", validationResults.Errors)
	}

	config := ConvertMasterConfigToOpenshiftControllerConfig(masterConfig)
	clientConfig, err := configapi.GetKubeConfigOrInClusterConfig(o.KubeConfigFile, config.ClientConnectionOverrides)
	if err != nil {
		return err
	}

	return RunOpenShiftControllerManager(config, clientConfig)
}
```

# xxx

- transitionToPhase() @pkg/build/controller/build/build_controller.go
o
```go
// transitionToPhase returns a buildUpdate object to transition a build to a new
// phase with the given reason and message
func transitionToPhase(phase buildv1.BuildPhase, reason buildv1.StatusReason, message string) *buildUpdate {
    update := &buildUpdate{}
    update.setPhase(phase)
    update.setReason(reason)
    update.setMessage(message)
    return update
}
```

# call graph

- main() @cmd/openshift/openshift.go
- CommandFor() @pkg/cmd/openshift/openshift.go
- NewCommandOpenShift() @pkg/cmd/openshift/openshift.go
- NewCommandStart() @pkg/cmd/server/start/start.go
- NewCommandStartMaster() @pkg/cmd/server/start/start\_master.go
- MasterOptions.StartMaster() @pkg/cmd/server/start/start\_master.go
- MasterOptions.RunMaster() @pkg/cmd/server/start/start\_master.go
- Master.Start() @pkg/cmd/server/start/start\_master.go
- RunOpenShiftControllerManager()

- main() @cmd/hypershift/main.go
- NewHyperShiftCommand() @cmd/hypershift/main.go
- NewOpenShiftControllerManagerCommand() @pkg/cmd/openshift-controller-manager/cmd.go
- OpenShiftControllerManager.StartControllerManager() @pkg/cmd/openshift-controller-manager/cmd.go
- OpenShiftControllerManager.RunControllerManager() @pkg/cmd/openshift-controller-manager/cmd.go
- RunOpenShiftControllerManager() @pkg/cmd/openshift-controller-manager/controller_manager.go

- startControllers() @pkg/cmd/openshift-controller-manager/controller_manager.go
- ControllerInitializers @pkg/cmd/openshift-controller-manager/controller/config.go
- RunBuildController() @pkg/cmd/openshift-controller-manager/controller/build.go
- BuildController.Run() @pkg/build/controller/build/build_controller.go
- BuildController.buildWorker() @pkg/build/controller/build/build_controller.go
- BuildController.buildWork() @pkg/build/controller/build/build_controller.go
- BuildController.handleBuild() @pkg/build/controller/build/build_controller.go
- BuildController.handleNewBuild() @pkg/build/controller/build/build_controller.go
- BuildController.createBuildPod() @pkg/build/controller/build/build_controller.go
- BuildController.createPodSpec() @pkg/build/controller/build/build_controller.go
- BuildDefaults.ApplyDefaults() @pkg/build/controller/build/defaults/defaults.go
- BuildDefaults.applyBuildDefaults() @pkg/build/controller/build/defaults/defaults.go
- addDefaultEnvVar() @pkg/build/controller/build/defaults/defaults.go
- SetBuildEnv() @pkg/build/util/util.go

# a


- main() @cmd/hypershift/main.go

```go
func main() {
    rand.Seed(time.Now().UTC().UnixNano())

    pflag.CommandLine.SetNormalizeFunc(utilflag.WordSepNormalizeFunc)
    pflag.CommandLine.AddGoFlagSet(goflag.CommandLine)

    logs.InitLogs()
    defer logs.FlushLogs()
    defer serviceability.BehaviorOnPanic(os.Getenv("OPENSHIFT_ON_PANIC"), version.Get())()
    defer serviceability.Profile(os.Getenv("OPENSHIFT_PROFILE")).Stop()

    if len(os.Getenv("GOMAXPROCS")) == 0 {
        runtime.GOMAXPROCS(runtime.NumCPU())
    }

    command := NewHyperShiftCommand()
    if err := command.Execute(); err != nil {
        fmt.Fprintf(os.Stderr, "%v\n", err)
        os.Exit(1)
    }
}
```

- NewHyperShiftCommand() @cmd/hypershift/main.go

```go
func NewHyperShiftCommand() *cobra.Command {
    cmd := &cobra.Command{
        Use:   "hypershift",
        Short: "Combined server command for OpenShift",
        Run: func(cmd *cobra.Command, args []string) {
            cmd.Help()
            os.Exit(1)
        },
    }

    startEtcd, _ := openshift_etcd.NewCommandStartEtcdServer(openshift_etcd.RecommendedStartEtcdServerName, "hypershift", os.Stdout, os.Stderr)
    startEtcd.Deprecated = "will be removed in 3.10"
    startEtcd.Hidden = true
    cmd.AddCommand(startEtcd)

    startOpenShiftAPIServer := openshift_apiserver.NewOpenShiftAPIServerCommand(openshift_apiserver.RecommendedStartAPIServerName, "hypershift", os.Stdout, os.Stderr)
    cmd.AddCommand(startOpenShiftAPIServer)

    startOpenShiftKubeAPIServer := openshift_kube_apiserver.NewOpenShiftKubeAPIServerServerCommand(openshift_kube_apiserver.RecommendedStartAPIServerName, "hypershift", os.Stdout, os.Stderr)
    cmd.AddCommand(startOpenShiftKubeAPIServer)

    startOpenShiftControllerManager := openshift_controller_manager.NewOpenShiftControllerManagerCommand(openshift_controller_manager.RecommendedStartControllerManagerName, "hypershift", os.Stdout, os.Stderr)
    cmd.AddCommand(startOpenShiftControllerManager)

    experimental := openshift_experimental.NewExperimentalCommand(os.Stdout, os.Stderr)
    cmd.AddCommand(experimental)

    return cmd
}
```

- NewOpenShiftControllerManagerCommand() @pkg/cmd/openshift-controller-manager/cmd.go

```go
func NewOpenShiftControllerManagerCommand(name, basename string, out, errout io.Writer) *cobra.Command {
    options := &OpenShiftControllerManager{Output: out}

    cmd := &cobra.Command{
        Use:   name,
        Short: "Start the OpenShift controllers",
        Long:  longDescription,
        Run: func(c *cobra.Command, args []string) {
            kcmdutil.CheckErr(options.Validate())

            origin.StartProfiler()

            if err := options.StartControllerManager(); err != nil {
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

    flags := cmd.Flags()
    // This command only supports reading from config
    flags.StringVar(&options.ConfigFile, "config", options.ConfigFile, "Location of the master configuration file to run from.")
    cmd.MarkFlagFilename("config", "yaml", "yml")
    cmd.MarkFlagRequired("config")
    flags.StringVar(&options.KubeConfigFile, "kubeconfig", options.KubeConfigFile, "Location of the master configuration file to run from.")
    cmd.MarkFlagFilename("kubeconfig", "kubeconfig")

    return cmd
}
```

- OpenShiftControllerManager.StartControllerManager() @pkg/cmd/openshift-controller-manager/cmd.go

```go
// StartAPIServer calls RunAPIServer and then waits forever
func (o *OpenShiftControllerManager) StartControllerManager() error {
    if err := o.RunControllerManager(); err != nil {
        return err
    }

    go daemon.SdNotify(false, "READY=1")
    select {}
}
```

- OpenShiftControllerManager.RunControllerManager() @pkg/cmd/openshift-controller-manager/cmd.go

```go
// RunAPIServer takes the options and starts the etcd server
func (o *OpenShiftControllerManager) RunControllerManager() error {
    masterConfig, err := configapilatest.ReadAndResolveMasterConfig(o.ConfigFile)
    if err != nil {
        return err
    }

    validationResults := validation.ValidateMasterConfig(masterConfig, nil)
    if len(validationResults.Warnings) != 0 {
        for _, warning := range validationResults.Warnings {
            glog.Warningf("%v", warning)
        }
    }
    if len(validationResults.Errors) != 0 {
        return kerrors.NewInvalid(configapi.Kind("MasterConfig"), "master-config.yaml", validationResults.Errors)
    }

    config := ConvertMasterConfigToOpenshiftControllerConfig(masterConfig)
    clientConfig, err := configapi.GetKubeConfigOrInClusterConfig(o.KubeConfigFile, config.ClientConnectionOverrides)
    if err != nil {
        return err
    }

    return RunOpenShiftControllerManager(config, clientConfig)
}
```

- RunOpenShiftControllerManager() @pkg/cmd/openshift-controller-manager/controller_manager.go

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
        if err := startControllers(controllerContext); err != nil {
            glog.Fatal(err)
        }
        controllerContext.StartInformers(stopCh)
    }

<snip>
```

- startControllers() @pkg/cmd/openshift-controller-manager/controller_manager.go

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
        started, err := initFn(controllerContext)
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

- ControllerInitializers @pkg/cmd/openshift-controller-manager/controller/config.go

```go
var ControllerInitializers = map[string]InitFunc{
    "openshift.io/serviceaccount": RunServiceAccountController,

    "openshift.io/namespace-security-allocation": RunNamespaceSecurityAllocationController,

    "openshift.io/default-rolebindings": RunDefaultRoleBindingController,

    "openshift.io/serviceaccount-pull-secrets": RunServiceAccountPullSecretsController,
    "openshift.io/origin-namespace":            RunOriginNamespaceController,
    "openshift.io/service-serving-cert":        RunServiceServingCertsController,

    "openshift.io/build":               RunBuildController,
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

- RunBuildController() @pkg/cmd/openshift-controller-manager/controller/build.go

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

    go buildcontroller.NewBuildController(buildControllerParams).Run(5, ctx.Stop)
    return true, nil
}
```

- BuildController.Run() @pkg/build/controller/build/build_controller.go

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
        go wait.Until(bc.buildWorker, time.Second, stopCh)
    }

    for i := 0; i < workers; i++ {
        go wait.Until(bc.buildConfigWorker, time.Second, stopCh)
    }

    metrics.IntializeMetricsCollector(bc.buildLister)

    <-stopCh
    glog.Infof("Shutting down build controller")
}
```

- BuildController.buildWorker() @pkg/build/controller/build/build_controller.go

```go
func (bc *BuildController) buildWorker() {
    for {
        if quit := bc.buildWork(); quit {
            return
        }
    }
}
```

- BuildController.buildWork() @pkg/build/controller/build/build_controller.go

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

    err = bc.handleBuild(build)
    bc.handleBuildError(err, key)
    return false
}
```

- BuildController.handleBuild() @pkg/build/controller/build/build_controller.go

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
        update, err = bc.handleNewBuild(build, pod)
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

- BuildController.handleNewBuild() @pkg/build/controller/build/build_controller.go

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

    return bc.createBuildPod(build)
}
```

- BuildController.createBuildPod() @pkg/build/controller/build/build_controller.go

```go
// createBuildPod creates a new pod to run a build
func (bc *BuildController) createBuildPod(build *buildv1.Build) (*buildUpdate, error) {
    update := &buildUpdate{}

<snip>

    // Create the build pod spec
    buildPod, err := bc.createPodSpec(build)
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

- BuildController.createPodSpec() @pkg/build/controller/build/build_controller.go

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
    if err := bc.buildDefaults.ApplyDefaults(podSpec); err != nil {
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

- BuildDefaults.ApplyDefaults() @pkg/build/controller/build/defaults/defaults.go

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
    b.applyBuildDefaults(build)

    glog.V(4).Infof("Applying defaults to pod %s/%s", pod.Namespace, pod.Name)
    b.applyPodDefaults(pod, build.Spec.Strategy.CustomStrategy != nil)

    err = setPodLogLevelFromBuild(pod, build)
    if err != nil {
        return err
    }

    return common.SetBuildInPod(pod, build)
}
```

- BuildDefaults.applyBuildDefaults() @pkg/build/controller/build/defaults/defaults.go

```go
func (b BuildDefaults) applyBuildDefaults(build *buildv1.Build) {
    // Apply default env
    for _, envVar := range b.Config.Env {
        glog.V(5).Infof("Adding default environment variable %s=%s to build %s/%s", envVar.Name, envVar.Value, build.Namespace, build.Name)
        externalEnv := corev1.EnvVar{}
        if err := legacyscheme.Scheme.Convert(&envVar, &externalEnv, nil); err != nil {
            panic(err)
        }
        addDefaultEnvVar(build, externalEnv)
    }

<snip>
```

- addDefaultEnvVar() @pkg/build/controller/build/defaults/defaults.go

```go
func addDefaultEnvVar(build *buildv1.Build, v corev1.EnvVar) {
    envVars := buildutil.GetBuildEnv(build)

    for i := range envVars {
        if envVars[i].Name == v.Name {
            return
        }
    }
    envVars = append(envVars, v)
    buildutil.SetBuildEnv(build, envVars)
}
```

- SetBuildEnv() @pkg/build/util/util.go

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
