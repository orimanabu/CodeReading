# お題

kube-apiserverのデフォルトのスケジューラ設定を追う

## Environment
- OpenShift v4.7 (https://github.com/openshift/kubernetes/tree/oc-4.7-kubernetes-1.20.1)

(基本的にはk8s v1.20.1と同じ)

# Code Reading

## 起動オプション

```sh
watch-termination --termination-touch-file=/var/log/kube-apiserver/.terminating --termination-log-file=/var/log/kube-apiserver/termination.log --graceful-termination-duration=135s --kubeconfig=/etc/kubernetes/static-pod-resources/configmaps/kube-apiserver-cert-syncer-kubeconfig/kubeconfig -- hyperkube kube-apiserver --openshift-config=/etc/kubernetes/static-pod-resources/configmaps/config/config.yaml --advertise-address=${HOST_IP}  -v=2
```
OpenShift的な事情があってwatch-terminationという謎プロセスの子プロセスとして起動しているが、ここは今回の本質じゃないので流す。

hyperkubeはkube-apiserverを呼び出すだけのシェルスクリプト。

`config.yaml` はmasterノードの `/etc/kubernetes/static-pod-resources/kube-apiserver-pod-*/configmaps/config/config.yaml` をhostPathでマウントしている。

```yaml
    volumeMounts:
    - mountPath: /etc/kubernetes/static-pod-resources
      name: resource-dir

<snip>

  volumes:
  - hostPath:
      path: /etc/kubernetes/static-pod-resources/kube-apiserver-pod-10
      type: ""
    name: resource-dir
```

config.yamlは拡張子がyamlなのに中身はjson...なのは置いておいて、スケジューラ設定に関する設定は入ってなさそう。

念のためconfig.yamlの中のfeature-gatesをメモしておく。

```sh
$ sudo jq '.apiServerArguments."feature-gates"' /etc/kubernetes/static-pod-resources/kube-apiserver-pod-10/configmaps/config/config.yaml 
[
  "APIPriorityAndFairness=true",
  "RotateKubeletServerCertificate=true",
  "SupportPodPidsLimit=true",
  "NodeDisruptionExclusion=true",
  "ServiceNodeExclusion=true",
  "SCTPSupport=true",
  "LegacyNodeRoleBehavior=false",
  "RemoveSelfLink=false"
]
```

## `main()` から `scheduler.New()` が呼ばれるまで

まず `main()` から `scheduler.New()` が呼ばれるまでを眺める。関数の呼び出しを追っているだけ。

1. `main.main()`
1. `app.NewSchedulerCommand()`
1. `app.runCommand()`
1. `app.Setup()`
1. `scheduler.New()`

<details>
<summary>main.main() @cmd/kube-scheduler/scheduler.go</summary>

- main.main() @cmd/kube-scheduler/scheduler.go

```go
func main() {
        rand.Seed(time.Now().UnixNano())

        command := app.NewSchedulerCommand()

        // TODO: once we switch everything over to Cobra commands, we can go back to calling
        // utilflag.InitFlags() (by removing its pflag.Parse() call). For now, we have to set the
        // normalize func and add the go flag set by hand.
        pflag.CommandLine.SetNormalizeFunc(cliflag.WordSepNormalizeFunc)
        // utilflag.InitFlags()
        logs.InitLogs()
        defer logs.FlushLogs()

        if err := command.Execute(); err != nil {
                os.Exit(1)
        }
}
```
</details>

<details>
<summary>app.NewSchedulerCommand() @cmd/kube-scheduler/app/server.go</summary>

- app.NewSchedulerCommand() @cmd/kube-scheduler/app/server.go

```go
// NewSchedulerCommand creates a *cobra.Command object with default parameters and registryOptions
func NewSchedulerCommand(registryOptions ...Option) *cobra.Command {

<snip>

        cmd := &cobra.Command{
                Use: "kube-scheduler",
                Long: `The Kubernetes scheduler is a control plane process which assigns
Pods to Nodes. The scheduler determines which Nodes are valid placements for
each Pod in the scheduling queue according to constraints and available
resources. The scheduler then ranks each valid Node and binds the Pod to a
suitable Node. Multiple different schedulers may be used within a cluster;
kube-scheduler is the reference implementation.
See [scheduling](https://kubernetes.io/docs/concepts/scheduling-eviction/)
for more information about scheduling and the kube-scheduler component.`,
                Run: func(cmd *cobra.Command, args []string) {
                        if err := runCommand(cmd, opts, registryOptions...); err != nil {
                                fmt.Fprintf(os.Stderr, "%v\n", err)
                                os.Exit(1)
                        }
                },
                Args: func(cmd *cobra.Command, args []string) error {
                        for _, arg := range args {
                                if len(arg) > 0 {
                                        return fmt.Errorf("%q does not take any arguments, got %q", cmd.CommandPath(), args)
                                }
                        }
                        return nil
                },
        }
```
</details>

<details>
<summary>app.runCommand() @cmd/kube-scheduler/app/server.go</summary>

- app.runCommand() @cmd/kube-scheduler/app/server.go

```go
// runCommand runs the scheduler.
func runCommand(cmd *cobra.Command, opts *options.Options, registryOptions ...Option) error {
        verflag.PrintAndExitIfRequested()
        cliflag.PrintFlags(cmd.Flags())

        ctx, cancel := context.WithCancel(context.Background())
        defer cancel()

        cc, sched, err := Setup(ctx, opts, registryOptions...)
        if err != nil {
                return err
        }

        return Run(ctx, cc, sched)
}
```
</details>

<details>
<summary>app.Setup() @cmd/kube-scheduler/app/server.go</summary>

- app.Setup() @cmd/kube-scheduler/app/server.go

```go
// Setup creates a completed config and a scheduler based on the command args and options
func Setup(ctx context.Context, opts *options.Options, outOfTreeRegistryOptions ...Option) (*schedulerserverconfig.CompletedConfig, *scheduler.Scheduler, error) {

<snip>

        // Create the scheduler.
        sched, err := scheduler.New(cc.Client,
                cc.InformerFactory,
                recorderFactory,
                ctx.Done(),
                scheduler.WithProfiles(cc.ComponentConfig.Profiles...),
                scheduler.WithAlgorithmSource(cc.ComponentConfig.AlgorithmSource),
                scheduler.WithPercentageOfNodesToScore(cc.ComponentConfig.PercentageOfNodesToScore),
                scheduler.WithFrameworkOutOfTreeRegistry(outOfTreeRegistry),
                scheduler.WithPodMaxBackoffSeconds(cc.ComponentConfig.PodMaxBackoffSeconds),
                scheduler.WithPodInitialBackoffSeconds(cc.ComponentConfig.PodInitialBackoffSeconds),
                scheduler.WithExtenders(cc.ComponentConfig.Extenders...),
                scheduler.WithParallelism(cc.ComponentConfig.Parallelism),
                scheduler.WithBuildFrameworkCapturer(func(profile kubeschedulerconfig.KubeSchedulerProfile) {
                        // Profiles are processed during Framework instantiation to set default plugins and configurations. Capturing them for logging
                        completedProfiles = append(completedProfiles, profile)
                }),
        )

```
</details>

## `scheduler.New()` の中

1. `options := defaultSchedulerOptions`
1. `source := options.schedulerAlgorithmSource`

`source` には `{Provider: "DefaultProvider"}` が入る

1. switch文の `case source.Provider != nil` に入る

`configurator.createFromProvider("DefaultProvider")` を呼ぶ

- scheduler.New() @pkg/scheduler/scheduler.go

```go
// New returns a Scheduler
func New(client clientset.Interface,
        informerFactory informers.SharedInformerFactory,
        recorderFactory profile.RecorderFactory,
        stopCh <-chan struct{},
        opts ...Option) (*Scheduler, error) {

<snip>

        options := defaultSchedulerOptions

<snip>

        var sched *Scheduler
        source := options.schedulerAlgorithmSource
        switch {
        case source.Provider != nil:
                // Create the config from a named algorithm provider.
                sc, err := configurator.createFromProvider(*source.Provider)
                if err != nil {
                        return nil, fmt.Errorf("couldn't create scheduler using provider %q: %v", *source.Provider, err)
                }
                sched = sc
        case source.Policy != nil:
                // Create the config from a user specified policy source.
                policy := &schedulerapi.Policy{}
                switch {
                case source.Policy.File != nil:
                        if err := initPolicyFromFile(source.Policy.File.Path, policy); err != nil {
                                return nil, err
                        }
                case source.Policy.ConfigMap != nil:
                        if err := initPolicyFromConfigMap(client, source.Policy.ConfigMap, policy); err != nil {
                                return nil, err
                        }
                }
                // Set extenders on the configurator now that we've decoded the policy
                // In this case, c.extenders should be nil since we're using a policy (and therefore not componentconfig,
                // which would have set extenders in the above instantiation of Configurator from CC options)
                configurator.extenders = policy.Extenders
                sc, err := configurator.createFromConfig(*policy)
                if err != nil {
                        return nil, fmt.Errorf("couldn't create scheduler from policy: %v", err)
                }
                sched = sc
        default:
                return nil, fmt.Errorf("unsupported algorithm source: %v", source)
        }
```

### `defaultSchedulerOptions`

- defaultSchedulerOptions @pkg/scheduler/scheduler.go

```go
var defaultSchedulerOptions = schedulerOptions{
        profiles: []schedulerapi.KubeSchedulerProfile{
                // Profiles' default plugins are set from the algorithm provider.
                {SchedulerName: v1.DefaultSchedulerName},
        },
        schedulerAlgorithmSource: schedulerapi.SchedulerAlgorithmSource{
                Provider: defaultAlgorithmSourceProviderName(),
        },
        percentageOfNodesToScore: schedulerapi.DefaultPercentageOfNodesToScore,
        podInitialBackoffSeconds: int64(internalqueue.DefaultPodInitialBackoffDuration.Seconds()),
        podMaxBackoffSeconds:     int64(internalqueue.DefaultPodMaxBackoffDuration.Seconds()),
}
```

- defaultAlgorithmSourceProviderName() @pkg/scheduler/scheduler.go

```go
func defaultAlgorithmSourceProviderName() *string {
        provider := schedulerapi.SchedulerDefaultProviderName
        Return &provider
}
```

- @pkg/scheduler/apis/config/types.go

```go
const (

        // SchedulerDefaultProviderName defines the default provider names
        SchedulerDefaultProviderName = "DefaultProvider"

)
```

### `source := options.schedulerAlgorithmSource`

- schedulerOptions @pkg/scheduler/scheduler.go

```go
import (
        schedulerapi "k8s.io/kubernetes/pkg/scheduler/apis/config"
)

<snip>

type schedulerOptions struct {
        schedulerAlgorithmSource schedulerapi.SchedulerAlgorithmSource
        percentageOfNodesToScore int32
        podInitialBackoffSeconds int64
        podMaxBackoffSeconds     int64
        // Contains out-of-tree plugins to be merged with the in-tree registry.
        frameworkOutOfTreeRegistry frameworkruntime.Registry
        profiles                   []schedulerapi.KubeSchedulerProfile
        extenders                  []schedulerapi.Extender
        frameworkCapturer          FrameworkCapturer
}
```

### `schedulerapi.SchedulerAlgorithmSource`

- SchedulerAlgorithmSource @pkg/scheduler/apis/config/types.go

```go
// SchedulerAlgorithmSource is the source of a scheduler algorithm. One source
// field must be specified, and source fields are mutually exclusive.
type SchedulerAlgorithmSource struct {
        // Policy is a policy based algorithm source.
        Policy *SchedulerPolicySource
        // Provider is the name of a scheduling algorithm provider to use.
        Provider *string
}
```

- SchedulerPolicySource @pkg/scheduler/apis/config/types.go

```go
// SchedulerPolicySource configures a means to obtain a scheduler Policy. One
// source field must be specified, and source fields are mutually exclusive.
type SchedulerPolicySource struct {
        // File is a file policy source.
        File *SchedulerPolicyFileSource
        // ConfigMap is a config map policy source.
        ConfigMap *SchedulerPolicyConfigMapSource
}
```

- SchedulerPolicyFileSource @pkg/scheduler/apis/config/types.go

```go
// SchedulerPolicyFileSource is a policy serialized to disk and accessed via
// path.
type SchedulerPolicyFileSource struct {
        // Path is the location of a serialized policy.
        Path string
}
```

- SchedulerPolicyConfigMapSource @pkg/scheduler/apis/config/types.go

```go
// SchedulerPolicyConfigMapSource is a policy serialized into a config map value
// under the SchedulerPolicyConfigMapKey key.
type SchedulerPolicyConfigMapSource struct {
        // Namespace is the namespace of the policy config map.
        Namespace string
        // Name is the name of the policy config map.
        Name string
}
```

## `configurator.createFromProvider(*source.Provider)` の中

`*source.Provider = "DefaultProvider"`

1. `scheduler.Configurator.createFromProvider()`
1. `algorithmprovider.NewRegistry()`
1. `algorithmprovider.getDefaultConfig()`
1. `algorithmprovider.applyFeatureGates()`

- scheduler.Configurator.createFromProvider() @pkg/scheduler/factory.go

```go
// createFromProvider creates a scheduler from the name of a registered algorithm provider.
func (c *Configurator) createFromProvider(providerName string) (*Scheduler, error) {
        klog.V(2).Infof("Creating scheduler from algorithm provider '%v'", providerName)
        r := algorithmprovider.NewRegistry()
        defaultPlugins, exist := r[providerName]
        if !exist {
                return nil, fmt.Errorf("algorithm provider %q is not registered", providerName)
        }

        for i := range c.profiles {
                prof := &c.profiles[i]
                plugins := &schedulerapi.Plugins{}
                plugins.Append(defaultPlugins)
                plugins.Apply(prof.Plugins)
                prof.Plugins = plugins
        }
        return c.create()
}
```

- algorithmprovider.NewRegistry() @pkg/scheduler/algorithmprovider/registry.go

```go
// Registry is a collection of all available algorithm providers.
type Registry map[string]*schedulerapi.Plugins

// NewRegistry returns an algorithm provider registry instance.
func NewRegistry() Registry {
        defaultConfig := getDefaultConfig()
        applyFeatureGates(defaultConfig)

        caConfig := getClusterAutoscalerConfig()
        applyFeatureGates(caConfig)

        return Registry{
                schedulerapi.SchedulerDefaultProviderName: defaultConfig,
                ClusterAutoscalerProvider:                 caConfig,
        }
}
```

- algorithmprovider.getDefaultConfig() @pkg/scheduler/algorithmprovider/registry.go

```go
func getDefaultConfig() *schedulerapi.Plugins {
        return &schedulerapi.Plugins{

<snip>

                PreFilter: &schedulerapi.PluginSet{
                        Enabled: []schedulerapi.Plugin{
                                {Name: noderesources.FitName},
                                {Name: nodeports.Name},
                                {Name: podtopologyspread.Name},
                                {Name: interpodaffinity.Name},
                                {Name: volumebinding.Name},
                        },
                },
                Filter: &schedulerapi.PluginSet{
                        Enabled: []schedulerapi.Plugin{
                                {Name: nodeunschedulable.Name},
                                {Name: nodename.Name},
                                {Name: tainttoleration.Name},
                                {Name: nodeaffinity.Name},
                                {Name: nodeports.Name},
                                {Name: noderesources.FitName},
                                {Name: volumerestrictions.Name},
                                {Name: nodevolumelimits.EBSName},
                                {Name: nodevolumelimits.GCEPDName},
                                {Name: nodevolumelimits.CSIName},
                                {Name: nodevolumelimits.AzureDiskName},
                                {Name: volumebinding.Name},
                                {Name: volumezone.Name},
                                {Name: podtopologyspread.Name},
                                {Name: interpodaffinity.Name},
                        },
                },

<snip>

                PreScore: &schedulerapi.PluginSet{
                        Enabled: []schedulerapi.Plugin{
                                {Name: interpodaffinity.Name},
                                {Name: podtopologyspread.Name},
                                {Name: tainttoleration.Name},
                        },
                },
                Score: &schedulerapi.PluginSet{
                        Enabled: []schedulerapi.Plugin{
                                {Name: noderesources.BalancedAllocationName, Weight: 1},
                                {Name: imagelocality.Name, Weight: 1},
                                {Name: interpodaffinity.Name, Weight: 1},
                                {Name: noderesources.LeastAllocatedName, Weight: 1},
                                {Name: nodeaffinity.Name, Weight: 1},
                                {Name: nodepreferavoidpods.Name, Weight: 10000},
                                // Weight is doubled because:
                                // - This is a score coming from user preference.
                                // - It makes its signal comparable to NodeResourcesLeastAllocated.
                                {Name: podtopologyspread.Name, Weight: 2},
                                {Name: tainttoleration.Name, Weight: 1},
                        },
                },


```

- algorithmprovider.applyFeatureGates() @pkg/scheduler/algorithmprovider/registry.go

```go
func applyFeatureGates(config *schedulerapi.Plugins) {
        if !utilfeature.DefaultFeatureGate.Enabled(features.DefaultPodTopologySpread) {
                // When feature is enabled, the default spreading is done by
                // PodTopologySpread plugin, which is enabled by default.
                klog.Infof("Registering SelectorSpread plugin")
                s := schedulerapi.Plugin{Name: selectorspread.Name}
                config.PreScore.Enabled = append(config.PreScore.Enabled, s)
                s.Weight = 1
                config.Score.Enabled = append(config.Score.Enabled, s)
        }
}

```
