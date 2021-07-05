# お題

kube-apiserverのデフォルトのスケジューラ設定を追う

## Environment
- OpenShift v4.7 (https://github.com/openshift/kubernetes/tree/oc-4.7-kubernetes-1.20.1)

(基本的にはk8s v1.20.1と同じ)

# 起動オプション

実際のコードを見る前に、OpenShift v4.7でのkube-apiserverの起動オプションを確認する。

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

# `main()` から `scheduler.New()` が呼ばれるまで

まず `main()` から `scheduler.New()` が呼ばれるまでを眺める。関数の呼び出しを追っているだけ。

1. `main.main()`

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

2. `app.NewSchedulerCommand()`
1. `app.runCommand()`
1. `app.Setup()`
1. `scheduler.New()`

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

# `scheduler.New()` の中

<details open>
<summary>scheduler.New() @pkg/scheduler/scheduler.go</summary>

- scheduler.New() @pkg/scheduler/scheduler.go

```go
// New returns a Scheduler
func New(client clientset.Interface,
        informerFactory informers.SharedInformerFactory,
        recorderFactory profile.RecorderFactory,
        stopCh <-chan struct{},
        opts ...Option) (*Scheduler, error) {

<snip>

        options := defaultSchedulerOptions // HERE

<snip>

        var sched *Scheduler
        source := options.schedulerAlgorithmSource // HERE
        switch {
        case source.Provider != nil:
                // Create the config from a named algorithm provider.
                sc, err := configurator.createFromProvider(*source.Provider) // HERE
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
</details>

## 処理の流れ
defaultSchedulerOptions.schedulerAlgorithmSource.Providerには `"DefaultProvider"` が入っている。

なので、switch文の `case source.Provider != nil` に入って、`configurator.createFromProvider("DefaultProvider")` を呼ぶ。

<details>
<summary>defaultSchedulerOptionsは `type schedulerOptions struct` @pkg/scheduler/scheduler.go</summary>
- scheduler.defaultSchedulerOptions @pkg/scheduler/scheduler.go

```go
import (
        schedulerapi "k8s.io/kubernetes/pkg/scheduler/apis/config"
)

<snip>

var defaultSchedulerOptions = schedulerOptions{
        profiles: []schedulerapi.KubeSchedulerProfile{
                // Profiles' default plugins are set from the algorithm provider.
                {SchedulerName: v1.DefaultSchedulerName},
        },
        schedulerAlgorithmSource: schedulerapi.SchedulerAlgorithmSource{ // HERE
                Provider: defaultAlgorithmSourceProviderName(),          // HERE
        },                                                               // HERE
        percentageOfNodesToScore: schedulerapi.DefaultPercentageOfNodesToScore,
        podInitialBackoffSeconds: int64(internalqueue.DefaultPodInitialBackoffDuration.Seconds()),
        podMaxBackoffSeconds:     int64(internalqueue.DefaultPodMaxBackoffDuration.Seconds()),
}
```
- scheduler.schedulerOptions @pkg/scheduler/scheduler.go

```go
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
</details>

<details>
<summary>`schedulerapi.SchedulerAlgorithmSource struct` の定義 @pkg/scheduler/apis/config/types.go</summary>

- schedulerapi.SchedulerAlgorithmSource @pkg/scheduler/apis/config/types.go

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
</details>

<details>
<summary>`defaultAlgorithmSourceProviderName()` は `"DefaultProvider"` を返す @pkg/scheduler/scheduler.go</summary>

- scheduler.defaultAlgorithmSourceProviderName() @pkg/scheduler/scheduler.go

```go
func defaultAlgorithmSourceProviderName() *string {
        provider := schedulerapi.SchedulerDefaultProviderName
        Return &provider
}
```

- schedulerapi.SchedulerDefaultProviderName @pkg/scheduler/apis/config/types.go

```go
const (

        // SchedulerDefaultProviderName defines the default provider names
        SchedulerDefaultProviderName = "DefaultProvider"

)
```
</details>


## その他の登場人物 (直接は関係ない)
一応 SchedulerAlgorithmSource.Policy に何が入ているかを確認しておく
<details>
<summary>SchedulerAlgorithmSource.Policy</summary>

---

<details>
<summary>    SchedulerPolicySource @pkg/scheduler/apis/config/types.go</summary>

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
</details>

<details>
<summary>SchedulerPolicyFileSource @pkg/scheduler/apis/config/types.go</summary>

- SchedulerPolicyFileSource @pkg/scheduler/apis/config/types.go

```go
// SchedulerPolicyFileSource is a policy serialized to disk and accessed via
// path.
type SchedulerPolicyFileSource struct {
        // Path is the location of a serialized policy.
        Path string
}
```
</details>

<details>
<summary>SchedulerPolicyConfigMapSource @pkg/scheduler/apis/config/types.go</summary>

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
</details>

---

</details>

# `configurator.createFromProvider(*source.Provider)` の中

`*source.Provider` には `"DefaultProvider"` が入っている。

<details>
<summary>scheduler.Configurator.createFromProvider() @pkg/scheduler/factory.go</summary>

- scheduler.Configurator.createFromProvider() @pkg/scheduler/factory.go

```go
// createFromProvider creates a scheduler from the name of a registered algorithm provider.
func (c *Configurator) createFromProvider(providerName string) (*Scheduler, error) {
        klog.V(2).Infof("Creating scheduler from algorithm provider '%v'", providerName)
        r := algorithmprovider.NewRegistry() // HERE
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
</details>

<details>
<summary>type Configurator struct @pkg/scheduler/factory.go</summary>

- type Configurator struct @pkg/scheduler/factory.go
```go
// Configurator defines I/O, caching, and other functionality needed to
// construct a new scheduler.
type Configurator struct {
        client clientset.Interface

        recorderFactory profile.RecorderFactory

        informerFactory informers.SharedInformerFactory

        // Close this to stop all reflectors
        StopEverything <-chan struct{}

        schedulerCache internalcache.Cache

        // Always check all predicates even if the middle of one predicate fails.
        alwaysCheckAllPredicates bool

        // percentageOfNodesToScore specifies percentage of all nodes to score in each scheduling cycle.
        percentageOfNodesToScore int32

        podInitialBackoffSeconds int64

        podMaxBackoffSeconds int64

        profiles          []schedulerapi.KubeSchedulerProfile
        registry          frameworkruntime.Registry
        nodeInfoSnapshot  *internalcache.Snapshot
        extenders         []schedulerapi.Extender
        frameworkCapturer FrameworkCapturer
}
```
</details>

## 流れ
1. `algorithmprovider.NewRegistry()`
  1. `algorithmprovider.getDefaultConfig()`
  1. `algorithmprovider.applyFeatureGates()`

<details>
<summary>algorithmprovider.NewRegistry() @pkg/scheduler/algorithmprovider/registry.go</summary>

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
</details>

<details>
<summary>algorithmprovider.getDefaultConfig() @pkg/scheduler/algorithmprovider/registry.go</summary>

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
</details>

<details>
<summary>algorithmprovider.applyFeatureGates() @pkg/scheduler/algorithmprovider/registry.go</summary>

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
</details>



<details>
<summary>schedulerapi.KubeSchedulerProfile struct @pkg/scheduler/apis/config/types.go</summary>

- schedulerapi.KubeSchedulerProfile struct @pkg/scheduler/apis/config/types.go

```go
// KubeSchedulerProfile is a scheduling profile.
type KubeSchedulerProfile struct {
        // SchedulerName is the name of the scheduler associated to this profile.
        // If SchedulerName matches with the pod's "spec.schedulerName", then the pod
        // is scheduled with this profile.
        SchedulerName string

        // Plugins specify the set of plugins that should be enabled or disabled.
        // Enabled plugins are the ones that should be enabled in addition to the
        // default plugins. Disabled plugins are any of the default plugins that
        // should be disabled.
        // When no enabled or disabled plugin is specified for an extension point,
        // default plugins for that extension point will be used if there is any.
        // If a QueueSort plugin is specified, the same QueueSort Plugin and
        // PluginConfig must be specified for all profiles.
        Plugins *Plugins

        // PluginConfig is an optional set of custom plugin arguments for each plugin.
        // Omitting config args for a plugin is equivalent to using the default config
        // for that plugin.
        PluginConfig []PluginConfig
}
```
</details>

<details>
<summary>type Plugins struct @pkg/scheduler/apis/config/types.go</summary>

- type Plugins struct @pkg/scheduler/apis/config/types.go

```go
// Plugins include multiple extension points. When specified, the list of plugins for
// a particular extension point are the only ones enabled. If an extension point is
// omitted from the config, then the default set of plugins is used for that extension point.
// Enabled plugins are called in the order specified here, after default plugins. If they need to
// be invoked before default plugins, default plugins must be disabled and re-enabled here in desired order.
type Plugins struct {
        // QueueSort is a list of plugins that should be invoked when sorting pods in the scheduling queue.
        QueueSort *PluginSet

        // PreFilter is a list of plugins that should be invoked at "PreFilter" extension point of the scheduling framework.
        PreFilter *PluginSet

        // Filter is a list of plugins that should be invoked when filtering out nodes that cannot run the Pod.
        Filter *PluginSet

        // PostFilter is a list of plugins that are invoked after filtering phase, no matter whether filtering succeeds or not.
        PostFilter *PluginSet

        // PreScore is a list of plugins that are invoked before scoring.
        PreScore *PluginSet

        // Score is a list of plugins that should be invoked when ranking nodes that have passed the filtering phase.
        Score *PluginSet

        // Reserve is a list of plugins invoked when reserving/unreserving resources
        // after a node is assigned to run the pod.
        Reserve *PluginSet

        // Permit is a list of plugins that control binding of a Pod. These plugins can prevent or delay binding of a Pod.
        Permit *PluginSet

        // PreBind is a list of plugins that should be invoked before a pod is bound.
        PreBind *PluginSet

        // Bind is a list of plugins that should be invoked at "Bind" extension point of the scheduling framework.
        // The scheduler call these plugins in order. Scheduler skips the rest of these plugins as soon as one returns success.
        Bind *PluginSet

        // PostBind is a list of plugins that should be invoked after a pod is successfully bound.
        PostBind *PluginSet
}
```
</details>

<details>
<summary>type PluginSet struct @pkg/scheduler/apis/config/types.go</summary>

- type PluginSet struct @pkg/scheduler/apis/config/types.go

```go
// PluginSet specifies enabled and disabled plugins for an extension point.
// If an array is empty, missing, or nil, default plugins at that extension point will be used.
type PluginSet struct {
        // Enabled specifies plugins that should be enabled in addition to default plugins.
        // These are called after default plugins and in the same order specified here.
        Enabled []Plugin
        // Disabled specifies default plugins that should be disabled.
        // When all default plugins need to be disabled, an array containing only one "*" should be provided.
        Disabled []Plugin
}
```
</details>

<details>
<summary>type Plugin struct @pkg/scheduler/apis/config/types.go</summary>

- type Plugin struct @pkg/scheduler/apis/config/types.go

```go
// Plugin specifies a plugin name and its weight when applicable. Weight is used only for Score plugins.
type Plugin struct {
        // Name defines the name of plugin
        Name string
        // Weight defines the weight of plugin, only used for Score plugins.
        Weight int32
}
```
</details>


<!--
<details>
<summary>
</summary>
- 

```go

```
</details>
-->
