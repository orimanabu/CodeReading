<details><summary>
[]()
</summary><div>
```go
```
</div>
</details>

<details><summary>
[origin.NewLeaderElection() @pkg/cmd/server/origin/leaderelection.go](https://github.com/openshift/origin/blob/release-3.6/pkg/cmd/server/origin/leaderelection.go)
</summary><div>

```go
// NewLeaderElection returns a plug that blocks controller startup until the lease is acquired
// and a function that will start the process to attain the lease. There are two modes for
// lease operation - a legacy mode that directly connects to etcd, and the preferred mode which
// coordinates on a service endpoints object in the kube-system namespace. The legacy mode will
// periodically poll to see if the endpoints object exists, and if so will stand down, allowing
// newer controllers to take over.
func NewLeaderElection(options configapi.MasterConfig, leader componentconfig.LeaderElectionConfiguration, kc kclientsetexternal.Interface) (plug.Plug, func(), error) {
    id := fmt.Sprintf("master-%s", kutilrand.String(8))
    name := "openshift-controller-manager"
    namespace := "kube-system"
    useEndpoints := false
    if election := options.ControllerConfig.Election; election != nil {
        if election.LockResource.Resource != "endpoints" || election.LockResource.Group != "" {
            return nil, nil, fmt.Errorf("only the \"endpoints\" resource is supported for election")
        }
        name = election.LockName
        namespace = election.LockNamespace
        useEndpoints = true
    }

    lock := &rl.EndpointsLock{
        EndpointsMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
        Client:        kc,
        LockConfig: rl.ResourceLockConfig{
            Identity: id,
        },
    }

    // legacy path, for native etcd leases. Will periodically check for the controller service to exist and
    // release any held lease if one is detected
    if !useEndpoints {
        ttl := time.Duration(options.ControllerLeaseTTL) * time.Second
        if ttl == 0 {
            return plug.New(!options.PauseControllers), func() {}, nil
        }

        client, err := etcd.MakeEtcdClient(options.EtcdClientInfo)
        if err != nil {
            return nil, nil, err
        }

        leaser := leaderlease.NewEtcd(
            client,
            path.Join(options.EtcdStorageConfig.OpenShiftStoragePrefix, "leases/controllers"),
            id,
            uint64(options.ControllerLeaseTTL),
        )

        leased := plug.NewLeased(leaser)
        return leased, legacyLeaderElectionStart(id, name, leased, lock, ttl), nil
    }
```
</div>
</details>

<details><summary>
[plug related @pkg/cmd/util/plug/plug.go]()
</summary><div>
```go
// Plug represents a synchronization primitive that holds and releases
// execution for other objects.
type Plug interface {
    // Begins operation of the plug and unblocks WaitForStart().
    // May be invoked multiple times but only the first invocation has
    // an effect.
    Start()
    // Ends operation of the plug and unblocks WaitForStop()
    // May be invoked multiple times but only the first invocation has
    // an effect. Calling Stop() before Start() is undefined. An error
    // may be returned with the stop.
    Stop(err error)
    // Blocks until Start() is invoked
    WaitForStart()
    // Blocks until Stop() is invoked
    WaitForStop() error
    // Returns true if Start() has been invoked
    IsStarted() bool
}

// plug is the default implementation of Plug
type plug struct {
    start   sync.Once
    stop    sync.Once
    startCh chan struct{}
    stopCh  chan error
}

// New returns a new plug that can begin in the Started state.
func New(started bool) Plug {
    p := &plug{
        startCh: make(chan struct{}),
        stopCh:  make(chan error, 1),
    }
    if started {
        p.Start()
    }
    return p
}
```
</div>
</details>

<details><summary>
[type leaderlease.Leaser interface @pkg/util/leaderlease/leaderlease.go]()
</summary><div>
```go
// Leaser allows a caller to acquire a lease and be notified when it is lost.
type Leaser interface {
    // AcquireAndHold tries to acquire the lease and hold it until it expires, the lease is lost,
    // or we observe another party take the lease. The provided function will be invoked when the
    // lease is acquired, and the provided channel will be closed when the lease is lost. If the
    // function returns true, the lease will be released on exit. If the function returns false,
    // the lease will be held.
    AcquireAndHold(chan error)
    // Release returns any active leases
    Release()
}
```
</div>
</details>

<details><summary>
[type leaderlease.Etcd struct @pkg/util/leaderlease/leaderlease.go]()
</summary><div>
```go
// Etcd takes and holds a leader lease until it can no longer confirm it owns
// the lease, then returns.
type Etcd struct {
    client     etcdclient.Client
    keysClient etcdclient.KeysAPI
    key        string
    value      string
    ttl        uint64

    // the fraction of the ttl to wait before trying to renew - for instance, 0.75 with TTL 20
    // will wait 15 seconds before attempting to renew the lease, then retry over the next 5
    // seconds in the event of an error no more than maxRetries times.
    waitFraction float32
    // the interval to wait when an error occurs acquiring the lease
    pauseInterval time.Duration
    // the maximum retries when releasing or renewing the lease
    maxRetries int
    // the shortest time between attempts to renew the lease
    minimumRetryInterval time.Duration
}
```
</div>
</details>

<details><summary>
[func leaderlease.NewEtcd() Leaser @pkg/util/leaderlease/leaderlease.go]()
</summary><div>
```go
// NewEtcd creates a Lease in etcd, storing value at key with expiration ttl
// and continues to refresh it until the key is lost, expires, or another
// client takes it.
func NewEtcd(client etcdclient.Client, key, value string, ttl uint64) Leaser {
    return &Etcd{
        client:     client,
        keysClient: etcdclient.NewKeysAPI(client),
        key:        key,
        value:      value,
        ttl:        ttl,

        waitFraction:         0.66,
        pauseInterval:        time.Second,
        maxRetries:           10,
        minimumRetryInterval: 100 * time.Millisecond,
    }
}
```
</div>
</details>

<details><summary>
[func NewLeased() *Leased @pkg/cmd/util/plug/plug.go]()
</summary><div>
```go
// Leaser controls access to a lease
type Leaser interface {
    // AcquireAndHold tries to acquire the lease and hold it until it expires, the lease is deleted,
    // or we observe another party take the lease. The notify channel will be sent a nil value
    // when the lease is held, and closed when the lease is lost. If an error is sent the lease
    // is also considered lost.
    AcquireAndHold(chan error)
    Release()
}

// leased uses a Leaser to control Start and Stop on a Plug
type Leased struct {
    Plug

    leaser Leaser
}

var _ Plug = &Leased{}

// NewLeased creates a Plug that starts when a lease is acquired
// and stops when it is lost.
func NewLeased(leaser Leaser) *Leased {
    return &Leased{
        Plug:   New(false),
        leaser: leaser,
    }
}
```
</div>
</details>

<details><summary>
[func legacyLeaderElectionStart() func() @pkg/cmd/server/origin/leaderelection.go]()
</summary><div>
```go
// legacyLeaderElectionStart waits to verify lock has not been taken, then attempts to acquire and hold
// the legacy lease. If it detects the lock is acquired it will stop immediately.
func legacyLeaderElectionStart(id, name string, leased *plug.Leased, lock rl.Interface, ttl time.Duration) func() {
    return func() {
        glog.V(2).Infof("Verifying no controller manager is running for %s", id)
        wait.PollInfinite(ttl/2, func() (bool, error) {
            _, err := lock.Get()
            if err == nil {
                return false, nil
            }
            if kapierrors.IsNotFound(err) {
                return true, nil
            }
            utilruntime.HandleError(fmt.Errorf("unable to confirm %s lease exists: %v", name, err))
            return false, nil
        })
        glog.V(2).Infof("Attempting to acquire controller lease as %s, renewing every %s", id, ttl)
        go leased.Run()
        go wait.PollInfinite(ttl/2, func() (bool, error) {
            _, err := lock.Get()
            if err == nil {
                glog.V(2).Infof("%s lease has been taken, %s is exiting", name, id)
                leased.Stop(nil)
                return true, nil
            }
            // NotFound indicates the endpoint is missing and the etcd lease should continue to be held
            if !kapierrors.IsNotFound(err) {
                utilruntime.HandleError(fmt.Errorf("unable to confirm %s lease exists: %v", name, err))
            }
            return false, nil
        })
    }
}
```
</div>
</details>

