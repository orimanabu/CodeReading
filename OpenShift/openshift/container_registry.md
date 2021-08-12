# 目的

OpenShiftの内部コンテナレジストリがデータをストレージに書く際、atomicityを考慮しているか (partial writeが発生しないような処理があるか) を調査する

ざっとgrepした感じ、

- func Commit() @vendor/github.com/docker/distribution/registry/storage/blobwriter.go

辺りがそれっぽい。

```go
// Commit marks the upload as completed, returning a valid descriptor. The
// final size and digest are checked against the first descriptor provided.
func (bw *blobWriter) Commit(ctx context.Context, desc distribution.Descriptor) (distribution.Descriptor, error) {
        dcontext.GetLogger(ctx).Debug("(*blobWriter).Commit")

        if err := bw.fileWriter.Commit(); err != nil {
                return distribution.Descriptor{}, err
        }

        bw.Close()
        desc.Size = bw.Size()

        canonical, err := bw.validateBlob(ctx, desc)
        if err != nil {
                return distribution.Descriptor{}, err
        }

        if err := bw.moveBlob(ctx, canonical); err != nil {
                return distribution.Descriptor{}, err
        }

        if err := bw.blobStore.linkBlob(ctx, canonical, desc.Digest); err != nil {
                return distribution.Descriptor{}, err
        }

        if err := bw.removeResources(ctx); err != nil {
                return distribution.Descriptor{}, err
        }

        err = bw.blobStore.blobAccessController.SetDescriptor(ctx, canonical.Digest, canonical)
        if err != nil {
                return distribution.Descriptor{}, err
        }

        bw.committed = true
        return canonical, nil
}
```

これを呼び出しているのは

- `pkg/dockerregistry/server/wrapped/blobwriter.go`
- `pkg/dockerregistry/server/pullthroughblobstore.go`
- `pkg/dockerregistry/server/quotarestrictedblobstore.go`
- `vendor/github.com/docker/distribution/notifications/listener.go`
- `vendor/github.com/docker/distribution/registry/proxy/proxyblobstore.go`
- `vendor/github.com/docker/distribution/registry/storage/blobwriter.go`

この辺りか

# 挙動の調査

inotify-tools入れたprivilegedコンテナでemptyPathのコンテナレジストリのストレージを見てみると、push時は一時的に `_upload` というディレクトリを掘ってその下にアップロードし、完了すると正規のblob用ディレクトリに移動して `_upload` ディレクトリを消す、みたいな動きをしているように見える。

ソース的にはこの辺りが参考になりそう。

<details>
<summary>
func pathFor() @vendor/github.com/docker/distribution/registry/storage/paths.go
</summary>

```go
// pathFor maps paths based on "object names" and their ids. The "object
// names" mapped by are internal to the storage system.
//
// The path layout in the storage backend is roughly as follows:
//
//              <root>/v2
//                      -> repositories/
//                              -><name>/
//                                      -> _manifests/
//                                              revisions
//                                                      -> <manifest digest path>
//                                                              -> link
//                                              tags/<tag>
//                                                      -> current/link
//                                                      -> index
//                                                              -> <algorithm>/<hex digest>/link
//                                      -> _layers/
//                                              <layer links to blob store>
//                                      -> _uploads/<id>
//                                              data
//                                              startedat
//                                              hashstates/<algorithm>/<offset>
//                      -> blob/<algorithm>
//                              <split directory content addressable storage>
//
// The storage backend layout is broken up into a content-addressable blob
// store and repositories. The content-addressable blob store holds most data
// throughout the backend, keyed by algorithm and digests of the underlying
// content. Access to the blob store is controlled through links from the
// repository to blobstore.
//
// A repository is made up of layers, manifests and tags. The layers component
// is just a directory of layers which are "linked" into a repository. A layer
// can only be accessed through a qualified repository name if it is linked in
// the repository. Uploads of layers are managed in the uploads directory,
// which is key by upload id. When all data for an upload is received, the
// data is moved into the blob store and the upload directory is deleted.
// Abandoned uploads can be garbage collected by reading the startedat file
// and removing uploads that have been active for longer than a certain time.
//
// The third component of the repository directory is the manifests store,
// which is made up of a revision store and tag store. Manifests are stored in
// the blob store and linked into the revision store.
// While the registry can save all revisions of a manifest, no relationship is
// implied as to the ordering of changes to a manifest. The tag store provides
// support for name, tag lookups of manifests, using "current/link" under a
// named tag directory. An index is maintained to support deletions of all
// revisions of a given manifest tag.
//
// We cover the path formats implemented by this path mapper below.
//
//      Manifests:
//
//      manifestRevisionsPathSpec:      <root>/v2/repositories/<name>/_manifests/revisions/
//      manifestRevisionPathSpec:      <root>/v2/repositories/<name>/_manifests/revisions/<algorithm>/<hex digest>/
//      manifestRevisionLinkPathSpec:  <root>/v2/repositories/<name>/_manifests/revisions/<algorithm>/<hex digest>/link
//
//      Tags:
//
//      manifestTagsPathSpec:                  <root>/v2/repositories/<name>/_manifests/tags/
//      manifestTagPathSpec:                   <root>/v2/repositories/<name>/_manifests/tags/<tag>/
//      manifestTagCurrentPathSpec:            <root>/v2/repositories/<name>/_manifests/tags/<tag>/current/link
//      manifestTagIndexPathSpec:              <root>/v2/repositories/<name>/_manifests/tags/<tag>/index/
//      manifestTagIndexEntryPathSpec:         <root>/v2/repositories/<name>/_manifests/tags/<tag>/index/<algorithm>/<hex digest>/
//      manifestTagIndexEntryLinkPathSpec:     <root>/v2/repositories/<name>/_manifests/tags/<tag>/index/<algorithm>/<hex digest>/link
//
//      Blobs:
//
//      layerLinkPathSpec:            <root>/v2/repositories/<name>/_layers/<algorithm>/<hex digest>/link
//
//      Uploads:
//
//      uploadDataPathSpec:             <root>/v2/repositories/<name>/_uploads/<id>/data
//      uploadStartedAtPathSpec:        <root>/v2/repositories/<name>/_uploads/<id>/startedat
//      uploadHashStatePathSpec:        <root>/v2/repositories/<name>/_uploads/<id>/hashstates/<algorithm>/<offset>
//
//      Blob Store:
//
//      blobsPathSpec:                  <root>/v2/blobs/
//      blobPathSpec:                   <root>/v2/blobs/<algorithm>/<first two hex bytes of digest>/<hex digest>
//      blobDataPathSpec:               <root>/v2/blobs/<algorithm>/<first two hex bytes of digest>/<hex digest>/data
//      blobMediaTypePathSpec:               <root>/v2/blobs/<algorithm>/<first two hex bytes of digest>/<hex digest>/data
//
// For more information on the semantic meaning of each path and their
// contents, please see the path spec documentation.
func pathFor(spec pathSpec) (string, error) {

        // Switch on the path object type and return the appropriate path. At
        // first glance, one may wonder why we don't use an interface to
        // accomplish this. By keep the formatting separate from the pathSpec, we
        // keep separate the path generation componentized. These specs could be
        // passed to a completely different mapper implementation and generate a
        // different set of paths.
        //
        // For example, imagine migrating from one backend to the other: one could
        // build a filesystem walker that converts a string path in one version,
        // to an intermediate path object, than can be consumed and mapped by the
        // other version.

        rootPrefix := []string{storagePathRoot, storagePathVersion}
        repoPrefix := append(rootPrefix, "repositories")

        switch v := spec.(type) {

...
```
</details>

# manifest

```yaml
spec:
  affinity:
    podAntiAffinity:
      preferredDuringSchedulingIgnoredDuringExecution:
      - podAffinityTerm:
          namespaces:
          - openshift-image-registry
          topologyKey: kubernetes.io/hostname
        weight: 100
  containers:
  - env:
    - name: REGISTRY_STORAGE
      value: filesystem
    - name: REGISTRY_STORAGE_FILESYSTEM_ROOTDIRECTORY
      value: /registry
    - name: REGISTRY_HTTP_ADDR
      value: :5000
    - name: REGISTRY_HTTP_NET
      value: tcp
    - name: REGISTRY_HTTP_SECRET
      value: 5c9ffd0bee5047468ef7fc2748d8c82c5b83d8eb29f6f33f41dcb40785e08dd9aa947570565075fca73efdec0b85909755da6bf117acde22cf942e99d1482514
    - name: REGISTRY_LOG_LEVEL
      value: info
    - name: REGISTRY_OPENSHIFT_QUOTA_ENABLED
      value: "true"
    - name: REGISTRY_STORAGE_CACHE_BLOBDESCRIPTOR
      value: inmemory
    - name: REGISTRY_STORAGE_DELETE_ENABLED
      value: "true"
    - name: REGISTRY_OPENSHIFT_METRICS_ENABLED
      value: "true"
    - name: REGISTRY_OPENSHIFT_SERVER_ADDR
      value: image-registry.openshift-image-registry.svc:5000
    - name: REGISTRY_HTTP_TLS_CERTIFICATE
      value: /etc/secrets/tls.crt
    - name: REGISTRY_HTTP_TLS_KEY
      value: /etc/secrets/tls.key
...
    volumeMounts:
    - mountPath: /registry
      name: registry-storage
    - mountPath: /etc/secrets
      name: registry-tls
    - mountPath: /etc/pki/ca-trust/source/anchors
      name: registry-certificates
    - mountPath: /usr/share/pki/ca-trust-source
      name: trusted-ca
    - mountPath: /var/lib/kubelet/
      name: installation-pull-secrets
    - mountPath: /var/run/secrets/kubernetes.io/serviceaccount
      name: registry-token-6fzsg
      readOnly: true
...
  volumes:
  - emptyDir: {}
    name: registry-storage
  - name: registry-tls
    projected:
      defaultMode: 420
      sources:
      - secret:
          name: image-registry-tls
  - configMap:
      defaultMode: 420
      name: image-registry-certificates
    name: registry-certificates
  - configMap:
      defaultMode: 420
      items:
      - key: ca-bundle.crt
        path: anchors/ca-bundle.crt
      name: trusted-ca
      optional: true
    name: trusted-ca
  - name: installation-pull-secrets
    secret:
      defaultMode: 420
      items:
      - key: .dockerconfigjson
        path: config.json
      optional: true
      secretName: installation-pull-secrets
  - name: registry-token-6fzsg
    secret:
      defaultMode: 420
      secretName: registry-token-6fzsg
```

# 

- ./vendor/github.com/docker/distribution/registry/storage/driver/storagedriver.go
- ./vendor/github.com/docker/distribution/registry/storage/driver/s3-aws/s3.go
- ./vendor/github.com/docker/distribution/registry/storage/driver/filesystem/driver.go

# データ構造

<details>
<summary>
type blobWriter struct @pkg/dockerregistry/server/wrapped/blobwriter.go
</summary>

```go
// blobWriter wraps a distribution.BlobWriter.
type blobWriter struct {
        distribution.BlobWriter
        wrapper Wrapper
}
```
</details>

<details>
<summary>
type BlobWriter interface @vendor/github.com/docker/distribution/blobs.go
</summary>

```go
// BlobWriter provides a handle for inserting data into a blob store.
// Instances should be obtained from BlobWriteService.Writer and
// BlobWriteService.Resume. If supported by the store, a writer can be
// recovered with the id.
type BlobWriter interface {
        io.WriteCloser
        io.ReaderFrom

        // Size returns the number of bytes written to this blob.
        Size() int64

        // ID returns the identifier for this writer. The ID can be used with the
        // Blob service to later resume the write.
        ID() string

        // StartedAt returns the time this blob write was started.
        StartedAt() time.Time

        // Commit completes the blob writer process. The content is verified 
        // against the provided provisional descriptor, which may result in an
        // error. Depending on the implementation, written data may be validated
        // against the provisional descriptor fields. If MediaType is not present,
        // the implementation may reject the commit or assign "application/octet-
        // stream" to the blob. The returned descriptor may have a different
        // digest depending on the blob store, referred to as the canonical
        // descriptor.
        Commit(ctx context.Context, provisional Descriptor) (canonical Descriptor, err error)
                
        // Cancel ends the blob write without storing any data and frees any
        // associated resources. Any data written thus far will be lost. Cancel
        // implementations should allow multiple calls even after a commit that
        // result in a no-op. This allows use of Cancel in a defer statement,
        // increasing the assurance that it is correctly called.
        Cancel(ctx context.Context) error
}
```
</details>

<details>
<summary>
type Wrapper func(...) error @pkg/dockerregistry/server/wrapped/wrapper.go
</summary>

```go
// Wrapper is a user defined function that wraps methods to control their
// execution flow, contexts and error reporing.
type Wrapper func(ctx context.Context, funcname string, f func(ctx context.Context) error) error
```
</details>

# 起動

- [func main() @cmd/dockerregistry/main.go](https://github.com/openshift/image-registry/blob/release-4.8/cmd/dockerregistry/main.go#L93)
<details>
<summary>
(snippet from func main() @cmd/dockerregistry/main.go)
</summary>

```go
func main() {
        ...
        dockerregistry.Execute(configFile)
}
```
</details>

- [func Execute() @pkg/cmd/dockerregistry/dockerregistry.go](https://github.com/openshift/image-registry/blob/release-4.8/pkg/cmd/dockerregistry/dockerregistry.go#L164)
<details>
<summary>
(snippet from func Execute() @pkg/cmd/dockerregistry/dockerregistry.go)
</summary>

```go
// Execute runs the Docker registry.
func Execute(configFile io.Reader) {
...
        srv, err := NewServer(ctx, dockerConfig, extraConfig)
...
```
</details>

<details>
<summary>
func NewServer() @pkg/cmd/dockerregistry/dockerregistry.go
</summary>

```go
func NewServer(ctx context.Context, dockerConfig *configuration.Configuration, extraConfig *registryconfig.Configuration) (*http.Server, error) {
...
        handler := server.NewApp(ctx, registryClient, dockerConfig, extraConfig, writeLimiter)
...
        return &http.Server{
                Addr:      dockerConfig.HTTP.Addr,
                Handler:   handler,
                TLSConfig: tlsConf,
        }, nil
}
```
</details>

<details>
<summary>
func server.NewApp() @pkg/dockerregistry/server/app.go
</summary>

```go
// NewApp configures the registry application and returns http.Handler for it.
// The program will be terminated if an error happens.
func NewApp(ctx context.Context, registryClient client.RegistryClient, dockerConfig *configuration.Configuration, extraConfig *registryconfig.Configuration, writeLimiter maxconnections.Limiter) http.Handler {
...
        superapp := supermiddleware.App(app)
```
</details>

<details>
<summary>
func supermiddleware.NewApp() @pkg/dockerregistry/server/supermiddleware/app.go
</summary>

```go
// NewApp configures the registry application to use specified set of                                                  
// middlewares. It returns an object that is ready to serve requests.                                                  
func NewApp(ctx context.Context, config *configuration.Configuration, app App) *handlers.App {                         
        inst := &instance{
                App: app,
        }                                                                                                              
        updateConfig(config, inst)
        return handlers.NewApp(ctx, config)                                                                            
} 
```
</details>

<details>
<summary>
func handlers.NewApp() @vendor/github.com/docker/distribution/registry/handlers/app.go
</summary>

```go
// NewApp takes a configuration and returns a configured app, ready to serve
// requests. The app only implements ServeHTTP and can be wrapped in other
// handlers accordingly.
func NewApp(ctx context.Context, config *configuration.Configuration) *App {
        app := &App{
                Config:  config,
                Context: ctx,
                router:  v2.RouterWithPrefix(config.HTTP.Prefix),
                isCache: config.Proxy.RemoteURL != "",
        }
...
        app.driver, err = factory.Create(config.Storage.Type(), storageParams)
...
```
</details>

`config.Storage.Type()` は `filesystem` とか `s3` とかを返す。

cf.
- https://docs.docker.com/registry/configuration/#list-of-configuration-options

OCP内部レジストリの場合、Deploymentから環境変数 `REGISTRY_STORAGE` で指定している値が該当する。

<details>
<summary>
func (storage Storage) Type() @vendor/github.com/docker/distribution/configuration/configuration.go
</summary>

```go
// Type returns the storage driver type, such as filesystem or s3
func (storage Storage) Type() string {
        var storageType []string

        // Return only key in this map
        for k := range storage {
                switch k {
                case "maintenance":
                        // allow configuration of maintenance
                case "cache":
                        // allow configuration of caching
                case "delete":
                        // allow configuration of delete
                case "redirect":
                        // allow configuration of redirect
                default:
                        storageType = append(storageType, k)
                }
        }
        if len(storageType) > 1 {
                panic("multiple storage drivers specified in configuration or environment: " + strings.Join(storageType, ", "))
        }
        if len(storageType) == 1 {
                return storageType[0]
        }
        return ""
}
```
</details>

<details>
<summary>
func Create() @vendor/github.com/docker/distribution/registry/storage/driver/factory/factory.go
</summary>

```go
// Create a new storagedriver.StorageDriver with the given name and
// parameters. To use a driver, the StorageDriverFactory must first be
// registered with the given name. If no drivers are found, an
// InvalidStorageDriverError is returned
func Create(name string, parameters map[string]interface{}) (storagedriver.StorageDriver, error) {
        driverFactory, ok := driverFactories[name]
        if !ok {        
                return nil, InvalidStorageDriverError{name}
        }
        return driverFactory.Create(parameters)
} 
```
</details>

driverFactoriesは `map[string]StorageDriverFactory` で、各ストレージドライバが `init()` の中で `factory.Register()` を呼び出して登録している。

<details>
<summary>
var driverFactories @vendor/github.com/docker/distribution/registry/storage/driver/factory/factory.go
</summary>

```go
// driverFactories stores an internal mapping between storage driver names and their respective
// factories
var driverFactories = make(map[string]StorageDriverFactory)
```
</details>

<details>
<summary>
func Register() @vendor/github.com/docker/distribution/registry/storage/driver/factory/factory.go
</summary>

```go
// Register makes a storage driver available by the provided name.
// If Register is called twice with the same name or if driver factory is nil, it panics.
// Additionally, it is not concurrency safe. Most Storage Drivers call this function
// in their init() functions. See the documentation for StorageDriverFactory for more.
func Register(name string, factory StorageDriverFactory) {
        if factory == nil {
                panic("Must not provide nil StorageDriverFactory")
        }       
        _, registered := driverFactories[name]
        if registered {
                panic(fmt.Sprintf("StorageDriverFactory named %s already registered", name))
        }

        driverFactories[name] = factory
}
```
</details>

<details>
<summary>
func init() @vendor/github.com/docker/distribution/registry/storage/driver/filesystem/driver.go
</summary>

```go
func init() {
        factory.Register(driverName, &filesystemDriverFactory{})
}
```
</details>

<details>
<summary>
func init() @vendor/github.com/docker/distribution/registry/storage/driver/s3-aws/s3.go
</summary>

```go
func init() {
...
        // Register this as the default s3 driver in addition to s3aws
        factory.Register("s3", &s3DriverFactory{})
        factory.Register(driverName, &s3DriverFactory{})
}
```
</details>

filesystemの場合、`factory.Create()` から `filesystem.FromParameters()` を呼び出す。

<details>
<summary>
func (factory *filesystemDriverFactory) Create() @vendor/github.com/docker/distribution/registry/storage/driver/filesystem/driver.go
</summary>

```go
func (factory *filesystemDriverFactory) Create(parameters map[string]interface{}) (storagedriver.StorageDriver, error) {
        return FromParameters(parameters)
}
```
</details>

<details>
<summary>
func FromParameters() @vendor/github.com/docker/distribution/registry/storage/driver/filesystem/driver.go
</summary>

```go
// FromParameters constructs a new Driver with a given parameters map
// Optional Parameters:
// - rootdirectory
// - maxthreads
func FromParameters(parameters map[string]interface{}) (*Driver, error) {
        params, err := fromParametersImpl(parameters)
        if err != nil || params == nil {
                return nil, err
        }
        return New(*params), nil
}
```
</details>

最終的に、`fromParametersImpl()` の中で `filesystem` ストレージドライバ固有のパラメータ(`rootdirectory`, `maxthreads`等)を設定している。

以上の初期化処理の流れから、ストレージドライバ固有の処理は基本的に `vendor/github.com/docker/distribution/registry/storage/driver/filesystem/driver.go` にあることがわかる。

<details>
<summary>
</summary>
- 

```go

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


