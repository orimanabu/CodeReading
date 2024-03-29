# 目的

OpenShiftの内部コンテナレジストリがデータをストレージに書く際、atomicityを考慮しているか (partial writeが発生しないような処理があるか) を調査する

ざっとgrepした感じ、

- [func Commit() @vendor/github.com/docker/distribution/registry/storage/blobwriter.go](https://github.com/openshift/image-registry/blob/master/vendor/github.com/docker/distribution/registry/storage/blobwriter.go#L57-L59)

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

# 環境

- OpenShift Container Platform v4.8
- コンテナレジストリのソースは[ここ](https://github.com/openshift/image-registry/tree/release-4.8)

# 挙動の調査

inotify-tools入れたprivilegedコンテナでemptyPathのコンテナレジストリのストレージを見てみると、push時は一時的に `_upload` というディレクトリを掘ってその下にアップロードし、完了すると正規のblob用ディレクトリに移動して `_upload` ディレクトリを消す、みたいな動きをしているように見える。

ここのコメントの説明が参考になる。

- [func pathFor() @vendor/github.com/docker/distribution/registry/storage/paths.go](https://github.com/openshift/image-registry/blob/master/vendor/github.com/docker/distribution/registry/storage/paths.go#L21-L105)
<details>
<summary>
(snippet from: func pathFor() @vendor/github.com/docker/distribution/registry/storage/paths.go)
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

# プロセス起動

- [func main() @cmd/dockerregistry/main.go](https://github.com/openshift/image-registry/blob/release-4.8/cmd/dockerregistry/main.go#L93)
<details>
<summary>
(snippet from: func main() @cmd/dockerregistry/main.go)
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
(snippet from: func Execute() @pkg/cmd/dockerregistry/dockerregistry.go)
</summary>

```go
// Execute runs the Docker registry.
func Execute(configFile io.Reader) {
...
        srv, err := NewServer(ctx, dockerConfig, extraConfig)
...
```
</details>

- [func NewServer() @pkg/cmd/dockerregistry/dockerregistry.go](https://github.com/openshift/image-registry/blob/release-4.8/pkg/cmd/dockerregistry/dockerregistry.go#L210)
<details>
<summary>
(snippet from: func NewServer() @pkg/cmd/dockerregistry/dockerregistry.go)
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

- [func server.NewApp() @pkg/dockerregistry/server/app.go](https://github.com/openshift/image-registry/blob/release-4.8/pkg/dockerregistry/server/app.go#L138)
<details>
<summary>
(snippet from: func server.NewApp() @pkg/dockerregistry/server/app.go)
</summary>

```go
// NewApp configures the registry application and returns http.Handler for it.
// The program will be terminated if an error happens.
func NewApp(ctx context.Context, registryClient client.RegistryClient, dockerConfig *configuration.Configuration, extraConfig *registryconfig.Configuration, writeLimiter maxconnections.Limiter) http.Handler {
...
        superapp := supermiddleware.App(app)
```
</details>

- [func supermiddleware.NewApp() @pkg/dockerregistry/server/supermiddleware/app.go](https://github.com/openshift/image-registry/blob/release-4.8/pkg/dockerregistry/server/supermiddleware/app.go#L96)
<details>
<summary>
(snippet from: func supermiddleware.NewApp() @pkg/dockerregistry/server/supermiddleware/app.go)
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

- [func handlers.NewApp() @vendor/github.com/docker/distribution/registry/handlers/app.go](https://github.com/openshift/image-registry/blob/master/vendor/github.com/docker/distribution/registry/handlers/app.go#L122)
<details>
<summary>
(snippet from: func handlers.NewApp() @vendor/github.com/docker/distribution/registry/handlers/app.go)
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

- [func (storage Storage) Type() @vendor/github.com/docker/distribution/configuration/configuration.go](https://github.com/openshift/image-registry/blob/master/vendor/github.com/docker/distribution/configuration/configuration.go#L420)
<details>
<summary>
(snippet from: func (storage Storage) Type() @vendor/github.com/docker/distribution/configuration/configuration.go)
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

- [func Create() @vendor/github.com/docker/distribution/registry/storage/driver/factory/factory.go](https://github.com/openshift/image-registry/blob/master/vendor/github.com/docker/distribution/registry/storage/driver/factory/factory.go#L54)
<details>
<summary>
(snippet from: func Create() @vendor/github.com/docker/distribution/registry/storage/driver/factory/factory.go)
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

- [var driverFactories @vendor/github.com/docker/distribution/registry/storage/driver/factory/factory.go](https://github.com/openshift/image-registry/blob/master/vendor/github.com/docker/distribution/registry/storage/driver/factory/factory.go#L11)
<details>
<summary>
(snippet from: var driverFactories @vendor/github.com/docker/distribution/registry/storage/driver/factory/factory.go)
</summary>

```go
// driverFactories stores an internal mapping between storage driver names and their respective
// factories
var driverFactories = make(map[string]StorageDriverFactory)
```
</details>

- [func Register() @vendor/github.com/docker/distribution/registry/storage/driver/factory/factory.go](https://github.com/openshift/image-registry/blob/master/vendor/github.com/docker/distribution/registry/storage/driver/factory/factory.go#L42)
<details>
<summary>
(snippet from: func Register() @vendor/github.com/docker/distribution/registry/storage/driver/factory/factory.go)
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

- [func init() @vendor/github.com/docker/distribution/registry/storage/driver/filesystem/driver.go](https://github.com/openshift/image-registry/blob/master/vendor/github.com/docker/distribution/registry/storage/driver/filesystem/driver.go#L38)
<details>
<summary>
(snippet from: func init() @vendor/github.com/docker/distribution/registry/storage/driver/filesystem/driver.go)
</summary>

```go
func init() {
        factory.Register(driverName, &filesystemDriverFactory{})
}
```
</details>

- [func init() @vendor/github.com/docker/distribution/registry/storage/driver/s3-aws/s3.go](https://github.com/openshift/image-registry/blob/master/vendor/github.com/docker/distribution/registry/storage/driver/s3-aws/s3.go#L134-L135)
<details>
<summary>
(snippet from: func init() @vendor/github.com/docker/distribution/registry/storage/driver/s3-aws/s3.go)
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

- [func (factory *filesystemDriverFactory) Create() @vendor/github.com/docker/distribution/registry/storage/driver/filesystem/driver.go](https://github.com/openshift/image-registry/blob/master/vendor/github.com/docker/distribution/registry/storage/driver/filesystem/driver.go#L45)
<details>
<summary>
(snippet from: func (factory *filesystemDriverFactory) Create() @vendor/github.com/docker/distribution/registry/storage/driver/filesystem/driver.go)
</summary>

```go
func (factory *filesystemDriverFactory) Create(parameters map[string]interface{}) (storagedriver.StorageDriver, error) {
        return FromParameters(parameters)
}
```
</details>

- [func FromParameters() @vendor/github.com/docker/distribution/registry/storage/driver/filesystem/driver.go](https://github.com/openshift/image-registry/blob/master/vendor/github.com/docker/distribution/registry/storage/driver/filesystem/driver.go#L67)
<details>
<summary>
(snippet from: func FromParameters() @vendor/github.com/docker/distribution/registry/storage/driver/filesystem/driver.go)
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

以上の初期化処理の流れから、ファイルストレージのストレージドライバ固有の処理は基本的に `vendor/github.com/docker/distribution/registry/storage/driver/filesystem/driver.go` にあることがわかる。

# Blobアップロード時

Blobアップロード時は、下記のディスパッチテーブルから、`StartBlobUpload()` が呼ばれる。またクライアントはアップロード完了時にHTTP PUTを送ることになっており [^1] 、その場合は `PutBlobUploadComplete` が呼ばれる。

[^1]: See also "[Completed Upload](https://docs.docker.com/registry/spec/api/#completed-upload)" in Docker Registry API Reference

- [func blobUploadDispatcher() @vendor/github.com/docker/distribution/registry/handlers/blobupload.go](https://github.com/openshift/image-registry/blob/master/vendor/github.com/docker/distribution/registry/handlers/blobupload.go#L32)
<details>
<summary>
(snippet from:
func blobUploadDispatcher() @vendor/github.com/docker/distribution/registry/handlers/blobupload.go
)
</summary>

```go
// blobUploadDispatcher constructs and returns the blob upload handler for the
// given request context.
func blobUploadDispatcher(ctx *Context, r *http.Request) http.Handler {
...
        handler := handlers.MethodHandler{
                "GET":  http.HandlerFunc(buh.GetUploadStatus),
                "HEAD": http.HandlerFunc(buh.GetUploadStatus),
        }

        if !ctx.readOnly {
                handler["POST"] = http.HandlerFunc(buh.StartBlobUpload)
                handler["PATCH"] = http.HandlerFunc(buh.PatchBlobData)
                handler["PUT"] = http.HandlerFunc(buh.PutBlobUploadComplete)
                handler["DELETE"] = http.HandlerFunc(buh.CancelBlobUpload)
        }
```
</details>

## `StartBlobUpload()`

- [func (buh *blobUploadHandler) StartBlobUpload() @vendor/github.com/docker/distribution/registry/handlers/blobupload.go](https://github.com/openshift/image-registry/blob/master/vendor/github.com/docker/distribution/registry/handlers/blobupload.go#L121)
<details>
<summary>
(snippet from:
func (buh *blobUploadHandler) StartBlobUpload() @vendor/github.com/docker/distribution/registry/handlers/blobupload.go
)
</summary>

```go
// StartBlobUpload begins the blob upload process and allocates a server-side
// blob writer session, optionally mounting the blob from a separate repository.
func (buh *blobUploadHandler) StartBlobUpload(w http.ResponseWriter, r *http.Request) {
...
        blobs := buh.Repository.Blobs(buh)
        upload, err := blobs.Create(buh, options...)
...
        buh.Upload = upload
```
</details>

`blobs.Create()` すると、`blobWriter` が返る。つまり、`buh.Upload` にはblobWriterが代入される (その中には `driver.Writer` が入っている)。

- [func (lbs *linkedBlobStore) Create @vendor/github.com/docker/distribution/registry/storage/linkedblobstore.go](https://github.com/openshift/image-registry/blob/master/vendor/github.com/docker/distribution/registry/storage/linkedblobstore.go#L174)
<details>
<summary>
(snippet from:
func (lbs *linkedBlobStore) Create @vendor/github.com/docker/distribution/registry/storage/linkedblobstore.go
)
</summary>

```go
var _ distribution.BlobStore = &linkedBlobStore{}
...
// Writer begins a blob write session, returning a handle.
func (lbs *linkedBlobStore) Create(ctx context.Context, options ...distribution.BlobCreateOption) (distribution.BlobWriter, error) {
...
        return lbs.newBlobUpload(ctx, uuid, path, startedAt, false)
}
```
</details>

- [func (lbs *linkedBlobStore) newBlobUpload() @vendor/github.com/docker/distribution/registry/storage/linkedblobstore.go](https://github.com/openshift/image-registry/blob/master/vendor/github.com/docker/distribution/registry/storage/linkedblobstore.go#L314-L324)
<details>
<summary>
(snippet from:
func (lbs *linkedBlobStore) newBlobUpload() @vendor/github.com/docker/distribution/registry/storage/linkedblobstore.go
)
</summary>

```go
// newBlobUpload allocates a new upload controller with the given state.
func (lbs *linkedBlobStore) newBlobUpload(ctx context.Context, uuid, path string, startedAt time.Time, append bool) (distribution.BlobWriter, error) {
        fw, err := lbs.driver.Writer(ctx, path, append)
        if err != nil {
                return nil, err
        }

        bw := &blobWriter{
                ctx:                    ctx,
                blobStore:              lbs,
                id:                     uuid,
                startedAt:              startedAt,
                digester:               digest.Canonical.Digester(),
                fileWriter:             fw,
                driver:                 lbs.driver,
                path:                   path,
                resumableDigestEnabled: lbs.resumableDigestEnabled,
        }

        return bw, nil
}
```
</details>

## `PutBlobUploadComplete()`

- [func (buh *blobUploadHandler) PutBlobUploadComplete() @vendor/github.com/docker/distribution/registry/handlers/blobupload.go](https://github.com/openshift/image-registry/blob/master/vendor/github.com/docker/distribution/registry/handlers/blobupload.go#L226)
<details>
<summary>
(snippet from:
func (buh *blobUploadHandler) PutBlobUploadComplete() @vendor/github.com/docker/distribution/registry/handlers/blobupload.go
)
</summary>

```go
// PutBlobUploadComplete takes the final request of a blob upload. The
// request may include all the blob data or no blob data. Any data
// provided is received and verified. If successful, the blob is linked
// into the blob store and 201 Created is returned with the canonical
// url of the blob.
func (buh *blobUploadHandler) PutBlobUploadComplete(w http.ResponseWriter, r *http.Request) {
...
        desc, err := buh.Upload.Commit(buh, distribution.Descriptor{
                Digest: dgst,

                // TODO(stevvooe): This isn't wildly important yet, but we should
                // really set the mediatype. For now, we can let the backend take care
                // of this.
        })
```
</details>

中で `blobWriter.Commit()` が呼ばれていることがわかる。ここでようやく冒頭の「ざっとgrepした感じここが怪しいかも」と書いたCommit処理に来た。

## `blobWriter.Commit()`

- [func (bw *blobWriter) Commit() @vendor/github.com/docker/distribution/registry/storage/blobwriter.go](https://github.com/openshift/image-registry/blob/master/vendor/github.com/docker/distribution/registry/storage/blobwriter.go#L74)
<details>
<summary>
(snippet from:
func (bw *blobWriter) Commit() @vendor/github.com/docker/distribution/registry/storage/blobwriter.go
)
</summary>

```go
// Commit marks the upload as completed, returning a valid descriptor. The
// final size and digest are checked against the first descriptor provided.
func (bw *blobWriter) Commit(ctx context.Context, desc distribution.Descriptor) (distribution.Descriptor, error) {
...
        if err := bw.moveBlob(ctx, canonical); err != nil {
                return distribution.Descriptor{}, err
        }
```
</details>

いろいろ後処理っぽいことをしつつ、`moveBlob()` を呼んでいる。

- [func (bw *blobWriter) moveBlob() @vendor/github.com/docker/distribution/registry/storage/blobwriter.go](https://github.com/openshift/image-registry/blob/master/vendor/github.com/docker/distribution/registry/storage/blobwriter.go#L347)
<details>
<summary>
(snippet from:
func (bw *blobWriter) moveBlob() @vendor/github.com/docker/distribution/registry/storage/blobwriter.go
)
</summary>

```go
// moveBlob moves the data into its final, hash-qualified destination,
// identified by dgst. The layer should be validated before commencing the
// move.
func (bw *blobWriter) moveBlob(ctx context.Context, desc distribution.Descriptor) error {
...
        return bw.blobStore.driver.Move(ctx, bw.path, blobPath)
}
```
</details>

最終的に、ストレージドライバの `Move()` を呼んでいる。filesystemドライバの場合は単に `os.Rename()` を呼び出すだけ、s3-awsドライバの場合は手動でコピー&削除、をやっている。

- [func (d *driver) Move() @vendor/github.com/docker/distribution/registry/storage/driver/filesystem/driver.go](https://github.com/openshift/image-registry/blob/master/vendor/github.com/docker/distribution/registry/storage/driver/filesystem/driver.go#L267)
<details>
<summary>
(snippet from:
func (d *driver) Move() @vendor/github.com/docker/distribution/registry/storage/driver/filesystem/driver.go
)
</summary>

```go
// Move moves an object stored at sourcePath to destPath, removing the original
// object.
func (d *driver) Move(ctx context.Context, sourcePath string, destPath string) error {
...
        err := os.Rename(source, dest)
        return err
}
```
</details>

- [func (d *driver) Move() @vendor/github.com/docker/distribution/registry/storage/driver/s3-aws/s3.go](https://github.com/openshift/image-registry/blob/master/vendor/github.com/docker/distribution/registry/storage/driver/s3-aws/s3.go#L799-L803)
<details>
<summary>
(snippet from:
func (d *driver) Move() @vendor/github.com/docker/distribution/registry/storage/driver/s3-aws/s3.go
)
</summary>

```go
// Move moves an object stored at sourcePath to destPath, removing the original
// object.
func (d *driver) Move(ctx context.Context, sourcePath string, destPath string) error {
        /* This is terrible, but aws doesn't have an actual move. */
        if err := d.copy(ctx, sourcePath, destPath); err != nil {
                return err
        }
        return d.Delete(ctx, sourcePath)
}
```
</details>



<!--
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

# xxx

- [func (r *repository) Manifests() @pkg/dockerregistry/server/repository.go](https://github.com/openshift/image-registry/blob/release-4.8/pkg/dockerregistry/server/repository.go#L108)
<details>
<summary>
(snippet from:
func (r *repository) Manifests() @pkg/dockerregistry/server/repository.go
)
</summary>

```go
// Manifests returns r, which implements distribution.ManifestService.
func (r *repository) Manifests(ctx context.Context, options ...distribution.ManifestServiceOption) (distribution.ManifestService, error) {
...
        ms = &manifestService{
                manifests:     ms,
                blobStore:     r.Blobs(ctx),
                serverAddr:    r.app.config.Server.Addr,
                imageStream:   r.imageStream,
                cache:         r.cache,
                acceptSchema2: r.app.config.Compatibility.AcceptSchema2,
        }
```
</details>

- [func (r *repository) Blobs() @pkg/dockerregistry/server/repository.go](https://github.com/openshift/image-registry/blob/release-4.8/pkg/dockerregistry/server/repository.go#L131)
<details>
<summary>
(snippet from:
func (r *repository) Blobs() @pkg/dockerregistry/server/repository.go
)
</summary>

```go
// Blobs returns a blob store which can delegate to remote repositories.
func (r *repository) Blobs(ctx context.Context) distribution.BlobStore {
...
        if audit.LoggerExists(ctx) {
                bs = audit.NewBlobStore(ctx, bs)
        }
```
</details>

- []()
<details>
<summary>
(snippet from:
)
</summary>

```go
```
</details>

- []()
<details>
<summary>
(snippet from:
)
</summary>

```go
```
</details>

- []()
<details>
<summary>
(snippet from:
)
</summary>

```go
```
</details>

- []()
<details>
<summary>
(snippet from:
)
</summary>

```go
```
</details>

- []()
<details>
<summary>
(snippet from:
)
</summary>

```go
```
</details>


-->


