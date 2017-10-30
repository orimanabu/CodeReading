# raftexampleを読む

## main()からの流れ

- main() @contrib/raftexample/main.go

```go
func main() {
	cluster := flag.String("cluster", "http://127.0.0.1:9021", "comma separated cluster peers")
	id := flag.Int("id", 1, "node ID")
	kvport := flag.Int("port", 9121, "key-value server port")
	join := flag.Bool("join", false, "join an existing cluster")
	flag.Parse()

	proposeC := make(chan string)
	defer close(proposeC)
	confChangeC := make(chan raftpb.ConfChange)
	defer close(confChangeC)

	// raft provides a commit stream for the proposals from the http api
	var kvs *kvstore
	getSnapshot := func() ([]byte, error) { return kvs.getSnapshot() }
	commitC, errorC, snapshotterReady := newRaftNode(*id, strings.Split(*cluster, ","), *join, getSnapshot, proposeC, confChangeC)

	kvs = newKVStore(<-snapshotterReady, proposeC, commitC, errorC)

	// the key-value http handler will propose updates to raft
	serveHttpKVAPI(kvs, *kvport, confChangeC, errorC)
}
```

newRaftNode()、newKVStore()、serveHttpKVAPI()の順で関数コール

## newRaftNode()

- newRaftNode() @contrib/raftexample/raft.go

```go
// newRaftNode initiates a raft instance and returns a committed log entry
// channel and error channel. Proposals for log updates are sent over the
// provided the proposal channel. All log entries are replayed over the
// commit channel, followed by a nil message (to indicate the channel is
// current), then new log entries. To shutdown, close proposeC and read errorC.
func newRaftNode(id int, peers []string, join bool, getSnapshot func() ([]byte, error), proposeC <-chan string,
    confChangeC <-chan raftpb.ConfChange) (<-chan *string, <-chan error, <-chan *snap.Snapshotter) {

    commitC := make(chan *string)
    errorC := make(chan error)

    rc := &raftNode{
        proposeC:    proposeC,
        confChangeC: confChangeC,
        commitC:     commitC,
        errorC:      errorC,
        id:          id,
        peers:       peers,
        join:        join,
        waldir:      fmt.Sprintf("raftexample-%d", id),
        snapdir:     fmt.Sprintf("raftexample-%d-snap", id),
        getSnapshot: getSnapshot,
        snapCount:   defaultSnapCount,
        stopc:       make(chan struct{}),
        httpstopc:   make(chan struct{}),
        httpdonec:   make(chan struct{}),

        snapshotterReady: make(chan *snap.Snapshotter, 1),
        // rest of structure populated after WAL replay
    }
    go rc.startRaft()
    return commitC, errorC, rc.snapshotterReady
}
```

- raftNode struct @contrib/raftexample/raft.go

```go
// A key-value stream backed by raft
type raftNode struct {
    proposeC    <-chan string            // proposed messages (k,v)
    confChangeC <-chan raftpb.ConfChange // proposed cluster config changes
    commitC     chan<- *string           // entries committed to log (k,v)
    errorC      chan<- error             // errors from raft session

    id          int      // client ID for raft session
    peers       []string // raft peer URLs
    join        bool     // node is joining an existing cluster
    waldir      string   // path to WAL directory
    snapdir     string   // path to snapshot directory
    getSnapshot func() ([]byte, error)
    lastIndex   uint64 // index of log at start

    confState     raftpb.ConfState
    snapshotIndex uint64
    appliedIndex  uint64

    // raft backing for the commit/error channel
    node        raft.Node
    raftStorage *raft.MemoryStorage
    wal         *wal.WAL

    snapshotter      *snap.Snapshotter
    snapshotterReady chan *snap.Snapshotter // signals when snapshotter is ready

    snapCount uint64
    transport *rafthttp.Transport
    stopc     chan struct{} // signals proposal channel closed
    httpstopc chan struct{} // signals http server to shutdown
    httpdonec chan struct{} // signals http server shutdown complete
}
```

### startRaft() @contrib/raftexample/raft.go

```go
func (rc *raftNode) startRaft() {
    if !fileutil.Exist(rc.snapdir) {
        if err := os.Mkdir(rc.snapdir, 0750); err != nil {
            log.Fatalf("raftexample: cannot create dir for snapshot (%v)", err)
        }
    }
    rc.snapshotter = snap.New(rc.snapdir)
    rc.snapshotterReady <- rc.snapshotter

    oldwal := wal.Exist(rc.waldir)
    rc.wal = rc.replayWAL()

    rpeers := make([]raft.Peer, len(rc.peers))
    for i := range rpeers {
        rpeers[i] = raft.Peer{ID: uint64(i + 1)}
    }
    c := &raft.Config{
        ID:              uint64(rc.id),
        ElectionTick:    10,
        HeartbeatTick:   1,
        Storage:         rc.raftStorage,
        MaxSizePerMsg:   1024 * 1024,
        MaxInflightMsgs: 256,
    }

    if oldwal {
        rc.node = raft.RestartNode(c)
    } else {
        startPeers := rpeers
        if rc.join {
            startPeers = nil
        }
        rc.node = raft.StartNode(c, startPeers)
    }

    ss := &stats.ServerStats{}
    ss.Initialize()

    rc.transport = &rafthttp.Transport{
        ID:          types.ID(rc.id),
        ClusterID:   0x1000,
        Raft:        rc,
        ServerStats: ss,
        LeaderStats: stats.NewLeaderStats(strconv.Itoa(rc.id)),
        ErrorC:      make(chan error),
    }

    rc.transport.Start()
    for i := range rc.peers {
        if i+1 != rc.id {
            rc.transport.AddPeer(types.ID(i+1), []string{rc.peers[i]})
        }
    }

    go rc.serveRaft()
    go rc.serveChannels()
}
```


## newKVStore()

- newKVStore() @contrib/raftexample/kvstore.go

```go
func newKVStore(snapshotter *snap.Snapshotter, proposeC chan<- string, commitC <-chan *string, errorC <-chan error) *kvstore {
    s := &kvstore{proposeC: proposeC, kvStore: make(map[string]string), snapshotter: snapshotter}
    // replay log into key-value map
    s.readCommits(commitC, errorC)
    // read commits from raft into kvStore map until error
    go s.readCommits(commitC, errorC)
    return s
}
```

## serveHttpKVAPI

- serveHttpKVAPI() @contrib/raftexample/httpapi.go

```go
// serveHttpKVAPI starts a key-value server with a GET/PUT API and listens.
func serveHttpKVAPI(kv *kvstore, port int, confChangeC chan<- raftpb.ConfChange, errorC <-chan error) {
    srv := http.Server{
        Addr: ":" + strconv.Itoa(port),
        Handler: &httpKVAPI{
            store:       kv,
            confChangeC: confChangeC,
        },
    }
    go func() {
        if err := srv.ListenAndServe(); err != nil {
            log.Fatal(err)
        }
    }()

    // exit when raft goes down
    if err, ok := <-errorC; ok {
        log.Fatal(err)
    }
}
```
