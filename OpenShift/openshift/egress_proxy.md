# Egress Router (HTTP Proxy Mode)

`EGRESS_SOURCE`, `EGRESS_GATEWAY` 等は、ノードのデフォルトゲートウェイが向いているインターフェースに対してつける必要がある。
そもそもEgressを使う時点でクラスターの外に抜けたいので、特に変ではないけど。

もしデフォルトルート向きじゃないインターフェースからEgress Proxyで抜けたいと思っても、設定してもうまく動かない。
理由はmacvlanインターフェースの親インターフェースとして、デフォルトルート向きのインターフェースを使うようハードコードされているから。

動きからなんとなく想像できたけど、念の為裏取り調査をしました。というのがこの文書です。

# 手始めに

Egress ProxyのPodを作るmanifestはこんな感じ。

- egress\_proxy\_pod.yaml
```
apiVersion: v1
kind: Pod
metadata:
  name: egress-http-proxy
  labels:
    name: egress-http-proxy
  annotations:
    pod.network.openshift.io/assign-macvlan: "true"
spec:
  initContainers:
  - name: egress-router-setup
    image: registry.access.redhat.com/openshift3/ose-egress-router
    securityContext:
      privileged: true
    env:
    - name: EGRESS_SOURCE
      value: 172.16.99.25/24
    - name: EGRESS_GATEWAY
      value: 172.16.99.254
    - name: EGRESS_ROUTER_MODE
      value: http-proxy
  containers:
  - name: egress-router-proxy
    image: registry.access.redhat.com/openshift3/ose-egress-http-proxy
    env:
    - name: EGRESS_HTTP_PROXY_DESTINATION
      value: |
        172.16.99.11
        10.0.1.11
```

`pod.network.openshift.io/assign-macvlan` から手始めに探索してみる...とgrepで発見。

[定義場所](https://github.com/openshift/origin/blob/release-3.11/vendor/github.com/openshift/api/network/v1/constants.go#L5)

- vendor/github.com/openshift/api/network/v1/constants.go
```
const (
    // Pod annotations
    AssignMacvlanAnnotation = "pod.network.openshift.io/assign-macvlan"
<snip>
```

次は`AssignMacvlanAnnotation`で検索。使っているのは`pkg/network/node/pod.go`の`maybeAddMacvlan()`だけ。

[annotationを読み出すところ](https://github.com/openshift/origin/blob/release-3.11/pkg/network/node/pod.go#L348)
[macvlanを作るところ](https://github.com/openshift/origin/blob/release-3.11/pkg/network/node/pod.go#L399-L406)


- pkg/network/node/pod.go
```
// Adds a macvlan interface to a container, if requested, for use with the egress router feature
func maybeAddMacvlan(pod *kapi.Pod, netns string) error {
    annotation, ok := pod.Annotations[networkapi.AssignMacvlanAnnotation]

<snip>

    var iface netlink.Link
    var err error
    if annotation == "true" {
        // Find interface with the default route
        routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
        if err != nil {
            return fmt.Errorf("failed to read routes: %v", err)
        }

        for _, r := range routes {
            if r.Dst == nil {
                iface, err = netlink.LinkByIndex(r.LinkIndex)
                if err != nil {
                    return fmt.Errorf("failed to get default route interface: %v", err)
                }
            }
        }
        if iface == nil {
            return fmt.Errorf("failed to find default route interface")
        }
    } else {
        iface, err = netlink.LinkByName(annotation)
        if err != nil {
            return fmt.Errorf("pod annotation %q is neither 'true' nor the name of a local network interface", networkapi.AssignMacvlanAnnotation)
        }
    }

<snip>

    err = netlink.LinkAdd(&netlink.Macvlan{
        LinkAttrs: netlink.LinkAttrs{
            MTU:         iface.Attrs().MTU,
            Name:        "macvlan0",
            ParentIndex: iface.Attrs().Index,
            Namespace:   netlink.NsFd(podNs.Fd()),
        },
        Mode: netlink.MACVLAN_MODE_PRIVATE,
    })

<snip>
```

と書かれている。
"Find interface with the default route" とナイスなコメントがついていて、`metadata.annotation.pod.network.openshift.io/assign-macvlan: "true"` であればデフォルトゲートウェイに向いているインターフェースに対して`ip link add link <でほげ向きインターフェース> name macvlan0 type macvlan mode private`して該当namespaceに突っ込んでいる。ことがわかる。
