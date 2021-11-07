# お題

`oc adm top pod` もしくは `kubectl top pod` のメモリ使用量がどこから来ているかを調べる。

# 参考資料

- [Memory_working_set vs Memory_rss in Kubernetes, which one you should monitor?](https://medium.com/@eng.mohamed.m.saeed/memory-working-set-vs-memory-rss-in-kubernetes-which-one-you-should-monitor-8ef77bf0acee)
- [A Deep Dive into Kubernetes Metrics](https://blog.freshtracks.io/a-deep-dive-into-kubernetes-metrics-b190cc97f0f6)
- [Collecting metrics with built-in Kubernetes monitoring tools](https://www.datadoghq.com/blog/how-to-collect-and-graph-kubernetes-metrics/)

- [oc adm top node and oc describe node show different millicore counts](https://access.redhat.com/solutions/3654511)

# Metrics API
OpenShiftの場合、従来？metric-serverが担当していた？Metrics APIはprometheus-adapterが代替している。
```
$ oc get apiservices | grep metrics
v1beta1.metrics.k8s.io                        openshift-monitoring/prometheus-adapter                      True        60d
```

リポジトリは[ここ](https://github.com/openshift/k8s-prometheus-adapter)

実際に稼動するPodはこの辺り。

```
$ oc -n openshift-monitoring get pod | grep adapter
prometheus-adapter-cfcc4d7b8-6mfss             1/1     Running   0          3d7h
prometheus-adapter-cfcc4d7b8-t6hgb             1/1     Running   0          3d7h
```

# Metrics APIの生の情報を見てみる

```
$ oc -n csi get pod -o wide
NAME            READY   STATUS             RESTARTS   AGE    IP             NODE       NOMINATED NODE   READINESS GATES
blockvol-fs-1   1/1     Running            0          2d2h   10.131.2.185   worker-4   <none>           <none>
```

```
$ kubectl get --raw /apis/metrics.k8s.io/v1beta1/namespaces/csi/pods/blockvol-fs-1 | jq
{
  "kind": "PodMetrics",
  "apiVersion": "metrics.k8s.io/v1beta1",
  "metadata": {
    "name": "blockvol-fs-1",
    "namespace": "csi",
    "creationTimestamp": "2021-11-05T16:06:02Z",
    "labels": {
      "app": "blockvol-fs"
    }
  },
  "timestamp": "2021-11-05T16:06:02Z",
  "window": "5m0s",
  "containers": [
    {
      "name": "POD",
      "usage": {
        "cpu": "0",
        "memory": "176Ki"
      }
    },
    {
      "name": "centos-tools",
      "usage": {
        "cpu": "0",
        "memory": "86704Ki"
      }
    }
  ]
}
```

```
[ori@localhost NEC]$ oc adm top pod
W1106 01:06:18.092970 2656666 top_pod.go:140] Using json format to get metrics. Next release will switch to protocol-buffers, switch early by passing --use-protocol-buffers flag
NAME            CPU(cores)   MEMORY(bytes)   
blockvol-fs-1   0m           84Mi            
```

```
$ oc adm top pod --containers
W1106 01:09:00.498253 2657204 top_pod.go:140] Using json format to get metrics. Next release will switch to protocol-buffers, switch early by passing --use-protocol-buffers flag
POD             NAME           CPU(cores)   MEMORY(bytes)   
blockvol-fs-1   POD            0m           0Mi             
blockvol-fs-1   centos-tools   0m           84Mi         
```


# メトリック一覧を取得する方法

1. サービスアカウント `prometheus-k8s` のアクセストークンを取得する

```sh
$ TOKEN=$(oc serviceaccounts get-token prometheus-k8s -n openshift-monitoring)
```

2. `prometheus-k8s` で公開されているRouteを確認する

```sh
$ oc -n openshift-monitoring get route/prometheus-k8s
```

3. RouteでexposeしたFQDNの `/targets` をブラウザで開く (もしくはRouteのURLをブラウザで開き、上のメニューの `Status` → `Targets` をクリックする)

4. `cadvisor` でページ内検索し、該当ノードのIPアドレスが含まれるURLを探す

```sh
$ URL=https://172.16.13.108:10250/metrics/cadvisor
```

5. curlする！

```sh
$ oc -n openshift-monitoring exec prometheus-k8s-0 -- curl -k -H "Authorization: Bearer ${TOKEN}" ${URL}
```

# oc 

- [NewCommandTop() @pkg/cli/admin/top/top.go](https://github.com/openshift/oc/blob/release-4.8/pkg/cli/admin/top/top.go#L24)

  - `oc adm top` の処理
  - `oc adm top pod` の処理は[ここ](https://github.com/openshift/oc/blob/release-4.8/pkg/cli/admin/top/top.go#L34)に飛ぶ
  
- [NewCmdTopPod() @vendor/k8s.io/kubectl/pkg/cmd/top/top_pod.go](https://github.com/openshift/oc/blob/release-4.8/vendor/k8s.io/kubectl/pkg/cmd/top/top_pod.go#L86)

  - `oc adm top pod` の処理
  - メイン処理は[ここ](https://github.com/openshift/oc/blob/release-4.8/vendor/k8s.io/kubectl/pkg/cmd/top/top_pod.go#L102)から `RunTopPod()` に飛ぶ
  
- [RunTopPod() @vendor/k8s.io/kubectl/pkg/cmd/top/top_pod.go](https://github.com/openshift/oc/blob/release-4.8/vendor/k8s.io/kubectl/pkg/cmd/top/top_pod.go#L165)

  - [ここ](https://github.com/openshift/oc/blob/release-4.8/vendor/k8s.io/kubectl/pkg/cmd/top/top_pod.go#L180)で `SupportedMetricsAPIVersionAvailable()` を呼ぶ
    - [SupportedMetricsAPIVersionAvailable() @vendor/k8s.io/kubectl/pkg/cmd/top/top.go](https://github.com/openshift/oc/blob/release-4.8/vendor/k8s.io/kubectl/pkg/cmd/top/top.go#L62)
	  - 指定したAPIグループのバージョンで、サポートされるMetrics APIがあるか

  - [ここ](https://github.com/openshift/oc/blob/release-4.8/vendor/k8s.io/kubectl/pkg/cmd/top/top_pod.go#L185)で `getMetricsFromMetricsAPI` を呼ぶ

    - [getMetricsFromMetricsAPI() @vendor/k8s.io/kubectl/pkg/cmd/top/top_pod.go](https://github.com/openshift/oc/blob/release-4.8/vendor/k8s.io/kubectl/pkg/cmd/top/top_pod.go#L210)
      - まず *vbeta1* のMetrics APIで情報を取る ([ここ](https://github.com/openshift/oc/blob/release-4.8/vendor/k8s.io/kubectl/pkg/cmd/top/top_pod.go#L218) or [ここ](https://github.com/openshift/oc/blob/release-4.8/vendor/k8s.io/kubectl/pkg/cmd/top/top_pod.go#L224))
        - [Get() @vendor/k8s.io/metrics/pkg/client/clientset/versioned/typed/metrics/v1beta1/podmetrics.go](https://github.com/openshift/oc/blob/release-4.8/vendor/k8s.io/metrics/pkg/client/clientset/versioned/typed/metrics/v1beta1/podmetrics.go#L61)
      - それをMetrics APIの情報に[変換](https://github.com/openshift/oc/blob/release-4.8/vendor/k8s.io/kubectl/pkg/cmd/top/top_pod.go#L230)する
        - [Convert_v1beta1_PodMetricsList_To_metrics_PodMetricsList() @vendor/k8s.io/metrics/pkg/apis/metrics/v1beta1/zz_generated.conversion.go](https://github.com/openshift/oc/blob/release-4.8/vendor/k8s.io/metrics/pkg/apis/metrics/v1beta1/zz_generated.conversion.go#L195)
        - [autoConvert_v1beta1_PodMetricsList_To_metrics_PodMetricsList() @vendor/k8s.io/metrics/pkg/apis/metrics/v1beta1/zz_generated.conversion.go](https://github.com/openshift/oc/blob/release-4.8/vendor/k8s.io/metrics/pkg/apis/metrics/v1beta1/zz_generated.conversion.go#L188)
