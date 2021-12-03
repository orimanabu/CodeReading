# お題

ImagePullBackOffとErrImagePullがどういうタイミングで遷移するか

# 初期化

[backoffの初期化](https://github.com/openshift/kubernetes/blob/release-4.8/pkg/kubelet/kubelet.go#L585)
```
imageBackOff := flowcontrol.NewBackOff(backOffPeriod, MaxContainerBackOff)
```

[backOffPeriod](https://github.com/openshift/kubernetes/blob/release-4.8/pkg/kubelet/kubelet.go#L162-L165)
```
// backOffPeriod is the period to back off when pod syncing results in an
// error. It is also used as the base period for the exponential backoff
// container restarts and image pulls.
backOffPeriod = time.Second * 10
```

[MaxContainerBackOff](https://github.com/openshift/kubernetes/blob/release-4.8/pkg/kubelet/kubelet.go#L134-L135)
```
// MaxContainerBackOff is the max backoff period, exported for the e2e test
MaxContainerBackOff = 300 * time.Second
```

# メイン処理

[EnsureImageExists() @pkg/kubelet/images/image_manager.go](https://github.com/openshift/kubernetes/blob/master/pkg/kubelet/images/image_manager.go#L89)

  - イメージをpullする (https://github.com/openshift/kubernetes/blob/master/pkg/kubelet/images/image_manager.go#L144)
  - エラーなら、次のバックオフ時間を設定する (https://github.com/openshift/kubernetes/blob/master/pkg/kubelet/images/image_manager.go#L148)
  
[Next() @vendor/k8s.io/client-go/util/flowcontrol/backoff.go](https://github.com/openshift/kubernetes/blob/master/staging/src/k8s.io/client-go/util/flowcontrol/backoff.go#L71)

  - 前のbackoff時間の倍を設定する (最大はmaxDuration)
  
