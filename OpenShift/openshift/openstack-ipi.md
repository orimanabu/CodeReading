# OpenStack IPIの仕組みのメモ

CodeReadingではないですが忘備録。

## 環境

```
$ oc version
Client Version: 4.8.20
Server Version: 4.8.20
Kubernetes Version: v1.21.4+6438632
```

```
$ oc get node
NAME                           STATUS   ROLES    AGE   VERSION
managed-mbggk-master-0         Ready    master   41h   v1.21.4+6438632
managed-mbggk-master-1         Ready    master   41h   v1.21.4+6438632
managed-mbggk-master-2         Ready    master   41h   v1.21.4+6438632
managed-mbggk-worker-0-4ckz2   Ready    worker   41h   v1.21.4+6438632
managed-mbggk-worker-0-6wcz5   Ready    worker   41h   v1.21.4+6438632
managed-mbggk-worker-0-fgmk7   Ready    worker   41h   v1.21.4+6438632
```

```
$ oc get node -o custom-columns=NAME:.metadata.name,INTERNAL-IP:.status.addresses[0].address
NAME                           INTERNAL-IP
managed-mbggk-master-0         10.0.3.211
managed-mbggk-master-1         10.0.3.51
managed-mbggk-master-2         10.0.3.229
managed-mbggk-worker-0-4ckz2   10.0.1.194
managed-mbggk-worker-0-6wcz5   10.0.2.41
managed-mbggk-worker-0-fgmk7   10.0.3.23
```

# IPIインストール特有の仕掛け

IPIインストールすると、`openshift-openstack-infra` というnamespaceができて、以下のPodが起動する。

```
$ oc -n openshift-openstack-infra get pod
NAME                                      READY   STATUS    RESTARTS   AGE
coredns-managed-mbggk-master-0            2/2     Running   0          41h
coredns-managed-mbggk-master-1            2/2     Running   0          41h
coredns-managed-mbggk-master-2            2/2     Running   0          41h
coredns-managed-mbggk-worker-0-4ckz2      2/2     Running   0          40h
coredns-managed-mbggk-worker-0-6wcz5      2/2     Running   0          40h
coredns-managed-mbggk-worker-0-fgmk7      2/2     Running   0          41h
haproxy-managed-mbggk-master-0            2/2     Running   0          41h
haproxy-managed-mbggk-master-1            2/2     Running   0          41h
haproxy-managed-mbggk-master-2            2/2     Running   0          41h
keepalived-managed-mbggk-master-0         2/2     Running   0          41h
keepalived-managed-mbggk-master-1         2/2     Running   0          41h
keepalived-managed-mbggk-master-2         2/2     Running   0          41h
keepalived-managed-mbggk-worker-0-4ckz2   2/2     Running   0          40h
keepalived-managed-mbggk-worker-0-6wcz5   2/2     Running   0          40h
keepalived-managed-mbggk-worker-0-fgmk7   2/2     Running   0          41h
```
これらはstatic podとしてデプロイされる。 

```
$ oc debug node/managed-mbggk-master-0 -- chroot /host ls /etc/kubernetes/manifests 2> /dev/null
coredns.yaml
etcd-pod.yaml
haproxy.yaml
keepalived.yaml
kube-apiserver-pod.yaml
kube-controller-manager-pod.yaml
kube-scheduler-pod.yaml
```

```
$ oc debug node/managed-mbggk-worker-0-4ckz2 -- chroot /host ls /etc/kubernetes/manifests 2> /dev/null
coredns.yaml
keepalived.yaml
```

static podのmanifestはMCOが生成している。

- [appendManifestsByPlatform() @pkg/operator/bootstrap.go](https://github.com/openshift/machine-config-operator/blob/release-4.9/pkg/operator/bootstrap.go#L234-L253)
```go
func appendManifestsByPlatform(manifests []manifest, infra configv1.Infrastructure) []manifest {
...
        if infra.Status.PlatformStatus.OpenStack != nil {
                manifests = append(manifests,
                        manifest{
                                name:     "manifests/on-prem/coredns.yaml",
                                filename: "openstack/manifests/coredns.yaml",
                        },
                        manifest{
                                name:     "manifests/on-prem/coredns-corefile.tmpl",
                                filename: "openstack/static-pod-resources/coredns/Corefile.tmpl",
                        },
                        manifest{
                                name:     "manifests/on-prem/keepalived.yaml",
                                filename: "openstack/manifests/keepalived.yaml",
                        },
                        manifest{
                                name:     "manifests/on-prem/keepalived.conf.tmpl",
                                filename: "openstack/static-pod-resources/keepalived/keepalived.conf.tmpl",
                        },
                )
        }
```

それぞれのイメージは、/root/buildinfoを見た感じだと

- coredns: 内部DNS用のコンテナイメージ
- keepalived: ipfailover用のコンテナイメージ
- haproxy: Router用のコンテナイメージ

を流用しているっぽい。

# coredns

各ノードのホスト名、および `api`, `api-int`, `*.apps` の名前解決用のAおよびAAAAレコードが生成される。

```
$ oc -n openshift-openstack-infra exec -it pod/coredns-managed-mbggk-master-0 -c coredns -- cat /etc/coredns/Corefile
. {
    errors
    bufsize 512
    health :18080
    forward . 10.68.5.26 {
        policy sequential
    }
    cache 30
    reload
    template IN A managed.example.com {
        match .*.apps.managed.example.com
        answer "{{ .Name }} 60 in {{ .Type }} 10.0.0.7"
        fallthrough
    }
    template IN AAAA managed.example.com {
        match .*.apps.managed.example.com
        fallthrough
    }
    template IN A managed.example.com {
        match api.managed.example.com
        answer "{{ .Name }} 60 in {{ .Type }} 10.0.0.5"
        fallthrough
    }
    template IN AAAA managed.example.com {
        match api.managed.example.com
        fallthrough
    }
    template IN A managed.example.com {
        match api-int.managed.example.com
        answer "{{ .Name }} 60 in {{ .Type }} 10.0.0.5"
        fallthrough
    }
    template IN AAAA managed.example.com {
        match api-int.managed.example.com
        fallthrough
    }
    hosts {
        10.0.3.211 managed-mbggk-master-0 managed-mbggk-master-0.managed.example.com
        10.0.3.51 managed-mbggk-master-1 managed-mbggk-master-1.managed.example.com
        10.0.3.229 managed-mbggk-master-2 managed-mbggk-master-2.managed.example.com
        10.0.1.194 managed-mbggk-worker-0-4ckz2 managed-mbggk-worker-0-4ckz2.managed.example.com
        10.0.2.41 managed-mbggk-worker-0-6wcz5 managed-mbggk-worker-0-6wcz5.managed.example.com
        10.0.3.23 managed-mbggk-worker-0-fgmk7 managed-mbggk-worker-0-fgmk7.managed.example.com
        fallthrough
    }
}
```

# haproxy on master

このhaproxyのコンフィグの気持ちがよくわかってない... IPv6の9445で来たら各masterノードのv4の6443に振り分けている？

```
$ oc -n openshift-openstack-infra exec -it pod/haproxy-managed-mbggk-master-0 -c haproxy -- cat /etc/haproxy/haproxy.cfg
global
  stats socket /var/lib/haproxy/run/haproxy.sock  mode 600 level admin expose-fd listeners
defaults
  maxconn 20000
  mode    tcp
  log     /var/run/haproxy/haproxy-log.sock local0
  option  dontlognull
  retries 3
  timeout http-request 30s
  timeout queue        1m
  timeout connect      10s
  timeout client       86400s
  timeout server       86400s
  timeout tunnel       86400s
frontend  main
  bind :::9445 v4v6
  default_backend masters
listen health_check_http_url
  bind :::50936 v4v6
  mode http
  monitor-uri /haproxy_ready
  option dontlognull
listen stats
  bind localhost:50000
  mode http
  stats enable
  stats hide-version
  stats uri /haproxy_stats
  stats refresh 30s
  stats auth Username:Password
backend masters
   option  httpchk GET /readyz HTTP/1.0
   option  log-health-checks
   balance roundrobin
   server managed-mbggk-master-0 10.0.3.211:6443 weight 1 verify none check check-ssl inter 1s fall 2 rise 3
   server managed-mbggk-master-2 10.0.3.229:6443 weight 1 verify none check check-ssl inter 1s fall 2 rise 3
   server managed-mbggk-master-1 10.0.3.51:6443 weight 1 verify none check check-ssl inter 1s fall 2 rise 3
```

# keepalived on master

api用の10.0.0.5、ingress用の10.0.0.7という2つのVIPを管理する。

```
$ oc -n openshift-openstack-infra exec -it pod/keepalived-managed-mbggk-master-0 -c keepalived -- cat /etc/keepalived/keepalived.conf
global_defs {
    enable_script_security
    script_user root
}

# These are separate checks to provide the following behavior:
# If the loadbalanced endpoint is responding then all is well regardless
# of what the local api status is. Both checks will return success and
# we'll have the maximum priority. This means as long as there is a node
# with a functional loadbalancer it will get the VIP.
# If all of the loadbalancers go down but the local api is still running,
# the _both check will still succeed and allow any node with a functional
# api to take the VIP. This isn't preferred because it means all api
# traffic will go through one node, but at least it keeps the api available.
vrrp_script chk_ocp_lb {
    script "/usr/bin/timeout 1.9 /etc/keepalived/chk_ocp_script.sh"
    interval 2
    weight 20
    rise 3
    fall 2
}

vrrp_script chk_ocp_both {
    script "/usr/bin/timeout 1.9 /etc/keepalived/chk_ocp_script_both.sh"
    interval 2
    # Use a smaller weight for this check so it won't trigger the move from
    # bootstrap to master by itself.
    weight 5
    rise 3
    fall 2
}

# TODO: Improve this check. The port is assumed to be alive.
# Need to assess what is the ramification if the port is not there.
vrrp_script chk_ingress {
    script "/usr/bin/timeout 0.9 /usr/bin/curl -o /dev/null -Lfs http://localhost:1936/healthz/ready"
    interval 1
    weight 50
}



vrrp_instance managed_API {
    state BACKUP
    interface ens3
    virtual_router_id 124
    priority 40
    advert_int 1
    
    authentication {
        auth_type PASS
        auth_pass managed_api_vip
    }
    virtual_ipaddress {
        10.0.0.5/32
    }
    track_script {
        chk_ocp_lb
        chk_ocp_both
    }
}

vrrp_instance managed_INGRESS {
    state BACKUP
    interface ens3
    virtual_router_id 75
    priority 20
    advert_int 1
    
    authentication {
        auth_type PASS
        auth_pass managed_ingress_vip
    }
    virtual_ipaddress {
        10.0.0.7/32
    }
    track_script {
        chk_ingress
    }
}
```

# keepalived on worker

ingress用の10.0.0.7をVIPとして管理する。

```
$ oc -n openshift-openstack-infra exec -it pod/keepalived-managed-mbggk-worker-0-4ckz2 -c keepalived -- cat /etc/keepalived/keepalived.conf
# TODO: Improve this check. The port is assumed to be alive.
# Need to assess what is the ramification if the port is not there.
vrrp_script chk_ingress {
    script "/usr/bin/timeout 0.9 /usr/bin/curl -o /dev/null -Lfs http://localhost:1936/healthz/ready"
    interval 1
    weight 50
}



vrrp_instance managed_INGRESS {
    state BACKUP
    interface ens3
    virtual_router_id 75
    priority 20
    advert_int 1
    
    authentication {
        auth_type PASS
        auth_pass managed_ingress_vip
    }
    virtual_ipaddress {
        10.0.0.7/32
    }
    track_script {
        chk_ingress
    }
}
```

