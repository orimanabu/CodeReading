# TripleOのovercloudで動くSoftwareDeploymentの仕組みを追いかける

## 動機

RDO Manager 改め TripleO <sup>[1] (#footnote1)</sup> は、Ironic で overcloud のイメージを流し込んで再起動した後、overcloud 内のソフトウェア (つまり OpenStack の各種サービス) の設定を Heat の SoftwareDeployment / SoftwareConfig リソースの仕組みを使って実施します。

overcloud 上の OpenStack の設定は、多数の SoftwareDeployment (Heat のリソース) の集合体となっていて、複雑に依存関係が定義されています。例えば Galera Cluster を構成する場合は、まず 1 台のコントローラノードで Galera の bootstrap 処理をした後に、残りのコントローラノードがそれに join して...的なことをする必要があるわけですが、そういった順序関係や待ち合わせ等が Heat リソースの依存関係として定義されています。

各 overcloud ノードでは、決められた SoftwareDeployment の設定を実行し、終わったら Heat コントローラ (つまり undercloud ノード上の heat-engine) に対して実行ステータスを signal として通知します。Heat コントローラは通知を受けると、該当ノードに対して次の SoftwareDeployment を準備します。該当ノードは、新しい SoftwareDeployment のメタデータをもらってさらに設定を進めます。

これらの overcloud ノード内のソフトウェア設定の流れをまとめたい、というのがこの文書の趣旨です。

<a name="footnote1">1</a>: https://www.rdoproject.org/blog/2016/02/rdo-manager-is-now-tripleo/

## TripleO 用語集

<dl>
<dt>THT
<dd>TripleO Heat Templates https://github.com/openstack/tripleo-heat-templates
<dt>DIB
<dd>Diskimage-builder https://github.com/openstack/diskimage-builder
<dt>RHOSP
<dd>Red Hat OpenStack Platform, Red Hat の OpenStack 製品の名称。バージョン 8 (Liberty) 以降はこの名称
<dt>RHEL OSP
<dd>Red Hat Enterprise Linux OpenStack, Red Hat の OpenStack 製品の名称。バージョン 7 (Kilo) 以前はこの名称
<dt>RDO Manager
<dd>RHOSP/RHEL OSP の upstream プロジェクト, 最近 TripleO に改名
<dt>OSP director
<dd>RDO Manager / TripleO の製品版 (downstream) の名称
</dl>

## おおまかな流れ

1. Heat コントローラ (heat-engine) は各ノードに対して、SoftwareDeployment リソースをメタデータとして用意する
1. 各 overcloud ノード上では、os-collect-config がメタデータを定期的にダウンロード
1. メタデータの変更があれば、os-collect-config が os-refresh-config を実行し、os-refresh-config が変更された設定を適用

![os-collect-config](https://wiki.openstack.org/w/images/thumb/9/92/Os-collect-config-and-friends.svg/990px-Os-collect-config-and-friends.svg.png "os-collect-config")
(図は https://wiki.openstack.org/wiki/OsCollectConfig より拝借)

## まめちしき

- SoftwareDeploymentには "group" が設定されている
- groupごとに、データを適用するための "hook" がある
  - groupが "puppet" なら、hook はpuppetを使って構成を進める
  - groupが "script" なら、hook はシェルスクリプトとして実行して構成を進める
- hookは /var/lib/heat-config/hooks 以下に配置されている
  - puppet hook では、Heat から指示された puppet manifest を、(os-refresh-config で配置した) hieradata を使って適用する
  - puppet manifest は /var/lib/heat-config/heat-config-puppt 以下に配置されている
    - ここにある各 .pp ファイルは、Heat の SoftwareDeploymet を puppet manifest の形で表現したものとなっている

## cloud-init
Nova のメタデータサービスから、os-collect-config に必要なデータをダウンロードする

- ダウンロード先: /var/lib/heat-cfntools/cfn-init-data

```
# python -m json.tool /var/lib/heat-cfntools/cfn-init-data
{
    "deployments": [],
    "os-collect-config": {
        "cfn": {
            "access_key_id": "6d67df916d7342a293c904ff5367e99c",
            "metadata_url": "http://10.3.22.41:8000/v1/",
            "path": "NovaCompute.Metadata",
            "secret_access_key": "6913250261c14e5da63b7b8fe2fcaaa2",
            "stack_name": "overcloud-Compute-cvtecso6nlho-0-durjwtkd5x53"
        }
    }
}
```

## os-collect-config

- 通常は systemd の unit として起動
- Heat APIのメタデータを定期的にモニターし、ダウンロードする
- メタデータの変更があれば、os-refresh-configを呼ぶ
  - メタデータ： これを使って設定を進める。ノード固有の値が入る
- cloud-initによって、初回起動時に設定される (/etc/os-collect-config.conf)
- メタデータのダウンロード先は/var/lib/os-collect-config

```
# cat /etc/os-collect-config.conf
[DEFAULT]
command = os-refresh-config

[cfn]
metadata_url = http://x.x.x.x:8000/v1/
stack_name = overcloud-Compute-cvtecso6nlho-0-durjwtkd5x53
secret_access_key = a913250261c14e5da63b7b8fe2fcaaa2
access_key_id = ad67df916d7342a293c904ff5367e99c
path = NovaCompute.Metadata
```

```
# ls -l /var/lib/os-collect-config/
total 240
-rw-------. 1 root root 55241 Apr 13 05:54 cfn.json
-rw-------. 1 root root 55241 Mar 23 01:56 cfn.json.last
-rw-------. 1 root root 14258 Mar 22 18:33 cfn.json.orig
-rw-------. 1 root root  1066 Apr 13 05:54 ec2.json
-rw-------. 1 root root  1066 Mar 22 18:33 ec2.json.last
-rw-------. 1 root root  1066 Mar 22 18:33 ec2.json.orig
-rw-------. 1 root root   335 Apr 13 05:54 heat_local.json
-rw-------. 1 root root   335 Mar 22 18:33 heat_local.json.last
-rw-------. 1 root root   335 Mar 22 18:33 heat_local.json.orig
-rw-------. 1 root root   589 Mar 23 01:55 os_config_files.json
-rw-------. 1 root root  3553 Mar 23 01:54 overcloud-allNodesConfig-zbigjr43tjbw-allNodesConfigImpl-3usqsshd74l3.json
-rw-------. 1 root root  3553 Mar 22 22:09 overcloud-allNodesConfig-zbigjr43tjbw-allNodesConfigImpl-3usqsshd74l3.json.last
-rw-------. 1 root root  3553 Mar 22 22:09 overcloud-allNodesConfig-zbigjr43tjbw-allNodesConfigImpl-3usqsshd74l3.json.orig
-rw-------. 1 root root  3685 Apr 13 05:54 overcloud-allNodesConfig-zbigjr43tjbw-allNodesConfigImpl-u2syhknkn7it.json
-rw-------. 1 root root  3685 Mar 23 01:55 overcloud-allNodesConfig-zbigjr43tjbw-allNodesConfigImpl-u2syhknkn7it.json.last
-rw-------. 1 root root  3685 Mar 23 01:55 overcloud-allNodesConfig-zbigjr43tjbw-allNodesConfigImpl-u2syhknkn7it.json.orig
-rw-------. 1 root root  3087 Mar 22 22:09 overcloud-allNodesConfig-zbigjr43tjbw-allNodesConfigImpl-v5c644ckvm6d.json
-rw-------. 1 root root  3087 Mar 22 18:37 overcloud-allNodesConfig-zbigjr43tjbw-allNodesConfigImpl-v5c644ckvm6d.json.last
-rw-------. 1 root root  3087 Mar 22 18:36 overcloud-allNodesConfig-zbigjr43tjbw-allNodesConfigImpl-v5c644ckvm6d.json.orig
-rw-------. 1 root root  1347 Apr 13 05:54 overcloud-CephClusterConfig-nfjjwhniium6-CephClusterConfigImpl-5kkrhawegvrk.json
-rw-------. 1 root root  1347 Mar 22 18:37 overcloud-CephClusterConfig-nfjjwhniium6-CephClusterConfigImpl-5kkrhawegvrk.json.last
-rw-------. 1 root root  1347 Mar 22 18:36 overcloud-CephClusterConfig-nfjjwhniium6-CephClusterConfigImpl-5kkrhawegvrk.json.orig
-rw-------. 1 root root  1145 Apr 13 05:54 overcloud-Compute-cvtecso6nlho-0-durjwtkd5x53-NetworkConfig-eecr3zz6dfer-OsNetConfigImpl-5avtuwbzzm5g.json
-rw-------. 1 root root  1145 Mar 22 18:34 overcloud-Compute-cvtecso6nlho-0-durjwtkd5x53-NetworkConfig-eecr3zz6dfer-OsNetConfigImpl-5avtuwbzzm5g.json.last
-rw-------. 1 root root  1145 Mar 22 18:33 overcloud-Compute-cvtecso6nlho-0-durjwtkd5x53-NetworkConfig-eecr3zz6dfer-OsNetConfigImpl-5avtuwbzzm5g.json.orig
-rw-------. 1 root root  6678 Apr 13 05:54 overcloud-Compute-cvtecso6nlho-0-durjwtkd5x53-NovaComputeConfig-peiajxiu4aah.json
-rw-------. 1 root root  6678 Mar 22 18:35 overcloud-Compute-cvtecso6nlho-0-durjwtkd5x53-NovaComputeConfig-peiajxiu4aah.json.last
-rw-------. 1 root root  6678 Mar 22 18:35 overcloud-Compute-cvtecso6nlho-0-durjwtkd5x53-NovaComputeConfig-peiajxiu4aah.json.orig
```

### tips

- main() は os_collect_config/collect.py
- オプション --one-time つきで実行された場合は、一度メタデータを取得して (必要に応じてさらに os-refresh-config して) 終了
- --one-time をつけなければ (通常 systemd からこの状態でサービスとして起動)、CONF.polling_interval (デフォルト 30 秒) ごとにメタデータをポーリング
- メタデータのポーリングは、Collector クラスが実行する。Collector としては、下記が用意されている。RHOSP では cfn を使う。
  - heat_local
  - ec2
  - cfn
  - heat
  - request
  - local
- cfn 用の Collector は os_collect_config/cfn.py

### main()

下記内容を無限ループ

1. collect_all() でメタデータを取得
1. call_command() で CONF.command (RHOSP の場合 os-refresh-config ← cloud-init で取得した設定ファイルに書かれている) を実行
1. CONF.polling_interval (デフォルト 30 秒) 待つ

## os-refresh-config
- メタデータの変更があった場合、os-collect-configから呼ばれる
- first boot時は必ず呼ばれる (初回起動時はメタデータがないので)
- /usr/libexec/os-refresh-config以下のスクリプトを実行
  - 下記の順に、ディレクトリ配下のファイル名順に実行
    -  /usr/libexec/os-refresh-config/pre-configure.d
    -  /usr/libexec/os-refresh-config/configure.d
    -  /usr/libexec/os-refresh-config/post-configure.d
  - 各スクリプトは、os-collect-configがダウンロードしたメタデータを元に実際に適用していく

- os-refresh-configの主な処理内容 (configure.d)

1. sysctlの設定
2. os-apply-configを実行
3. os-net-configの実行
4. ゲートウェイの設定
5. hieradataをダウンロード・配置
6. /etc/hostsの設定
7. HeatのSoftwareConfigurationリソースのデプロイメント

## os-apply-config
- os-refresh-configから呼ばれる (/usr/libexec/os-refresh-config/configure.d/20-os-apply-config)
- (Puppetでうまく構成できない)設定ファイルを作成

例: the configuration of hieradata location、os-collect-configの設定ファイル

## heat-config-notify
- HeatのSoftwareDeploymentの終了ステータスをundercloudに通知する


## 参考文献

- OpenStack Wiki: [TripleO] (https://wiki.openstack.org/wiki/TripleO)
- OpenStack docs: [Welcome to TripleO documentation] (http://docs.openstack.org/developer/tripleo-docs/)
- OpenStack docs: [OpenStack on OpenStack, or TripleO] (http://docs.openstack.org/developer/tripleo-incubator/README.html)
- OpenStack Summit Portland 2013: OpenStack-on-OpenStack Overview [video](https://www.openstack.org/summit/portland-2013/session-videos/presentation/openstack-on-openstack-overview) [slides](http://www.slideshare.net/openstack/robert-collins-openstack-on-openstack-201304162)
- OpenStack Summit Portland 2013: Deploying and Managing OpenStack with Heat [video](https://www.openstack.org/summit/portland-2013/session-videos/presentation/deploying-and-managing-openstack-with-heat) [slides](http://spamaps.org/files/OpenStackSummit_HeatOpenStackManagement.pdf)
- [TripleO: OpenStack on OpenStack] (http://events.linuxfoundation.org/sites/events/files/slides/TripleO%20Overview.pdf)
- Steve Hardy's blog: [Heat Nested Resource Introspection] (http://hardysteven.blogspot.jp/2013_08_01_archive.html)
- Steve Hardy's blog: [Heat Providers/Environments 101] (http://hardysteven.blogspot.jp/2013_10_01_archive.html)
- Steve Hardy's blog: [Using Heat ResourceGroup resources] (http://hardysteven.blogspot.jp/2014/09/using-heat-resourcegroup-resources.html)
- Steve Hardy's blog: [Debugging TripleO Heat templates] (http://hardysteven.blogspot.jp/2015/04/debugging-tripleo-heat-templates.html)
- Steve Hardy's blog: [Heat SoftwareConfig resources - primer/overview] (http://hardysteven.blogspot.jp/2015/05/heat-softwareconfig-resources.html)
- Steve Hardy's blog: [TripleO Heat templates Part 1 - Roles and Groups] (http://hardysteven.blogspot.jp/2015/05/tripleo-heat-templates-part-1-roles-and.html)
- Steve Hardy's blog: [TripleO Heat templates Part 2 - Node initial deployment & config] (http://hardysteven.blogspot.jp/2015/05/tripleo-heat-templates-part-2-node.html)
- Steve Hardy's blog: [TripleO Heat templates Part 3 - Cluster configuration, introduction/primer] (http://hardysteven.blogspot.jp/2015/05/tripleo-heat-templates-part-3-cluster.html)
- OpenStack Summit Atlanta 2014: Extending TripleO for OpenStack Infrastructure Management [video](https://www.openstack.org/summit/openstack-summit-atlanta-2014/session-videos/presentation/extending-tripleo-for-openstack-infrastructure-management) [slides](http://noslzzp.com/wp-content/uploads/2014/05/extending-tripleo-for-openstack-management.pdf)
- OpenStack Summit Atlanta 2014: Application software configuration using Heat [video](https://www.openstack.org/summit/openstack-summit-atlanta-2014/session-videos/presentation/application-software-configuration-using-heat) [slides](https://www.openstack.org/assets/presentation-media/heat-software-config.pdf)
- OSC2014-fall: [「HP Helion」から見えてくるOpenStackの近未来像] (http://www.ospn.jp/osc2014-fall/pdf/OSC2014_fall_HP.pdf)
- DevConf 2014: [TripleO: Provision your datacenter with OpenStack] (https://github.com/ifarkas/devconf2014-tripleo)
- OpenStack Summit Tokyo 2015: Running an OpenStack Cloud for Several Years and Living to Tell the Tale [video](https://www.openstack.org/summit/tokyo-2015/videos/presentation/running-an-openstack-cloud-for-several-years-and-living-to-tell-the-tale) [slides](https://www.openstack.org/assets/Uploads/Running-an-OpenStack-Cloud-for-several-years-and-living-to-tell-the-tale.pdf)
- OpenStack Summit Paris 2014: How to use TripleO tools for your own project [video](https://www.youtube.com/watch?v=eB05hYkSCBU) [slides](http://www.slideshare.net/goneri/open-stack-summitparis2014presodeck4x3rd1014final-41228683)
- [TripleO Updates - Liberty Edition] (http://www.slideshare.net/openstack/tripleo-updates-liberty-edition)
- [TripleO - OpenStack on OpenStack - Deploy OpenStack using OpenStack] (http://www.slideshare.net/kiranmurari/tripleo)
- [クラウドオーケストレーション「OpenStack Heat」に迫る!] (http://www.slideshare.net/enakai/open-stack-heat20140207)
- [An Introduction to OpenStack Heat] (http://www.slideshare.net/mirantis/an-introduction-to-openstack-heat)
- [HP Helion 標準搭載!! OpenStack TripleO解説課題 – OpenStack最新情報セミナー 2015年2月] (http://www.slideshare.net/VirtualTech-JP/vtj-triple-o20150218b)
- [TripleO with already deployed servers] (http://blog-slagle.rhcloud.com/?p=299)
- [TripleO Liberty Recap] (http://blog-slagle.rhcloud.com/?p=286)
