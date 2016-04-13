# TripleOのovercloudで動くSoftwareDeploymentの仕組みを追いかける

RDO Manager 改め TripleO <sup>[1] (#footnote1)</sup> は、Ironic で overcloud のイメージを流し込んで再起動した後、overcloud 内のソフトウェア (つまり OpenStack の各種サービス) の設定を Heat の SoftwareDeployment / SoftwareConfig リソースの仕組みを使って実施する。

overcloud 上の OpenStack の設定は、多数の SoftwareDeployment (Heat のリソース) の集合体となっていて、複雑に依存関係が定義されている。例えば Galera Cluster を構成する場合は、最初に 1 ノードで bootstrap した後に残りのノードが join して...的なことをする必要があるわけだけど、そういった順序関係や待ち合わせ等が Heat リソースの依存関係として定義されている。各 overcloud ノードでは、決められた SoftwareDeployment の設定を実行し、終わったら Heat コントローラ (つまり undercloud ノード) に対して実行ステータスを signal として通知し、Heat コントローラは該当ノードに対して次の SoftwareDeployment を適用する。該当ノードは、新しい SoftwareDeployment のメタデータをもらって設定を進める。

この、overcloud ノード内のソフトウェア設定の流れをまとめたい、というのがこの文書の趣旨なのです。

<a name="footnote1">1</a>: https://www.rdoproject.org/blog/2016/02/rdo-manager-is-now-tripleo/

## おおまかな流れ

1. Heat コントローラ (heat-engine) は各ノードに対して、SoftwareDeploymentリソースをメタデータとして用意する
1. 各 overcloud ノード上では、os-collect-configがメタデータをダウンロード
1. メタデータの変更があれば、os-collect-config が os-refresh-config を実行し、os-refresh-config が変更された設定を適用

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
Nova metadata サービスから、os-collect-config に必要なデータをダウンロードする

- /var/lib/heat-cfntools/cfn-init-data

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

- systemdにより起動
- Heat APIのメタデータをモニターし、ダウンロードする
- メタデータの変更があれば、os-refresh-configを呼ぶ
- メタデータ： これを使って設定を進める。ノード固有の値が入る
- cloud-initによって、初回起動時に設定される (/etc/os-collect-config.conf)
- メタデータのダウンロード先は/var/lib/os-collect-config

### os-collect-config tips

- オプション --one-time つきで実行された場合は、一度メタデータを取得して (必要に応じてさらに os-refresh-config して) 終了
- --one-time をつけなければ (通常 systemd からこの状態でサービスとして起動)、CONF.polling_interval (デフォルト 30 秒) ごとにメタデータをポーリング

## os-refresh-config
- メタデータの変更があった場合、os-collect-configから呼ばれる
- first boot時は必ず呼ばれる (初回起動時はメタデータがないので)
- /usr/libexec/os-refresh-config以下のスクリプトを実行
  - 下記の順に、ディレクトリ配下のファイル名順に実行
    -  /usr/libexec/os-refresh-config/pre-configure.d
    -  /usr/libexec/os-refresh-config/configure.d
    -  /usr/libexec/os-refresh-config/post-configure.d
  - 各スクリプトは、os-collect-configがダウンロードしたメタデータを元に実際に適用していく

- os-refresh-configの主な実施内容 (configure.d)
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

