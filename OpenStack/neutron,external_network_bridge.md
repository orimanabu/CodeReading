# Neutron L3 Agentのexternal_network_bridgeの調査

## 調査同期
/etc/neutron/l3_agent.iniのDEFAULT.external_network_bridge を設定すると、仮想ルータの qg が br-int に、qr が br-ex にささって、br-int と br-ex の間に仮想ルータが挟まるような形になる。

external_network_bridge を設定しない場合は、仮想ルータの qg、qr ともに br-int にささって、br-int と br-ex は int-br-ex、phy-br-ex 間でOVSの内部リンクでつながる。

...ように見えるけど本当？

## 見るところ
とりあえず grep すると、パラメータ external_network_bridge は neutron/agent/l3/config.py で読み込まれて、neutron/agent/l3/agent.py で処理されているっぽい。

あとは neutron/agent/l3/namespaces.py、neutron/agent/l3/router_info.py が怪しい。

結論から書いておくと、router_info.py を見ると、external_network_bridge が設定されていればそのブリッジに、設定されていなければ br-int に仮想ルータがささるロジックが書いてあった。

## neutron/agent/l3/agent.pyでexternal_network_bridgeを参照しているところ
- L3NATAgent._fetch_external_net_id() @neutron/agent/l3/agent.py

```
        # L3 agent doesn't use external_network_bridge to handle external
        # networks, so bridge_mappings with provider networks will be used
        # and the L3 agent is able to handle any external networks.
        if not self.conf.external_network_bridge:
            return
```

関数の先頭で、パラメータ external_network_bridge が設定されていなければそのまま抜けている (None で返る)。
設定されている場合は RPC で外部ネットワークのIDを取ってきてそれを返す。

この関数を読んでいるのは同じファイルの _process_router_if_compatible()。

- L3NATAgent._process_router_if_compatible() @neutron/agent/l3/agent.py

_fetch_external_net_id() の戻り値があれば、仮想ルータの external_gateway_info の値と比べる。
同じでなければ例外を上げる。

### call flow
- PrefixDelegation.after_start() @neutron/agent/linux/pd.py
- L3NATAgentWithStateReport.after_start() @neutron/agent/l3/agent.py
- L3NATAgent.after_start() @neutron/agent/l3/agent.py
- L3NATAgent._process_routers_loop() @neutron/agent/l3/agent.py
- L3NATAgent._process_router_update() @neutron/agent/l3/agent.py
- L3NATAgent._process_router_if_compatible() @neutron/agent/l3/agent.py

pd: Prefix Delegation


## neutron/agent/l3/router_info.pyでexternal_network_bridgeを参照しているところ
- RouterInfo._plug_external_gateway() @eutron/agent/l3/router_info.py

self.driver.plug() の引き数として bridge に渡している。

```
    def _plug_external_gateway(self, ex_gw_port, interface_name, ns_name):
        self.driver.plug(ex_gw_port['network_id'],
                         ex_gw_port['id'],
                         interface_name,
                         ex_gw_port['mac_address'],
                         bridge=self.agent_conf.external_network_bridge,
                         namespace=ns_name,
                         prefix=EXTERNAL_DEV_PREFIX)
```

self.driver は \_\_init\_\_() で interface_driver が代入されている。
これは多分 /etc/neutron/l3_agent.ini で定義されている値だと思ってみる。

```
interface_driver =neutron.agent.linux.interface.OVSInterfaceDriver
```

このクラスは下記で定義されている。

- class OVSInterfaceDriver @neutron/agent/linux/interface.py

plug() は親クラス LinuxInterfaceDriver で定義されている。

- LinuxInterfaceDriver.plug() @neutron/agent/linux/interface.py

```
    def plug(self, network_id, port_id, device_name, mac_address,
             bridge=None, namespace=None, prefix=None):
        if not ip_lib.device_exists(device_name,
                                    namespace=namespace):
            self.plug_new(network_id, port_id, device_name, mac_address,
                          bridge, namespace, prefix)
        else:
            LOG.info(_LI("Device %s already exists"), device_name)
```

デバイスがなければ結局 OVSInterfaceDriver の plug_new() が呼ばれる。

```
    def plug_new(self, network_id, port_id, device_name, mac_address,
                 bridge=None, namespace=None, prefix=None):
        """Plug in the interface."""
        if not bridge:
            bridge = self.conf.ovs_integration_bridge
    (snip)
```

つまり、external_network_bridge が定義されていなければ、ここで引き数 bridge が None になるので、結果的に br-int が使われることがわかる。



## neutron/agent/l3/namespace.pyでexternal_network_bridgeを参照しているところ

- RouterNamespace.delete() @neutron/agent/l3/namespaces.py

self.driver.unplug() の引き数 bridge に external_network_bridge が設定される。
その後は OVSInterfaceDriver の unplug() に行くっぽい。



