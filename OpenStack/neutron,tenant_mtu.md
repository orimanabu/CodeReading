# NeutronのテナントネットワークごとにでMTUを変えたい
## 見るところ
- class Router(object) @neutron/wsgi.py
- class APIRouter(wsgi.Router) @neutron/api/v2/router.py


## 見るところ
- ML2Plugin._get_network_mtu() @neutron/plugins/ml2/plugin.py

type_driver.get_mtu()

- ML2Plugin.create_network() @neutron/plugins/ml2/plugin.py
- ML2Plugin._create_network_db() @neutron/plugins/ml2/plugin.py
- ML2Plugin._get_network_mtu() @neutron/plugins/ml2/plugin.py

- ML2Plugin.update_network() @neutron/plugins/ml2/plugin.py
- ML2Plugin._get_network_mtu() @neutron/plugins/ml2/plugin.py

- ML2Plugin.get_network() @neutron/plugins/ml2/plugin.py
- ML2Plugin._get_network_mtu() @neutron/plugins/ml2/plugin.py

- ML2Plugin.get_networks() @neutron/plugins/ml2/plugin.py
- ML2Plugin._get_network_mtu() @neutron/plugins/ml2/plugin.py

class VlanTypeDriver @neutron/plugins/ml2/drivers/type_vlan.py

parent: SegmentTypeDriver @neutron/plugins/ml2/drivers/helpers.py

parent: BaseTypeDriver @neutron/plugins/ml2/drivers/helpers.py

VlanTypeDriver.get_mtu() @neutron/plugins/ml2/drivers/type_vlan.py

```
    def get_mtu(self, physical_network):
        seg_mtu = super(VlanTypeDriver, self).get_mtu()
        mtu = []
        if seg_mtu > 0:
            mtu.append(seg_mtu)
        if physical_network in self.physnet_mtus:
            mtu.append(int(self.physnet_mtus[physical_network]))
        return min(mtu) if mtu else 0
```

BaseTypeDriver.get_mtu() @neutron/plugins/ml2/drivers/helpers.py

```
    def get_mtu(self, physical_network=None):
        return p_utils.get_deployment_physnet_mtu()
```

get_deployment_physnet_mtu()  @neutron/plugins/common/utils.py

```
def get_deployment_physnet_mtu():
    """Retrieves global physical network MTU setting.

    Plugins should use this function to retrieve the MTU set by the operator
    that is equal to or less than the MTU of their nodes' physical interfaces.
    Note that it is the responsibility of the plugin to deduct the value of
    any encapsulation overhead required before advertising it to VMs.
    """
    return cfg.CONF.global_physnet_mtu
```

class VxlanTypeDriver @neutron/plugins/ml2/drivers/type_vlan.py

parent: EndpointTunnelTypeDriver @neutron/plugins/ml2/drivers/type_tunnel.py

parent: TunnelTypeDriver @neutron/plugins/ml2/drivers/type_tunnel.py

parent: SegmentTypeDriver @neutron/plugins/ml2/drivers/helpers.py

parent: BaseTypeDriver @neutron/plugins/ml2/drivers/helpers.py

VxlanTypeDriver.get_mtu() @neutron/plugins/ml2/drivers/type_vlan.py

```
    def get_mtu(self, physical_network=None):
        mtu = super(VxlanTypeDriver, self).get_mtu()
        return mtu - p_const.VXLAN_ENCAP_OVERHEAD if mtu else 0
```

TunnelTypeDriver @neutron/plugins/ml2/drivers/type_tunnel.py

```
    def get_mtu(self, physical_network=None):
        seg_mtu = super(TunnelTypeDriver, self).get_mtu()
        mtu = []
        if seg_mtu > 0:
            mtu.append(seg_mtu)
        if cfg.CONF.ml2.path_mtu > 0:
            mtu.append(cfg.CONF.ml2.path_mtu)
        return min(mtu) if mtu else 0
```

## その他
- @neutron/extensions/netmtu.py
- @neutron/db/db_base_plugin_common.py
- @neutron/db/models_v2.py
- @neutron/db/netmtu_db.py

