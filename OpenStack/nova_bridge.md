# お題: ブリッジを挟まない方法の調査
前提

- ML2プラグイン, OVS
- nova-networkではなくneutron使用

メモ

- Network API (nova-network or neutron)
- Security Group API (nova or neutron)

Security Group APIは、Network APIがNeutronの場合はnova、neutronのどちらでも動く

## Network API
/etc/nova/nova.conf
```
# The full class name of the network API class to use (string
# value)
#network_api_class=nova.network.api.API
network_api_class=nova.network.neutronv2.api.API
```

- API() @nova/network/__init__.py

Neutron:

 - API.deallocate_for_instance() @nova/network/neutronv2/api.py
 - API.__unbind_ports() @nova/network/neutronv2/api.py

Nova:

 - API.deallocate_for_instance() @nova/network/api.py


## セキュリティグループの設定にしたがってiptablesのルールを作成するところ
- SecurityGroupAgentRpc.init_firewall() @neutron/agent/securitygroups_rpc.py
- OVSHybridIptablesFirewallDriver @@neutron/agent/linux/iptables_firewall.py
- IptablesFirewallDriver.__init__() @@neutron/agent/linux/iptables_firewall.py
- IptablesManager.__init__() @@neutron/agent/linux/iptables_manager.py

## qbrブリッジを挟む処理
- resume or spawn
- _create_domain_and_network()
- LibvirtDriver.plug_vifs() @nova/virt/libvirt/driver.py
- LibvirtGenericVIFDriver.plug() @nova/virt/libvirt/vif.py
- LibvirtGenericVIFDriver.plug_ovs() @nova/virt/libvirt/vif.py
- LibvirtGenericVIFDriver.plug_ovs_hybrid() @nova/virt/libvirt/vif.py
- LibvirtGenericVIFDriver._plug_bridge_with_port() @nova/virt/libvirt/vif.py

  この中でbrctl addしている

- LibvirtGenericVIFDriver.get_br_name() @nova/virt/libvirt/vif.py

  qbrなブリッジ名はここでわかる

## 仮想ポートの接続

```
    def plug_ovs(self, instance, vif):
        if self.get_firewall_required(vif) or vif.is_hybrid_plug_enabled():
            self.plug_ovs_hybrid(instance, vif)
        else:
            self.plug_ovs_bridge(instance, vif)
```

<!---
self.get_firewall_required()
	vif.is_neutron_filtering_enabled()
		neutron portのbinding:vif_detailsプロパティのport_filterを返す
vif.is_hybrid_plug_enabled()
--->


## メカニズムドライバーの初期化
- OpenvswitchMechanismDriver.__init__() @neutron/plugins/ml2/drivers/mech_openvswitch.py

- is_security_enabled() @neutron/agent/securitygroups_rpc.py の戻り値で port_filter、ovs_hybrid_plugを初期化
- _is_valid_driver_combination() @neutron/agent/securitygroups_rpc.py
- cfg.CONF.SECURITYGROUP.enable_security_groupの値で戻る


<!---
# Error
2016-02-01 23:47:32.264 21348 DEBUG keystoneclient.session [req-59a1e660-29ed-4100-9381-bd39da92c93b 9033020dd4e04a34923f9f7ae87e255d ef7504d62f314183b454e2957c843ff7 - - -] REQ: curl -g -i -X PUT http://10.0.1.111:9696/v2.0/ports/None.json -H "User-Agent: python-neutronclient" -H "Content-Type: application/json" -H "Accept: application/json" -H "X-Auth-Token: {SHA1}fc37e56302cc5e59e9a90e5ffeba4a95c974e19a" -d '{"port": {"device_owner": "", "binding:host_id": null, "device_id": ""}}' _http_log_request /usr/lib/python2.7/site-packages/keystoneclient/session.py:195
2016-02-01 23:47:32.317 21348 DEBUG keystoneclient.session [req-59a1e660-29ed-4100-9381-bd39da92c93b 9033020dd4e04a34923f9f7ae87e255d ef7504d62f314183b454e2957c843ff7 - - -] RESP: _http_log_response /usr/lib/python2.7/site-packages/keystoneclient/session.py:224
2016-02-01 23:47:32.318 21348 DEBUG neutronclient.v2_0.client [req-59a1e660-29ed-4100-9381-bd39da92c93b 9033020dd4e04a34923f9f7ae87e255d ef7504d62f314183b454e2957c843ff7 - - -] Error message: 404 Not Found

The resource could not be found.

    _handle_fault_response /usr/lib/python2.7/site-packages/neutronclient/v2_0/client.py:176
2016-02-01 23:47:32.318 21348 ERROR nova.network.neutronv2.api [req-59a1e660-29ed-4100-9381-bd39da92c93b 9033020dd4e04a34923f9f7ae87e255d ef7504d62f314183b454e2957c843ff7 - - -] Unable to clear device ID for port 'None'
2016-02-01 23:47:32.318 21348 TRACE nova.network.neutronv2.api Traceback (most recent call last):
2016-02-01 23:47:32.318 21348 TRACE nova.network.neutronv2.api   File "/usr/lib/python2.7/site-packages/nova/network/neutronv2/api.py", line 366, in _unbind_ports
2016-02-01 23:47:32.318 21348 TRACE nova.network.neutronv2.api     port_client.update_port(port_id, port_req_body)
2016-02-01 23:47:32.318 21348 TRACE nova.network.neutronv2.api   File "/usr/lib/python2.7/site-packages/neutronclient/v2_0/client.py", line 102, in with_params
2016-02-01 23:47:32.318 21348 TRACE nova.network.neutronv2.api     ret = self.function(instance, *args, **kwargs)
2016-02-01 23:47:32.318 21348 TRACE nova.network.neutronv2.api   File "/usr/lib/python2.7/site-packages/neutronclient/v2_0/client.py", line 549, in update_port
2016-02-01 23:47:32.318 21348 TRACE nova.network.neutronv2.api     return self.put(self.port_path % (port), body=body)
2016-02-01 23:47:32.318 21348 TRACE nova.network.neutronv2.api   File "/usr/lib/python2.7/site-packages/neutronclient/v2_0/client.py", line 302, in put
2016-02-01 23:47:32.318 21348 TRACE nova.network.neutronv2.api     headers=headers, params=params)
2016-02-01 23:47:32.318 21348 TRACE nova.network.neutronv2.api   File "/usr/lib/python2.7/site-packages/neutronclient/v2_0/client.py", line 270, in retry_request
2016-02-01 23:47:32.318 21348 TRACE nova.network.neutronv2.api     headers=headers, params=params)
2016-02-01 23:47:32.318 21348 TRACE nova.network.neutronv2.api   File "/usr/lib/python2.7/site-packages/neutronclient/v2_0/client.py", line 211, in do_request
2016-02-01 23:47:32.318 21348 TRACE nova.network.neutronv2.api     self._handle_fault_response(status_code, replybody)
2016-02-01 23:47:32.318 21348 TRACE nova.network.neutronv2.api   File "/usr/lib/python2.7/site-packages/neutronclient/v2_0/client.py", line 185, in _handle_fault_response
2016-02-01 23:47:32.318 21348 TRACE nova.network.neutronv2.api     exception_handler_v20(status_code, des_error_body)
2016-02-01 23:47:32.318 21348 TRACE nova.network.neutronv2.api   File "/usr/lib/python2.7/site-packages/neutronclient/v2_0/client.py", line 83, in exception_handler_v20
2016-02-01 23:47:32.318 21348 TRACE nova.network.neutronv2.api     message=message)
2016-02-01 23:47:32.318 21348 TRACE nova.network.neutronv2.api NeutronClientException: 404 Not Found
2016-02-01 23:47:32.318 21348 TRACE nova.network.neutronv2.api
2016-02-01 23:47:32.318 21348 TRACE nova.network.neutronv2.api The resource could not be found.
2016-02-01 23:47:32.318 21348 TRACE nova.network.neutronv2.api
2016-02-01 23:47:32.318 21348 TRACE nova.network.neutronv2.api
2016-02-01 23:47:32.318 21348 TRACE nova.network.neutronv2.api

Unable to clear device ID for port 'None'
API._unbind_ports() @nova/network/neutronv2/api.py

  API.allocate_for_instance() @nova/network/neutronv2/api.py
* API.deallocate_for_instance() @nova/network/neutronv2/api.py
  API.deallocate_port_for_instance() @nova/network/neutronv2/api.py
--->

## security_group_api

/etc/nova/nova.conf
```
# The full class name of the security API class (string value)
#security_group_api=nova
security_group_api=neutron
```

### 定義
- get_openstack_security_group_driver() @nova/network/security_group/openstack_driver.py

  + nova: nova.compute.api.SecurityGroupAPI

    - class SecurityGroupAPI @nova/compute/api.py

  + neutron: nova.network.security_group.neutron_driver.SecurityGroupAPI

    - class SecurityGroupApi @nova/network/security_group/neutron_driver.py

- base class: SecurityGroupBase @nova/network/security_group/security_group_base.py

### 読んでいるところ
- ConductorManager.__init__() @nova/conductor/manager.py
```
        self.security_group_api = (
            openstack_driver.get_openstack_security_group_driver())
```

- API.__init__() @nova/compute/api.py
```
        self.security_group_api = (security_group_api or
            openstack_driver.get_openstack_security_group_driver(
                skip_policy_check=skip_policy_check))
```

- SecurityGroupControllerBase.__init__() @nova/api/openstack/compute/contrib/security_groups.py
```
        self.security_group_api = (
            openstack_driver.get_openstack_security_group_driver())
```
