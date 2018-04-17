# QoS implementation - Nova vs Neutron vs Cinder

# Nova QoS

## Flavor

### m1.normal : a flavor without QoS properties

Create a flavor without QoS properties.

```
openstack flavor create --ram 1024 --disk 20 --vcpus 1 m1.normal
```

```
[stack@director ~]$ openstack flavor show m1.normal
+----------------------------+--------------------------------------------+
| Field                      | Value                                      |
+----------------------------+--------------------------------------------+
| OS-FLV-DISABLED:disabled   | False                                      |
| OS-FLV-EXT-DATA:ephemeral  | 0                                          |
| access_project_ids         | None                                       |
| disk                       | 20                                         |
| id                         | ed846e28-510c-4ca8-8bd9-0e06f5de6461       |
| name                       | m1.normal                                  |
| os-flavor-access:is_public | True                                       |
| properties                 | aggregate_instance_extra_specs:host='vlan' |
| ram                        | 1024                                       |
| rxtx_factor                | 1.0                                        |
| swap                       |                                            |
| vcpus                      | 1                                          |
+----------------------------+--------------------------------------------+
```

### m1.resquota : a flavor with QoS properties

Create a flavor with QoS properties.

```
openstack flavor create --ram 1024 --disk 20 --vcpus 1 m1.resquota
```

```
openstack flavor set m1.resquota \
--property quota:cpu_shares=512 \
--property quota:disk_read_bytes_sec=1000000 \
--property quota:disk_write_bytes_sec=1024000 \
--property quota:vif_outbound_average=32768 \
--property quota:vif_outbound_peak=65536 \
--property quota:vif_outbound_burst=131072 \
--property quota:vif_inbound_average=32768 \
--property quota:vif_inbound_peak=65536 \
--property quota:vif_inbound_burst=131072
```

```
[stack@director scripts]$ openstack flavor show m1.resquota
+----------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Field                      | Value                                                                                                                                                                                                                                                                                                          |
+----------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| OS-FLV-DISABLED:disabled   | False                                                                                                                                                                                                                                                                                                          |
| OS-FLV-EXT-DATA:ephemeral  | 0                                                                                                                                                                                                                                                                                                              |
| access_project_ids         | None                                                                                                                                                                                                                                                                                                           |
| disk                       | 20                                                                                                                                                                                                                                                                                                             |
| id                         | bb3c4ff8-c09f-444d-955e-46e4e1f6fb4a                                                                                                                                                                                                                                                                           |
| name                       | m1.resquota                                                                                                                                                                                                                                                                                                    |
| os-flavor-access:is_public | True                                                                                                                                                                                                                                                                                                           |
| properties                 | quota:cpu_shares='512', quota:disk_read_bytes_sec='1000000', quota:disk_write_bytes_sec='1024000', quota:vif_inbound_average='32768', quota:vif_inbound_burst='131072', quota:vif_inbound_peak='65536', quota:vif_outbound_average='32768', quota:vif_outbound_burst='131072', quota:vif_outbound_peak='65536' |
| ram                        | 1024                                                                                                                                                                                                                                                                                                           |
| rxtx_factor                | 1.0                                                                                                                                                                                                                                                                                                            |
| swap                       |                                                                                                                                                                                                                                                                                                                |
| vcpus                      | 1                                                                                                                                                                                                                                                                                                              |
+----------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
```

## Instance

### Create an insntance without QoS properties

```
[stack@director ~]$ openstack server create --wait --flavor m1.normal  --key-name sshkey_test --image rhel7 --security-group sg_test --network mplane_vlan11 --network provider_test15 --network provider_test16 --availability-zone az_vlan vm_normal

+-----------------------------+----------------------------------------------------------------------------------------+
| Field                       | Value                                                                                  |
+-----------------------------+----------------------------------------------------------------------------------------+
| OS-DCF:diskConfig           | MANUAL                                                                                 |
| OS-EXT-AZ:availability_zone | az_vlan                                                                                |
| OS-EXT-STS:power_state      | Running                                                                                |
| OS-EXT-STS:task_state       | None                                                                                   |
| OS-EXT-STS:vm_state         | active                                                                                 |
| OS-SRV-USG:launched_at      | 2018-04-16T12:50:22.000000                                                             |
| OS-SRV-USG:terminated_at    | None                                                                                   |
| accessIPv4                  |                                                                                        |
| accessIPv6                  |                                                                                        |
| addresses                   | mplane_vlan11=10.11.0.57; provider_test16=192.168.16.55; provider_test15=192.168.15.58 |
| adminPass                   | BG79PRhis4FP                                                                           |
| config_drive                |                                                                                        |
| created                     | 2018-04-16T12:50:10Z                                                                   |
| flavor                      | m1.normal (ed846e28-510c-4ca8-8bd9-0e06f5de6461)                                       |
| hostId                      | 708fc4d3217216cfed661ae2aaf627fec49f12437d221cf1fd1faed9                               |
| id                          | 30ad89ac-5906-49ca-8d52-3c6343c598f6                                                   |
| image                       | rhel7 (c11a1c31-f703-4ae6-a689-5a6b9a624625)                                           |
| key_name                    | sshkey_test                                                                            |
| name                        | vm_normal                                                                              |
| progress                    | 0                                                                                      |
| project_id                  | 995b4947cc4044fba99bade057053803                                                       |
| properties                  |                                                                                        |
| security_groups             | name='sg_test'                                                                         |
|                             | name='sg_test'                                                                         |
|                             | name='sg_test'                                                                         |
| status                      | ACTIVE                                                                                 |
| updated                     | 2018-04-16T12:50:22Z                                                                   |
| user_id                     | 5a86b1db33b64571953b2022186010fe                                                       |
| volumes_attached            |                                                                                        |
+-----------------------------+----------------------------------------------------------------------------------------+
```

### Create an instance with QoS properties

```
[stack@director ~]$ openstack server create --wait --flavor m1.resquota  --key-name sshkey_test --image rhel7 --security-group sg_test --network mplane_vlan11 --network provider_test15 --network provider_test16 --availability-zone az_vlan vm_resquota

+-----------------------------+----------------------------------------------------------------------------------------+
| Field                       | Value                                                                                  |
+-----------------------------+----------------------------------------------------------------------------------------+
| OS-DCF:diskConfig           | MANUAL                                                                                 |
| OS-EXT-AZ:availability_zone | az_vlan                                                                                |
| OS-EXT-STS:power_state      | Running                                                                                |
| OS-EXT-STS:task_state       | None                                                                                   |
| OS-EXT-STS:vm_state         | active                                                                                 |
| OS-SRV-USG:launched_at      | 2018-04-16T12:48:48.000000                                                             |
| OS-SRV-USG:terminated_at    | None                                                                                   |
| accessIPv4                  |                                                                                        |
| accessIPv6                  |                                                                                        |
| addresses                   | mplane_vlan11=10.11.0.51; provider_test16=192.168.16.51; provider_test15=192.168.15.57 |
| adminPass                   | ZS6k7mACH3qt                                                                           |
| config_drive                |                                                                                        |
| created                     | 2018-04-16T12:48:32Z                                                                   |
| flavor                      | m1.resquota (bb3c4ff8-c09f-444d-955e-46e4e1f6fb4a)                                     |
| hostId                      | 708fc4d3217216cfed661ae2aaf627fec49f12437d221cf1fd1faed9                               |
| id                          | 850724a4-029c-457b-a99d-3a18e8e413da                                                   |
| image                       | rhel7 (c11a1c31-f703-4ae6-a689-5a6b9a624625)                                           |
| key_name                    | sshkey_test                                                                            |
| name                        | vm_resquota                                                                            |
| progress                    | 0                                                                                      |
| project_id                  | 995b4947cc4044fba99bade057053803                                                       |
| properties                  |                                                                                        |
| security_groups             | name='sg_test'                                                                         |
|                             | name='sg_test'                                                                         |
|                             | name='sg_test'                                                                         |
| status                      | ACTIVE                                                                                 |
| updated                     | 2018-04-16T12:48:48Z                                                                   |
| user_id                     | 5a86b1db33b64571953b2022186010fe                                                       |
| volumes_attached            |                                                                                        |
+-----------------------------+----------------------------------------------------------------------------------------+
```

```
[stack@director ~]$ openstack server create --wait --flavor m1.normal  --key-name sshkey_test --image rhel7 --security-group sg_test --network mplane_vlan11 --network provider_test15 --network provider_test16 --availability-zone az_vlan vm_neutron_qos

+-----------------------------+----------------------------------------------------------------------------------------+
| Field                       | Value                                                                                  |
+-----------------------------+----------------------------------------------------------------------------------------+
| OS-DCF:diskConfig           | MANUAL                                                                                 |
| OS-EXT-AZ:availability_zone | az_vlan                                                                                |
| OS-EXT-STS:power_state      | Running                                                                                |
| OS-EXT-STS:task_state       | None                                                                                   |
| OS-EXT-STS:vm_state         | active                                                                                 |
| OS-SRV-USG:launched_at      | 2018-04-16T13:21:24.000000                                                             |
| OS-SRV-USG:terminated_at    | None                                                                                   |
| accessIPv4                  |                                                                                        |
| accessIPv6                  |                                                                                        |
| addresses                   | mplane_vlan11=10.11.0.53; provider_test16=192.168.16.53; provider_test15=192.168.15.53 |
| adminPass                   | U8NbAriWSbwU                                                                           |
| config_drive                |                                                                                        |
| created                     | 2018-04-16T13:21:11Z                                                                   |
| flavor                      | m1.normal (ed846e28-510c-4ca8-8bd9-0e06f5de6461)                                       |
| hostId                      | 708fc4d3217216cfed661ae2aaf627fec49f12437d221cf1fd1faed9                               |
| id                          | 9e6c9377-ff30-4aa8-9220-2e663dfd54b7                                                   |
| image                       | rhel7 (c11a1c31-f703-4ae6-a689-5a6b9a624625)                                           |
| key_name                    | sshkey_test                                                                            |
| name                        | vm_neutron_qos                                                                         |
| progress                    | 0                                                                                      |
| project_id                  | 995b4947cc4044fba99bade057053803                                                       |
| properties                  |                                                                                        |
| security_groups             | name='sg_test'                                                                         |
|                             | name='sg_test'                                                                         |
|                             | name='sg_test'                                                                         |
| status                      | ACTIVE                                                                                 |
| updated                     | 2018-04-16T13:21:24Z                                                                   |
| user_id                     | 5a86b1db33b64571953b2022186010fe                                                       |
| volumes_attached            |                                                                                        |
+-----------------------------+----------------------------------------------------------------------------------------+
```

## CPU QoS

### Without QoS

libvit XML:

```xml
  <cputune>
    <shares>1024</shares>
  </cputune>
```

Resulted cgroups setting:

```
[root@comp-1 ~]# cat /sys/fs/cgroup/cpu/machine.slice/machine-qemu\\x2d11\\x2dinstance\\x2d00000042.scope/cpu.shares
1024
```

### With QoS

libvit XML: "quota:cpu_shares=512"

```xml
  <cputune>
    <shares>512</shares>
  </cputune>
```

Resulted cgroups setting:

```
[root@comp-1 ~]# cat /sys/fs/cgroup/cpu/machine.slice/machine-qemu\\x2d10\\x2dinstance\\x2d00000041.scope/cpu.shares
512
```

## Disk I/O QoS

### Without QoS

libvirt XML:

```xml
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2' cache='none'/>
      <source file='/var/lib/nova/instances/30ad89ac-5906-49ca-8d52-3c6343c598f6/disk'/>
      <backingStore type='file' index='1'>
        <format type='raw'/>
        <source file='/var/lib/nova/instances/_base/a24c93285792d6ac5a718a70a6ef23e119f98f54'/>
        <backingStore/>
      </backingStore>
      <target dev='vda' bus='virtio'/>
      <alias name='virtio-disk0'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x06' function='0x0'/>
    </disk>
```

Qemu options:

```
-drive file=/var/lib/nova/instances/30ad89ac-5906-49ca-8d52-3c6343c598f6/disk,format=qcow2,if=none,id=drive-virtio-disk0,cache=none
```


### With QoS

libvit XML: with "quota:disk\_read\_bytes\_sec=1000000" and "quota:disk\_write\_bytes\_sec=1024000" flavor properties, disk related XML gets <iotune> element.

```xml
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2' cache='none'/>
      <source file='/var/lib/nova/instances/850724a4-029c-457b-a99d-3a18e8e413da/disk'/>
      <backingStore type='file' index='1'>
        <format type='raw'/>
        <source file='/var/lib/nova/instances/_base/a24c93285792d6ac5a718a70a6ef23e119f98f54'/>
        <backingStore/>
      </backingStore>
      <target dev='vda' bus='virtio'/>
      <iotune>
        <read_bytes_sec>1000000</read_bytes_sec>
        <write_bytes_sec>1024000</write_bytes_sec>
      </iotune>
      <alias name='virtio-disk0'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x06' function='0x0'/>
    </disk>
```

Qemu options: <iotune> elements are translated into throttling.bps-read and throttling.bps-write Qemu options.

```
-drive file=/var/lib/nova/instances/850724a4-029c-457b-a99d-3a18e8e413da/disk,format=qcow2,if=none,id=drive-virtio-disk0,cache=none,throttling.bps-read=1000000,throttling.bps-write=1024000
```

See also: [I/O scheduling, iotune and difference between read_bytes_sec and read_bytes_sec_max in qemu/kvm](https://access.redhat.com/solutions/3153531)

## Network QoS

### Without QoS

#### libvirt XML

```xml
    <interface type='bridge'>
      <mac address='fa:16:3e:be:fd:48'/>
      <source bridge='br-int'/>
      <virtualport type='openvswitch'>
        <parameters interfaceid='b614c1d3-75e5-483f-88fd-cec050652945'/>
      </virtualport>
      <target dev='tapb614c1d3-75'/>
      <model type='virtio'/>
      <alias name='net0'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x03' function='0x0'/>
    </interface>
```

#### tc outputs

##### qdisc

```
[root@comp-1 ~]# tc qdisc show dev tapb614c1d3-75
qdisc pfifo_fast 0: root refcnt 2 bands 3 priomap  1 2 2 2 1 2 0 0 1 1 1 1 1 1 1 1
```

##### no settings for class, filter

```
[root@comp-1 ~]# tc class show dev tapb614c1d3-75
[root@comp-1 ~]# tc filter show dev tapb614c1d3-75
```

### Wth QoS

#### libvirt XML

All interfaces got QoS settings from the flavor as <bandwidth> elements.

```xml
    <interface type='bridge'>
      <mac address='fa:16:3e:8d:f3:ae'/>
      <source bridge='br-int'/>
      <virtualport type='openvswitch'>
        <parameters interfaceid='bb8410ad-a026-4e9a-8f0b-0e8f611d5588'/>
      </virtualport>
      <bandwidth>
        <inbound average='32768' peak='65536' burst='131072'/>
        <outbound average='32768' peak='65536' burst='131072'/>
      </bandwidth>
      <target dev='tapbb8410ad-a0'/>
      <model type='virtio'/>
      <alias name='net0'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x03' function='0x0'/>
    </interface>
```

```xml
    <interface type='bridge'>
      <mac address='fa:16:3e:60:1e:07'/>
      <source bridge='br-int'/>
      <virtualport type='openvswitch'>
        <parameters interfaceid='a1e966cd-47e7-4bc2-967c-13638afd47ec'/>
      </virtualport>
      <bandwidth>
        <inbound average='32768' peak='65536' burst='131072'/>
        <outbound average='32768' peak='65536' burst='131072'/>
      </bandwidth>
      <target dev='tapa1e966cd-47'/>
      <model type='virtio'/>
      <alias name='net1'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x04' function='0x0'/>
    </interface>
```

```xml
    <interface type='bridge'>
      <mac address='fa:16:3e:15:9c:1c'/>
      <source bridge='br-int'/>
      <virtualport type='openvswitch'>
        <parameters interfaceid='e0bb2633-17ce-4eda-9161-e6ffdf3243c6'/>
      </virtualport>
      <bandwidth>
        <inbound average='32768' peak='65536' burst='131072'/>
        <outbound average='32768' peak='65536' burst='131072'/>
      </bandwidth>
      <target dev='tape0bb2633-17'/>
      <model type='virtio'/>
      <alias name='net2'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x05' function='0x0'/>
    </interface>
```

#### tc outputs

##### qdisc

```
[root@comp-1 ~]# tc qdisc show dev tapbb8410ad-a0
qdisc htb 1: root refcnt 2 r2q 10 default 1 direct_packets_stat 1
qdisc sfq 2: parent 1:1 limit 127p quantum 1514b depth 127 divisor 1024 perturb 10sec
```

- htb: Hierarchical Token Bucket
- sfq: Stochastic Fairness Queueing

##### class

```
[root@comp-1 ~]# tc class show dev tapbb8410ad-a0
class htb 1:1 root leaf 2: prio 0 rate 262144Kbit ceil 524288Kbit burst 128Mb cburst 1572b
```

- average: 32768 KB/s = 262144 Kbps
- peak: 65536 KB/s = 524288 Kbps
- burst: 131072 KB = 128MB

##### filter

```
[root@comp-1 ~]# tc filter show dev tapbb8410ad-a0
filter parent 1: protocol all pref 1 fw
filter parent 1: protocol all pref 1 fw handle 0x1 classid :1
```

# Neutron QoS

## Bandwidth QoS Policy

Create a QoS policy.

```
[stack@director ~]$ openstack network qos policy create bw-limiter
+-------------+--------------------------------------+
| Field       | Value                                |
+-------------+--------------------------------------+
| description |                                      |
| id          | 3f828df0-aa14-4443-949c-f370e55ebb85 |
| is_default  | False                                |
| name        | bw-limiter                           |
| project_id  | 80d05afc3ed94fa087db9c63be5bbe42     |
| rules       | []                                   |
| shared      | False                                |
+-------------+--------------------------------------+
```

Create a QoS rule in the policy.

```
[stack@director ~]$ openstack network qos rule create --type bandwidth-limit --max-kbps 3000 --max-burst-kbits 300 --egress bw-limiter
+----------------+--------------------------------------+
| Field          | Value                                |
+----------------+--------------------------------------+
| direction      | egress                               |
| id             | 8c4b887e-d69f-4b32-a9c3-b77b82b17311 |
| max_burst_kbps | 300                                  |
| max_kbps       | 3000                                 |
| name           | None                                 |
| project_id     |                                      |
+----------------+--------------------------------------+
```

Apply the Qos policy to a port connected to an instance.

```
[stack@director ~]$ openstack port list | grep 192.168.16.53
| 679563b6-d1a2-498a-a431-f2b29c6f1538 |                       | fa:16:3e:74:b8:a8 | ip_address='192.168.16.53', subnet_id='2ddd1144-5961-4919-b70c-7b30cf983efd' | ACTIVE |
```

```
[root@comp-1 ~]# ovs-ofctl show br-int
OFPT_FEATURES_REPLY (xid=0x2): dpid:00006625ae757e4f
n_tables:254, n_buffers:0
capabilities: FLOW_STATS TABLE_STATS PORT_STATS QUEUE_STATS ARP_MATCH_IP
actions: output enqueue set_vlan_vid set_vlan_pcp strip_vlan mod_dl_src mod_dl_dst mod_nw_src mod_nw_dst mod_nw_tos mod_tp_src mod_tp_dst
<snip>
 26(tap679563b6-d1): addr:fe:16:3e:74:b8:a8
     config:     0
     state:      0
     current:    10MB-FD COPPER
     speed: 10 Mbps now, 0 Mbps max
<snip>
```

```
[stack@director ~]$ openstack port set 679563b6-d1a2-498a-a431-f2b29c6f1538 --qos-policy bw-limiter
[stack@director ~]$ openstack port show 679563b6-d1a2-498a-a431-f2b29c6f1538
+-----------------------+------------------------------------------------------------------------------+
| Field                 | Value                                                                        |
+-----------------------+------------------------------------------------------------------------------+
| admin_state_up        | UP                                                                           |
| allowed_address_pairs |                                                                              |
| binding_host_id       | comp-1.ngpf.local                                                            |
| binding_profile       |                                                                              |
| binding_vif_details   | datapath_type='system', ovs_hybrid_plug='False', port_filter='True'          |
| binding_vif_type      | ovs                                                                          |
| binding_vnic_type     | normal                                                                       |
| created_at            | 2018-04-16T13:21:15Z                                                         |
| data_plane_status     | None                                                                         |
| description           |                                                                              |
| device_id             | 9e6c9377-ff30-4aa8-9220-2e663dfd54b7                                         |
| device_owner          | compute:az_vlan                                                              |
| dns_assignment        | None                                                                         |
| dns_name              | None                                                                         |
| extra_dhcp_opts       |                                                                              |
| fixed_ips             | ip_address='192.168.16.53', subnet_id='2ddd1144-5961-4919-b70c-7b30cf983efd' |
| id                    | 679563b6-d1a2-498a-a431-f2b29c6f1538                                         |
| ip_address            | None                                                                         |
| mac_address           | fa:16:3e:74:b8:a8                                                            |
| name                  |                                                                              |
| network_id            | f6ccca52-8f58-4a0d-b412-e6010cc8dc30                                         |
| option_name           | None                                                                         |
| option_value          | None                                                                         |
| port_security_enabled | True                                                                         |
| project_id            | 995b4947cc4044fba99bade057053803                                             |
| qos_policy_id         | 3f828df0-aa14-4443-949c-f370e55ebb85                                         |
| revision_number       | 9                                                                            |
| security_group_ids    | 0efa2fbf-7f69-45fe-8471-7a6f5a0dd22d                                         |
| status                | ACTIVE                                                                       |
| subnet_id             | None                                                                         |
| tags                  |                                                                              |
| trunk_details         | None                                                                         |
| updated_at            | 2018-04-16T13:35:45Z                                                         |
+-----------------------+------------------------------------------------------------------------------+
```

The QoS parameters are set in ingress\_policing\_burst and ingress\_policing\_rate column in "interface" OVSDB table.

```
[root@comp-1 ~]# ovs-vsctl list interface | grep tap679563b6-d1 -A7 -B 26
_uuid               : a99e9ecb-f19d-4232-9c1e-8dfa1b874e1e
admin_state         : up
bfd                 : {}
bfd_status          : {}
cfm_fault           : []
cfm_fault_status    : []
cfm_flap_count      : []
cfm_health          : []
cfm_mpid            : []
cfm_remote_mpids    : []
cfm_remote_opstate  : []
duplex              : full
error               : []
external_ids        : {attached-mac="fa:16:3e:74:b8:a8", iface-id="679563b6-d1a2-498a-a431-f2b29c6f1538", iface-status=active, vm-id="9e6c9377-ff30-4aa8-9220-2e663dfd54b7"}
ifindex             : 65
ingress_policing_burst: 300
ingress_policing_rate: 3000
lacp_current        : []
link_resets         : 1
link_speed          : 10000000
link_state          : up
lldp                : {}
mac                 : []
mac_in_use          : "fe:16:3e:74:b8:a8"
mtu                 : 1500
mtu_request         : []
name                : "tap679563b6-d1"
ofport              : 26
ofport_request      : []
options             : {}
other_config        : {}
statistics          : {collisions=0, rx_bytes=0, rx_crc_err=0, rx_dropped=0, rx_errors=0, rx_frame_err=0, rx_over_err=0, rx_packets=0, tx_bytes=438, tx_dropped=0, tx_errors=0, tx_packets=5}
status              : {driver_name=tun, driver_version="1.6", firmware_version=""}
type                : ""
```

OVS sets the QoS policy as tc qdisc.

```
[root@comp-1 ~]# tc qdisc show dev tap679563b6-d1
qdisc pfifo_fast 0: root refcnt 2 bands 3 priomap  1 2 2 2 1 2 0 0 1 1 1 1 1 1 1 1
qdisc ingress ffff: parent ffff:fff1 ----------------
```

```
[root@comp-1 ~]# tc class show dev tap679563b6-d1
[root@comp-1 ~]# tc class show dev tap679563b6-d1 root
[root@comp-1 ~]# tc class show dev tap679563b6-d1 parent ffff:fff1
```

```
[root@comp-1 ~]# tc filter show dev tap679563b6-d1 root
filter parent ffff: protocol all pref 49 basic
filter parent ffff: protocol all pref 49 basic handle 0x1
 police 0xd rate 3000Kbit burst 38400b mtu 64Kb action drop overhead 0b
ref 1 bind 1
```

```
[root@comp-1 ~]# tc filter show dev tap679563b6-d1 parent ffff:fff1
filter parent ffff: protocol all pref 49 basic
filter parent ffff: protocol all pref 49 basic handle 0x1
 police 0xd rate 3000Kbit burst 38400b mtu 64Kb action drop overhead 0b
ref 1 bind 1
```

## DSCP marking

Create a QoS policy.

```
[stack@director ~]$ openstack network qos policy create dscp-marking
+-------------+--------------------------------------+
| Field       | Value                                |
+-------------+--------------------------------------+
| description |                                      |
| id          | 3be649b0-1c77-469c-b182-645cea3d7931 |
| is_default  | False                                |
| name        | dscp-marking                         |
| project_id  | 80d05afc3ed94fa087db9c63be5bbe42     |
| rules       | []                                   |
| shared      | False                                |
+-------------+--------------------------------------+
```

Create a QoS rule in the policy.

```
[stack@director ~]$ openstack network qos rule create dscp-marking --type dscp-marking --dscp-mark 26
+------------+--------------------------------------+
| Field      | Value                                |
+------------+--------------------------------------+
| dscp_mark  | 26                                   |
| id         | 12923ae9-7205-4b8f-98aa-3e1bdb71ae2a |
| name       | None                                 |
| project_id |                                      |
+------------+--------------------------------------+
```

Apply the Qos policy to a port connected to an instance.

```
[stack@director ~]$ openstack port list | grep 192.168.15.53
| 68fe8005-c472-4e14-9225-e023cc21a47e |                       | fa:16:3e:47:d6:e9 | ip_address='192.168.15.53', subnet_id='79ea83e9-554a-46f5-963c-2a3d4f053a2b' | ACTIVE |
```

```
[stack@director ~]$ openstack port set 68fe8005-c472-4e14-9225-e023cc21a47e --qos-policy dscp-marking
[stack@director ~]$ openstack port show 68fe8005-c472-4e14-9225-e023cc21a47e
+-----------------------+------------------------------------------------------------------------------+
| Field                 | Value                                                                        |
+-----------------------+------------------------------------------------------------------------------+
| admin_state_up        | UP                                                                           |
| allowed_address_pairs |                                                                              |
| binding_host_id       | comp-1.ngpf.local                                                            |
| binding_profile       |                                                                              |
| binding_vif_details   | datapath_type='system', ovs_hybrid_plug='False', port_filter='True'          |
| binding_vif_type      | ovs                                                                          |
| binding_vnic_type     | normal                                                                       |
| created_at            | 2018-04-16T13:21:14Z                                                         |
| data_plane_status     | None                                                                         |
| description           |                                                                              |
| device_id             | 9e6c9377-ff30-4aa8-9220-2e663dfd54b7                                         |
| device_owner          | compute:az_vlan                                                              |
| dns_assignment        | None                                                                         |
| dns_name              | None                                                                         |
| extra_dhcp_opts       |                                                                              |
| fixed_ips             | ip_address='192.168.15.53', subnet_id='79ea83e9-554a-46f5-963c-2a3d4f053a2b' |
| id                    | 68fe8005-c472-4e14-9225-e023cc21a47e                                         |
| ip_address            | None                                                                         |
| mac_address           | fa:16:3e:47:d6:e9                                                            |
| name                  |                                                                              |
| network_id            | fa0585ab-da08-423f-8b36-f2d9e4a169f6                                         |
| option_name           | None                                                                         |
| option_value          | None                                                                         |
| port_security_enabled | True                                                                         |
| project_id            | 995b4947cc4044fba99bade057053803                                             |
| qos_policy_id         | 3be649b0-1c77-469c-b182-645cea3d7931                                         |
| revision_number       | 9                                                                            |
| security_group_ids    | 0efa2fbf-7f69-45fe-8471-7a6f5a0dd22d                                         |
| status                | ACTIVE                                                                       |
| subnet_id             | None                                                                         |
| tags                  |                                                                              |
| trunk_details         | None                                                                         |
| updated_at            | 2018-04-16T14:07:21Z                                                         |
+-----------------------+------------------------------------------------------------------------------+
```

OVS injects the DSCP mark using "mod\_nw\_tos" action.

```
[root@comp-1 ~]# ovs-ofctl dump-flows br-int
NXST_FLOW reply (xid=0x4):
 cookie=0xf8ec0bba40ce1ad5, duration=83.655s, table=0, n_packets=0, n_bytes=0, idle_age=83, priority=65535,reg2=0,in_port=25 actions=mod_nw_tos:104,load:0x37->NXM_NX_REG2[0..5],resubmit(,0)
 cookie=0x6a2c0f73194aab10, duration=4802.839s, table=0, n_packets=1147, n_bytes=117336, idle_age=1057, priority=3,in_port=1,dl_vlan=11 actions=mod_vlan_vid:14,resubmit(,60)
 cookie=0x6a2c0f73194aab10, duration=4800.839s, table=0, n_packets=0, n_bytes=0, idle_age=4800, priority=3,in_port=1,dl_vlan=15 actions=mod_vlan_vid:15,resubmit(,60)
 cookie=0x6a2c0f73194aab10, duration=4798.834s, table=0, n_packets=0, n_bytes=0, idle_age=4798, priority=3,in_port=1,dl_vlan=16 actions=mod_vlan_vid:16,resubmit(,60)
 cookie=0x6a2c0f73194aab10, duration=1589578.123s, table=0, n_packets=3184444, n_bytes=191795700, idle_age=0, hard_age=65534, priority=2,in_port=1 actions=drop
 cookie=0x6a2c0f73194aab10, duration=1589578.892s, table=0, n_packets=362684, n_bytes=34978542, idle_age=1057, hard_age=65534, priority=0 actions=resubmit(,60)
 cookie=0x6a2c0f73194aab10, duration=1589578.893s, table=23, n_packets=0, n_bytes=0, idle_age=65534, hard_age=65534, priority=0 actions=drop
 cookie=0x6a2c0f73194aab10, duration=1589578.889s, table=24, n_packets=0, n_bytes=0, idle_age=65534, hard_age=65534, priority=0 actions=drop
 cookie=0x6a2c0f73194aab10, duration=4800.755s, table=60, n_packets=461, n_bytes=41376, idle_age=1089, priority=100,in_port=18 actions=load:0x12->NXM_NX_REG5[],load:0xe->NXM_NX_REG6[],resubmit(,71)
<snip>
```

Note that DiffServ code point 26 is equivalent for TOS value 104.

- DSCP 26 = 011010 (Class AF31)
- TOS 104 = 0110 1000

Tcpdump: "tos 0x68" means TOS field 104.

```
09:11:27.086290 fa:16:3e:47:d6:e9 > fa:16:3e:17:d4:a9, ethertype 802.1Q (0x8100), length 102: vlan 15, p 0, ethertype IPv4, (tos 0x68, ttl 64, id 14955, offset 0, flags [DF], proto ICMP (1), length 84)
    192.168.15.53 > 192.168.15.50: ICMP echo request, id 16632, seq 165, length 64
```

Wireshark:

![DSCP marking pcap](qos.png "DSCP marking pcap")

# Cinder QoS

<details>
<summary>
Cinder QoS properties are propagated to Nova via connection info, then implemented as Qemu throttle.
</summary>

<div>
In Cinder, QoS specs are parsed and set to connection info.

- \_parse\_connection\_options() @cinder/volume/manager.py

```python
class VolumeManager(manager.CleanableManager,
                    manager.SchedulerDependentManager):
<snip>
    def _parse_connection_options(self, context, volume, conn_info):
        # Add qos_specs to connection info
        typeid = volume.volume_type_id
        specs = None
        if typeid:
            res = volume_types.get_volume_type_qos_specs(typeid)
            qos = res['qos_specs']
            # only pass qos_specs that is designated to be consumed by
            # front-end, or both front-end and back-end.
            if qos and qos.get('consumer') in ['front-end', 'both']:
                specs = qos.get('specs')

            if specs is not None:
                # Compute fixed IOPS values for per-GB keys
                if 'write_iops_sec_per_gb' in specs:
                    specs['write_iops_sec'] = (
                        int(specs['write_iops_sec_per_gb']) * int(volume.size))
                    specs.pop('write_iops_sec_per_gb')

                if 'read_iops_sec_per_gb' in specs:
                    specs['read_iops_sec'] = (
                        int(specs['read_iops_sec_per_gb']) * int(volume.size))
                    specs.pop('read_iops_sec_per_gb')

                if 'total_iops_sec_per_gb' in specs:
                    specs['total_iops_sec'] = (
                        int(specs['total_iops_sec_per_gb']) * int(volume.size))
                    specs.pop('total_iops_sec_per_gb')

        qos_spec = dict(qos_specs=specs)
        conn_info['data'].update(qos_spec)
```

Nova gets QoS settings from the connection info and stores them to LibvirtConfigGuestDisk.

- LibvirtBaseVolumeDriver.get\_config() @nova/virt/libvirt/volume/volume.py

```python
class LibvirtBaseVolumeDriver(object):
<snip>
    def get_config(self, connection_info, disk_info):
        """Returns xml for libvirt."""
        conf = vconfig.LibvirtConfigGuestDisk()
<snip>
        # Extract rate_limit control parameters
        if 'qos_specs' in data and data['qos_specs']:
            tune_opts = ['total_bytes_sec', 'read_bytes_sec',
                         'write_bytes_sec', 'total_iops_sec',
                         'read_iops_sec', 'write_iops_sec']
            specs = data['qos_specs']
            if isinstance(specs, dict):
                for k, v in specs.items():
                    if k in tune_opts:
                        new_key = 'disk_' + k
                        setattr(conf, new_key, v)
            else:
                LOG.warning('Unknown content in connection_info/'
                            'qos_specs: %s', specs)

```

\<iotune\> element is generated from LibvirtConfigGuestDisk.

- LibvirtConfigGuestDisk.format\_dom() @nova/virt/libvirt/config.py

```python
class LibvirtConfigGuestDisk(LibvirtConfigGuestDevice):
<snip>
    def format_dom(self):
        iotune = etree.Element("iotune")

        if self.disk_read_bytes_sec is not None:
            iotune.append(self._text_node("read_bytes_sec",
                self.disk_read_bytes_sec))

        if self.disk_read_iops_sec is not None:
            iotune.append(self._text_node("read_iops_sec",
                self.disk_read_iops_sec))

        if self.disk_write_bytes_sec is not None:
            iotune.append(self._text_node("write_bytes_sec",
                self.disk_write_bytes_sec))

        if self.disk_write_iops_sec is not None:
            iotune.append(self._text_node("write_iops_sec",
                self.disk_write_iops_sec))

        if self.disk_total_bytes_sec is not None:
            iotune.append(self._text_node("total_bytes_sec",
                self.disk_total_bytes_sec))

        if self.disk_total_iops_sec is not None:
            iotune.append(self._text_node("total_iops_sec",
                self.disk_total_iops_sec))

        if len(iotune) > 0:
            dev.append(iotune)
```

</div>
</details>

# Appendix

## libvirt XML with m1.normal flavor

```xml
<domain type='kvm' id='11'>
  <name>instance-00000042</name>
  <uuid>30ad89ac-5906-49ca-8d52-3c6343c598f6</uuid>
  <metadata>
    <nova:instance xmlns:nova="http://openstack.org/xmlns/libvirt/nova/1.0">
      <nova:package version="16.0.2-9.el7ost"/>
      <nova:name>vm_normal</nova:name>
      <nova:creationTime>2018-04-16 12:50:16</nova:creationTime>
      <nova:flavor name="m1.normal">
        <nova:memory>1024</nova:memory>
        <nova:disk>20</nova:disk>
        <nova:swap>0</nova:swap>
        <nova:ephemeral>0</nova:ephemeral>
        <nova:vcpus>1</nova:vcpus>
      </nova:flavor>
      <nova:owner>
        <nova:user uuid="5a86b1db33b64571953b2022186010fe">test</nova:user>
        <nova:project uuid="995b4947cc4044fba99bade057053803">test</nova:project>
      </nova:owner>
      <nova:root type="image" uuid="c11a1c31-f703-4ae6-a689-5a6b9a624625"/>
    </nova:instance>
  </metadata>
  <memory unit='KiB'>1048576</memory>
  <currentMemory unit='KiB'>1048576</currentMemory>
  <vcpu placement='static'>1</vcpu>
  <cputune>
    <shares>1024</shares>
  </cputune>
  <resource>
    <partition>/machine</partition>
  </resource>
  <sysinfo type='smbios'>
    <system>
      <entry name='manufacturer'>Red Hat</entry>
      <entry name='product'>OpenStack Compute</entry>
      <entry name='version'>16.0.2-9.el7ost</entry>
      <entry name='serial'>4c4c4544-004a-5310-804e-b9c04f504d32</entry>
      <entry name='uuid'>30ad89ac-5906-49ca-8d52-3c6343c598f6</entry>
      <entry name='family'>Virtual Machine</entry>
    </system>
  </sysinfo>
  <os>
    <type arch='x86_64' machine='pc-i440fx-rhel7.4.0'>hvm</type>
    <boot dev='hd'/>
    <smbios mode='sysinfo'/>
  </os>
  <features>
    <acpi/>
    <apic/>
  </features>
  <cpu mode='custom' match='exact' check='full'>
    <model fallback='forbid'>Skylake-Client</model>
    <vendor>Intel</vendor>
    <topology sockets='1' cores='1' threads='1'/>
    <feature policy='require' name='ss'/>
    <feature policy='require' name='hypervisor'/>
    <feature policy='require' name='tsc_adjust'/>
    <feature policy='require' name='avx512f'/>
    <feature policy='require' name='avx512dq'/>
    <feature policy='require' name='clflushopt'/>
    <feature policy='require' name='avx512cd'/>
    <feature policy='require' name='avx512bw'/>
    <feature policy='require' name='avx512vl'/>
    <feature policy='require' name='pdpe1gb'/>
  </cpu>
  <clock offset='utc'>
    <timer name='pit' tickpolicy='delay'/>
    <timer name='rtc' tickpolicy='catchup'/>
    <timer name='hpet' present='no'/>
  </clock>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>destroy</on_crash>
  <devices>
    <emulator>/usr/libexec/qemu-kvm</emulator>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2' cache='none'/>
      <source file='/var/lib/nova/instances/30ad89ac-5906-49ca-8d52-3c6343c598f6/disk'/>
      <backingStore type='file' index='1'>
        <format type='raw'/>
        <source file='/var/lib/nova/instances/_base/a24c93285792d6ac5a718a70a6ef23e119f98f54'/>
        <backingStore/>
      </backingStore>
      <target dev='vda' bus='virtio'/>
      <alias name='virtio-disk0'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x06' function='0x0'/>
    </disk>
    <controller type='usb' index='0' model='piix3-uhci'>
      <alias name='usb'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x01' function='0x2'/>
    </controller>
    <controller type='pci' index='0' model='pci-root'>
      <alias name='pci.0'/>
    </controller>
    <interface type='bridge'>
      <mac address='fa:16:3e:be:fd:48'/>
      <source bridge='br-int'/>
      <virtualport type='openvswitch'>
        <parameters interfaceid='b614c1d3-75e5-483f-88fd-cec050652945'/>
      </virtualport>
      <target dev='tapb614c1d3-75'/>
      <model type='virtio'/>
      <alias name='net0'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x03' function='0x0'/>
    </interface>
    <interface type='bridge'>
      <mac address='fa:16:3e:dc:dd:a8'/>
      <source bridge='br-int'/>
      <virtualport type='openvswitch'>
        <parameters interfaceid='7fe68949-32a2-461d-8c6c-c5cca0dfff7d'/>
      </virtualport>
      <target dev='tap7fe68949-32'/>
      <model type='virtio'/>
      <alias name='net1'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x04' function='0x0'/>
    </interface>
    <interface type='bridge'>
      <mac address='fa:16:3e:66:02:79'/>
      <source bridge='br-int'/>
      <virtualport type='openvswitch'>
        <parameters interfaceid='78f00f22-370b-47c2-a721-a47cbbd434d0'/>
      </virtualport>
      <target dev='tap78f00f22-37'/>
      <model type='virtio'/>
      <alias name='net2'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x05' function='0x0'/>
    </interface>
    <serial type='pty'>
      <source path='/dev/pts/2'/>
      <log file='/var/lib/nova/instances/30ad89ac-5906-49ca-8d52-3c6343c598f6/console.log' append='off'/>
      <target port='0'/>
      <alias name='serial0'/>
    </serial>
    <console type='pty' tty='/dev/pts/2'>
      <source path='/dev/pts/2'/>
      <log file='/var/lib/nova/instances/30ad89ac-5906-49ca-8d52-3c6343c598f6/console.log' append='off'/>
      <target type='serial' port='0'/>
      <alias name='serial0'/>
    </console>
    <input type='tablet' bus='usb'>
      <alias name='input0'/>
      <address type='usb' bus='0' port='1'/>
    </input>
    <input type='mouse' bus='ps2'>
      <alias name='input1'/>
    </input>
    <input type='keyboard' bus='ps2'>
      <alias name='input2'/>
    </input>
    <graphics type='vnc' port='5901' autoport='yes' listen='10.20.0.101' keymap='en-us'>
      <listen type='address' address='10.20.0.101'/>
    </graphics>
    <video>
      <model type='cirrus' vram='16384' heads='1' primary='yes'/>
      <alias name='video0'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x02' function='0x0'/>
    </video>
    <memballoon model='virtio'>
      <stats period='10'/>
      <alias name='balloon0'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x07' function='0x0'/>
    </memballoon>
  </devices>
  <seclabel type='dynamic' model='selinux' relabel='yes'>
    <label>system_u:system_r:svirt_t:s0:c93,c547</label>
    <imagelabel>system_u:object_r:svirt_image_t:s0:c93,c547</imagelabel>
  </seclabel>
  <seclabel type='dynamic' model='dac' relabel='yes'>
    <label>+107:+107</label>
    <imagelabel>+107:+107</imagelabel>
  </seclabel>
</domain>
```

## Qemu command line with m1.normal flavor

```
/usr/libexec/qemu-kvm \
-name guest=instance-00000042,debug-threads=on \
-S \
-object secret,id=masterKey0,format=raw,file=/var/lib/libvirt/qemu/domain-11-instance-00000042/master-key.aes \
-machine pc-i440fx-rhel7.4.0,accel=kvm,usb=off,dump-guest-core=off \
-cpu Skylake-Client,ss=on,hypervisor=on,tsc_adjust=on,avx512f=on,avx512dq=on,clflushopt=on,avx512cd=on,avx512bw=on,avx512vl=on,pdpe1gb=on \
-m 1024 \
-realtime mlock=off \
-smp 1,sockets=1,cores=1,threads=1 \
-uuid 30ad89ac-5906-49ca-8d52-3c6343c598f6 \
-smbios type=1,manufacturer=Red Hat,product=OpenStack Compute,version=16.0.2-9.el7ost,serial=4c4c4544-004a-5310-804e-b9c04f504d32,uuid=30ad89ac-5906-49ca-8d52-3c6343c598f6,family=Virtual Machine \
-no-user-config \
-nodefaults \
-chardev socket,id=charmonitor,path=/var/lib/libvirt/qemu/domain-11-instance-00000042/monitor.sock,server,nowait \
-mon chardev=charmonitor,id=monitor,mode=control \
-rtc base=utc,driftfix=slew \
-global kvm-pit.lost_tick_policy=delay \
-no-hpet \
-no-shutdown \
-boot strict=on \
-device piix3-usb-uhci,id=usb,bus=pci.0,addr=0x1.0x2 \
-drive file=/var/lib/nova/instances/30ad89ac-5906-49ca-8d52-3c6343c598f6/disk,format=qcow2,if=none,id=drive-virtio-disk0,cache=none \
-device virtio-blk-pci,scsi=off,bus=pci.0,addr=0x6,drive=drive-virtio-disk0,id=virtio-disk0,bootindex=1 \
-netdev tap,fd=32,id=hostnet0,vhost=on,vhostfd=34 \
-device virtio-net-pci,netdev=hostnet0,id=net0,mac=fa:16:3e:be:fd:48,bus=pci.0,addr=0x3 \
-netdev tap,fd=35,id=hostnet1,vhost=on,vhostfd=36 \
-device virtio-net-pci,netdev=hostnet1,id=net1,mac=fa:16:3e:dc:dd:a8,bus=pci.0,addr=0x4 \
-netdev tap,fd=37,id=hostnet2,vhost=on,vhostfd=38 \
-device virtio-net-pci,netdev=hostnet2,id=net2,mac=fa:16:3e:66:02:79,bus=pci.0,addr=0x5 \
-add-fd set=6,fd=40 \
-chardev pty,id=charserial0,logfile=/dev/fdset/6,logappend=on \
-device isa-serial,chardev=charserial0,id=serial0 \
-device usb-tablet,id=input0,bus=usb.0,port=1 \
-vnc 10.20.0.101:1 \
-k en-us \
-device cirrus-vga,id=video0,bus=pci.0,addr=0x2 \
-device virtio-balloon-pci,id=balloon0,bus=pci.0,addr=0x7 \
-msg timestamp=on
```

## libvirt XML with m1.resquota flavor

```xml
<domain type='kvm' id='10'>
  <name>instance-00000041</name>
  <uuid>850724a4-029c-457b-a99d-3a18e8e413da</uuid>
  <metadata>
    <nova:instance xmlns:nova="http://openstack.org/xmlns/libvirt/nova/1.0">
      <nova:package version="16.0.2-9.el7ost"/>
      <nova:name>vm_resquota</nova:name>
      <nova:creationTime>2018-04-16 12:48:40</nova:creationTime>
      <nova:flavor name="m1.resquota">
        <nova:memory>1024</nova:memory>
        <nova:disk>20</nova:disk>
        <nova:swap>0</nova:swap>
        <nova:ephemeral>0</nova:ephemeral>
        <nova:vcpus>1</nova:vcpus>
      </nova:flavor>
      <nova:owner>
        <nova:user uuid="5a86b1db33b64571953b2022186010fe">test</nova:user>
        <nova:project uuid="995b4947cc4044fba99bade057053803">test</nova:project>
      </nova:owner>
      <nova:root type="image" uuid="c11a1c31-f703-4ae6-a689-5a6b9a624625"/>
    </nova:instance>
  </metadata>
  <memory unit='KiB'>1048576</memory>
  <currentMemory unit='KiB'>1048576</currentMemory>
  <vcpu placement='static'>1</vcpu>
  <cputune>
    <shares>512</shares>
  </cputune>
  <resource>
    <partition>/machine</partition>
  </resource>
  <sysinfo type='smbios'>
    <system>
      <entry name='manufacturer'>Red Hat</entry>
      <entry name='product'>OpenStack Compute</entry>
      <entry name='version'>16.0.2-9.el7ost</entry>
      <entry name='serial'>4c4c4544-004a-5310-804e-b9c04f504d32</entry>
      <entry name='uuid'>850724a4-029c-457b-a99d-3a18e8e413da</entry>
      <entry name='family'>Virtual Machine</entry>
    </system>
  </sysinfo>
  <os>
    <type arch='x86_64' machine='pc-i440fx-rhel7.4.0'>hvm</type>
    <boot dev='hd'/>
    <smbios mode='sysinfo'/>
  </os>
  <features>
    <acpi/>
    <apic/>
  </features>
  <cpu mode='custom' match='exact' check='full'>
    <model fallback='forbid'>Skylake-Client</model>
    <vendor>Intel</vendor>
    <topology sockets='1' cores='1' threads='1'/>
    <feature policy='require' name='ss'/>
    <feature policy='require' name='hypervisor'/>
    <feature policy='require' name='tsc_adjust'/>
    <feature policy='require' name='avx512f'/>
    <feature policy='require' name='avx512dq'/>
    <feature policy='require' name='clflushopt'/>
    <feature policy='require' name='avx512cd'/>
    <feature policy='require' name='avx512bw'/>
    <feature policy='require' name='avx512vl'/>
    <feature policy='require' name='pdpe1gb'/>
  </cpu>
  <clock offset='utc'>
    <timer name='pit' tickpolicy='delay'/>
    <timer name='rtc' tickpolicy='catchup'/>
    <timer name='hpet' present='no'/>
  </clock>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>destroy</on_crash>
  <devices>
    <emulator>/usr/libexec/qemu-kvm</emulator>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2' cache='none'/>
      <source file='/var/lib/nova/instances/850724a4-029c-457b-a99d-3a18e8e413da/disk'/>
      <backingStore type='file' index='1'>
        <format type='raw'/>
        <source file='/var/lib/nova/instances/_base/a24c93285792d6ac5a718a70a6ef23e119f98f54'/>
        <backingStore/>
      </backingStore>
      <target dev='vda' bus='virtio'/>
      <iotune>
        <read_bytes_sec>1000000</read_bytes_sec>
        <write_bytes_sec>1024000</write_bytes_sec>
      </iotune>
      <alias name='virtio-disk0'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x06' function='0x0'/>
    </disk>
    <controller type='usb' index='0' model='piix3-uhci'>
      <alias name='usb'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x01' function='0x2'/>
    </controller>
    <controller type='pci' index='0' model='pci-root'>
      <alias name='pci.0'/>
    </controller>
    <interface type='bridge'>
      <mac address='fa:16:3e:8d:f3:ae'/>
      <source bridge='br-int'/>
      <virtualport type='openvswitch'>
        <parameters interfaceid='bb8410ad-a026-4e9a-8f0b-0e8f611d5588'/>
      </virtualport>
      <bandwidth>
        <inbound average='32768' peak='65536' burst='131072'/>
        <outbound average='32768' peak='65536' burst='131072'/>
      </bandwidth>
      <target dev='tapbb8410ad-a0'/>
      <model type='virtio'/>
      <alias name='net0'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x03' function='0x0'/>
    </interface>
    <interface type='bridge'>
      <mac address='fa:16:3e:60:1e:07'/>
      <source bridge='br-int'/>
      <virtualport type='openvswitch'>
        <parameters interfaceid='a1e966cd-47e7-4bc2-967c-13638afd47ec'/>
      </virtualport>
      <bandwidth>
        <inbound average='32768' peak='65536' burst='131072'/>
        <outbound average='32768' peak='65536' burst='131072'/>
      </bandwidth>
      <target dev='tapa1e966cd-47'/>
      <model type='virtio'/>
      <alias name='net1'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x04' function='0x0'/>
    </interface>
    <interface type='bridge'>
      <mac address='fa:16:3e:15:9c:1c'/>
      <source bridge='br-int'/>
      <virtualport type='openvswitch'>
        <parameters interfaceid='e0bb2633-17ce-4eda-9161-e6ffdf3243c6'/>
      </virtualport>
      <bandwidth>
        <inbound average='32768' peak='65536' burst='131072'/>
        <outbound average='32768' peak='65536' burst='131072'/>
      </bandwidth>
      <target dev='tape0bb2633-17'/>
      <model type='virtio'/>
      <alias name='net2'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x05' function='0x0'/>
    </interface>
    <serial type='pty'>
      <source path='/dev/pts/0'/>
      <log file='/var/lib/nova/instances/850724a4-029c-457b-a99d-3a18e8e413da/console.log' append='off'/>
      <target port='0'/>
      <alias name='serial0'/>
    </serial>
    <console type='pty' tty='/dev/pts/0'>
      <source path='/dev/pts/0'/>
      <log file='/var/lib/nova/instances/850724a4-029c-457b-a99d-3a18e8e413da/console.log' append='off'/>
      <target type='serial' port='0'/>
      <alias name='serial0'/>
    </console>
    <input type='tablet' bus='usb'>
      <alias name='input0'/>
      <address type='usb' bus='0' port='1'/>
    </input>
    <input type='mouse' bus='ps2'>
      <alias name='input1'/>
    </input>
    <input type='keyboard' bus='ps2'>
      <alias name='input2'/>
    </input>
    <graphics type='vnc' port='5900' autoport='yes' listen='10.20.0.101' keymap='en-us'>
      <listen type='address' address='10.20.0.101'/>
    </graphics>
    <video>
      <model type='cirrus' vram='16384' heads='1' primary='yes'/>
      <alias name='video0'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x02' function='0x0'/>
    </video>
    <memballoon model='virtio'>
      <stats period='10'/>
      <alias name='balloon0'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x07' function='0x0'/>
    </memballoon>
  </devices>
  <seclabel type='dynamic' model='selinux' relabel='yes'>
    <label>system_u:system_r:svirt_t:s0:c315,c689</label>
    <imagelabel>system_u:object_r:svirt_image_t:s0:c315,c689</imagelabel>
  </seclabel>
  <seclabel type='dynamic' model='dac' relabel='yes'>
    <label>+107:+107</label>
    <imagelabel>+107:+107</imagelabel>
  </seclabel>
</domain>
```

## Qemu command line with m1.resquota flavor

```
/usr/libexec/qemu-kvm \
-name guest=instance-00000041,debug-threads=on \
-S \
-object secret,id=masterKey0,format=raw,file=/var/lib/libvirt/qemu/domain-10-instance-00000041/master-key.aes \
-machine pc-i440fx-rhel7.4.0,accel=kvm,usb=off,dump-guest-core=off \
-cpu Skylake-Client,ss=on,hypervisor=on,tsc_adjust=on,avx512f=on,avx512dq=on,clflushopt=on,avx512cd=on,avx512bw=on,avx512vl=on,pdpe1gb=on \
-m 1024 \
-realtime mlock=off \
-smp 1,sockets=1,cores=1,threads=1 \
-uuid 850724a4-029c-457b-a99d-3a18e8e413da \
-smbios type=1,manufacturer=Red Hat,product=OpenStack Compute,version=16.0.2-9.el7ost,serial=4c4c4544-004a-5310-804e-b9c04f504d32,uuid=850724a4-029c-457b-a99d-3a18e8e413da,family=Virtual Machine \
-no-user-config \
-nodefaults \
-chardev socket,id=charmonitor,path=/var/lib/libvirt/qemu/domain-10-instance-00000041/monitor.sock,server,nowait \
-mon chardev=charmonitor,id=monitor,mode=control \
-rtc base=utc,driftfix=slew \
-global kvm-pit.lost_tick_policy=delay \
-no-hpet \
-no-shutdown \
-boot strict=on \
-device piix3-usb-uhci,id=usb,bus=pci.0,addr=0x1.0x2 \
-drive file=/var/lib/nova/instances/850724a4-029c-457b-a99d-3a18e8e413da/disk,format=qcow2,if=none,id=drive-virtio-disk0,cache=none,throttling.bps-read=1000000,throttling.bps-write=1024000 \
-device virtio-blk-pci,scsi=off,bus=pci.0,addr=0x6,drive=drive-virtio-disk0,id=virtio-disk0,bootindex=1 \
-netdev tap,fd=31,id=hostnet0,vhost=on,vhostfd=33 \
-device virtio-net-pci,netdev=hostnet0,id=net0,mac=fa:16:3e:8d:f3:ae,bus=pci.0,addr=0x3 \
-netdev tap,fd=34,id=hostnet1,vhost=on,vhostfd=35 \
-device virtio-net-pci,netdev=hostnet1,id=net1,mac=fa:16:3e:60:1e:07,bus=pci.0,addr=0x4 \
-netdev tap,fd=36,id=hostnet2,vhost=on,vhostfd=37 \
-device virtio-net-pci,netdev=hostnet2,id=net2,mac=fa:16:3e:15:9c:1c,bus=pci.0,addr=0x5 \
-add-fd set=6,fd=39 \
-chardev pty,id=charserial0,logfile=/dev/fdset/6,logappend=on \
-device isa-serial,chardev=charserial0,id=serial0 \
-device usb-tablet,id=input0,bus=usb.0,port=1 \
-vnc 10.20.0.101:0 \
-k en-us \
-device cirrus-vga,id=video0,bus=pci.0,addr=0x2 \
-device virtio-balloon-pci,id=balloon0,bus=pci.0,addr=0x7 \
-msg timestamp=on
```

[Extra Spec](https://docs.openstack.org/nova/pike/admin/flavors.html#extra-specs)
[Create](https://docs.openstack.org/nova/pike/admin/flavors2.html#create-a-flavor)
[Pike Flavors](https://docs.openstack.org/nova/pike/admin/flavors.html)
[Supported QoS rule types](https://docs.openstack.org/neutron/pike/admin/config-qos.html#supported-qos-rule-types)
[DSCP marking BP](https://blueprints.launchpad.net/neutron/+spec/ml2-ovs-qos-with-dscp)
[DSCP marking](https://specs.openstack.org/openstack/neutron-specs/specs/newton/ml2-qos-with-dscp.html)
[Using OpenStack Networking with QoS](https://docs.openstack.org/liberty/ja/networking-guide/adv-config-qos.html)
[Neutron QoS API workflow](https://gist.github.com/sc68cal/6689999)
[Neutron QoS](https://docs.openstack.org/neutron/latest/contributor/internals/quality_of_service.html)
(https://ask.openstack.org/en/question/109689/qos-neutron-bandwidth-limit-method/)
[Port QoS](https://docs.openstack.org/dragonflow/latest/specs/port_qos.html)
[libvirt xml](https://libvirt.org/formatdomain.html)
[Resource Quota](https://wiki.openstack.org/wiki/InstanceResourceQuota)

[Openstack Network QoS intro](http://stanzgy.github.io/nova-network-qos/#slide1)
[Neutron DSCP (pdf)](https://www.openstack.org/assets/presentation-media/Neutron-DSCP-Policing-Your-Network2.pdf)

[OVS QoS](http://d.hatena.ne.jp/oraccha/20120723/1343034433)
[Qemu throttle](https://github.com/qemu/qemu/blob/master/docs/throttle.txt)

[I/O scheduling, iotune and difference between read_bytes_sec and read_bytes_sec_max in qemu/kvm](https://access.redhat.com/solutions/3153531)

[仮想マシンのリソース制限 (pdf)](http://www.hitachi.co.jp/Prod/comp/soft1/openstack/pdf/17th_opnstk_users_event20140120.pdf)
