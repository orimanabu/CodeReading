# NovaとNeutronのQoSの違い

# まずNovaのQoS

- m1.normal : QoSなしのflavor
- m1.resquota : QoSありのflavor

## Create a flavor
```
openstack flavor create --ram 1024 --disk 20 --vcpus 1 m1.normal
openstack flavor create --ram 1024 --disk 20 --vcpus 1 m1.resquota
```

## Set QoS properties for the flavor
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

## Start an instance with the flavor

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

## CPU tuning

### m1.normal

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

### m1.resquota

libvit XML:

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

Default cgroups setting:

```
[root@comp-1 ~]# cat /sys/fs/cgroup/cpu/cpu.shares
1024
```

## Disk I/O tuning

libvit XML:

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

Qemu options: throttling.bps-read, throttling.bps-write

```
-drive file=/var/lib/nova/instances/850724a4-029c-457b-a99d-3a18e8e413da/disk,format=qcow2,if=none,id=drive-virtio-disk0,cache=none,throttling.bps-read=1000000,throttling.bps-write=1024000
```

See also: [I/O scheduling, iotune and difference between read_bytes_sec and read_bytes_sec_max in qemu/kvm](https://access.redhat.com/solutions/3153531)

## Network I/O tuning

### m1.normal

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

### m1.reqauota

#### libvirt XML

All interfaces got QoS settings from the flavor.

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

# Neutron

```sh
neutron qos-policy-create bw-limiter
```

```sh
neutron qos-bandwidth-limit-rule-create bw-limiter --max-kbps 3000   --max-burst-kbps 300
```

```sh

```

```sh

```

```sh

```

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
/usr/libexec/qemu-kvm -name guest=instance-00000042,debug-threads=on -S -object secret,id=masterKey0,format=raw,file=/var/lib/libvirt/qemu/domain-11-instance-00000042/master-key.aes -machine pc-i440fx-rhel7.4.0,accel=kvm,usb=off,dump-guest-core=off -cpu Skylake-Client,ss=on,hypervisor=on,tsc_adjust=on,avx512f=on,avx512dq=on,clflushopt=on,avx512cd=on,avx512bw=on,avx512vl=on,pdpe1gb=on -m 1024 -realtime mlock=off -smp 1,sockets=1,cores=1,threads=1 -uuid 30ad89ac-5906-49ca-8d52-3c6343c598f6 -smbios type=1,manufacturer=Red Hat,product=OpenStack Compute,version=16.0.2-9.el7ost,serial=4c4c4544-004a-5310-804e-b9c04f504d32,uuid=30ad89ac-5906-49ca-8d52-3c6343c598f6,family=Virtual Machine -no-user-config -nodefaults -chardev socket,id=charmonitor,path=/var/lib/libvirt/qemu/domain-11-instance-00000042/monitor.sock,server,nowait -mon chardev=charmonitor,id=monitor,mode=control -rtc base=utc,driftfix=slew -global kvm-pit.lost_tick_policy=delay -no-hpet -no-shutdown -boot strict=on -device piix3-usb-uhci,id=usb,bus=pci.0,addr=0x1.0x2 -drive file=/var/lib/nova/instances/30ad89ac-5906-49ca-8d52-3c6343c598f6/disk,format=qcow2,if=none,id=drive-virtio-disk0,cache=none -device virtio-blk-pci,scsi=off,bus=pci.0,addr=0x6,drive=drive-virtio-disk0,id=virtio-disk0,bootindex=1 -netdev tap,fd=32,id=hostnet0,vhost=on,vhostfd=34 -device virtio-net-pci,netdev=hostnet0,id=net0,mac=fa:16:3e:be:fd:48,bus=pci.0,addr=0x3 -netdev tap,fd=35,id=hostnet1,vhost=on,vhostfd=36 -device virtio-net-pci,netdev=hostnet1,id=net1,mac=fa:16:3e:dc:dd:a8,bus=pci.0,addr=0x4 -netdev tap,fd=37,id=hostnet2,vhost=on,vhostfd=38 -device virtio-net-pci,netdev=hostnet2,id=net2,mac=fa:16:3e:66:02:79,bus=pci.0,addr=0x5 -add-fd set=6,fd=40 -chardev pty,id=charserial0,logfile=/dev/fdset/6,logappend=on -device isa-serial,chardev=charserial0,id=serial0 -device usb-tablet,id=input0,bus=usb.0,port=1 -vnc 10.20.0.101:1 -k en-us -device cirrus-vga,id=video0,bus=pci.0,addr=0x2 -device virtio-balloon-pci,id=balloon0,bus=pci.0,addr=0x7 -msg timestamp=on
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
/usr/libexec/qemu-kvm -name guest=instance-00000041,debug-threads=on -S -object secret,id=masterKey0,format=raw,file=/var/lib/libvirt/qemu/domain-10-instance-00000041/master-key.aes -machine pc-i440fx-rhel7.4.0,accel=kvm,usb=off,dump-guest-core=off -cpu Skylake-Client,ss=on,hypervisor=on,tsc_adjust=on,avx512f=on,avx512dq=on,clflushopt=on,avx512cd=on,avx512bw=on,avx512vl=on,pdpe1gb=on -m 1024 -realtime mlock=off -smp 1,sockets=1,cores=1,threads=1 -uuid 850724a4-029c-457b-a99d-3a18e8e413da -smbios type=1,manufacturer=Red Hat,product=OpenStack Compute,version=16.0.2-9.el7ost,serial=4c4c4544-004a-5310-804e-b9c04f504d32,uuid=850724a4-029c-457b-a99d-3a18e8e413da,family=Virtual Machine -no-user-config -nodefaults -chardev socket,id=charmonitor,path=/var/lib/libvirt/qemu/domain-10-instance-00000041/monitor.sock,server,nowait -mon chardev=charmonitor,id=monitor,mode=control -rtc base=utc,driftfix=slew -global kvm-pit.lost_tick_policy=delay -no-hpet -no-shutdown -boot strict=on -device piix3-usb-uhci,id=usb,bus=pci.0,addr=0x1.0x2 -drive file=/var/lib/nova/instances/850724a4-029c-457b-a99d-3a18e8e413da/disk,format=qcow2,if=none,id=drive-virtio-disk0,cache=none,throttling.bps-read=1000000,throttling.bps-write=1024000 -device virtio-blk-pci,scsi=off,bus=pci.0,addr=0x6,drive=drive-virtio-disk0,id=virtio-disk0,bootindex=1 -netdev tap,fd=31,id=hostnet0,vhost=on,vhostfd=33 -device virtio-net-pci,netdev=hostnet0,id=net0,mac=fa:16:3e:8d:f3:ae,bus=pci.0,addr=0x3 -netdev tap,fd=34,id=hostnet1,vhost=on,vhostfd=35 -device virtio-net-pci,netdev=hostnet1,id=net1,mac=fa:16:3e:60:1e:07,bus=pci.0,addr=0x4 -netdev tap,fd=36,id=hostnet2,vhost=on,vhostfd=37 -device virtio-net-pci,netdev=hostnet2,id=net2,mac=fa:16:3e:15:9c:1c,bus=pci.0,addr=0x5 -add-fd set=6,fd=39 -chardev pty,id=charserial0,logfile=/dev/fdset/6,logappend=on -device isa-serial,chardev=charserial0,id=serial0 -device usb-tablet,id=input0,bus=usb.0,port=1 -vnc 10.20.0.101:0 -k en-us -device cirrus-vga,id=video0,bus=pci.0,addr=0x2 -device virtio-balloon-pci,id=balloon0,bus=pci.0,addr=0x7 -msg timestamp=on
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
