# お題

- VLAN tagは誰がどこで設定しているか

調査結果: CNIプラグインからNetLink経由で各デバドラの中で設定している。実際にタグの付け外しをしているのはNICのFirmware。

# 環境
- OpenShift v4.8
- RHCOS kernel 4.18.0-305.19.1.el8_4.x86_64

# CNI側

- [ApplyVFConfig() @pkg/sriov/sriov.go](https://github.com/openshift/sriov-cni/blob/release-4.8/pkg/sriov/sriov.go#L272)

  - NetlinkManagerのメソッド `LinkSetVfVlan()` を呼ぶ: https://github.com/openshift/sriov-cni/blob/release-4.8/pkg/sriov/sriov.go#L299

- [LinkSetVfVlan() @pkg/sriov/sriov.go](https://github.com/openshift/sriov-cni/blob/release-4.8/pkg/sriov/sriov.go#L45)

  - NetLinkのメソッド `LinkSetVfVlan()` を呼ぶ: https://github.com/openshift/sriov-cni/blob/release-4.8/pkg/sriov/sriov.go#L46

- [LinkSetVfVlan() @vendor/github.com/vishvananda/netlink/link_linux.go](https://github.com/openshift/sriov-cni/blob/release-4.8/vendor/github.com/vishvananda/netlink/link_linux.go#L448)

  - Handle structの `LinkSetVfVlan()` を呼ぶ: https://github.com/openshift/sriov-cni/blob/release-4.8/vendor/github.com/vishvananda/netlink/link_linux.go#L449

    - pkgHandleの宣言: https://github.com/openshift/sriov-cni/blob/release-4.8/vendor/github.com/vishvananda/netlink/handle_linux.go#L13


- [LinkSetVfVlan() @vendor/github.com/vishvananda/netlink/link_linux.go](https://github.com/openshift/sriov-cni/blob/release-4.8/vendor/github.com/vishvananda/netlink/link_linux.go#L454)

  - NetLinkの `RTM_SETLINK` で `IFLA_VF_VLAN` を設定:

    - https://github.com/openshift/sriov-cni/blob/release-4.8/vendor/github.com/vishvananda/netlink/link_linux.go#L457
    - https://github.com/openshift/sriov-cni/blob/release-4.8/vendor/github.com/vishvananda/netlink/link_linux.go#L469

# Kernel

- `RTM_SETLINK` はここに飛ぶ: https://github.com/torvalds/linux/blob/v4.18/net/core/rtnetlink.c#L4768

- [rtnl_setlink() @net/core/rtnetlink.c](https://github.com/torvalds/linux/blob/v5.13/net/core/rtnetlink.c#L3015)

  - `do_setlink()` を呼ぶ: https://github.com/torvalds/linux/blob/v4.18/net/core/rtnetlink.c#L2636

- [do_setlink() @net/core/rtnetlink.c](https://github.com/torvalds/linux/blob/v4.18/net/core/rtnetlink.c#L2261)

  - `do_setvfinfo()` を呼ぶ: https://github.com/torvalds/linux/blob/v4.18/net/core/rtnetlink.c#L2460

- [do_setvfinfo() @net/core/rtnetlink.c](https://github.com/torvalds/linux/blob/v4.18/net/core/rtnetlink.c#L2069)

  - `ops->ndo_set_vf_vlan()` を呼ぶ: https://github.com/torvalds/linux/blob/v4.18/net/core/rtnetlink.c#L2090

これ以降は、各デバイスドライ内に実装された `ndo_set_vf_vlan()` が呼ばれる。例えばIntel i40eの場合は...

- [struct net_device_ops i40e_netdev_ops @drivers/net/ethernet/intel/i40e/i40e_main.c](https://github.com/torvalds/linux/blob/v4.18/drivers/net/ethernet/intel/i40e/i40e_main.c#L11852)

  - `i40e_ndo_set_vf_port_vlan()` に入る: https://github.com/torvalds/linux/blob/v4.18/drivers/net/ethernet/intel/i40e/i40e_main.c#L11871
  
- [i40e_ndo_set_vf_port_vlan() @drivers/net/ethernet/intel/i40e/i40e_virtchnl_pf.c](https://github.com/torvalds/linux/blob/v4.18/drivers/net/ethernet/intel/i40e/i40e_virtchnl_pf.c#L3922)

  - `i40e_add_vlan_all_mac()` を呼ぶ: https://github.com/torvalds/linux/blob/v4.18/drivers/net/ethernet/intel/i40e/i40e_virtchnl_pf.c#L4019
  
- [i40e_add_vlan_all_mac() @drivers/net/ethernet/intel/i40e/i40e_main.c](https://github.com/torvalds/linux/blob/v4.18/drivers/net/ethernet/intel/i40e/i40e_main.c#L2715)

  - `i40e_add_filter()` を呼ぶ: https://github.com/torvalds/linux/blob/v4.18/drivers/net/ethernet/intel/i40e/i40e_main.c#L2724

- [i40e_add_vlan_all_mac() @drivers/net/ethernet/intel/i40e/i40e_main.c](https://github.com/torvalds/linux/blob/v4.18/drivers/net/ethernet/intel/i40e/i40e_main.c#L1332)

  - なんかビットを立ててFirmwareの設定をしているっぽい: https://github.com/torvalds/linux/blob/v4.18/drivers/net/ethernet/intel/i40e/i40e_main.c#L1361-L1362
