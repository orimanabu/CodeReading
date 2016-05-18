# openstack-puppet-moduleでpacemakerを設定するところ

## 動機

後で書く

## Active-StandbyかActive-Activeか

いきなりキーワード、clone_params で指定している。
```
# grep -R 'clone_params' /usr/share/openstack-puppet
/usr/share/openstack-puppet/modules/pacemaker/README.md:"group_params" and "clone_params" map transparently to the command
/usr/share/openstack-puppet/modules/pacemaker/README.md:line for pcs.  I.e., if $clone_params is set to "interleave=true", the
/usr/share/openstack-puppet/modules/pacemaker/README.md:If $clone_params is undef, --clone is omitted from the "pcs resource
/usr/share/openstack-puppet/modules/pacemaker/README.md:myservice already exists without $clone_params, declaring
/usr/share/openstack-puppet/modules/pacemaker/README.md:"pcmk_resource {'myservice': ..." with $clone_params will have no
/usr/share/openstack-puppet/modules/pacemaker/README.md:$clone_params succeeds as expected.
/usr/share/openstack-puppet/modules/pacemaker/README.md:      clone_params => '',
/usr/share/openstack-puppet/modules/pacemaker/README.md:      clone_params    => '',
/usr/share/openstack-puppet/modules/pacemaker/README.md:      clone_params    => 'interleave=true',
/usr/share/openstack-puppet/modules/pacemaker/README.md:      clone_params        => 'globally-unique=true clone-max=3 interleave=true',
/usr/share/openstack-puppet/modules/pacemaker/lib/puppet/provider/pcmk_resource/default.rb:    clone_params = @resource[:clone_params]
/usr/share/openstack-puppet/modules/pacemaker/lib/puppet/provider/pcmk_resource/default.rb:    if clone_params then suffixes +=1 end
/usr/share/openstack-puppet/modules/pacemaker/lib/puppet/provider/pcmk_resource/default.rb:      raise(Puppet::Error, "May only define one of clone_params, "+
/usr/share/openstack-puppet/modules/pacemaker/lib/puppet/provider/pcmk_resource/default.rb:    if clone_params
/usr/share/openstack-puppet/modules/pacemaker/lib/puppet/provider/pcmk_resource/default.rb:      if not_empty_string(clone_params)
/usr/share/openstack-puppet/modules/pacemaker/lib/puppet/provider/pcmk_resource/default.rb:        cmd += ' ' + clone_params
/usr/share/openstack-puppet/modules/pacemaker/lib/puppet/provider/pcmk_resource/default.rb:  def clone_params
/usr/share/openstack-puppet/modules/pacemaker/lib/puppet/provider/pcmk_resource/default.rb:    @resource[:clone_params]
/usr/share/openstack-puppet/modules/pacemaker/lib/puppet/provider/pcmk_resource/default.rb:  def clone_params=(value)
Binary file /usr/share/openstack-puppet/modules/pacemaker/lib/puppet/provider/pcmk_resource/.default.rb.swp matches
/usr/share/openstack-puppet/modules/pacemaker/lib/puppet/type/pcmk_resource.rb:  newproperty(:clone_params) do
/usr/share/openstack-puppet/modules/pacemaker/manifests/resource/filesystem.pp:# [*clone_params*]
/usr/share/openstack-puppet/modules/pacemaker/manifests/resource/filesystem.pp:  $clone_params       = undef,
/usr/share/openstack-puppet/modules/pacemaker/manifests/resource/filesystem.pp:    clone_params       => $clone_params,
/usr/share/openstack-puppet/modules/pacemaker/manifests/resource/lsb.pp:  $clone_params       = undef,
/usr/share/openstack-puppet/modules/pacemaker/manifests/resource/lsb.pp:    clone_params       => $clone_params,
/usr/share/openstack-puppet/modules/pacemaker/manifests/resource/ocf.pp:# [*clone_params*]
/usr/share/openstack-puppet/modules/pacemaker/manifests/resource/ocf.pp:  $clone_params       = undef,
/usr/share/openstack-puppet/modules/pacemaker/manifests/resource/ocf.pp:    clone_params       => $clone_params,
/usr/share/openstack-puppet/modules/pacemaker/manifests/resource/route.pp:  $clone_params       = undef,
/usr/share/openstack-puppet/modules/pacemaker/manifests/resource/route.pp:    clone_params       => $clone_params,
/usr/share/openstack-puppet/modules/pacemaker/manifests/resource/service.pp:# [*clone_params*]
/usr/share/openstack-puppet/modules/pacemaker/manifests/resource/service.pp:  $clone_params       = undef,
/usr/share/openstack-puppet/modules/pacemaker/manifests/resource/service.pp:      clone_params       => $clone_params,
/usr/share/openstack-puppet/modules/pacemaker/manifests/resource/systemd.pp:  $clone_params       = undef,
/usr/share/openstack-puppet/modules/pacemaker/manifests/resource/systemd.pp:    clone_params       => $clone_params,
/usr/share/openstack-puppet/modules/pacemaker/tests/init.pp:  clone_params => '',
/usr/share/openstack-puppet/modules/pacemaker/tests/init.pp:  clone_params    => '',
/usr/share/openstack-puppet/modules/pacemaker/tests/init.pp:  clone_params    => 'interleave=true',
/usr/share/openstack-puppet/modules/pacemaker/tests/init.pp:  clone_params        => 'globally-unique=true clone-max=3 interleave=true',
```
見るのは README.md と lib/puppet/provider/pcmk_resource/default.rb。

- README.md

```
### Resources

A few different types are provided for several pacemaker resource
types.  Howerver, all of these types end up wrapping the pcmk_resource
provider.  The pcmk_resource provider itself essentially wraps the
"pcs resource" command.  Params such as "resource_params,"
"group_params" and "clone_params" map transparently to the command
line for pcs.  I.e., if $clone_params is set to "interleave=true", the
pcs command to create the resource looks like:

    pcs resource create <res_name> <res_type> ... --clone interleave=true

If $clone_params is undef, --clone is omitted from the "pcs resource
create command".  Likewise for $group_params and $master_params.  Use
empty strings for parameters where --clone or --master is
desired on the command line without extra parameters.

$meta_params and $op_params behave somewhat similarly, but without the
distinction between empty strings and undef.  I.e., either "meta
<my-meta-params>" should be present in the pcs resource create command
or not at all.

Finally, $resource_params are simply params that show up as options in
the command immediately after the resource type without any additional
keywords.
```

- lib/puppet/provider/pcmk_resource/default.rb

```
  def create
    # (snip)
    if clone_params
      cmd += ' --clone'
      if not_empty_string(clone_params)
        cmd += ' ' + clone_params
      end
    end
    # (snip)
  end
```
