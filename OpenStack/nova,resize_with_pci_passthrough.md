# nova resizeでPCI Passthroughのextra_specが無視されている？

バージョン

- RHOSP9 (Mitaka)
- RHEL7.3

## 動機

nova resizeで、PCI PassthroughするGPUが1枚のflavorから2枚のflavorにresizeする。

- resize前flavor: vcpu=8, memory=32G, disk=16G, GPU=1
- resize後flavor: vcpu=16, memory=64G, disk=16G, GPU=2

resize後、vcpuとメモリは増えているが、GPUが1枚のまま。の理由を調査。

## 準備

flavorを作る。
```
[root@osp7ps-controller01 ~(keystone_admin)]# nova flavor-create tmp1 auto 32768 16 8
+--------------------------------------+------+-----------+------+-----------+------+-------+-------------+-----------+
| ID                                   | Name | Memory_MB | Disk | Ephemeral | Swap | VCPUs | RXTX_Factor | Is_Public |
+--------------------------------------+------+-----------+------+-----------+------+-------+-------------+-----------+
| 66b43c2b-6da8-417b-a97f-a2d10a12bec0 | tmp1 | 32768     | 16   | 0         |      | 8     | 1.0         | True      |
+--------------------------------------+------+-----------+------+-----------+------+-------+-------------+-----------+
[root@osp7ps-controller01 ~(keystone_admin)]# nova flavor-key tmp1 set pci_passthrough:alias=QuadroM4000-video:1
[root@osp7ps-controller01 ~(keystone_admin)]# nova flavor-create tmp2 auto 65536 16 16
+--------------------------------------+------+-----------+------+-----------+------+-------+-------------+-----------+
| ID                                   | Name | Memory_MB | Disk | Ephemeral | Swap | VCPUs | RXTX_Factor | Is_Public |
+--------------------------------------+------+-----------+------+-----------+------+-------+-------------+-----------+
| 4fa11306-394e-483a-a4ac-efe2d9255808 | tmp2 | 65536     | 16   | 0         |      | 16    | 1.0         | True      |
+--------------------------------------+------+-----------+------+-----------+------+-------+-------------+-----------+
[root@osp7ps-controller01 ~(keystone_admin)]# nova flavor-key tmp2 set pci_passthrough:alias=QuadroM4000-video:2
```

```
[root@osp7ps-controller01 ~(keystone_admin)]# openstack flavor show tmp1
+----------------------------+---------------------------------------------+
| Field                      | Value                                       |
+----------------------------+---------------------------------------------+
| OS-FLV-DISABLED:disabled   | False                                       |
| OS-FLV-EXT-DATA:ephemeral  | 0                                           |
| disk                       | 16                                          |
| id                         | 66b43c2b-6da8-417b-a97f-a2d10a12bec0        |
| name                       | tmp1                                        |
| os-flavor-access:is_public | True                                        |
| properties                 | pci_passthrough:alias='QuadroM4000-video:1' |
| ram                        | 32768                                       |
| rxtx_factor                | 1.0                                         |
| swap                       |                                             |
| vcpus                      | 8                                           |
+----------------------------+---------------------------------------------+
[root@osp7ps-controller01 ~(keystone_admin)]# openstack flavor show tmp2
+----------------------------+---------------------------------------------+
| Field                      | Value                                       |
+----------------------------+---------------------------------------------+
| OS-FLV-DISABLED:disabled   | False                                       |
| OS-FLV-EXT-DATA:ephemeral  | 0                                           |
| disk                       | 16                                          |
| id                         | 4fa11306-394e-483a-a4ac-efe2d9255808        |
| name                       | tmp2                                        |
| os-flavor-access:is_public | True                                        |
| properties                 | pci_passthrough:alias='QuadroM4000-video:2' |
| ram                        | 65536                                       |
| rxtx_factor                | 1.0                                         |
| swap                       |                                             |
| vcpus                      | 16                                          |
+----------------------------+---------------------------------------------+
[root@osp7ps-controller01 ~(keystone_admin)]#
```

GPUを1枚PCI Passthroughした場合のlibvirt XML:
```
<hostdev mode='subsystem' type='pci' managed='yes'>
  <driver name='vfio' />
  <source>
    <address domain='0x0000' bus='0x08' slot='0x00' function='0x0' />
  </source>
  <alias name='hostdev0' />
  <address type='pci' domain='0x0000' bus='0x00' slot='0x05' function='0x0' />
</hostdev>
```
これをGPU2枚のflavorにresizeしてもhostdevが1個のままなので困っている。

本当はこうなって欲しい。GPUを2枚PCI Passthroughした場合のlibvirt XML:
```
<hostdev mode='subsystem' type='pci' managed='yes'>
  <driver name='vfio' />
  <source>
    <address domain='0x0000' bus='0x08' slot='0x00' function='0x0' />
  </source>
  <alias name='hostdev0' />
  <address type='pci' domain='0x0000' bus='0x00' slot='0x05' function='0x0' />
</hostdev>
<hostdev mode='subsystem' type='pci' managed='yes'>
  <driver name='vfio' />
  <source>
    <address domain='0x0000' bus='0x88' slot='0x00' function='0x0' />
  </source>
  <alias name='hostdev1' />
  <address type='pci' domain='0x0000' bus='0x00' slot='0x06' function='0x0' />
</hostdev>
```

resizeではなく、最初からGPUx2のflavorでインスタンスを作ると、ちゃんとhostdevは2個生える。

## 結論

まだ調査中なので結論は出ていません。

## とっかかり

/var/log/nova/nova-compute.logで

```
Attempting claim: memory xxx MB, disk xxx GB, vcpus xx CPU
```
(値はresize先のflavorのスペック)

と出てからresize処理が進むっぽい。
これは Claim.\_claim\_test() @compute/claims.py が出している。
この関数の中でresize前の諸々確認をしている。最後に
```
Claim successfull
```
と表示して諸々確認おしまい。関係なかった。

## 次のとっかかり

```
Migrating
```
と出てresize開始。
これは ComputeManager.\_prep\_resize() @compute/manager.py が出している。

### 'Migrating'表示までの道のり

- API.resize() @compute/api.py

```python
        current_instance_type = instance.get_flavor()
```

```python
            new_instance_type = flavors.get_flavor_by_flavor_id(
                    flavor_id, read_deleted="no")
```

```python
        scheduler_hint = {'filter_properties': filter_properties}
        self.compute_task_api.resize_instance(context, instance,
                extra_instance_updates, scheduler_hint=scheduler_hint,
                flavor=new_instance_type,
                reservations=quotas.reservations or [],
                clean_shutdown=clean_shutdown)
```

```python
    def __init__(self, image_api=None, network_api=None, volume_api=None,
                 security_group_api=None, skip_policy_check=False, **kwargs):

(snip)

        self.compute_task_api = conductor.ComputeTaskAPI()
```

(ComputeTaskAPI() @conductor/\_\_init\_\_.py)
```python
from nova.conductor import api as conductor_api

(snip)

def ComputeTaskAPI(*args, **kwargs):
    use_local = kwargs.pop('use_local', False)
    if CONF.conductor.use_local or use_local:
        api = conductor_api.LocalComputeTaskAPI
    else:
        api = conductor_api.ComputeTaskAPI
    return api(*args, **kwargs)
```

- ComputeTaskAPI.resize\_instance() @conductor/api.py

```python
from nova.conductor import rpcapi

(snip)

    def __init__(self):
        self.conductor_compute_rpcapi = rpcapi.ComputeTaskAPI()

(snip)

    def resize_instance(self, context, instance, extra_instance_updates,
                        scheduler_hint, flavor, reservations,
                        clean_shutdown=True):
        # NOTE(comstud): 'extra_instance_updates' is not used here but is
        # needed for compatibility with the cells_rpcapi version of this
        # method.
        self.conductor_compute_rpcapi.migrate_server(
            context, instance, scheduler_hint, live=False, rebuild=False,
            flavor=flavor, block_migration=None, disk_over_commit=None,
            reservations=reservations, clean_shutdown=clean_shutdown)
```

- ComputeTaskAPI.resize\_instance() @conductor/rpcapi.py (client side)

```python
    def migrate_server(self, context, instance, scheduler_hint, live, rebuild,
                  flavor, block_migration, disk_over_commit,
                  reservations=None, clean_shutdown=True, request_spec=None):
        kw = {'instance': instance, 'scheduler_hint': scheduler_hint,
              'live': live, 'rebuild': rebuild, 'flavor': flavor,
              'block_migration': block_migration,
              'disk_over_commit': disk_over_commit,
              'reservations': reservations,
              'clean_shutdown': clean_shutdown,
              'request_spec': request_spec,
              }
        version = '1.13'
        if not self.client.can_send_version(version):
            del kw['request_spec']
            version = '1.11'
        if not self.client.can_send_version(version):
            del kw['clean_shutdown']
            version = '1.10'
        if not self.client.can_send_version(version):
            kw['flavor'] = objects_base.obj_to_primitive(flavor)
            version = '1.6'
        if not self.client.can_send_version(version):
            kw['instance'] = jsonutils.to_primitive(
                    objects_base.obj_to_primitive(instance))
            version = '1.4'
        cctxt = self.client.prepare(version=version)
        return cctxt.call(context, 'migrate_server', **kw)
```

```python
from nova import rpc

(snip)

    def __init__(self):
        super(ComputeTaskAPI, self).__init__()
        target = messaging.Target(topic=CONF.conductor.topic,
                                  namespace='compute_task',
                                  version='1.0')
        serializer = objects_base.NovaObjectSerializer()
        self.client = rpc.get_client(target, serializer=serializer)
```

(get_client() @rpc.py)

```python
import oslo_messaging as messaging

(snip)

def get_client(target, version_cap=None, serializer=None):
    assert TRANSPORT is not None
    serializer = RequestContextSerializer(serializer)
    return messaging.RPCClient(TRANSPORT,
                               target,
                               version_cap=version_cap,
                               serializer=serializer)
```

(RPCClient.prepare() @../oslo_messaging/rpc/client.py)

```python
        return _CallContext._prepare(self,
                                     exchange, topic, namespace,
                                     version, server, fanout,
                                     timeout, version_cap, retry)
```

(\_CallContext.\_prepare() @../oslo_messaging/rpc/client.py)

```python
    def _prepare(cls, base,
                 exchange=_marker, topic=_marker, namespace=_marker,
                 version=_marker, server=_marker, fanout=_marker,
                 timeout=_marker, version_cap=_marker, retry=_marker):
        """Prepare a method invocation context. See RPCClient.prepare()."""
        if version is not None and version is not cls._marker:
            # quick sanity check to make sure parsable version numbers are used
            try:
                utils.version_is_compatible(version, version)
            except (IndexError, ValueError):
                raise exceptions.MessagingException(
                    "Version must contain a major and minor integer. Got %s"
                    % version)
        kwargs = dict(
            exchange=exchange,
            topic=topic,
            namespace=namespace,
            version=version,
            server=server,
            fanout=fanout)
        kwargs = dict([(k, v) for k, v in kwargs.items()
                       if v is not cls._marker])
        target = base.target(**kwargs)

        if timeout is cls._marker:
            timeout = base.timeout
        if retry is cls._marker:
            retry = base.retry
        if version_cap is cls._marker:
            version_cap = base.version_cap

        return _CallContext(base.transport, target,
                            base.serializer,
                            timeout, version_cap, retry)
```

(\_CallContext.cast() @../oslo_messaging/rpc/client.py)

```python
    def call(self, ctxt, method, **kwargs):
        """Invoke a method and wait for a reply. See RPCClient.call()."""
        if self.target.fanout:
            raise exceptions.InvalidTarget('A call cannot be used with fanout',
                                           self.target)

        msg = self._make_message(ctxt, method, kwargs)
        msg_ctxt = self.serializer.serialize_context(ctxt)

        timeout = self.timeout
        if self.timeout is None:
            timeout = self.conf.rpc_response_timeout

        if self.version_cap:
            self._check_version_cap(msg.get('version'))

        try:
            result = self.transport._send(self.target, msg_ctxt, msg,
                                          wait_for_reply=True, timeout=timeout,
                                          retry=self.retry)
        except driver_base.TransportDriverError as ex:
            raise ClientSendError(self.target, ex)
        return self.serializer.deserialize_entity(ctxt, result)
```

- ComputeTaskManager.migrate\_server() @conductor/manager.py

```python
    def migrate_server(self, context, instance, scheduler_hint, live, rebuild,
            flavor, block_migration, disk_over_commit, reservations=None,
            clean_shutdown=True, request_spec=None):
        if instance and not isinstance(instance, nova_object.NovaObject):
            # NOTE(danms): Until v2 of the RPC API, we need to tolerate
            # old-world instance objects here
            attrs = ['metadata', 'system_metadata', 'info_cache',
                     'security_groups']
            instance = objects.Instance._from_db_object(
                context, objects.Instance(), instance,
                expected_attrs=attrs)
        # NOTE: Remove this when we drop support for v1 of the RPC API
        if flavor and not isinstance(flavor, objects.Flavor):
            # Code downstream may expect extra_specs to be populated since it
            # is receiving an object, so lookup the flavor to ensure this.
            flavor = objects.Flavor.get_by_id(context, flavor['id'])             ###
        if live and not rebuild and not flavor:
            self._live_migrate(context, instance, scheduler_hint,
                               block_migration, disk_over_commit, request_spec)
        elif not live and not rebuild and flavor:
            instance_uuid = instance.uuid
            with compute_utils.EventReporter(context, 'cold_migrate',
                                             instance_uuid):
                self._cold_migrate(context, instance, flavor,
                                   scheduler_hint['filter_properties'],
                                   reservations, clean_shutdown)
        else:
            raise NotImplementedError()
```

  ちなみにこの関数はlive migrationのときも呼ばれる。resizeのときは
```python
        self.conductor_compute_rpcapi.migrate_server(
            context, instance, scheduler_hint, live=False, rebuild=False,
            flavor=flavor, block_migration=None, disk_over_commit=None,
            reservations=reservations, clean_shutdown=clean_shutdown)
```
  live migrationのときは
```python
        scheduler_hint = {'host': host_name}
        self.conductor_compute_rpcapi.migrate_server(
            context, instance, scheduler_hint, True, False, None,
            block_migration, disk_over_commit, None, request_spec=request_spec)
```
  という感じで呼ばれる。

- ComputeTaskManager.\_cold\_migrate() @conductor/manager.py

```python
    def _cold_migrate(self, context, instance, flavor, filter_properties,
                      reservations, clean_shutdown):
        image = utils.get_image_from_system_metadata(
            instance.system_metadata)

        request_spec = scheduler_utils.build_request_spec(
            context, image, [instance], instance_type=flavor)                  ###
        task = self._build_cold_migrate_task(context, instance, flavor,
                                             filter_properties, request_spec,
                                             reservations, clean_shutdown)
        try:
            task.execute()
        except exception.NoValidHost as ex:

(snip)
```

```python
    def _build_cold_migrate_task(self, context, instance, flavor,
                                 filter_properties, request_spec, reservations,
                                 clean_shutdown):
        return migrate.MigrationTask(context, instance, flavor,
                                     filter_properties, request_spec,
                                     reservations, clean_shutdown,
                                     self.compute_rpcapi,
                                     self.scheduler_client)
```

- TaskBase.execute() @conductor/tasks/base.py

```python
    def execute(self):
        """Run task's logic, written in _execute() method
        """
        return self._execute()
```

- MigrationTask._execute() @conductor/tasks/migrate.py

```python
    def _execute(self):
        image = self.request_spec.get('image')
        self.quotas = objects.Quotas.from_reservations(self.context,
                                                       self.reservations,
                                                       instance=self.instance)
        scheduler_utils.setup_instance_group(self.context, self.request_spec,
                                             self.filter_properties)
        scheduler_utils.populate_retry(self.filter_properties,
                                       self.instance.uuid)
        # TODO(sbauza): Hydrate here the object until we modify the
        # scheduler.utils methods to directly use the RequestSpec object
        spec_obj = objects.RequestSpec.from_primitives(
            self.context, self.request_spec, self.filter_properties)
        hosts = self.scheduler_client.select_destinations(
            self.context, spec_obj)                                              ###
        host_state = hosts[0]

        scheduler_utils.populate_filter_properties(self.filter_properties,
                                                   host_state)
        # context is not serializable
        self.filter_properties.pop('context', None)

        (host, node) = (host_state['host'], host_state['nodename'])
        self.compute_rpcapi.prep_resize(
            self.context, image, self.instance, self.flavor, host,
            self.reservations, request_spec=self.request_spec,
            filter_properties=self.filter_properties, node=node,
            clean_shutdown=self.clean_shutdown)
```

```python
    def __init__(self, context, instance, flavor, filter_properties,

(snip)

        self.compute_rpcapi = compute_rpcapi
```

- ComputeManager.prep\_resize() @compute/rpcapi.py

```python
    def prep_resize(self, ctxt, image, instance, instance_type, host,
                    reservations=None, request_spec=None,
                    filter_properties=None, node=None,
                    clean_shutdown=True):
        image_p = jsonutils.to_primitive(image)
        msg_args = {'instance': instance,
                    'instance_type': instance_type,
                    'image': image_p,
                    'reservations': reservations,
                    'request_spec': request_spec,
                    'filter_properties': filter_properties,
                    'node': node,
                    'clean_shutdown': clean_shutdown}
        version = '4.1'
        if not self.client.can_send_version(version):
            version = '4.0'
            msg_args['instance_type'] = objects_base.obj_to_primitive(
                                            instance_type)
        cctxt = self.client.prepare(server=host, version=version)
        cctxt.cast(ctxt, 'prep_resize', **msg_args)
```

- ComputeManager.prep\_resize() @compute/manager.py

```python
    def prep_resize(self, context, image, instance, instance_type,
                    reservations, request_spec, filter_properties, node,
                    clean_shutdown):
        """Initiates the process of moving a running instance to another host.

        Possibly changes the RAM and disk size in the process.

        """
        if node is None:
            node = self.driver.get_available_nodes(refresh=True)[0]
            LOG.debug("No node specified, defaulting to %s", node,
                      instance=instance)

        # NOTE(melwitt): Remove this in version 5.0 of the RPC API
        # Code downstream may expect extra_specs to be populated since it
        # is receiving an object, so lookup the flavor to ensure this.
        if not isinstance(instance_type, objects.Flavor):
            instance_type = objects.Flavor.get_by_id(context,
                                                     instance_type['id'])

        quotas = objects.Quotas.from_reservations(context,
                                                  reservations,
                                                  instance=instance)
        with self._error_out_instance_on_exception(context, instance,
                                                   quotas=quotas):
            compute_utils.notify_usage_exists(self.notifier, context, instance,
                                              current_period=True)
            self._notify_about_instance_usage(
                    context, instance, "resize.prep.start")
            try:
                self._prep_resize(context, image, instance,
                                  instance_type, quotas,
                                  request_spec, filter_properties,
                                  node, clean_shutdown)
            # NOTE(dgenin): This is thrown in LibvirtDriver when the
            #               instance to be migrated is backed by LVM.
            #               Remove when LVM migration is implemented.
            except exception.MigrationPreCheckError:
                raise
            except Exception:
                # try to re-schedule the resize elsewhere:
                exc_info = sys.exc_info()
                self._reschedule_resize_or_reraise(context, image, instance,
                        exc_info, instance_type, quotas, request_spec,
                        filter_properties)
            finally:
                extra_usage_info = dict(
                        new_instance_type=instance_type.name,
                        new_instance_type_id=instance_type.id)

                self._notify_about_instance_usage(
                    context, instance, "resize.prep.end",
                    extra_usage_info=extra_usage_info)
```

- ComputeManager.\_prep\_resize() @compute/manager.py

```python
    def _prep_resize(self, context, image, instance, instance_type,
            quotas, request_spec, filter_properties, node,
            clean_shutdown=True):

        if not filter_properties:
            filter_properties = {}

        if not instance.host:
            self._set_instance_obj_error_state(context, instance)
            msg = _('Instance has no source host')
            raise exception.MigrationError(reason=msg)

        same_host = instance.host == self.host
        # if the flavor IDs match, it's migrate; otherwise resize
        if same_host and instance_type.id == instance['instance_type_id']:
            # check driver whether support migrate to same host
            if not self.driver.capabilities['supports_migrate_to_same_host']:
                raise exception.UnableToMigrateToSelf(
                    instance_id=instance.uuid, host=self.host)

        # NOTE(danms): Stash the new instance_type to avoid having to
        # look it up in the database later
        instance.new_flavor = instance_type
        # NOTE(mriedem): Stash the old vm_state so we can set the
        # resized/reverted instance back to the same state later.
        vm_state = instance.vm_state
        LOG.debug('Stashing vm_state: %s', vm_state, instance=instance)
        instance.system_metadata['old_vm_state'] = vm_state
        instance.save()

        limits = filter_properties.get('limits', {})
        rt = self._get_resource_tracker(node)
        with rt.resize_claim(context, instance, instance_type,
                             image_meta=image, limits=limits) as claim:
            LOG.info(_LI('Migrating'), context=context, instance=instance)
            self.compute_rpcapi.resize_instance(
                    context, instance, claim.migration, image,
                    instance_type, quotas.reservations,
                    clean_shutdown)
```

### 'Migrating'がログに出た後、仮想マシンインスタンス起動までの流れ

- ComputeAPI.resize\_instance() @compute/rpcapi.py (client side)

```python
    def resize_instance(self, ctxt, instance, migration, image, instance_type,
                        reservations=None, clean_shutdown=True):
        msg_args = {'instance': instance, 'migration': migration,
                    'image': image, 'reservations': reservations,
                    'instance_type': instance_type,
                    'clean_shutdown': clean_shutdown,
        }
        version = '4.1'
        if not self.client.can_send_version(version):
            msg_args['instance_type'] = objects_base.obj_to_primitive(
                                            instance_type)
            version = '4.0'
        cctxt = self.client.prepare(server=_compute_host(None, instance),
                version=version)
        cctxt.cast(ctxt, 'resize_instance', **msg_args)
```

- ComputeManager.resize\_instance() @compute/manager.py

```python
            # TODO(chaochin) Remove this until v5 RPC API
            # Code downstream may expect extra_specs to be populated since it
            # is receiving an object, so lookup the flavor to ensure this.
            if (not instance_type or
                not isinstance(instance_type, objects.Flavor)):
                instance_type = objects.Flavor.get_by_id(
                    context, migration['new_instance_type_id'])

(snip)

            self.compute_rpcapi.finish_resize(context, instance,
                    migration, image, disk_info,
                    migration.dest_compute, reservations=quotas.reservations)
```

- ComputeAPI.finish\_resize() @compute/rpcapi.py (client side)

```python
    def finish_resize(self, ctxt, instance, migration, image, disk_info,
            host, reservations=None):
        version = '4.0'
        cctxt = self.client.prepare(server=host, version=version)
        cctxt.cast(ctxt, 'finish_resize',
                   instance=instance, migration=migration,
                   image=image, disk_info=disk_info, reservations=reservations)
```

- ComputeManager.finish\_resize() @compute/manager.py

```python
    def finish_resize(self, context, disk_info, image, instance,
                      reservations, migration):
        """Completes the migration process.

        Sets up the newly transferred disk and turns on the instance at its
        new host machine.

        """
        quotas = objects.Quotas.from_reservations(context,
                                                  reservations,
                                                  instance=instance)
        try:
            image_meta = objects.ImageMeta.from_dict(image)
            self._finish_resize(context, instance, migration,
                                disk_info, image_meta)
            quotas.commit()
        except Exception:
            LOG.exception(_LE('Setting instance vm_state to ERROR'),
                          instance=instance)
            with excutils.save_and_reraise_exception():
                try:
                    quotas.rollback()
                except Exception:
                    LOG.exception(_LE("Failed to rollback quota for failed "
                                      "finish_resize"),
                                  instance=instance)
                self._set_instance_obj_error_state(context, instance)
```

- ComputeManager.\_finish\_resize() @compute/manager.py

```python
        old_instance_type_id = migration['old_instance_type_id']
        new_instance_type_id = migration['new_instance_type_id']
        old_instance_type = instance.get_flavor()
        # NOTE(mriedem): Get the old_vm_state so we know if we should
        # power on the instance. If old_vm_state is not set we need to default
        # to ACTIVE for backwards compatibility
        old_vm_state = instance.system_metadata.get('old_vm_state',
                                                    vm_states.ACTIVE)
        instance.old_flavor = old_instance_type

        if old_instance_type_id != new_instance_type_id:
            instance_type = instance.get_flavor('new')
            self._set_instance_info(instance, instance_type)
            for key in ('root_gb', 'swap', 'ephemeral_gb'):
                if old_instance_type[key] != instance_type[key]:
                    resize_instance = True
                    break
        instance.apply_migration_context()
```

```python
            self.driver.finish_migration(context, migration, instance,
                                         disk_info,
                                         network_info,
                                         image_meta, resize_instance,
                                         block_device_info, power_on)
```

- LibvirtDriver.finish_migration() @virt/libvirt/driver.py

```python
        xml = self._get_guest_xml(context, instance, network_info,
                                  block_disk_info, image_meta,
                                  block_device_info=block_device_info,
                                  write_to_disk=True)
```

```python
        # NOTE(mriedem): vifs_already_plugged=True here, regardless of whether
        # or not we've migrated to another host, because we unplug VIFs locally
        # and the status change in the port might go undetected by the neutron
        # L2 agent (or neutron server) so neutron may not know that the VIF was
        # unplugged in the first place and never send an event.
        self._create_domain_and_network(context, xml, instance, network_info,
                                        block_disk_info,
                                        block_device_info=block_device_info,
                                        power_on=power_on,
                                        vifs_already_plugged=True)
```

- LibvirtDriver.\_create\_domain\_and\_network() @virt/libvirt/driver.py

```python
        pause = bool(events)
        guest = None
        try:
            with self.virtapi.wait_for_instance_event(
                    instance, events, deadline=timeout,
                    error_callback=self._neutron_failed_callback):
                self.plug_vifs(instance, network_info)
                self.firewall_driver.setup_basic_filtering(instance,
                                                           network_info)
                self.firewall_driver.prepare_instance_filter(instance,
                                                             network_info)
                with self._lxc_disk_handler(instance, instance.image_meta,
                                            block_device_info, disk_info):
                    guest = self._create_domain(
                        xml, pause=pause, power_on=power_on)

                self.firewall_driver.apply_instance_filter(instance,
                                                           network_info)
```

- LibvirtDriver.\_create\_domain() @compute/manager.py

```python
    # TODO(sahid): Consider renaming this to _create_guest.
    def _create_domain(self, xml=None, domain=None,
                       power_on=True, pause=False):
        """Create a domain.

        Either domain or xml must be passed in. If both are passed, then
        the domain definition is overwritten from the xml.

        :returns guest.Guest: Guest just created
        """
        if xml:
            guest = libvirt_guest.Guest.create(xml, self._host)
        else:
            guest = libvirt_guest.Guest(domain)

        if power_on or pause:
            guest.launch(pause=pause)

        if not utils.is_neutron():
            guest.enable_hairpin()

        return guest
```

- Guest.create() @virt/libvirt/guest.py

```python
    def create(cls, xml, host):
        """Create a new Guest

        :param xml: XML definition of the domain to create
        :param host: host.Host connection to define the guest on

        :returns guest.Guest: Guest ready to be launched
        """
        try:
            # TODO(sahid): Host.write_instance_config should return
            # an instance of Guest
            domain = host.write_instance_config(xml)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE('Error defining a domain with XML: %s'),
                          encodeutils.safe_decode(xml))
        return cls(domain)
```

- Host.write\_instance\_config() @virt/libvirt/host.py

```python
    def write_instance_config(self, xml):
        """Defines a domain, but does not start it.

        :param xml: XML domain definition of the guest.

        :returns: a virDomain instance
        """
        return self.get_connection().defineXML(xml)
```

- Host.get_connection().defineXML() @virt/libvirt/host.py

```python

```

## 「怪しそう」なところ

ComputeManager.\_finish\_resize() @compute/manager.py で呼ばれている ComputeManager.\_set\_instance\_info() @compute/manager.py。

```python
    def _set_instance_info(instance, instance_type):
        instance.instance_type_id = instance_type.id
        instance.memory_mb = instance_type.memory_mb
        instance.vcpus = instance_type.vcpus
        instance.root_gb = instance_type.root_gb
        instance.ephemeral_gb = instance_type.ephemeral_gb
        instance.flavor = instance_type
```

LibvirtDriver.finish\_migration() @virt/libvirt/driver.py で呼ばれる LibvirtDriver.\_get\_guest\_xml() @virt/libvirt/driver.py

```python
    def _get_guest_xml(self, context, instance, network_info, disk_info,
                       image_meta, rescue=None,
                       block_device_info=None, write_to_disk=False):
        # NOTE(danms): Stringifying a NetworkInfo will take a lock. Do
        # this ahead of time so that we don't acquire it while also
        # holding the logging lock.
        network_info_str = str(network_info)
        msg = ('Start _get_guest_xml '
               'network_info=%(network_info)s '
               'disk_info=%(disk_info)s '
               'image_meta=%(image_meta)s rescue=%(rescue)s '
               'block_device_info=%(block_device_info)s' %
               {'network_info': network_info_str, 'disk_info': disk_info,
                'image_meta': image_meta, 'rescue': rescue,
                'block_device_info': block_device_info})
        # NOTE(mriedem): block_device_info can contain auth_password so we
        # need to sanitize the password in the message.
        LOG.debug(strutils.mask_password(msg), instance=instance)
        conf = self._get_guest_config(instance, network_info, image_meta,
                                      disk_info, rescue, block_device_info,
                                      context)
        xml = conf.to_xml()

        if write_to_disk:
            instance_dir = libvirt_utils.get_instance_path(instance)
            xml_path = os.path.join(instance_dir, 'libvirt.xml')
            libvirt_utils.write_to_file(xml_path, xml)

        LOG.debug('End _get_guest_xml xml=%(xml)s',
                  {'xml': xml}, instance=instance)
        return xml
```

さらに LibvirtDriver.\_get\_guest\_config() @virt/libvirt/driver.py が呼ばれる。
これは結構長い。
この中でlibvirtのXMLを作っている。PCI関連はここ:

```python
        pci_devs = pci_manager.get_instance_pci_devs(instance, 'all')

        guest_numa_config = self._get_guest_numa_config(
            instance.numa_topology, flavor, pci_devs, allowed_cpus, image_meta)
```

```python
        if virt_type in ('xen', 'qemu', 'kvm'):
            for pci_dev in pci_manager.get_instance_pci_devs(instance):
                guest.add_device(self._get_guest_pci_device(pci_dev))
```

get\_instance\_pci\_devs() @pci/manager.py

```python
def get_instance_pci_devs(inst, request_id=None):
    """Get the devices allocated to one or all requests for an instance.

    - For generic PCI request, the request id is None.
    - For sr-iov networking, the request id is a valid uuid
    - There are a couple of cases where all the PCI devices allocated to an
      instance need to be returned. Refer to libvirt driver that handles
      soft_reboot and hard_boot of 'xen' instances.
    """
    pci_devices = inst.pci_devices
    return [device for device in pci_devices if
                   device.request_id == request_id or request_id == 'all']
```

## 通常のnova boot

- API.create() @compute/api.py
- API.\_create\_instance() @compute/api.py
- ComputeTaskAPI.build_instances() @conductor/api.py
- ComputeTaskAPI.build_instances() @conductor/rpcapi.py
- ComputeTaskManager.build_instances() @conductor/manager.py
  ここでスケジューリングしている
  - ComputeTaskManager.\_schedule\_instances() @conductor/manager.py
- ComputeAPI.build\_and\_run\_instance() @compute/rpcapi.py
- ComputeManager.build\_and\_run\_instance() @compute/manager.py
- ComputeManager.\_do\_build\_and\_run\_instance() @compute/manager.py
- ComputeManager.\_build\_and\_run\_instance() @compute/manager.py
- LibvirtDriver.spawn() @virt/libvirt/driver.py
- LibvirtDriver.\_create\_domain\_and\_network() @virt/libvirt/driver.py

## スケジューリング

- ComputeTaskManager.\_schedule\_instances() @conductor/manager.py
- SchedulerClient.select\_destinations() @scheduler/client/\_\_init\_\_.py
- SchedulerQueryClient.select\_destinations() @scheduler/client/query.py
- SchedulerAPI.select\_destinations() @scheduler/rpcapi.py
- SchedulerManager.select\_destinations() @scheduler/manager.py
- FilterScheduler.select\_destinations() @scheduler/filter\_scheduler.py
- FilterScheduler.\_schedule() @scheduler/filter\_scheduler.py

```python
        for num in range(num_instances):
            # Filter local hosts based on requirements ...
            hosts = self.host_manager.get_filtered_hosts(hosts,
                    spec_obj, index=num)
            if not hosts:
                # Can't get any more locally.
                break

            LOG.debug("Filtered %(hosts)s", {'hosts': hosts})

            weighed_hosts = self.host_manager.get_weighed_hosts(hosts,
                    spec_obj)

            LOG.debug("Weighed %(hosts)s", {'hosts': weighed_hosts})
```

  self.host_managerは、FilterSchedulerの親クラスである class Scheduler @scheduler/driver.py で初期化されている。

```python
class Scheduler(object):
    """The base class that all Scheduler classes should inherit from."""

    def __init__(self):
        try:
            self.host_manager = driver.DriverManager(
                    "nova.scheduler.host_manager",
                    CONF.scheduler_host_manager,
                    invoke_on_load=True).driver
```

  CONF.scheduler\_host\_manager のデフォルト値は "host_manager"。

- HostManager.get\_filtered\_hosts() @scheduler/host_manager.py

```python
        return self.filter_handler.get_filtered_objects(filters,
                hosts, spec_obj, index)
```

filter_handlerは、class HostFilterHandler @scheduler/filters/\_\_init\_\_.py。

```python
class BaseHostFilter(filters.BaseFilter):
    """Base class for host filters."""
    def _filter_one(self, obj, filter_properties):
        """Return True if the object passes the filter, otherwise False."""
        return self.host_passes(obj, filter_properties)

    def host_passes(self, host_state, filter_properties):
        """Return True if the HostState passes the filter, otherwise False.
        Override this in a subclass.
        """
        raise NotImplementedError()


class HostFilterHandler(filters.BaseFilterHandler):
    def __init__(self):
        super(HostFilterHandler, self).__init__(BaseHostFilter)
```

親クラスは class BaseFilter @filter.py。
```python
class BaseFilter(object):
    """Base class for all filter classes."""
    def _filter_one(self, obj, spec_obj):
        """Return True if it passes the filter, False otherwise.
        Override this in a subclass.
        """
        return True

    def filter_all(self, filter_obj_list, spec_obj):
        """Yield objects that pass the filter.

        Can be overridden in a subclass, if you need to base filtering
        decisions on all objects.  Otherwise, one can just override
        _filter_one() to filter a single object.
        """
        for obj in filter_obj_list:
            if self._filter_one(obj, spec_obj):
                yield obj

    # Set to true in a subclass if a filter only needs to be run once
    # for each request rather than for each instance
    run_filter_once_per_request = False

    def run_filter_for_index(self, index):
        """Return True if the filter needs to be run for the "index-th"
        instance in a request.  Only need to override this if a filter
        needs anything other than "first only" or "all" behaviour.
        """
        if self.run_filter_once_per_request and index > 0:
            return False
        else:
            return True
```
