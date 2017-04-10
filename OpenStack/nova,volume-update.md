# nova volume-updateを追う

バージョン

- RHOSP9 (Mitaka)
- RHEL7.3

## 動機

nova volume-update が何をしているかを追う。

最終的にはqemuのdrive-mirrorを呼んでいる。

## さっそく読む

"nova volume-update" を実行したら、novaclientのdo\_volume\_update()が呼ばれる。

- do\_volume\_update() @novaclient/v2/shell.py

```python
def do_volume_update(cs, args):
    """Update volume attachment."""
    cs.volumes.update_server_volume(_find_server(cs, args.server).id,
                                    args.attachment_id,
                                    args.new_volume)
```

- VolumeManager.update\_server\_volume() @novaclient.v2/volumes.py

```python
    def update_server_volume(self, server_id, attachment_id, new_volume_id):
        """
        Update the volume identified by the attachment ID, that is attached to
        the given server ID

        :param server_id: The ID of the server
        :param attachment_id: The ID of the attachment
        :param new_volume_id: The ID of the new volume to attach
        :rtype: :class:`Volume`
        """
        body = {'volumeAttachment': {'volumeId': new_volume_id}}
        return self._update("/servers/%s/os-volume_attachments/%s" %
                            (server_id, attachment_id,),
                            body, "volumeAttachment")
```

Manager._update() @novaclient/base.py

```python
    def _update(self, url, body, response_key=None, **kwargs):
        self.run_hooks('modify_body_for_update', body, **kwargs)
        resp, body = self.api.client.put(url, body=body)
        if body:
            if response_key:
                return self.resource_class(self, body[response_key], resp=resp)
            else:
                return self.resource_class(self, body, resp=resp)
        else:
            return StrWithMeta(body, resp)
```

- Volumes.get\_resources() @api/openstack/compute/volumes.py

```python
    def get_resources(self):
        resources = []

        res = extensions.ResourceExtension(
            ALIAS, VolumeController(), collection_actions={'detail': 'GET'})
        resources.append(res)

        res = extensions.ResourceExtension('os-volumes_boot',
                                           inherits='servers')
        resources.append(res)

        res = extensions.ResourceExtension('os-volume_attachments',
                                           VolumeAttachmentController(),
                                           parent=dict(
                                                member_name='server',
                                                collection_name='servers'))
        resources.append(res)

        res = extensions.ResourceExtension(
            'os-snapshots', SnapshotController(),
            collection_actions={'detail': 'GET'})
        resources.append(res)

        return resources
```

- Volumes.get\_resources() @api/openstack/compute/legacy\_v2/contrib/volumes.py

```python
    def get_resources(self):
        resources = []

        # NOTE(justinsb): No way to provide singular name ('volume')
        # Does this matter?
        res = extensions.ResourceExtension('os-volumes',
                                        VolumeController(),
                                        collection_actions={'detail': 'GET'})
        resources.append(res)

        attachment_controller = VolumeAttachmentController(self.ext_mgr)
        res = extensions.ResourceExtension('os-volume_attachments',
                                           attachment_controller,
                                           parent=dict(
                                                member_name='server',
                                                collection_name='servers'))
        resources.append(res)

        res = extensions.ResourceExtension('os-volumes_boot',
                                           inherits='servers')
        resources.append(res)

        res = extensions.ResourceExtension('os-snapshots',
                                        SnapshotController(),
                                        collection_actions={'detail': 'GET'})
        resources.append(res)

        return resources
```


os-volume-attachment-update

VolumeAttachmentController.update() @api/openstack/compute/volumes.py

```python
    def update(self, req, server_id, id, body):
        context = req.environ['nova.context']
        authorize(context)
        authorize_attach(context, action='update')

        old_volume_id = id
        try:
            old_volume = self.volume_api.get(context, old_volume_id)

            new_volume_id = body['volumeAttachment']['volumeId']
            new_volume = self.volume_api.get(context, new_volume_id)
        except exception.VolumeNotFound as e:
            raise exc.HTTPNotFound(explanation=e.format_message())

        instance = common.get_instance(self.compute_api, context, server_id)

        bdms = objects.BlockDeviceMappingList.get_by_instance_uuid(
                context, instance.uuid)
        found = False
        try:
            for bdm in bdms:
                if bdm.volume_id != old_volume_id:
                    continue
                try:
                    self.compute_api.swap_volume(context, instance, old_volume,
                                                 new_volume)
                    found = True
                    break
                except exception.VolumeUnattached:
                    # The volume is not attached.  Treat it as NotFound
                    # by falling through.
                    pass
                except exception.InvalidVolume as e:
                    raise exc.HTTPBadRequest(explanation=e.format_message())
        except exception.InstanceIsLocked as e:
            raise exc.HTTPConflict(explanation=e.format_message())
        except exception.InstanceInvalidState as state_error:
            common.raise_http_conflict_for_instance_invalid_state(state_error,
                    'swap_volume', server_id)

        if not found:
            msg = _("The volume was either invalid or not attached to the "
                    "instance.")
            raise exc.HTTPNotFound(explanation=msg)
```

VolumeAttachmentController.update() @api/openstack/compute/legacy_v2/contrib/volumes.py

```python
    def update(self, req, server_id, id, body):
        if (not self.ext_mgr or
                not self.ext_mgr.is_loaded('os-volume-attachment-update')):
            raise exc.HTTPBadRequest()
        context = req.environ['nova.context']
        authorize(context)
        authorize_attach(context, action='update')

        if not self.is_valid_body(body, 'volumeAttachment'):
            msg = _("volumeAttachment not specified")
            raise exc.HTTPBadRequest(explanation=msg)

        old_volume_id = id
        old_volume = self.volume_api.get(context, old_volume_id)

        try:
            new_volume_id = body['volumeAttachment']['volumeId']
        except KeyError:
            msg = _("volumeId must be specified.")
            raise exc.HTTPBadRequest(explanation=msg)
        self._validate_volume_id(new_volume_id)
        new_volume = self.volume_api.get(context, new_volume_id)

        instance = common.get_instance(self.compute_api, context, server_id)

        bdms = objects.BlockDeviceMappingList.get_by_instance_uuid(
                context, instance.uuid)
        found = False
        try:
            for bdm in bdms:
                if bdm.volume_id != old_volume_id:
                    continue
                try:
                    self.compute_api.swap_volume(context, instance, old_volume,
                                                 new_volume)
                    found = True
                    break
                except exception.VolumeUnattached:
                    # The volume is not attached.  Treat it as NotFound
                    # by falling through.
                    pass
        except exception.InstanceIsLocked as e:
            raise exc.HTTPConflict(explanation=e.format_message())
        except exception.InstanceInvalidState as state_error:
            common.raise_http_conflict_for_instance_invalid_state(state_error,
                    'swap_volume', server_id)

        if not found:
            msg = _("volume_id not found: %s") % old_volume_id
            raise exc.HTTPNotFound(explanation=msg)
        else:
            return webob.Response(status_int=202)
```

Volume\_attachment\_update @api/openstack/compute/legacy\_v2/contrib/volume\_attachment\_update.py

```python
class Volume_attachment_update(extensions.ExtensionDescriptor):
    """Support for updating a volume attachment."""

    name = "VolumeAttachmentUpdate"
    alias = "os-volume-attachment-update"
    namespace = ("http://docs.openstack.org/compute/ext/"
                "os-volume-attachment-update/api/v2")
    updated = "2013-06-20T00:00:00Z"
```


API.swap_volume() @compute/api.py

```python
    def swap_volume(self, context, instance, old_volume, new_volume):
        """Swap volume attached to an instance."""
        if old_volume['attach_status'] == 'detached':
            raise exception.VolumeUnattached(volume_id=old_volume['id'])
        # The caller likely got the instance from volume['attachments']
        # in the first place, but let's sanity check.
        if not old_volume.get('attachments', {}).get(instance.uuid):
            msg = _("Old volume is attached to a different instance.")
            raise exception.InvalidVolume(reason=msg)
        if new_volume['attach_status'] == 'attached':
            msg = _("New volume must be detached in order to swap.")
            raise exception.InvalidVolume(reason=msg)
        if int(new_volume['size']) < int(old_volume['size']):
            msg = _("New volume must be the same size or larger.")
            raise exception.InvalidVolume(reason=msg)
        self.volume_api.check_detach(context, old_volume)
        self.volume_api.check_attach(context, new_volume, instance=instance)
        self.volume_api.begin_detaching(context, old_volume['id'])
        self.volume_api.reserve_volume(context, new_volume['id'])
        try:
            self.compute_rpcapi.swap_volume(
                    context, instance=instance,
                    old_volume_id=old_volume['id'],
                    new_volume_id=new_volume['id'])
        except Exception:
            with excutils.save_and_reraise_exception():
                self.volume_api.roll_detaching(context, old_volume['id'])
                self.volume_api.unreserve_volume(context, new_volume['id'])
```

- ComputeAPI.swap_volume() @compute/rpcapi.py

```python
    def swap_volume(self, ctxt, instance, old_volume_id, new_volume_id):
        version = '4.0'
        cctxt = self.client.prepare(server=_compute_host(None, instance),
                version=version)
        cctxt.cast(ctxt, 'swap_volume',
                   instance=instance, old_volume_id=old_volume_id,
                   new_volume_id=new_volume_id)
```

- ComputeManager.swap_volume() @compute/manager.py

```python
    def swap_volume(self, context, old_volume_id, new_volume_id, instance):
        """Swap volume for an instance."""
        context = context.elevated()

        bdm = objects.BlockDeviceMapping.get_by_volume_and_instance(
                context, old_volume_id, instance.uuid)
        connector = self.driver.get_volume_connector(instance)

        resize_to = 0
        old_vol_size = self.volume_api.get(context, old_volume_id)['size']
        new_vol_size = self.volume_api.get(context, new_volume_id)['size']
        if new_vol_size > old_vol_size:
            resize_to = new_vol_size

        LOG.info(_LI('Swapping volume %(old_volume)s for %(new_volume)s'),
                  {'old_volume': old_volume_id, 'new_volume': new_volume_id},
                  context=context, instance=instance)
        comp_ret, new_cinfo = self._swap_volume(context, instance,
                                                         bdm,
                                                         connector,
                                                         old_volume_id,
                                                         new_volume_id,
                                                         resize_to)

        save_volume_id = comp_ret['save_volume_id']

        # Update bdm
        values = {
            'connection_info': jsonutils.dumps(new_cinfo),
            'delete_on_termination': False,
            'source_type': 'volume',
            'destination_type': 'volume',
            'snapshot_id': None,
            'volume_id': save_volume_id,
            'no_device': None}

        if resize_to:
            values['volume_size'] = resize_to

        LOG.debug("swap_volume: Updating volume %(volume_id)s BDM record with "
                  "%(updates)s", {'volume_id': bdm.volume_id,
                                  'updates': values},
                  context=context, instance=instance)
        bdm.update(values)
        bdm.save()
```

- ComputeManager.\_swap\_volume() @compute/manager.py

```python
    def _swap_volume(self, context, instance, bdm, connector,
                     old_volume_id, new_volume_id, resize_to):
        mountpoint = bdm['device_name']
        failed = False
        new_cinfo = None
        try:
            old_cinfo, new_cinfo = self._init_volume_connection(context,
                                                                new_volume_id,
                                                                old_volume_id,
                                                                connector,
                                                                instance,
                                                                bdm)
            LOG.debug("swap_volume: Calling driver volume swap with "
                      "connection infos: new: %(new_cinfo)s; "
                      "old: %(old_cinfo)s",
                      {'new_cinfo': new_cinfo, 'old_cinfo': old_cinfo},
                      contex=context, instance=instance)
            self.driver.swap_volume(old_cinfo, new_cinfo, instance, mountpoint,
                                    resize_to)
        except Exception:
            failed = True
            with excutils.save_and_reraise_exception():
                if new_cinfo:
                    msg = _LE("Failed to swap volume %(old_volume_id)s "
                              "for %(new_volume_id)s")
                    LOG.exception(msg, {'old_volume_id': old_volume_id,
                                        'new_volume_id': new_volume_id},
                                  context=context,
                                  instance=instance)
                else:
                    msg = _LE("Failed to connect to volume %(volume_id)s "
                              "with volume at %(mountpoint)s")
                    LOG.exception(msg, {'volume_id': new_volume_id,
                                        'mountpoint': bdm['device_name']},
                                  context=context,
                                  instance=instance)
                self.volume_api.roll_detaching(context, old_volume_id)
                self.volume_api.unreserve_volume(context, new_volume_id)
        finally:
            conn_volume = new_volume_id if failed else old_volume_id
            if new_cinfo:
                LOG.debug("swap_volume: calling Cinder terminate_connection "
                          "for %(volume)s", {'volume': conn_volume},
                          context=context, instance=instance)
                self.volume_api.terminate_connection(context,
                                                     conn_volume,
                                                     connector)
            # If Cinder initiated the swap, it will keep
            # the original ID
            comp_ret = self.volume_api.migrate_volume_completion(
                                                      context,
                                                      old_volume_id,
                                                      new_volume_id,
                                                      error=failed)
            LOG.debug("swap_volume: Cinder migrate_volume_completion "
                      "returned: %(comp_ret)s", {'comp_ret': comp_ret},
                      context=context, instance=instance)

        return (comp_ret, new_cinfo)
```

- LibvirtDriver.swap_volume() @virt/libvirt/driver.py

```python
    def swap_volume(self, old_connection_info,
                    new_connection_info, instance, mountpoint, resize_to):

        guest = self._host.get_guest(instance)

        disk_dev = mountpoint.rpartition("/")[2]
        if not guest.get_disk(disk_dev):
            raise exception.DiskNotFound(location=disk_dev)
        disk_info = {
            'dev': disk_dev,
            'bus': blockinfo.get_disk_bus_for_disk_dev(
                CONF.libvirt.virt_type, disk_dev),
            'type': 'disk',
            }
        self._connect_volume(new_connection_info, disk_info)
        conf = self._get_volume_config(new_connection_info, disk_info)
        if not conf.source_path:
            self._disconnect_volume(new_connection_info, disk_dev)
            raise NotImplementedError(_("Swap only supports host devices"))

        # Save updates made in connection_info when connect_volume was called
        volume_id = new_connection_info.get('serial')
        bdm = objects.BlockDeviceMapping.get_by_volume_and_instance(
            nova_context.get_admin_context(), volume_id, instance.uuid)
        driver_bdm = driver_block_device.DriverVolumeBlockDevice(bdm)
        driver_bdm['connection_info'] = new_connection_info
        driver_bdm.save()

        self._swap_volume(guest, disk_dev, conf.source_path, resize_to)
        self._disconnect_volume(old_connection_info, disk_dev)
```

- LibvirtDriver.\_swap\_volume() @virt/libvirt/driver.py

```python
    def _swap_volume(self, guest, disk_path, new_path, resize_to):
        """Swap existing disk with a new block device."""
        dev = guest.get_block_device(disk_path)

        # Save a copy of the domain's persistent XML file
        xml = guest.get_xml_desc(dump_inactive=True, dump_sensitive=True)

        # Abort is an idempotent operation, so make sure any block
        # jobs which may have failed are ended.
        try:
            dev.abort_job()
        except Exception:
            pass

        try:
            # NOTE (rmk): blockRebase cannot be executed on persistent
            #             domains, so we need to temporarily undefine it.
            #             If any part of this block fails, the domain is
            #             re-defined regardless.
            if guest.has_persistent_configuration():
                guest.delete_configuration()

            # Start copy with VIR_DOMAIN_REBASE_REUSE_EXT flag to
            # allow writing to existing external volume file
            dev.rebase(new_path, copy=True, reuse_ext=True)

            while dev.wait_for_job():
                time.sleep(0.5)

            dev.abort_job(pivot=True)
            if resize_to:
                # NOTE(alex_xu): domain.blockJobAbort isn't sync call. This
                # is bug in libvirt. So we need waiting for the pivot is
                # finished. libvirt bug #1119173
                while dev.wait_for_job(wait_for_job_clean=True):
                    time.sleep(0.5)
                dev.resize(resize_to * units.Gi / units.Ki)
        finally:
            self._host.write_instance_config(xml)
```

- BlockDevice.rebase() @virt/libvirt/guest.py

```python
    def rebase(self, base, shallow=False, reuse_ext=False,
               copy=False, relative=False):
        """Rebases block to new base

        :param shallow: Limit copy to top of source backing chain
        :param reuse_ext: Reuse existing external file of a copy
        :param copy: Start a copy job
        :param relative: Keep backing chain referenced using relative names
        """
        flags = shallow and libvirt.VIR_DOMAIN_BLOCK_REBASE_SHALLOW or 0
        flags |= reuse_ext and libvirt.VIR_DOMAIN_BLOCK_REBASE_REUSE_EXT or 0
        flags |= copy and libvirt.VIR_DOMAIN_BLOCK_REBASE_COPY or 0
        flags |= relative and libvirt.VIR_DOMAIN_BLOCK_REBASE_RELATIVE or 0
        return self._guest._domain.blockRebase(
            self._disk, base, self.REBASE_DEFAULT_BANDWIDTH, flags=flags)
```

- virDomain.blockRebase() @/usr/lib64/python2.7/site-packages/libvirt.py

```python
    def blockRebase(self, disk, base, bandwidth=0, flags=0):
        """Populate a disk image with data from its backing image chain, and
        setting the backing image to @base, or alternatively copy an entire
        backing chain to a new file @base.

        When @flags is 0, this starts a pull, where @base must be the absolute
        path of one of the backing images further up the chain, or None to
        convert the disk image so that it has no backing image.  Once all
        data from its backing image chain has been pulled, the disk no
        longer depends on those intermediate backing images.  This function
        pulls data for the entire device in the background.  Progress of
        the operation can be checked with virDomainGetBlockJobInfo() with a
        job type of VIR_DOMAIN_BLOCK_JOB_TYPE_PULL, and the operation can be
        aborted with virDomainBlockJobAbort().  When finished, an asynchronous
        event is raised to indicate the final status, and the job no longer
        exists.  If the job is aborted, a new one can be started later to
        resume from the same point.

        If @flags contains VIR_DOMAIN_BLOCK_REBASE_RELATIVE, the name recorded
        into the active disk as the location for @base will be kept relative.
        The operation will fail if libvirt can't infer the name.

        When @flags includes VIR_DOMAIN_BLOCK_REBASE_COPY, this starts a copy,
        where @base must be the name of a new file to copy the chain to.  By
        default, the copy will pull the entire source chain into the destination
        file, but if @flags also contains VIR_DOMAIN_BLOCK_REBASE_SHALLOW, then
        only the top of the source chain will be copied (the source and
        destination have a common backing file).  By default, @base will be
        created with the same file format as the source, but this can be altered
        by adding VIR_DOMAIN_BLOCK_REBASE_COPY_RAW to force the copy to be raw
        (does not make sense with the shallow flag unless the source is also raw),
        or by using VIR_DOMAIN_BLOCK_REBASE_REUSE_EXT to reuse an existing file
        which was pre-created with the correct format and metadata and sufficient
        size to hold the copy. In case the VIR_DOMAIN_BLOCK_REBASE_SHALLOW flag
        is used the pre-created file has to exhibit the same guest visible contents
        as the backing file of the original image. This allows a management app to
        pre-create files with relative backing file names, rather than the default
        of absolute backing file names; as a security precaution, you should
        generally only use reuse_ext with the shallow flag and a non-raw
        destination file.  By default, the copy destination will be treated as
        type='file', but using VIR_DOMAIN_BLOCK_REBASE_COPY_DEV treats the
        destination as type='block' (affecting how virDomainGetBlockInfo() will
        report allocation after pivoting).

        A copy job has two parts; in the first phase, the @bandwidth parameter
        affects how fast the source is pulled into the destination, and the job
        can only be canceled by reverting to the source file; progress in this
        phase can be tracked via the virDomainBlockJobInfo() command, with a
        job type of VIR_DOMAIN_BLOCK_JOB_TYPE_COPY.  The job transitions to the
        second phase when the job info states cur == end, and remains alive to
        mirror all further changes to both source and destination.  The user
        must call virDomainBlockJobAbort() to end the mirroring while choosing
        whether to revert to source or pivot to the destination.  An event is
        issued when the job ends, and depending on the hypervisor, an event may
        also be issued when the job transitions from pulling to mirroring.  If
        the job is aborted, a new job will have to start over from the beginning
        of the first phase.

        Some hypervisors will restrict certain actions, such as virDomainSave()
        or virDomainDetachDevice(), while a copy job is active; they may
        also restrict a copy job to transient domains.

        The @disk parameter is either an unambiguous source name of the
        block device (the <source file='...'/> sub-element, such as
        "/path/to/image"), or the device target shorthand (the
        <target dev='...'/> sub-element, such as "vda").  Valid names
        can be found by calling virDomainGetXMLDesc() and inspecting
        elements within //domain/devices/disk.

        The @base parameter can be either a path to a file within the backing
        chain, or the device target shorthand (the <target dev='...'/>
        sub-element, such as "vda") followed by an index to the backing chain
        enclosed in square brackets. Backing chain indexes can be found by
        inspecting //disk//backingStore/@index in the domain XML. Thus, for
        example, "vda[3]" refers to the backing store with index equal to "3"
        in the chain of disk "vda".

        The maximum bandwidth that will be used to do the copy can be
        specified with the @bandwidth parameter.  If set to 0, there is no
        limit.  If @flags includes VIR_DOMAIN_BLOCK_REBASE_BANDWIDTH_BYTES,
        @bandwidth is in bytes/second; otherwise, it is in MiB/second.
        Values larger than 2^52 bytes/sec may be rejected due to overflow
        considerations based on the word size of both client and server,
        and values larger than 2^31 bytes/sec may cause overflow problems
        if later queried by virDomainGetBlockJobInfo() without scaling.
        Hypervisors may further restrict the range of valid bandwidth
        values.  Some hypervisors do not support this feature and will
        return an error if bandwidth is not 0; in this case, it might still
        be possible for a later call to virDomainBlockJobSetSpeed() to
        succeed.  The actual speed can be determined with
        virDomainGetBlockJobInfo().

        When @base is None and @flags is 0, this is identical to
        virDomainBlockPull().  When @flags contains VIR_DOMAIN_BLOCK_REBASE_COPY,
        this command is shorthand for virDomainBlockCopy() where the destination
        XML encodes @base as a <disk type='file'>, @bandwidth is properly scaled
        and passed as a typed parameter, the shallow and reuse external flags
        are preserved, and remaining flags control whether the XML encodes a
        destination format of raw instead of leaving the destination identical
        to the source format or probed from the reused file. """
        ret = libvirtmod.virDomainBlockRebase(self._o, disk, base, bandwidth, flags)
        if ret == -1: raise libvirtError ('virDomainBlockRebase() failed', dom=self)
        return ret
```

- src/libvirt-domain.c

```c
int
virDomainBlockRebase(virDomainPtr dom, const char *disk,
                     const char *base, unsigned long bandwidth,
                     unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(dom, "disk=%s, base=%s, bandwidth=%lu, flags=%x",
                     disk, NULLSTR(base), bandwidth, flags);

    virResetLastError();

    virCheckDomainReturn(dom, -1);
    conn = dom->conn;

    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonNullArgGoto(disk, error);

    if (flags & VIR_DOMAIN_BLOCK_REBASE_COPY) {
        virCheckNonNullArgGoto(base, error);
    } else if (flags & (VIR_DOMAIN_BLOCK_REBASE_SHALLOW |
                        VIR_DOMAIN_BLOCK_REBASE_REUSE_EXT |
                        VIR_DOMAIN_BLOCK_REBASE_COPY_RAW |
                        VIR_DOMAIN_BLOCK_REBASE_COPY_DEV)) {
        virReportInvalidArg(flags, "%s",
                            _("use of flags requires a copy job"));
        goto error;
    }

    if (conn->driver->domainBlockRebase) {
        int ret;
        ret = conn->driver->domainBlockRebase(dom, disk, base, bandwidth,
                                              flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(dom->conn);
    return -1;
}
```

- src/qemu/qemu_driver.c

```c
static virHypervisorDriver qemuHypervisorDriver = {
(snip)
    .domainBlockRebase = qemuDomainBlockRebase, /* 0.9.10 */
(snip)
}
```

```c
static int
qemuDomainBlockRebase(virDomainPtr dom, const char *path, const char *base,
                      unsigned long bandwidth, unsigned int flags)
{
    virQEMUDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
    unsigned long long speed = bandwidth;
    virStorageSourcePtr dest = NULL;

    virCheckFlags(VIR_DOMAIN_BLOCK_REBASE_SHALLOW |
                  VIR_DOMAIN_BLOCK_REBASE_REUSE_EXT |
                  VIR_DOMAIN_BLOCK_REBASE_COPY |
                  VIR_DOMAIN_BLOCK_REBASE_COPY_RAW |
                  VIR_DOMAIN_BLOCK_REBASE_RELATIVE |
                  VIR_DOMAIN_BLOCK_REBASE_COPY_DEV |
                  VIR_DOMAIN_BLOCK_REBASE_BANDWIDTH_BYTES, -1);

    if (!(vm = qemuDomObjFromDomain(dom)))
        return -1;

    if (virDomainBlockRebaseEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    /* For normal rebase (enhanced blockpull), the common code handles
     * everything, including vm cleanup. */
    if (!(flags & VIR_DOMAIN_BLOCK_REBASE_COPY))
        return qemuDomainBlockPullCommon(driver, vm, path, base, bandwidth, flags);

    /* If we got here, we are doing a block copy rebase. */
    if (VIR_ALLOC(dest) < 0)
        goto cleanup;
    dest->type = (flags & VIR_DOMAIN_BLOCK_REBASE_COPY_DEV) ?
        VIR_STORAGE_TYPE_BLOCK : VIR_STORAGE_TYPE_FILE;
    if (VIR_STRDUP(dest->path, base) < 0)
        goto cleanup;
    if (flags & VIR_DOMAIN_BLOCK_REBASE_COPY_RAW)
        dest->format = VIR_STORAGE_FILE_RAW;

    /* Convert bandwidth MiB to bytes, if necessary */
    if (!(flags & VIR_DOMAIN_BLOCK_REBASE_BANDWIDTH_BYTES)) {
        if (speed > LLONG_MAX >> 20) {
            virReportError(VIR_ERR_OVERFLOW,
                           _("bandwidth must be less than %llu"),
                           LLONG_MAX >> 20);
            goto cleanup;
        }
        speed <<= 20;
    }

    /* XXX: If we are doing a shallow copy but not reusing an external
     * file, we should attempt to pre-create the destination with a
     * relative backing chain instead of qemu's default of absolute */
    if (flags & VIR_DOMAIN_BLOCK_REBASE_RELATIVE) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("Relative backing during copy not supported yet"));
        goto cleanup;
    }

    /* We rely on the fact that VIR_DOMAIN_BLOCK_REBASE_SHALLOW
     * and VIR_DOMAIN_BLOCK_REBASE_REUSE_EXT map to the same values
     * as for block copy. */
    flags &= (VIR_DOMAIN_BLOCK_REBASE_SHALLOW |
              VIR_DOMAIN_BLOCK_REBASE_REUSE_EXT);
    ret = qemuDomainBlockCopyCommon(vm, dom->conn, path, dest,
                                    speed, 0, 0, flags, true);
    dest = NULL;

 cleanup:
    virDomainObjEndAPI(&vm);
    virStorageSourceFree(dest);
    return ret;
}
```

```c
static int
qemuDomainBlockCopyCommon(virDomainObjPtr vm,
                          virConnectPtr conn,
                          const char *path,
                          virStorageSourcePtr mirror,
                          unsigned long long bandwidth,
                          unsigned int granularity,
                          unsigned long long buf_size,
                          unsigned int flags,
                          bool keepParentLabel)
{
    virQEMUDriverPtr driver = conn->privateData;
    qemuDomainObjPrivatePtr priv;
    char *device = NULL;
    virDomainDiskDefPtr disk = NULL;
    int ret = -1;
    struct stat st;
    bool need_unlink = false;
    virQEMUDriverConfigPtr cfg = NULL;
    const char *format = NULL;
    int desttype = virStorageSourceGetActualType(mirror);

    /* Preliminaries: find the disk we are editing, sanity checks */
    virCheckFlags(VIR_DOMAIN_BLOCK_COPY_SHALLOW |
                  VIR_DOMAIN_BLOCK_COPY_REUSE_EXT, -1);

    priv = vm->privateData;
    cfg = virQEMUDriverGetConfig(driver);

    if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("domain is not running"));
        goto endjob;
    }

    if (!(disk = qemuDomainDiskByName(vm->def, path)))
        goto endjob;

    if (!(device = qemuAliasFromDisk(disk)))
        goto endjob;

    if (qemuDomainDiskBlockJobIsActive(disk))
        goto endjob;

    if (disk->device == VIR_DOMAIN_DISK_DEVICE_LUN &&
        qemuDomainDefValidateDiskLunSource(mirror) < 0)
        goto endjob;

    if (!(virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DRIVE_MIRROR) &&
          virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_BLOCKJOB_ASYNC))) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("block copy is not supported with this QEMU binary"));
        goto endjob;
    }
    if (vm->persistent) {
        /* XXX if qemu ever lets us start a new domain with mirroring
         * already active, we can relax this; but for now, the risk of
         * 'managedsave' due to libvirt-guests means we can't risk
         * this on persistent domains.  */
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("domain is not transient"));
        goto endjob;
    }

    if (qemuDomainDetermineDiskChain(driver, vm, disk, false, true) < 0)
        goto endjob;

    /* clear the _SHALLOW flag if there is only one layer */
    if (!disk->src->backingStore)
        flags &= ~VIR_DOMAIN_BLOCK_COPY_SHALLOW;

    /* unless the user provides a pre-created file, shallow copy into a raw
     * file is not possible */
    if ((flags & VIR_DOMAIN_BLOCK_COPY_SHALLOW) &&
        !(flags & VIR_DOMAIN_BLOCK_COPY_REUSE_EXT) &&
        mirror->format == VIR_STORAGE_FILE_RAW) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("shallow copy of disk '%s' into a raw file "
                         "is not possible"),
                       disk->dst);
        goto endjob;
    }

    /* Prepare the destination file.  */
    /* XXX Allow non-file mirror destinations */
    if (!virStorageSourceIsLocalStorage(mirror)) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("non-file destination not supported yet"));
        goto endjob;
    }
    if (stat(mirror->path, &st) < 0) {
        if (errno != ENOENT) {
            virReportSystemError(errno, _("unable to stat for disk %s: %s"),
                                 disk->dst, mirror->path);
            goto endjob;
        } else if (flags & VIR_DOMAIN_BLOCK_COPY_REUSE_EXT ||
                   desttype == VIR_STORAGE_TYPE_BLOCK) {
            virReportSystemError(errno,
                                 _("missing destination file for disk %s: %s"),
                                 disk->dst, mirror->path);
            goto endjob;
        }
    } else if (!S_ISBLK(st.st_mode)) {
        if (st.st_size && !(flags & VIR_DOMAIN_BLOCK_COPY_REUSE_EXT)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("external destination file for disk %s already "
                             "exists and is not a block device: %s"),
                           disk->dst, mirror->path);
            goto endjob;
        }
        if (desttype == VIR_STORAGE_TYPE_BLOCK) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("blockdev flag requested for disk %s, but file "
                             "'%s' is not a block device"),
                           disk->dst, mirror->path);
            goto endjob;
        }
    }

    if (!mirror->format) {
        if (!(flags & VIR_DOMAIN_BLOCK_COPY_REUSE_EXT)) {
            mirror->format = disk->src->format;
        } else {
            /* If the user passed the REUSE_EXT flag, then either they
             * can also pass the RAW flag or use XML to tell us the format.
             * So if we get here, we assume it is safe for us to probe the
             * format from the file that we will be using.  */
            mirror->format = virStorageFileProbeFormat(mirror->path, cfg->user,
                                                       cfg->group);
        }
    }

    /* pre-create the image file */
    if (!(flags & VIR_DOMAIN_BLOCK_COPY_REUSE_EXT)) {
        int fd = qemuOpenFile(driver, vm, mirror->path,
                              O_WRONLY | O_TRUNC | O_CREAT,
                              &need_unlink, NULL);
        if (fd < 0)
            goto endjob;
        VIR_FORCE_CLOSE(fd);
    }

    if (mirror->format > 0)
        format = virStorageFileFormatTypeToString(mirror->format);

    if (virStorageSourceInitChainElement(mirror, disk->src,
                                         keepParentLabel) < 0)
        goto endjob;

    if (qemuDomainDiskChainElementPrepare(driver, vm, mirror, false) < 0) {
        qemuDomainDiskChainElementRevoke(driver, vm, mirror);
        goto endjob;
    }

    /* Actually start the mirroring */
    qemuDomainObjEnterMonitor(driver, vm);
    ret = qemuMonitorDriveMirror(priv->mon, device, mirror->path, format,
                                 bandwidth, granularity, buf_size, flags);
    virDomainAuditDisk(vm, NULL, mirror, "mirror", ret >= 0);
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;
    if (ret < 0) {
        qemuDomainDiskChainElementRevoke(driver, vm, mirror);
        goto endjob;
    }

    /* Update vm in place to match changes.  */
    need_unlink = false;
    disk->mirror = mirror;
    mirror = NULL;
    disk->mirrorJob = VIR_DOMAIN_BLOCK_JOB_TYPE_COPY;
    QEMU_DOMAIN_DISK_PRIVATE(disk)->blockjob = true;

    if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm, driver->caps) < 0)
        VIR_WARN("Unable to save status on vm %s after state change",
                 vm->def->name);

 endjob:
    if (need_unlink && unlink(mirror->path))
        VIR_WARN("unable to unlink just-created %s", mirror->path);
    virStorageSourceFree(mirror);
    qemuDomainObjEndJob(driver, vm);

 cleanup:
    VIR_FREE(device);
    virObjectUnref(cfg);
    return ret;
}
```

- src/qemu/qemu_monitor.c

```c
int
qemuMonitorDriveMirror(qemuMonitorPtr mon,
                       const char *device, const char *file,
                       const char *format, unsigned long long bandwidth,
                       unsigned int granularity, unsigned long long buf_size,
                       unsigned int flags)
{
    VIR_DEBUG("device=%s, file=%s, format=%s, bandwidth=%lld, "
              "granularity=%#x, buf_size=%lld, flags=%x",
              device, file, NULLSTR(format), bandwidth, granularity,
              buf_size, flags);

    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONDriveMirror(mon, device, file, format, bandwidth,
                                      granularity, buf_size, flags);
}
```

- src/qemu/qemu_monitor_json.c

```c
int
qemuMonitorJSONDriveMirror(qemuMonitorPtr mon,
                           const char *device, const char *file,
                           const char *format, unsigned long long speed,
                           unsigned int granularity,
                           unsigned long long buf_size,
                           unsigned int flags)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    bool shallow = (flags & VIR_DOMAIN_BLOCK_REBASE_SHALLOW) != 0;
    bool reuse = (flags & VIR_DOMAIN_BLOCK_REBASE_REUSE_EXT) != 0;

    cmd = qemuMonitorJSONMakeCommand("drive-mirror",
                                     "s:device", device,
                                     "s:target", file,
                                     "Y:speed", speed,
                                     "z:granularity", granularity,
                                     "P:buf-size", buf_size,
                                     "s:sync", shallow ? "top" : "full",
                                     "s:mode", reuse ? "existing" : "absolute-paths",
                                     "S:format", format,
                                     NULL);
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}
```
