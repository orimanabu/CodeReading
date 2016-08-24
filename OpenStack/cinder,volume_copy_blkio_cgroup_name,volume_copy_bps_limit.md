# Cinderのパラメータvolume_copy_blkio_cgroup_name, volume_copy_bps_limitの調査

- バージョン

  * RHOSP7 (Kilo)
  * RHEL7

## 動機

パラメータvolume_copy_blkio_cgroup_name, volume_copy_bps_limitを設定すると、cinder-volumeからのボリューム操作でcgroupsによる帯域制御ができそう。どの操作で効くか、EMC VNXバックエンドの場合はどうか、の観点で調査。

# パラメータの定義・初期化

## ひとことまとめ

class BlkioCGroupのインスタンスにパラメータvolume_copy_blkio_cgroup_name, volume_copy_bps_limitを格納し、Throttle.set_default()に渡す。
これを後でThrottle.get_default()で取り出して使う。

## 詳細

### パラメータ定義

volume_opts @cinder/volume/driver.py

```
volume_opts = [
(snip)
    cfg.StrOpt('volume_copy_blkio_cgroup_name',
               default='cinder-volume-copy',
               help='The blkio cgroup name to be used to limit bandwidth '
                    'of volume copy'),
    cfg.IntOpt('volume_copy_bps_limit',
               default=0,
               help='The upper limit of bandwidth of volume copy. '
                    '0 => unlimited'),
(snip)
]
```

このパラメータは、BaseVD.set_throttle() @cinder/volume/driver.py の中で使われている。

### パラメータの格納

BaseVD.set_throttle()内では、class BlkioCgroup @volume/throttling.py のインスタンスをパラメータvolume_copy_blkio_cgroup_name、volume_copy_bps_limitの値を使って初期化している。

- BaseVD.set_throttle() @cinder/volume/driver.py

```
    def set_throttle(self):
        bps_limit = ((self.configuration and
                      self.configuration.safe_get('volume_copy_bps_limit')) or
                     CONF.volume_copy_bps_limit)
        cgroup_name = ((self.configuration and
                        self.configuration.safe_get(
                            'volume_copy_blkio_cgroup_name')) or
                       CONF.volume_copy_blkio_cgroup_name)
        self._throttle = None
        if bps_limit:
            try:
                self._throttle = throttling.BlkioCgroup(int(bps_limit),
                                                        cgroup_name)
            except processutils.ProcessExecutionError as err:
                LOG.warning(_LW('Failed to activate volume copy throttling: '
                                '%(err)s'), {'err': six.text_type(err)})
        throttling.Throttle.set_default(self._throttle)
```

BaseVD.set_throttle()は VolumeManager.init_host() @cinder/volume/manager.py で呼び出される。
VolumeManager.init_host()は

- Service.start() @cinder/service.py
- WSGIService.start() @cinder/service.py

から呼ばれる。前者はcinder-volume、後者はcinder-apiの起動時に呼ばれる。

## 余談: cinder-volumeの起動

main() @cinder/cmd/volume.py から始まる。

backendごとに Service.create() @cinder/service.py を呼んで、プロセスを生成する。

```
def main():
    objects.register_all()
    CONF(sys.argv[1:], project='cinder',
         version=version.version_string())
    logging.setup(CONF, "cinder")
    python_logging.captureWarnings(True)
    utils.monkey_patch()
    launcher = service.get_launcher()
    if CONF.enabled_backends:
        for backend in CONF.enabled_backends:
            CONF.register_opt(host_opt, group=backend)
            backend_host = getattr(CONF, backend).backend_host
            host = "%s@%s" % (backend_host or CONF.host, backend)
            server = service.Service.create(host=host,
                                            service_name=backend,
                                            binary='cinder-volume')
            # Dispose of the whole DB connection pool here before
            # starting another process.  Otherwise we run into cases where
            # child processes share DB connections which results in errors.
            session.dispose_engine()
            launcher.launch_service(server)
    else:
        server = service.Service.create(binary='cinder-volume')
        launcher.launch_service(server)
    launcher.wait()
```

その後、下記順に処理が進み、子プロセスを起動する。

- Launcher.launch_service() @cinder/service.py
- ProcessLauncher.launch_service() @cinder/openstack/common/service.py


# BlkioCgroups

- クラス: class BlkioCgroup @volume/throttling.py

  * class Throttle @volume/throttling.py の派生クラス

- コンストラクタで "cgcreate" を実行

```
    def __init__(self, bps_limit, cgroup_name):
(snip)
        try:
            utils.execute('cgcreate', '-g', 'blkio:%s' % self.cgroup,
                          run_as_root=True)
(snip)
```

- メソッドsubcommand()を呼び出すと、 "cgset" してから "cgexec" を経由で指定したコマンドを実行する。



# パラメータの取り出し

Throttle.get_default() @cinder/volume/throttling.py で値を参照している。
これが呼ばれる部分を見ていく。

```
class Throttle(object):
    def set_default(throttle):
        Throttle.DEFAULT = throttle

    def get_default():
        return Throttle.DEFAULT or Throttle()
```

# パラメータが実際に使われている箇所

Throttle.get_default() @cinder/volume/throttling.pyを呼び出しているところは2箇所ある。

- convert_image() @cinder/image/image_utils.py
- copy_volume() @cinder/volume/utils.py

## convert_image()でThrottleがどう使われているか

convert_image() @cinder/image/image_utils.py

```
def convert_image(source, dest, out_format, run_as_root=True, throttle=None):
    if not throttle:
        throttle = throttling.Throttle.get_default()
    with throttle.subcommand(source, dest) as throttle_cmd:
        _convert_image(tuple(throttle_cmd['prefix']),
                       source, dest,
                       out_format, run_as_root=run_as_root)
```

_convert_image() @cinder/image/image_utils.py の中で qemu-img コマンドを呼び出している。

```
def _convert_image(prefix, source, dest, out_format, run_as_root=True):
(snip)
    cmd = prefix + ('qemu-img', 'convert',
                    '-O', out_format, source, dest)
(snip)
    utils.execute(*cmd, run_as_root=run_as_root)
```

## convert_image()のコールパス

convert_image() @cinder/image/image_utils.py は2箇所から呼ばれている。

- fetch_to_volume_format() @cinder/image/image_utils.py
- upload_volume() @cinder/image/image_utils.py

### fetch_to_volume_format()経由の場合

fetch_to_volume_format() @cinder/image/image_utils.py は2箇所から呼ばれている。

- fetch_to_vhd() @cinder/image/image_utils.py
- fetch_to_raw() @cinder/image/image_utils.py

前者はWindowsドライバでのみ使用されるルーチンなので、後者に注目する。
fetch_to_raw() @cinder/image/image_utils.py は下記の順で呼び出される。

- CreateVolumeFromSpecTask.execute() @cinder/volume/flows/manager/create_volume.py
- CreateVolumeFromSpecTask._create_from_image() @cinder/volume/flows/manager/create_volume.py
- CreateVolumeFromSpecTask._copy_image_to_volume() @cinder/volume/flows/manager/create_volume.py
- BaseVD.copy_image_to_volume() @cinder/volume/driver.py
- fetch_to_raw() @cinder/image/image_utils.py

Cinderでは、各API処理の内容はtaskflowという仕組みでサブタスクに分割して抽象化されている。
CreateVolumeFromSpecTaskはそのサブタスクのひとつで、cinder createした際に呼び出される。

cinder createのAPI処理は、get_flow() @cinder/volume/flows/manager/create_volume.py の中でtaskflowのタスクで表現されている。

```
    volume_flow.add(ExtractVolumeSpecTask(db),
                    NotifyVolumeActionTask(db, "create.start"),
                    CreateVolumeFromSpecTask(db, driver),
                    CreateVolumeOnFinishTask(db, "create.end"))
```

### upload_volume()経由の場合

upload_volume() @cinder/image/image_utils.py は下記の順で呼び出される。

- VolumeActionsController._volume_upload_image() @cinder/api/contrib/volume_actions.py
- BaseVD.copy_volume_to_image() @cinder/volume/driver.py
- upload_volume() @cinder/image/image_utils.py

VolumeActionsController._volume_upload_image (Volume Action: "os-volume_upload_image") はCinderボリュームからGlanceイメージを作るときに呼ばれる。

- http://old-wiki.openstack.org/CreateVolumeFromImage
- http://docs.openstack.org/developer/cinder/api/cinder.api.contrib.volume_actions.html


## copy_volume()でThrottleがどう使われているか

```
def copy_volume(srcstr, deststr, size_in_m, blocksize, sync=False,
                execute=utils.execute, ionice=None, throttle=None,
                sparse=False):
    if not throttle:
        throttle = throttling.Throttle.get_default()
    with throttle.subcommand(srcstr, deststr) as throttle_cmd:
        _copy_volume(throttle_cmd['prefix'], srcstr, deststr,
                     size_in_m, blocksize, sync=sync,
                     execute=execute, ionice=ionice, sparse=sparse)
```

_copy_volume() @cinder/volume/utils.py の中で dd コマンドを呼び出している

```
def _copy_volume(prefix, srcstr, deststr, size_in_m, blocksize, sync=False,
                 execute=utils.execute, ionice=None, sparse=False):
(snip)
    cmd = ['dd', 'if=%s' % srcstr, 'of=%s' % deststr,
           'count=%d' % count, 'bs=%s' % blocksize]
(snip)
    cmd = prefix + cmd
(snip)
    execute(*cmd, run_as_root=True)
```

## copy_volume()のコールパス

- fetch_to_volume_format() @cinder/image/image_utils.py

convert_volume()と同様のパス。
convert_volume()中で、qemu-imgがない場合にddでそのままコピーするパスで呼ばれる。

- BaseVD.copy_volume_data() @cinder/volume/driver.py

VolumeAdminController._migrate_volume() @cinder/api/contrib/admin_actions.py
VolumeManager.migrate_volume() @cinder/volume/manager.py
VolumeManager._migrate_volume_generic() @cinder/volume/manager.py

Volume Action: "os-migrate_volume"

- clear_volume() volume/utils.py

/dev/zeroで埋めるときに呼ばれる。2つのドライバで使用。

  - BlockDeviceDriver.delete_volume() @cinder/volume/drivers/block_device.py
  - LVMVolumeDriver.delete_volume() @cinder/volume/drivers/lvm.py


# EMC VNX

## ドライバで使われるファイル

- cinder/volume/drivers/emc/emc_cli_fc.py
- cinder/volume/drivers/emc/emc_vnx_cli.py

## ドライバの設定

```
volume_driver=cinder.volume.drivers.emc.emc_cli_fc.EMCCLIFCDriver
```

ドライバのクラス: class EMCCLIFCDriver @cinder/volume/drivers/emc/emc_cli_fc.py

コンストラクタの中でVNX CLIを呼び出す準備をしている。

```
    def __init__(self, *args, **kwargs):
        super(EMCCLIFCDriver, self).__init__(*args, **kwargs)
        self.cli = emc_vnx_cli.getEMCVnxCli(
            'FC',
            configuration=self.configuration)
        self.VERSION = self.cli.VERSION
```

プール指定の有無によって、EMCVnxCliArrayもしくはEMCVnxCliPoolが使われる。

```
def getEMCVnxCli(prtcl, configuration=None):
    configuration.append_config_values(loc_opts)
    pool_name = configuration.safe_get("storage_vnx_pool_name")

    if pool_name is None or len(pool_name.strip()) == 0:
        return EMCVnxCliArray(prtcl, configuration=configuration)
    else:
        return EMCVnxCliPool(prtcl, configuration=configuration)
```

- class EMCVnxCliArray @cinder/volume/drivers/emc/emc_vnx_cli.py
- class EMCVnxCliAPool @cinder/volume/drivers/emc/emc_vnx_cli.py

どちらのクラスも class EMCVnxCliBase @cinder/volume/drivers/emc/emc_vnx_cli.py の派生クラス。

## ドライバの親クラス

継承関係の確認

- class EMCCLIFCDriver @cinder/volume/drivers/emc/emc_cli_fc.py

```
class EMCCLIFCDriver(driver.FibreChannelDriver):
```

- class FibreChannelDriver @cinder/volume/driver.py

```
class FibreChannelDriver(VolumeDriver):
```

- class VolumeDriver @cinder/volume/driver.py

```
class VolumeDriver(ConsistencyGroupVD, TransferVD, ManageableVD, ExtendVD,
                   CloneableVD, CloneableImageVD, SnapshotVD, ReplicaVD,
                   RetypeVD, LocalVD, MigrateVD, BaseVD):
```

最終的に、BaseVDにたどり着く。




class EMCVnxCliBase(object):
class EMCVnxCliPool(EMCVnxCliBase):
class EMCVnxCliArray(EMCVnxCliBase):
