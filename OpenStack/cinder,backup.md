# EMC ScaleIOのCinder backendを使っている場合に、cinder backup-createするとエラーになる件の調査

- バージョン
  - RHEL OSP7 (Kilo)
  - RHEL7

## 調査動機
EMC ScaleIOのCinder backendを使っている場合に、cinder backup-createするとエラーになる

- /var/log/cinder/backup.log

```
2016-05-18 10:49:49.842 79745 INFO cinder.backup.manager [req-cb1df107-413b-4637-9e0c-a233e3c8c191 dbd7e197f81649d29592af26b7c818e7 c993dbf34a8148cbb62a9dabb2a5b58b - - -] Create backup started, backup: 4102fbdc-ee40-4f6c-8d4b-bf6d8b72e079 volume: 319b8ba8-f5f8-4395-9392-78e8e64edddd.
2016-05-18 10:49:49.848 79745 INFO cinder.backup.manager [req-cb1df107-413b-4637-9e0c-a233e3c8c191 dbd7e197f81649d29592af26b7c818e7 c993dbf34a8148cbb62a9dabb2a5b58b - - -] Backend not found in hostname (None) so using default.
2016-05-18 10:49:49.850 79745 WARNING cinder.backup.manager [req-cb1df107-413b-4637-9e0c-a233e3c8c191 dbd7e197f81649d29592af26b7c818e7 c993dbf34a8148cbb62a9dabb2a5b58b - - -] ### BackupManager.create_backup: backend=ScaleIO, _get_driver(backend)=<cinder.volume.drivers.emc.scaleio.ScaleIODriver object at 0x4700a10>, context=<cinder.context.RequestContext object at 0x4aa4f90>, backup=<cinder.db.sqlalchemy.models.Backup object at 0x4abfc50>, backup_service=<cinder.backup.drivers.swift.SwiftBackupDriver object at 0x4ab8a90>
2016-05-18 10:49:50.126 79745 WARNING cinder.volume.driver [req-cb1df107-413b-4637-9e0c-a233e3c8c191 dbd7e197f81649d29592af26b7c818e7 c993dbf34a8148cbb62a9dabb2a5b58b - - -] ### BaseVD.backup_volume: self=<cinder.volume.drivers.emc.scaleio.ScaleIODriver object at 0x4700a10>, context=<cinder.context.RequestContext object at 0x4aa4f90>, volume=<cinder.db.sqlalchemy.models.Volume object at 0x4b89f90>, properties={'initiator': 'iqn.1994-05.com.redhat:5b99a6e59ffa', 'ip': '203.104.224.69', 'platform': 'x86_64', 'host': 'controller0.serius.mirp', 'os_type': 'linux2', 'multipath': False}, backup_service=<cinder.backup.drivers.swift.SwiftBackupDriver object at 0x4ab8a90>
2016-05-18 10:49:50.126 79745 WARNING cinder.backup.manager [req-cb1df107-413b-4637-9e0c-a233e3c8c191 dbd7e197f81649d29592af26b7c818e7 c993dbf34a8148cbb62a9dabb2a5b58b - - -] ### create_backup: [exception] err=_attach_volume() takes exactly 3 arguments (4 given)
2016-05-18 10:49:50.176 79745 ERROR oslo_messaging.rpc.dispatcher [req-cb1df107-413b-4637-9e0c-a233e3c8c191 dbd7e197f81649d29592af26b7c818e7 c993dbf34a8148cbb62a9dabb2a5b58b - - -] Exception during message handling: _attach_volume() takes exactly 3 arguments (4 given)
2016-05-18 10:49:50.176 79745 TRACE oslo_messaging.rpc.dispatcher Traceback (most recent call last):
2016-05-18 10:49:50.176 79745 TRACE oslo_messaging.rpc.dispatcher   File "/usr/lib/python2.7/site-packages/oslo_messaging/rpc/dispatcher.py", line 142, in _dispatch_and_reply
2016-05-18 10:49:50.176 79745 TRACE oslo_messaging.rpc.dispatcher     executor_callback))
2016-05-18 10:49:50.176 79745 TRACE oslo_messaging.rpc.dispatcher   File "/usr/lib/python2.7/site-packages/oslo_messaging/rpc/dispatcher.py", line 186, in _dispatch
2016-05-18 10:49:50.176 79745 TRACE oslo_messaging.rpc.dispatcher     executor_callback)
2016-05-18 10:49:50.176 79745 TRACE oslo_messaging.rpc.dispatcher   File "/usr/lib/python2.7/site-packages/oslo_messaging/rpc/dispatcher.py", line 130, in _do_dispatch
2016-05-18 10:49:50.176 79745 TRACE oslo_messaging.rpc.dispatcher     result = func(ctxt, **new_args)
2016-05-18 10:49:50.176 79745 TRACE oslo_messaging.rpc.dispatcher   File "/usr/lib/python2.7/site-packages/osprofiler/profiler.py", line 105, in wrapper
2016-05-18 10:49:50.176 79745 TRACE oslo_messaging.rpc.dispatcher     return f(*args, **kwargs)
2016-05-18 10:49:50.176 79745 TRACE oslo_messaging.rpc.dispatcher   File "/usr/lib/python2.7/site-packages/cinder/backup/manager.py", line 303, in create_backup
2016-05-18 10:49:50.176 79745 TRACE oslo_messaging.rpc.dispatcher     'fail_reason': six.text_type(err)})
2016-05-18 10:49:50.176 79745 TRACE oslo_messaging.rpc.dispatcher   File "/usr/lib/python2.7/site-packages/oslo_utils/excutils.py", line 85, in __exit__
2016-05-18 10:49:50.176 79745 TRACE oslo_messaging.rpc.dispatcher     six.reraise(self.type_, self.value, self.tb)
2016-05-18 10:49:50.176 79745 TRACE oslo_messaging.rpc.dispatcher   File "/usr/lib/python2.7/site-packages/cinder/backup/manager.py", line 295, in create_backup
2016-05-18 10:49:50.176 79745 TRACE oslo_messaging.rpc.dispatcher     backup_service)
2016-05-18 10:49:50.176 79745 TRACE oslo_messaging.rpc.dispatcher   File "/usr/lib/python2.7/site-packages/osprofiler/profiler.py", line 105, in wrapper
2016-05-18 10:49:50.176 79745 TRACE oslo_messaging.rpc.dispatcher     return f(*args, **kwargs)
2016-05-18 10:49:50.176 79745 TRACE oslo_messaging.rpc.dispatcher   File "/usr/lib/python2.7/site-packages/cinder/volume/driver.py", line 745, in backup_volume
2016-05-18 10:49:50.176 79745 TRACE oslo_messaging.rpc.dispatcher     attach_info, volume = self._attach_volume(context, volume, properties)
2016-05-18 10:49:50.176 79745 TRACE oslo_messaging.rpc.dispatcher TypeError: _attach_volume() takes exactly 3 arguments (4 given)
2016-05-18 10:49:50.176 79745 TRACE oslo_messaging.rpc.dispatcher
```

(注) '###' の行は手で入れたデバッグプリント

BaseVD.backup_volume() の self が cinder.volume.drivers.emc.scaleio.ScaleIODriver なのがポイント。

```
2016-05-18 10:49:50.126 79745 WARNING cinder.volume.driver [req-cb1df107-413b-4637-9e0c-a233e3c8c191 dbd7e197f81649d29592af26b7c818e7 c993dbf34a8148cbb62a9dabb2a5b58b - - -] ### BaseVD.backup_volume: self=<cinder.volume.drivers.emc.scaleio.ScaleIODriver object at 0x4700a10>, context=<cinder.context.RequestContext object at 0x4aa4f90>, volume=<cinder.db.sqlalchemy.models.Volume object at 0x4b89f90>, properties={'initiator': 'iqn.1994-05.com.redhat:5b99a6e59ffa', 'ip': '203.104.224.69', 'platform': 'x86_64', 'host': 'controller0.serius.mirp', 'os_type': 'linux2', 'multipath': False}, backup_service=<cinder.backup.drivers.swift.SwiftBackupDriver object at 0x4ab8a90>
```

## cinder backup-createを実行すると、BackupManager.create_backup() が呼ばれる

その中でバックエンドドライバーの backup_volume() を呼び出す

- BackupManager.create_backup() @backup/manager.py

```
            self._get_driver(backend).backup_volume(context, backup,
                                                    backup_service)
```

## class ScaleIODriver @volume/drivers/emc/scaleio.py には backup_volume() が定義されていないので、親クラスの (さらに親クラスの) 同メソッドが呼ばれる

- BaseVD.backup_volume() @volume/driver.py

```
        attach_info, volume = self._attach_volume(context, volume, properties)
```

## ここで呼んでいる self._attach_volume() は同クラス内のメソッドを想定している

- BaseVD.backup_volume() @volume/driver.py

```
class BaseVD(object):
    (snip)
    def _attach_volume(self, context, volume, properties, remote=False):
        """Attach the volume."""
        if remote:
        (snip)
```

が、ScaleIODriver クラスで同名の _attach_volume() が定義されているため、こちらが呼ばれる

- ScaleIODriver._attach_volume @volume/drivers/emc/scaleio.py

```
class ScaleIODriver(driver.VolumeDriver):
    (snip)
    def _attach_volume(self, volume, sdc_ip):
        # We need to make sure we even *have* a local path
        LOG.info("ScaleIO attach volume in scaleio cinder driver")
        volname = self.id_to_base64(volume.id)
        (snip)
```

## BaseVD と ScaleIODriver で _attach_volume() の引き数の数が異なるために TypeError の例外が発生する

```
2016-05-18 10:21:14.187 12347 ERROR oslo_messaging.rpc.dispatcher [req-31edebe3-5444-4880-97cf-1b8b5c8244b6 dbd7e197f81649d29592af26b7c818e7 c993dbf34a8148cbb62a9dabb2a5b58b - - -] Exception during message handling: _attach_volume() takes exactly 3 arguments (4 given)
2016-05-18 10:21:14.187 12347 TRACE oslo_messaging.rpc.dispatcher Traceback (most recent call last):
2016-05-18 10:21:14.187 12347 TRACE oslo_messaging.rpc.dispatcher   File "/usr/lib/python2.7/site-packages/oslo_messaging/rpc/dispatcher.py", line 142, in _dispatch_and_reply
2016-05-18 10:21:14.187 12347 TRACE oslo_messaging.rpc.dispatcher     executor_callback))
2016-05-18 10:21:14.187 12347 TRACE oslo_messaging.rpc.dispatcher   File "/usr/lib/python2.7/site-packages/oslo_messaging/rpc/dispatcher.py", line 186, in _dispatch
2016-05-18 10:21:14.187 12347 TRACE oslo_messaging.rpc.dispatcher     executor_callback)
2016-05-18 10:21:14.187 12347 TRACE oslo_messaging.rpc.dispatcher   File "/usr/lib/python2.7/site-packages/oslo_messaging/rpc/dispatcher.py", line 130, in _do_dispatch
2016-05-18 10:21:14.187 12347 TRACE oslo_messaging.rpc.dispatcher     result = func(ctxt, **new_args)
2016-05-18 10:21:14.187 12347 TRACE oslo_messaging.rpc.dispatcher   File "/usr/lib/python2.7/site-packages/osprofiler/profiler.py", line 105, in wrapper
2016-05-18 10:21:14.187 12347 TRACE oslo_messaging.rpc.dispatcher     return f(*args, **kwargs)
2016-05-18 10:21:14.187 12347 TRACE oslo_messaging.rpc.dispatcher   File "/usr/lib/python2.7/site-packages/cinder/backup/manager.py", line 303, in create_backup
2016-05-18 10:21:14.187 12347 TRACE oslo_messaging.rpc.dispatcher     'fail_reason': six.text_type(err)})
2016-05-18 10:21:14.187 12347 TRACE oslo_messaging.rpc.dispatcher   File "/usr/lib/python2.7/site-packages/oslo_utils/excutils.py", line 85, in __exit__
2016-05-18 10:21:14.187 12347 TRACE oslo_messaging.rpc.dispatcher     six.reraise(self.type_, self.value, self.tb)
2016-05-18 10:21:14.187 12347 TRACE oslo_messaging.rpc.dispatcher   File "/usr/lib/python2.7/site-packages/cinder/backup/manager.py", line 295, in create_backup
2016-05-18 10:21:14.187 12347 TRACE oslo_messaging.rpc.dispatcher     backup_service)
2016-05-18 10:21:14.187 12347 TRACE oslo_messaging.rpc.dispatcher   File "/usr/lib/python2.7/site-packages/osprofiler/profiler.py", line 105, in wrapper
2016-05-18 10:21:14.187 12347 TRACE oslo_messaging.rpc.dispatcher     return f(*args, **kwargs)
2016-05-18 10:21:14.187 12347 TRACE oslo_messaging.rpc.dispatcher   File "/usr/lib/python2.7/site-packages/cinder/volume/driver.py", line 745, in backup_volume
2016-05-18 10:21:14.187 12347 TRACE oslo_messaging.rpc.dispatcher     attach_info, volume = self._attach_volume(context, volume, properties)
2016-05-18 10:21:14.187 12347 TRACE oslo_messaging.rpc.dispatcher TypeError: _attach_volume() takes exactly 3 arguments (4 given)
```
