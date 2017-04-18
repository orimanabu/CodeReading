# mirror\_run()を追う

drive\_mirror QMPから呼ばれるコルーチンmirror\_run()の中身。

## 概要

最終的に、dirty bitmapを見ながらループする。おおまかなループの流れはこんな感じ。

- mirror\_run()
- mirror\_iteration()
- mirror\_do\_read()
- bdrv\_aio\_read() @block/io.c
  - bdrv\_co\_aio\_rw\_vector @io.c
- mirror\_read\_complete()
- bdrv\_aio\_writev() @block/io.c
  - bdrv\_co\_aio\_rw\_vector @io.c
- mirror\_write\_complete()
- mirror\_iteration\_done()
- qemu\_coroutine\_enter()

