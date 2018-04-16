# OVS

```sh
ovs-vsctl list open_vswitch
```

```sh
ovs-vsctl list-br | while read bridge; do
echo "=> ${bridge}"
echo "==> ovs-ofctl show"
ovs-ofctl show ${bridge}
echo "==> ovs-ofctl dump-ports-desc"
ovs-ofctl dump-ports-desc ${bridge}
echo "==> ovs-ofctl dump-ports"
ovs-ofctl dump-ports ${bridge}
done
```

```sh
ovs-vsctl --columns=statistics list interface vhua831831d-46 | grep -o 'tx_dropped=[0-9]*'&& sleep 10 &&  ovs-vsctl --columns=statistics list interface vhua831831d-46 | grep -o 'tx_dropped=[0-9]*'
```

# perf

## basic

Capture perf: 
```sh
perf record -g -C <pmd_cpu1>,<pmd_cpu2>,.. sleep 60
```

for each pmd\_cpu:
```sh
perf report -g --no-children -C <pmd_cpu> --stdio
```

and the stats:
```sh
// clear the stats after the reproducer is stable
ovs-appctl dpif-netdev/pmd-stats-clear
```

```sh
// wait one minute
sleep 60
```

```sh
// capture the PMD stats
ovs-appctl dpif-netdev/pmd-stats-show
```

## Obtain the number of context switches on Core#17

```sh
perf record -e sched:sched_switch -C 17  sleep 10; perf report --stdio
```

# tuna

```sh
tuna -t ovs-vswitchd -CP
```

```sh
tuna -t qemu-kvm -CP
```

```sh
tuna -P | grep -E -v migration\|kworker\|ksoftirqd  | grep "0xffff"
```

# Move processes other than PMD to non-PMD cores

```sh
NON_PMD_CPU_RANGE="13,15"
OVS_PID="$(pidof ovs-vswitchd)"
for pid in $(ps -e -T  | grep ${OVS_PID} | grep -v 'pmd' | awk '{ print $2 }')
do
    taskset -p -c ${NON_PMD_CPU_RANGE} ${pid}
done
```

# List PMD thread with ps

```sh
ps -eLo tid,pid,ppid,psr,pcpu,cputime,size,etime,cmd,comm
```

PSR:       processor that process is currently assigned to.

# virsh

```sh
virsh vcpupin <DOMAIN>
virsh emulatorpin <DOMAIN>
```

# grub related

```sh
isol_cpus=$(awk '{ for (i = 1; i <= NF; i++) if ($i ~ /nohz_full/) print $i };' /proc/cmdline | cut -d"=" -f2)
if [ ! -z "$isol_cpus" ]; then
  grubby --update-kernel=grubby --default-kernel --args=isolcpus=$isol_cpus
fi
```
