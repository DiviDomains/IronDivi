#!/bin/bash
# D5 release gate in a throwaway Ubuntu 22.04 VM on a libvirt host (default hp1):
# run.sh SIGSEGVs a control process and irondivid under systemd-coredump (A) and
# a plain "core" pattern (B). Cores must appear for the control and never for
# irondivid. systemd-coredump ignores RLIMIT_CORE, so A tests PR_SET_DUMPABLE.
#   IRONDIVID=<path on BUILD_HOST> scripts/tests/core-dump-vm/vm.sh
set -e
HOST=${VM_HOST:-hp1}; BUILD_HOST=${BUILD_HOST:-hp3}
B=${IRONDIVID:-remote-cargo/target/irondivi-diag/debug/irondivid}
D=/var/tmp/d5vm; HERE=$(cd "$(dirname "$0")" && pwd)
IMG=https://cloud-images.ubuntu.com/releases/22.04/release/ubuntu-22.04-server-cloudimg-amd64.img
ssh $HOST "mkdir -p $D/iso && cd $D && { [ -f jammy.img ] || curl -sfLo jammy.img $IMG; }"
scp -q "$HERE/run.sh" $HOST:$D/iso/run.sh; scp -q "$HERE/user-data" $HOST:$D/user-data
ssh $BUILD_HOST "cat $B" | ssh $HOST "cat > $D/iso/irondivid && chmod +x $D/iso/irondivid"
ssh $HOST 'bash -s' <<EOF
cd $D
virsh -c qemu:///system undefine d5vm >/dev/null 2>&1 || true
sudo -n rm -f console.log disk.qcow2 t.iso
xorriso -as mkisofs -quiet -R -J -o t.iso iso/
qemu-img create -q -f qcow2 -F qcow2 -b $D/jammy.img disk.qcow2 10G
chmod a+r t.iso disk.qcow2 user-data
virt-install -q --connect qemu:///system --name d5vm --memory 2048 --vcpus 2 --osinfo ubuntu22.04 \
  --import --disk $D/disk.qcow2,bus=virtio --disk $D/t.iso,device=cdrom \
  --cloud-init user-data=$D/user-data --network network=default --graphics none \
  --serial file,path=$D/console.log --noautoconsole --noreboot
for i in \$(seq 150); do virsh -c qemu:///system list --name | grep -q d5vm || break; sleep 6; done
sudo -n cat console.log | tr -d '\r' | grep -E 'core_pattern|Max core|exit=|D5-|D5VM-DONE'
virsh -c qemu:///system undefine d5vm >/dev/null; sudo -n rm -f console.log disk.qcow2 t.iso
EOF
