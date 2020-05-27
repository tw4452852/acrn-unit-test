#!/usr/bin/env bash

# set -x

[ "$1" = '--help' ] && exit 1;

killall qemu-system-x86_64

./grub_iso acrn-unit_test.iso ~/work/fusa/acrn-sliced-mainline/hypervisor/build/acrn.32.out $@

qemu-system-x86_64 -machine q35,kernel_irqchip=split,accel=kvm -cpu max,level=22,invtsc -m 4G -smp cpus=8,cores=4,threads=2 -enable-kvm -device isa-debug-exit -device intel-iommu,intremap=on,aw-bits=48,caching-mode=on,device-iotlb=on -debugcon file:/dev/stdout -serial mon:stdio -display none  -boot d -cdrom ./acrn-unit_test.iso || true


