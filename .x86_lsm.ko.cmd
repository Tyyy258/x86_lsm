cmd_/home/ubuntu/op-tee/yzc/modules/x86_lsm/x86_lsm.ko := ld -r -m elf_x86_64  -z max-page-size=0x200000 -z noexecstack   --build-id  -T ./scripts/module-common.lds -o /home/ubuntu/op-tee/yzc/modules/x86_lsm/x86_lsm.ko /home/ubuntu/op-tee/yzc/modules/x86_lsm/x86_lsm.o /home/ubuntu/op-tee/yzc/modules/x86_lsm/x86_lsm.mod.o;  true