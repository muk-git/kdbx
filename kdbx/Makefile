
# If buliding for xen dom0, uncomment below and see comment in kdbx_io.c
## KBUILD_CPPFLAGS +=-DCONFIG_KDBX_FOR_XEN_DOM0

# compile kvm guests with: KDBX_CONFIG_SWITCH_TO_TTY (CONFIG_SERIAL_8250=y)
## KBUILD_CPPFLAGS +=-DKDBX_CONFIG_SWITCH_TO_TTY

obj-y += kdbxmain.o kdbx_cmds.o kdbx_wp.o kdbx_guest.o kdbx_mem_rw.o kdbx_io.o
obj-y += kdbx_fixup.o
obj-y += udis86-1.7/

clean:
	(cd udis86-1.7 && make clean)
	rm -f modules.order .*.o.cmd *.o .*.o.d modules.builtin built-in.mod.c 
	rm -f built-in.a modules_thick.builtin .built-in.a.cmd
