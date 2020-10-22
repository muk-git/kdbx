
# compile guest with : KDBX_CONFIG_SWITCH_TO_TTY
# if not found, it will return null, otherwise returns "vmio-guest"
# thus if found, returned value will not be null
ifneq (,$(findstring vmio-guest, $(CURDIR)))
KBUILD_CPPFLAGS +=-DKDBX_CONFIG_SWITCH_TO_TTY
endif

KBUILD_CPPFLAGS +=-DCONFIG_VMIO

obj-y += kdbxmain.o kdbx_cmds.o kdbx_wp.o kdbx_guest.o kdbx_mem_rw.o kdbx_io.o
obj-y += kdbx_fixup.o
obj-y += udis86-1.7/

clean:
	(cd udis86-1.7 && make clean)
	rm -f modules.order .*.o.cmd *.o .*.o.d modules.builtin built-in.mod.c 
