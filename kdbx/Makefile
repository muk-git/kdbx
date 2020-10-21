
# KBUILD_CPPFLAGS +=-DKDBX_CONFIG_SWITCH_TO_TTY

obj-y += kdbxmain.o kdbx_cmds.o kdbx_io.o kdbx_wp.o kdbx_guest.o kdbx_mem_rw.o
obj-y += udis86-1.7/

clean:
	(cd udis86-1.7 && make clean)
	rm -f *.o modules.builtin built-in.mod.c 
