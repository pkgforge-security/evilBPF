ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm/')

# Use pkg-config instead of hardcoded path
LIBBPF_CFLAGS ?= $(shell pkg-config --cflags libbpf)
LIBBPF_LDFLAGS ?= $(shell pkg-config --static --libs libbpf)
LIBELF_LDFLAGS ?= $(shell pkg-config --static --libs libelf)

COMMON_INCLUDES = -I.
RELEASE_DIR = $(ROOTDIR)/../dst

# Default target
all: $(APPS)

release_dest: $(APPS)
	mkdir -p $(RELEASE_DIR)
	cp $(APPS) $(RELEASE_DIR)

release: release_dest
	$(MAKE) clean

%.o: %.c
	$(call msg,CC,$@)
	clang -O2 $(CFLAGS) $(LIBBPF_CFLAGS) -c $< -o $@ $(INCLUDES) $(COMMON_INCLUDES)

# Build application binary
$(APPS): %: | $(APPS).skel.h $(OBJ)
	$(call msg,BINARY,$@)
	clang -O2 $@.c $(CFLAGS) $(OBJ) $(LIBBPF_CFLAGS) $(LIBBPF_LDFLAGS) $(LIBELF_LDFLAGS) -o $@ -static
	strip $@

# eBPF skeleton
$(APPS).skel.h: $(APPS).bpf.o
	$(call msg,GEN-SKEL,$@)
	bpftool gen skeleton $< > $@

$(APPS).bpf.o: $(EBPF).bpf.o
	$(call msg,BPF,$@)
	bpftool gen object $@ $<

# Build each eBPF object file
$(EBPF).bpf.o: $(EBPF).bpf.c vmlinux.h
	$(call msg,BPF,$@)
	clang -O2 -target bpf -D__KERNEL__ -D__TARGET_ARCH_$(ARCH) \
		$(CFLAGS) $(LIBBPF_CFLAGS) $(INCLUDES) $(COMMON_INCLUDES) $(CLANG_BPF_SYS_INCLUDES) \
		-c $(filter %.c,$^) -o $@
	llvm-strip -g --strip-unneeded $@

vmlinux.h:
	$(call msg,VMH, $@)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

clean:
	rm -f $(APPS) $(EBPF).bpf.o $(EBPF).skel.h vmlinux.h $(EXTRA_APPS) $(OBJ) $(APPS).bpf.o $(APPS).skel.h

xdpstatus:
	watch -n 0.5 bpftool net

debug:
	cat /sys/kernel/debug/tracing/trace_pipe

.PHONY: clean debug xdpstatus
