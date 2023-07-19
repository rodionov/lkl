
KASAN_SANITIZE_kasan.o := n

obj-y = bootmem.o
obj-$(CONFIG_KASAN) += kasan.o

obj-$(CONFIG_MMU) += tlb.o
obj-$(CONFIG_MMU) += mem.o