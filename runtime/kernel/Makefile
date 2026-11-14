ifneq ($(KERNELRELEASE),)

ccflags-y += -I$(src)/..

obj-m += autoshield.o
autoshield-y := module.o vm.o safe_mem.o

else

KDIR ?=
ARCH ?=
CROSS_COMPILE ?=
KCFLAGS ?=
PREPARE_MODULES ?= 1

.PHONY: all clean

all:
	@test -n "$(KDIR)" || (echo "KDIR must point to a configured kernel build tree"; exit 1)
ifeq ($(PREPARE_MODULES),1)
	$(MAKE) -C "$(KDIR)" \
		$(if $(ARCH),ARCH="$(ARCH)") \
		$(if $(CROSS_COMPILE),CROSS_COMPILE="$(CROSS_COMPILE)") \
		modules_prepare
endif
	$(MAKE) -C "$(KDIR)" M="$(CURDIR)" \
		$(if $(ARCH),ARCH="$(ARCH)") \
		$(if $(CROSS_COMPILE),CROSS_COMPILE="$(CROSS_COMPILE)") \
		$(if $(KCFLAGS),KCFLAGS="$(KCFLAGS)") \
		modules

clean:
	@test -n "$(KDIR)" || (echo "KDIR must point to a configured kernel build tree"; exit 1)
	$(MAKE) -C "$(KDIR)" M="$(CURDIR)" clean

endif
