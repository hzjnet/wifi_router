## Makefile for libwifisoncfg
#
# -- .so (shared object) files will have unused objects removed
# Ultimately, the trimmed down .so file is used on the target.
#

# Shared Makefile stuff, place at BEGINNING of this Makefile

LIBWIFISONDIR := $(shell pwd)
ifneq ($(strip $(TOOLPREFIX)),)
export  CROSS:=$(TOOLPREFIX)
endif

export CC = $(CROSS)gcc
export CFLAGS += -O2 -Wall -Werror -fPIC -D_BYTE_ORDER=_BIG_ENDIAN
export OBJEXT = o
export COMPILE = $(CC) $(DEFS) $(INCLUDES) $(CFLAGS)

CFLAGS += -I. -I$(GWINCLUDE) -I$(STAGING_DIR)/usr/lib/ -I$(STAGING_DIR)/usr/include/whc-wlb

ifeq ($(LIBCFG80211_SUPPORT),y)
CFLAGS += -I$(STAGING_DIR)/usr/include/libnl
endif

ifeq ($(QCA_PARTNER_PLATFORM),y)
CFLAGS += -DQCA_PARTNER_PLATFORM
endif

ifeq ($(ENABLE_DEBUG),y)
CFLAGS += -DDEBUG
endif

LIBWIFISON_INSTALL_ROOT := $(LIBWIFISONDIR)/install

ifndef INSTALL_ROOT
INSTALL_ROOT=$(LIBWIFISON_INSTALL_ROOT)
endif

LIBWIFISON_INSTALL_INCLUDE = $(INSTALL_ROOT)/include
LIBWIFISON_INSTALL_LIB = $(INSTALL_ROOT)/lib

# What we build by default:
ALL=libwifisoncfg.so

OBJS = wlanif_wext.o wlanif_cmn.o sonlib_qti.o sonlib_cmn.o

ifeq ($(LIBCFG80211_SUPPORT),y)
OBJS += wlanif_cfg80211.o
CFLAGS += -DLIBCFG80211_SUPPORT
endif

# Making default targets:
all: local install
	@echo All done in `pwd`

local : $(ALL)
	@echo Made outputs in `pwd`

# Doing installation (see comments at top of this file)
# Note: header files should be installed with "ln -s -f" in order to
# prevent compiler from using old copies of local header files!
install: local
	@cp -a -f $(ALL) $(LIBWIFISON_INSTALL_LIB)
	@cp -a -f *.h $(LIBWIFISON_INSTALL_INCLUDE)
	@echo Installed outputs from `pwd`

# Making our specific library outputs
$(ALL) : $(OBJS)
	rm -f $@
	$(COMPILE) -shared -o $@ $(OBJS) $(LIBS)

# Remove all generated files
clean:
	@rm -f *.o *.so

.PHONY: all clean install

