.DEFAULT_GOAL=help
.PHONY: run build clean help
DIR := $(realpath $(dir $(realpath $(lastword $(MAKEFILE_LIST)))))
STONESOUP := $(DIR)/stonesoup
SS_DEPS = $(STONESOUP)/dependencies
CFLAGS := -fno-stack-protector
CPPFLAGS := -DSTONESOUP_TRACE=1 -I$(SS_DEPS)/include
LDFLAGS := -L$(SS_DEPS)/lib -L$(SS_DEPS)/lib64 -Wl,-R$(STONESOUP)/workspace/install/lib -Wl,-R$(STONESOUP)/workspace/install/lib64 -Wl,-R$(SS_DEPS)/lib -Wl,-R$(SS_DEPS)/lib64 -Wl,-z,execstack -L$(SS_DEPS)/lib64 -L$(SS_DEPS)/lib -L$(SS_DEPS)/lib -Wl,--as-needed
LIBS := -ldl
PKG_CONFIG_PATH=$(SS_DEPS)/lib:$(SS_DEPS)/lib/pkgconfig:$(SS_DEPS)/lib64:$(SS_DEPS)/lib64/pkgconfig
TARGET = install/bin/svn


run: $(TARGET) ## Run the test case

build: $(TARGET) ## Build the test case

$(TARGET): .installed
	cd src && ./configure -v --prefix="$(DIR)/install" --with-apr="$(SS_DEPS)/bin/apr-1-config" --with-apr-util="$(SS_DEPS)/bin/apu-1-config" --with-serf --with-sqlite="$(SS_DEPS)" --with-sasl --with-libmagic --with-zlib --without-kwallet --without-gnome-keyring --disable-keychain --without-trang --without-doxygen --without-swig --without-jikes --without-ctypesgen --without-junit --without-jdk --without-apxs --with-editor="/usr/bin/vi" --disable-shared --with-pic=yes CFLAGS="$(CFLAGS)" CPPFLAGS="$(CPPFLAGS)" LDFLAGS="$(LDFLAGS)" LIBS="$(LIBS)" PKG_CONFIG_PATH="$(PKG_CONFIG_PATH)"
	$(MAKE) -C src VERBOSE=1
	$(MAKE) -C src install

clean: ## Clean the test case
	$(MAKE) -C src clean

.installed: ## Install the dependencies
	sh install-dependencies.sh

help: ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
