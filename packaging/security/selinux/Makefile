# SELinux refpolicy build for spt.
#
# Usage:
#   make            # builds spt.pp from spt.te + spt.fc
#   sudo make install  # installs the module via semodule -i
#   sudo make relabel  # restorecon -R for spt-labeled paths
#   sudo make uninstall  # semodule -r spt
#
# Requires the `selinux-policy-devel` (Fedora/RHEL) or
# `selinux-policy-dev` (Debian) package, which ships
# /usr/share/selinux/devel/Makefile.

NAME := spt

# Prefer the refpolicy devel Makefile if present (Fedora/RHEL style).
REFPOLICY_MAKE := /usr/share/selinux/devel/Makefile

ifeq ($(wildcard $(REFPOLICY_MAKE)),$(REFPOLICY_MAKE))

# Delegate to refpolicy's standard build chain. This is the canonical
# path on Fedora/RHEL/CentOS.
all install relabel uninstall:
	$(MAKE) -f $(REFPOLICY_MAKE) $@

else

# Fallback: drive checkmodule + semodule_package directly. Used on
# Debian/Ubuntu with the SELinux module bits installed.
CHECKMODULE := checkmodule
SEMODULE_PACKAGE := semodule_package
SEMODULE := semodule
RESTORECON := restorecon

all: $(NAME).pp

$(NAME).mod: $(NAME).te
	$(CHECKMODULE) -M -m -o $@ $<

$(NAME).pp: $(NAME).mod $(NAME).fc
	$(SEMODULE_PACKAGE) -o $@ -m $(NAME).mod -f $(NAME).fc

install: $(NAME).pp
	$(SEMODULE) -i $(NAME).pp

relabel:
	$(RESTORECON) -RFv /usr/local/bin/spt /etc/spt /var/lib/spt /var/log/spt /run/spt 2>/dev/null || true

uninstall:
	$(SEMODULE) -r $(NAME)

clean:
	rm -f $(NAME).mod $(NAME).pp tmp/$(NAME).mod.fc

.PHONY: all install relabel uninstall clean

endif
