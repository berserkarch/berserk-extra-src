# ===== Settings =====
OUTDIR       ?= ../themes
BASE_THEME   ?= ../themes/BerserkDark
THEME_PREFIX ?= BerserkDark
GTK_VERS     ?= 3 4

VARIANTS := blue teal green yellow orange red pink purple slate

COLOR_blue   := \#2777ff
COLOR_teal   := \#00c5cf
COLOR_green  := \#06a284
COLOR_yellow := \#d69f0d
COLOR_orange := \#fd7d00
COLOR_red    := \#ec0101
COLOR_pink   := \#cd0245
COLOR_purple := \#a400a4
COLOR_slate  := \#5b739d

.PHONY: all clean $(VARIANTS)

all: $(VARIANTS)

$(VARIANTS):
	@echo ">> Generating $(THEME_PREFIX)-$@ (accent $(COLOR_$@))"
	@variant_dir="$(OUTDIR)/$(THEME_PREFIX)-$@"; \
	cp -a "$(BASE_THEME)" "$$variant_dir"; \
	for ver in $(GTK_VERS); do \
	  mkdir -p "$$variant_dir/gtk-$$ver.0"; \
	  printf '@import "../../$(BASE_THEME)/gtk-%s.0/gtk.css";\n@define-color accent_bg_color $(COLOR_$@);' "$$ver" \
	    > "$$variant_dir/gtk-$$ver.0/gtk.css"; \
	  printf '@import "../../$(BASE_THEME)/gtk-%s.0/gtk.css";\n@define-color accent_bg_color $(COLOR_$@);' "$$ver" \
	    > "$$variant_dir/gtk-$$ver.0/gtk-dark.css"; \
	done
	@echo ">> Done: $(OUTDIR)/$(THEME_PREFIX)-$@"

clean:
	@echo ">> Cleaning generated variants"
	@for v in $(VARIANTS); do \
	  rm -rf "$(OUTDIR)/$(THEME_PREFIX)-$$v"; \
	done
