.PHONY: all

all: string_funcs.html math_funcs.html nss_tables.html

%.html:  %.md
	pandoc -f markdown -t html5 -s --toc --toc-depth=2 -o $@ $<
