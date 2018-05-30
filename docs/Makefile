.PHONY: all

all: string_funcs.html math_funcs.html nss_tables.html bloom_filter1.html

%.html:  %.md
	pandoc -f markdown -t html5 --mathjax -s --toc --toc-depth=2 -o $@ $<
