.PHONY: all clean distclean
all: main.pdf

main.pdf:
	latexmk -pdf -interaction=nonstopmode main.tex

clean:
	latexmk -c

distclean:
	latexmk -C
