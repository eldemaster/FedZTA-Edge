.PHONY: all clean distclean
all: main.pdf

main.pdf: main.tex refs.bib $(wildcard sections/*.tex) $(wildcard figures/*.pdf)
	latexmk -pdf -interaction=nonstopmode main.tex

clean:
	latexmk -c

distclean:
	latexmk -C
