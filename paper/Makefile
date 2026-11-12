BIBS = refs refs_intro refs_background refs_system refs_evaluation refs_security

.PHONY: all bibs clean distclean
all: main.pdf

# Create empty placeholder .bib files for any that do not exist yet
# (never committed; other workers own their refs_<section>.bib).
bibs:
	@for b in $(BIBS); do [ -e $$b.bib ] || touch $$b.bib; done

main.pdf: bibs
	latexmk -pdf -interaction=nonstopmode main.tex

clean:
	latexmk -c

distclean:
	latexmk -C
