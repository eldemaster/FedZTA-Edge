# Paper layout

```
paper/
  main.tex            preamble, title, abstract, Conclusion (owner: main)
  refs.bib            shared BibTeX entries (owner: main)
  refs_<section>.bib  per-section BibTeX (intro, background, system, evaluation, security); cite keys prefixed <section>:
  sections/           intro.tex background.tex system.tex evaluation.tex security.tex
  figures/            figures (graphicx path is set to figures/)
  Makefile            `make` builds main.pdf via latexmk
  .latexmkrc          also creates missing .bib files
```

Each `sections/*.tex` holds body only (starts with `\section{...}`; no preamble, no `\begin{document}`).
`main.tex` includes each via `\IfFileExists`, so the paper builds while sections are missing.

## Build

```
cd paper
make          # latexmk -pdf; creates empty missing refs_*.bib first
make clean    # remove aux files
```

Empty placeholder `.bib` files are generated locally and should not be committed by anyone other than their owner.
Packages available to sections: tikz (arrows.meta, positioning, shapes.geometric, fit, calc), amsmath, booktabs, graphicx, multirow, hyperref, algorithm + algorithmic.
