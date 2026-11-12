# Paper layout

```
paper/
  main.tex            preamble, title, abstract, Conclusion (owner: main)
  refs.bib            single merged bibliography; one entry per work, unprefixed keys
  sections/           intro.tex background.tex system.tex evaluation.tex security.tex
  figures/            figures (graphicx path is set to figures/)
  Makefile            `make` builds main.pdf via latexmk
  .latexmkrc          latexmk settings (pdf, bibtex)
  main.pdf            prebuilt PDF, committed for viewing
```

Each `sections/*.tex` holds body only (starts with `\section{...}`; no preamble, no `\begin{document}`).
`main.tex` includes each via `\input` in the order intro, background, system, evaluation, security.

## Build

```
cd paper
make          # latexmk -pdf
make clean    # remove aux files
```

Packages available to sections: tikz (arrows.meta, positioning, shapes.geometric, fit, calc), amsmath, booktabs, graphicx, multirow, hyperref, algorithm + algpseudocode.
