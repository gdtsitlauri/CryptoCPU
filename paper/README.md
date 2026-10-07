# Design and implementation of an encrypted instruction set processor on FPGA

George David Tsitlauri — **BSc thesis, 2025**, University of Thessaly.

- [cryptocpu.pdf](cryptocpu.pdf): the paper in IEEE conference style (three pages and references).
- [cryptocpu.tex](cryptocpu.tex): editable LaTeX source.
- [references.bib](references.bib): bibliography.

The paper presents the CryptoCPU BSc thesis, 2025. Its verification and
performance tables come from the [recorded host run](../results/host/README.md),
whose manifest retains the verification dates and source hashes. Section V gives
the FPGA implementation of the thesis prototype on an Artix-7, with resource
estimates for the present configuration.

The document uses the standard `IEEEtran` conference class on A4, two columns and
numbered citations, following the
[IEEE template guidance](https://conferences.ieeeauthorcenter.ieee.org/write-your-paper/authoring-tools-and-templates/).
The paper accompanies the thesis; IEEE formatting does not indicate publication or acceptance.

## Build

With [Tectonic](https://tectonic-typesetting.github.io/book/latest/installation/),
run from the repository root:

```text
tectonic paper/cryptocpu.tex
```

Tectonic obtains the required LaTeX packages and runs the bibliography passes.
This workspace has a portable executable at
`_build/toolchain/tectonic/tectonic.exe`.

With a TeX Live or MiKTeX installation containing IEEEtran:

```text
cd paper
pdflatex cryptocpu
bibtex cryptocpu
pdflatex cryptocpu
pdflatex cryptocpu
```

Generated auxiliary files are ignored. The checked-in PDF is the reading copy;
the original thesis is in [legacy](../legacy/README.md).
