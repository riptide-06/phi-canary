# phi-canary paper builds. Four PDFs, one content source; the wrappers differ
# only in \ifanon and \ifshort, so the builds cannot diverge in content.
# sty/ is on TEXINPUTS so the vendored style loads by name (loading it by
# path makes LaTeX warn that the requested and provided package names differ).
export TEXINPUTS := .:./sty:
LATEXMK := latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=out
TARGETS := full-named full-anon short-named short-anon

.PHONY: all clean numbers $(TARGETS)

all: $(TARGETS)

numbers:
	python3 numbers.py > /dev/null

$(TARGETS): numbers
	$(LATEXMK) phi-canary-$@.tex

clean:
	latexmk -C -outdir=out 2>/dev/null || true
	rm -rf out
