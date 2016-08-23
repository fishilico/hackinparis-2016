RM ?= rm -f
RST2HTML ?= rst2html
SED ?= sed
SPHINXBUILD ?= sphinx-build

RST_FILES := $(wildcard challenge*.rst) README.rst
HTML_OUTFILES := $(RST_FILES:%.rst=%.rst.html)

all: html sphinx

clean:
	$(RM) $(HTML_OUTFILES)
	$(RM) -r build/

html: $(HTML_OUTFILES)

%.rst.html: %.rst
	$(RST2HTML) $< > $@

# Make links to local files in README file
README.rst.html: README.rst
	$(SED) 's/\(\S*\.rst\)/`\1 <\1.html>`_/g' $< | $(RST2HTML) > $@

sphinx:
	$(SPHINXBUILD) -b html . build

.PHONY: all clean html sphinx
