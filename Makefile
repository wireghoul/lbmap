####
# lbmap makefile
###
LIBFILES := lib/lbmap/
DISTFILES := Changelog  lbmap  LICENSE  README htfuzz.pl htfuzz-ssl.pl fuzz
VERSION=`./lbmap --version | cut -d' ' -f 3`
.PHONY : clean

dist: clean $(LIBFILES) $(DISTFILES)
	mkdir -p lbmap-$(VERSION)/lib
	cp -f $(DISTFILES) lbmap-$(VERSION)
	cp -fr $(LIBFILES) lbmap-$(VERSION)/lib
	tar zcf lbmap-$(VERSION).tar.gz lbmap-$(VERSION)
	zip -9r lbmap-$(VERSION).zip lbmap-$(VERSION)
	rm -r lbmap-$(VERSION)

clean:
	rm -f lbmap-*.tar.gz lbmap-*.zip

