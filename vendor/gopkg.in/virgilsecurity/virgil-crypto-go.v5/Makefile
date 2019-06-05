TEMPDIR := $(shell mktemp -d)
BRANCH ?=master

all:
	rm -rf lib/
	rm -rf include/
	git clone --branch=$(BRANCH) https://github.com/VirgilSecurity/virgil-crypto.git $(TEMPDIR)
	cd $(TEMPDIR); \
	cmake -H. -B_build -DCMAKE_INSTALL_PREFIX=_install -DLANG=go -DINSTALL_CORE_LIBS=ON -DVIRGIL_CRYPTO_FEATURE_PYTHIA=ON; \
	cmake --build _build --target install 
	cp -r $(TEMPDIR)/_install/* .
	rm -rf $(TEMPDIR)d
	rm -rf lib/cmake/
	rm -rf lib/pkgconfig/


