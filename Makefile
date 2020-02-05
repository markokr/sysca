
VER := $(shell python3 setup.py --version)
TGZ = dist/sysca-$(VER).tar.gz

all:
	tox -e lint
	tox -e py3-cryptography28

test:
	#rm -rf cover
	tox -e lint
	tox -e py36-cryptography21
	tox -e py36-cryptography22
	tox -e py36-cryptography23
	tox -e py36-cryptography24
	tox -e py36-cryptography25
	tox -e py37-cryptography26
	tox -e py37-cryptography27
	tox -e py38-cryptography28

sdist: $(TGZ)
$(TGZ):
	python3 setup.py sdist

upload: $(TGZ)
	twine upload $(TGZ)

show:
	for fn in /usr/share/ca-certificates/mozilla/*.crt; do \
		printf "\n# $${fn}\n"; ./local.py show "$${fn}"; \
	done
