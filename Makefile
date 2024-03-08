
VER := $(shell python3 setup.py --version)
TGZ = dist/sysca-$(VER).tar.gz

all:
	tox -e lint
	tox -e py3-cryptography37

test:
	#rm -rf cover
	tox -e lint
	tox -e py38-cryptography30
	tox -e py38-cryptography31
	tox -e py38-cryptography32
	tox -e py39-cryptography33
	tox -e py38-cryptography34
	tox -e py38-cryptography35
	#tox -e py39-cryptography36
	tox -e py39-cryptography37
	tox -e py310-cryptography39
	tox -e py310-cryptography40
	tox -e py311-cryptography41
	tox -e py311-cryptography42

sdist: $(TGZ)
$(TGZ):
	python3 setup.py sdist

upload: $(TGZ)
	twine upload $(TGZ)

show:
	for fn in /usr/share/ca-certificates/mozilla/*.crt; do \
		printf "\n# $${fn}\n"; ./local.py show "$${fn}"; \
	done
