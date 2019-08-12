
all:
	tox

test:
	tox -e lint
	tox -e py3-cryptography21
	tox -e py3-cryptography22
	tox -e py3-cryptography23
	tox -e py3-cryptography24
	tox -e py3-cryptography25
	tox -e py3-cryptography26
	tox -e py3-cryptography27

sdist:
	rm -f dist/*
	python3 setup.py sdist

clitests:
	./tests/cli/test_basics.sh
	#./tests/cli/test_gpg.sh
	./tests/cli/test_keys.sh
	./tests/cli/test_selfsign.sh
	./tests/cli/test_crl_direct.sh
	./tests/cli/test_crl_indirect.sh

upload:
	twine upload dist/*

