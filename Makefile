
all:
	tox -e lint
	tox -e cio28
	#tox -e py3-cryptography27

test:
	#rm -rf cover
	tox -e lint
	tox -e py3-cryptography21
	tox -e py3-cryptography22
	tox -e py3-cryptography23
	tox -e py36-cryptography24
	tox -e py37-cryptography25
	tox -e py38-cryptography26
	tox -e py3-cryptography27

sdist:
	rm -f dist/*
	python3 setup.py sdist

upload:
	twine upload dist/*

show:
	for fn in /usr/share/ca-certificates/mozilla/*.crt; do \
		printf "\n# $${fn}\n"; ./local.py show "$${fn}"; \
	done
