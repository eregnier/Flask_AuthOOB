.PHONY: build push clean deploy

build:
	rm -rf dist
	pipenv run python setup.py sdist
	pipenv run python setup.py bdist_wheel

publish: build
	pipenv run twine upload dist/*

check: build
	pipenv run twine check dist/*

clean:
	rm -rf build dist q.egg-info
	find -name *.pyc -delete
	@- git status

deploy: push clean

test:
	pipenv run py.test -xs
