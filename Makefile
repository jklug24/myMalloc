.PHONY: all
all: git-commit

.PHONY: git-commit
git-commit:
	git add *.c Makefile >> .local.git.out  || echo
	git commit -a -m 'Commit' >> .local.git.out || echo

.PHONY: tests
tests:
	$(MAKE) -C tests

.PHONY: examples
examples:
	$(MAKE) -C examples

.PHONY: test
test: tests
	python ./runtest.py

.PHONY: clean
clean: 
	$(MAKE) -C tests clean
	$(MAKE) -C examples clean
