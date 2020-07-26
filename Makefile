SOURCE=		src
PYTHON=		python3.7
VENV=		venv
DOCS=		htmlcov
DISTDIRS=	*.egg-info build dist

SOFTHSM2_CONF=		${CURDIR}/testing/softhsm/softhsm.conf
SOFTHSM2_MODULE?=	$(shell sh testing/softhsm/find_libsofthsm2.sh)
BUILDINFO=		$(SOURCE)/kskm/buildinfo.py

TEST_ENV=		SOFTHSM2_CONF=$(SOFTHSM2_CONF) \
			SOFTHSM2_MODULE=$(SOFTHSM2_MODULE)
PYTEST_OPTS=		--verbose --pylama --isort --black
PYTEST_CACHE=		.pytest_cache

all: $(BUILDINFO)

$(VENV): $(VENV)/.depend

$(VENV)/.depend: setup.py
	$(PYTHON) -m venv $(VENV)
	$(VENV)/bin/pip install wheel
	$(VENV)/bin/pip install -e ".[online,testing]"
	touch $(VENV)/.depend

upgrade-venv:: setup.py
	$(VENV)/bin/pip install --upgrade -e ".[online,testing]"
	touch $(VENV)/.depend

wheel: $(BUILDINFO)
	$(VENV)/bin/python setup.py bdist_wheel

softhsm:
	test -f $(SOFTHSM2_MODULE) || echo "Failed to find SoftHSM module"
	(cd testing/softhsm; make SOFTHSM_CONF=$(SOFTHSM2_CONF) all)

test: $(VENV) softhsm $(BUILDINFO)
	env $(TEST_ENV) $(VENV)/bin/pytest $(PYTEST_OPTS) $(SOURCE)

container:
	docker build --tag wksr .

coverage: $(VENV) softhsm $(BUILDINFO)
	env $(TEST_ENV) $(VENV)/bin/coverage run -m pytest $(PYTEST_OPTS) $(SOURCE)
	$(VENV)/bin/coverage html

reformat: $(VENV)
	$(VENV)/bin/isort --recursive $(SOURCE)
	$(VENV)/bin/black $(SOURCE)

typecheck: $(VENV)
	$(VENV)/bin/mypy --ignore-missing-imports $(SOURCE)

$(BUILDINFO): $(SOURCE)
	if [ -d .git ]; then \
		printf "__commit__ = \"`git rev-parse HEAD`\"\n__timestamp__ = \"`date +'%Y-%m-%d %H:%M:%S %Z'`\"\n" > $@ ;\
	else \
		echo "" > $@ ;\
	fi

clean:
	(cd testing/softhsm; make SOFTHSM_CONF=$(SOFTHSM2_CONF) clean)
	rm -fr $(DOCS) $(DISTDIRS)
	rm -f $(BUILDINFO)

realclean: clean
	rm -fr $(VENV)
	rm -fr $(PYTEST_CACHE)
