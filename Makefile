SOURCE=		src
PYTHON=		python3.7
VENV=		venv
DOCS=		htmlcov
DISTDIRS=	*.egg-info build dist
GREEN_FLAGS=	-vv

SOFTHSM2_CONF=		${CURDIR}/testing/softhsm/softhsm.conf
SOFTHSM2_MODULE?=	$(shell sh testing/softhsm/find_libsofthsm2.sh)

TEST_ENV=		SOFTHSM2_CONF=$(SOFTHSM2_CONF) \
			SOFTHSM2_MODULE=$(SOFTHSM2_MODULE)

all:

$(VENV): $(VENV)/.depend

$(VENV)/.depend: setup.py
	$(PYTHON) -m venv $(VENV)
	$(VENV)/bin/pip install -e ".[online,testing]"
	touch $(VENV)/.depend

upgrade-venv:: setup.py
	$(VENV)/bin/pip install --upgrade -e ".[online,testing]"
	touch $(VENV)/.depend

wheel:
	$(VENV)/bin/python setup.py bdist_wheel

softhsm:
	test -f $(SOFTHSM2_MODULE) || echo "Failed to find SoftHSM module"
	(cd testing/softhsm; make SOFTHSM_CONF=$(SOFTHSM2_CONF) all)

test: $(VENV) softhsm
	env $(TEST_ENV) $(VENV)/bin/green $(GREEN_FLAGS)

container:
	docker build --tag wksr .

coverage: $(VENV) softhsm
	env $(TEST_ENV) $(VENV)/bin/coverage run --source $(SOURCE) -m nose -w $(SOURCE) --verbose
	$(VENV)/bin/coverage html

lint: $(VENV)
	$(VENV)/bin/pylama $(SOURCE)

typecheck: $(VENV)
	$(VENV)/bin/mypy $(SOURCE) $(SOURCE)/kskm/tools

clean:
	(cd testing/softhsm; make SOFTHSM_CONF=$(SOFTHSM2_CONF) clean)
	rm -fr $(DOCS) $(DISTDIRS)

realclean: clean
	rm -fr $(VENV)
