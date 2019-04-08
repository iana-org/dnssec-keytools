SOURCE=		src
PYTHON=		python3.7
VENV=		venv
DOCS=		htmlcov
DISTDIRS=	*.egg-info build dist
GREEN_FLAGS=	-vv

SOFTHSM_CONF=	${CURDIR}/softhsm.conf


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
	(cd testing/softhsm; make SOFTHSM_CONF=$(SOFTHSM_CONF) softhsm)

test: $(VENV) softhsm
	env SOFTHSM2_CONF=$(SOFTHSM_CONF) $(VENV)/bin/green $(GREEN_FLAGS)

container:
	docker build --tag wksr .

coverage: $(VENV)
	$(VENV)/bin/coverage run -m unittest discover --verbose
	$(VENV)/bin/coverage html

lint: $(VENV)
	$(VENV)/bin/pylama $(SOURCE)

typecheck: $(VENV)
	$(VENV)/bin/mypy $(SOURCE)

clean:
	(cd testing/softhsm; make SOFTHSM_CONF=$(SOFTHSM_CONF) clean)
	rm -fr $(DOCS) $(DISTDIRS)

realclean: clean
	rm -fr $(VENV)
