SOURCE=		src
DOCS=		htmlcov
DISTDIRS=	*.egg-info build dist

SOFTHSM2_CONF=		${CURDIR}/testing/softhsm/softhsm.conf
SOFTHSM2_MODULE?=	$(shell sh testing/softhsm/find_libsofthsm2.sh)
BUILDINFO=		$(SOURCE)/kskm/buildinfo.py

TEST_ENV=	SOFTHSM2_CONF=$(SOFTHSM2_CONF) \
		SOFTHSM2_MODULE=$(SOFTHSM2_MODULE)
PYTEST_OPTS=	--verbose
PYTEST_CACHE=	.pytest_cache

all: $(BUILDINFO)

depend: softhsm
	poetry install --all-extras

wheel: $(BUILDINFO)
	poetry build -f wheel

softhsm:
	test -f $(SOFTHSM2_MODULE) || echo "Failed to find SoftHSM module"
	(cd testing/softhsm; make SOFTHSM_CONF=$(SOFTHSM2_CONF) all)

test: softhsm $(BUILDINFO)
	env $(TEST_ENV) poetry run python -m pytest $(PYTEST_OPTS) $(SOURCE)

container:
	docker build --tag wksr .

coverage: softhsm $(BUILDINFO)
	env $(TEST_ENV) poetry run coverage run -m pytest $(PYTEST_OPTS) $(SOURCE)
	poetry run coverage html

reformat:
	poetry run ruff format $(SOURCE)

lint:
	poetry run ruff check $(SOURCE)

typecheck:
	poetry run mypy --ignore-missing-imports $(SOURCE)

vscode_packages:
	sudo apt-get update
	sudo apt-get install -y swig softhsm2

# This target is used by the devcontainer.json to configure the devcontainer
vscode: vscode_packages softhsm
	pip3 install poetry
	poetry install --all-extras

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
