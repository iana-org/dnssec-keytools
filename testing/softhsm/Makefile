SOFTHSM_CONF=		${CURDIR}/softhsm.conf
SOFTHSM_SO_PIN=		1234567890
SOFTHSM_PIN =		123456
SOFTHSM_ENV=		SOFTHSM2_CONF=$(SOFTHSM_CONF)
SOFTHSM_INIT=		--init-token \
			--so-pin $(SOFTHSM_SO_PIN) \
			--pin $(SOFTHSM_PIN)
SOFTHSM_IMPORT=		--pin $(SOFTHSM_PIN)
SOFTHSM_BIN=		env $(SOFTHSM_ENV) softhsm2-util

TOKENDIR=		${CURDIR}/tokens
STATUSFILE=		$(TOKENDIR)/.initialized

P11MODULE?=		$(shell sh find_libsofthsm2.sh)
PKCS11TOOL=		env $(SOFTHSM_ENV) pkcs11-tool --module $(P11MODULE) --login --pin $(SOFTHSM_PIN)

KSRSIGNER_YAML=		${CURDIR}/ksrsigner.yaml
KSRSIGNER_TEMPLATE=	${CURDIR}/ksrsigner.template.yaml

RSA_SIZE=		2048
EC_CURVE=		prime256v1

KEYS=			rsa-$(RSA_SIZE)-1.key rsa-$(RSA_SIZE)-2.key rsa-$(RSA_SIZE)-3.key rsa-$(RSA_SIZE)-4.key \
			ec-$(EC_CURVE)-1.key ec-$(EC_CURVE)-2.key ec-$(EC_CURVE)-3.key ec-$(EC_CURVE)-4.key
KEYS_PKCS8=		rsa-$(RSA_SIZE)-1.p8 rsa-$(RSA_SIZE)-2.p8 rsa-$(RSA_SIZE)-3.p8 rsa-$(RSA_SIZE)-4.p8 \
			ec-$(EC_CURVE)-1.p8 ec-$(EC_CURVE)-2.p8 ec-$(EC_CURVE)-3.p8 ec-$(EC_CURVE)-4.p8

CLEANFILES=		*.p8 *.key softhsm.initialized $(TOKENDIR) $(SOFTHSM_CONF) $(KSRSIGNER_YAML) *.log

LABEL_TOKEN_0=		"SoftHSM-0"
LABEL_TOKEN_1=		"SoftHSM-1"
LABEL_TOKEN_2=		"SoftHSM-2"

LABEL_WRAP=		backup
LABEL_RSA=		test_rsa

.SUFFIXES:		.p8 .key


all: softhsm $(KSRSIGNER_YAML)

test: keys ta inventory backup restore

conf: $(SOFTHSM_CONF) $(KSRSIGNER_YAML)

softhsm: $(STATUSFILE)

keys: $(KEYS)

ta: $(KSRSIGNER_YAML) $(STATUSFILE)
	kskm-trustanchor

inventory: $(KSRSIGNER_YAML) $(STATUSFILE)
	kskm-keymaster inventory

backup: $(KSRSIGNER_YAML) $(STATUSFILE)
	kskm-keymaster wrapgen --label $(LABEL_WRAP) --algorithm AES256
	kskm-keymaster keygen --label $(LABEL_RSA) --algorithm RSASHA256 --size 2048
	kskm-keymaster backup --wrap-label $(LABEL_WRAP) --label $(LABEL_RSA) --outfile wrapped_key.yaml

restore: $(KSRSIGNER_YAML) $(STATUSFILE)
	kskm-keymaster keydelete --force --label $(LABEL_RSA)
	kskm-keymaster restore --wrap-label $(LABEL_WRAP) --infile wrapped_key.yaml

$(KSRSIGNER_YAML): $(KSRSIGNER_TEMPLATE)
	sed -e 's,__P11MODULE__,$(P11MODULE),' \
	    -e 's,__SOFTHSM_PIN__,$(SOFTHSM_PIN),' \
	    -e 's,__SOFTHSM_CONF__,$(SOFTHSM_CONF),' < $< > $@

$(SOFTHSM_CONF):
	echo "directories.tokendir = $(TOKENDIR)" > $@
	echo "objectstore.backend = file" >> $@
	echo "log.level = DEBUG" >> $@
	echo "slots.removable = false" >> $@

empty: $(SOFTHSM_CONF) $(TOKENDIR) $(KEYS_PKCS8)
	rm -fr $(TOKENDIR)/*
	$(SOFTHSM_BIN) $(SOFTHSM_INIT) --free --label $(LABEL_TOKEN_0)  --module $(P11MODULE)

$(STATUSFILE): $(SOFTHSM_CONF) $(TOKENDIR) $(KEYS_PKCS8)
	rm -fr $(TOKENDIR)/*
	$(SOFTHSM_BIN) $(SOFTHSM_INIT) --free --label $(LABEL_TOKEN_0)
	$(SOFTHSM_BIN) $(SOFTHSM_INIT) --free --label $(LABEL_TOKEN_1)
	$(SOFTHSM_BIN) $(SOFTHSM_INIT) --free --label $(LABEL_TOKEN_2)
	# token 0
	$(SOFTHSM_BIN) $(SOFTHSM_IMPORT) --import rsa-$(RSA_SIZE)-1.p8 --token $(LABEL_TOKEN_0) --id 01 --label RSA1
	$(SOFTHSM_BIN) $(SOFTHSM_IMPORT) --import rsa-$(RSA_SIZE)-2.p8 --token $(LABEL_TOKEN_0) --id 02 --label RSA2
	$(SOFTHSM_BIN) $(SOFTHSM_IMPORT) --import ec-$(EC_CURVE)-1.p8 --token $(LABEL_TOKEN_0) --id 03 --label EC1
	$(SOFTHSM_BIN) $(SOFTHSM_IMPORT) --import ec-$(EC_CURVE)-2.p8 --token $(LABEL_TOKEN_0) --id 04 --label EC2
	# token 1
	$(SOFTHSM_BIN) $(SOFTHSM_IMPORT) --import rsa-$(RSA_SIZE)-3.p8 --token $(LABEL_TOKEN_1) --id 05 --label RSA3
	$(SOFTHSM_BIN) $(SOFTHSM_IMPORT) --import ec-$(EC_CURVE)-3.p8 --token $(LABEL_TOKEN_1) --id 06 --label EC3
	# token 2
	$(SOFTHSM_BIN) $(SOFTHSM_IMPORT) --import rsa-$(RSA_SIZE)-4.p8 --token $(LABEL_TOKEN_2) --id 07 --label RSA4
	$(SOFTHSM_BIN) $(SOFTHSM_IMPORT) --import ec-$(EC_CURVE)-4.p8 --token $(LABEL_TOKEN_2) --id 08 --label EC4
	touch $(STATUSFILE)

show:
	$(SOFTHSM_BIN) --show-slots

keylist:
	$(PKCS11TOOL) --list-token-slots || true
	$(PKCS11TOOL) --list-objects --token-label $(LABEL_TOKEN_0)
	$(PKCS11TOOL) --list-objects --token-label $(LABEL_TOKEN_1)
	$(PKCS11TOOL) --list-objects --token-label $(LABEL_TOKEN_2)

$(TOKENDIR):
	mkdir $@

rsa-$(RSA_SIZE)-1.p8: rsa-$(RSA_SIZE)-1.key
rsa-$(RSA_SIZE)-2.p8: rsa-$(RSA_SIZE)-2.key
rsa-$(RSA_SIZE)-3.p8: rsa-$(RSA_SIZE)-3.key
rsa-$(RSA_SIZE)-4.p8: rsa-$(RSA_SIZE)-4.key

ec-$(EC_CURVE)-1.p8: ec-$(EC_CURVE)-1.key
ec-$(EC_CURVE)-2.p8: ec-$(EC_CURVE)-2.key
ec-$(EC_CURVE)-3.p8: ec-$(EC_CURVE)-3.key
ec-$(EC_CURVE)-4.p8: ec-$(EC_CURVE)-4.key

rsa-$(RSA_SIZE)-1.key:
	cp $@.in $@

rsa-$(RSA_SIZE)-2.key:
	cp $@.in $@

rsa-$(RSA_SIZE)-3.key:
	openssl genrsa $(RSA_SIZE) > $@

rsa-$(RSA_SIZE)-4.key:
	openssl genrsa $(RSA_SIZE) > $@

ec-$(EC_CURVE)-1.key:
	cp $@.in $@

ec-$(EC_CURVE)-2.key:
	cp $@.in $@

ec-$(EC_CURVE)-3.key:
	openssl ecparam -name prime256v1 -genkey -noout -out $@

ec-$(EC_CURVE)-4.key:
	openssl ecparam -name prime256v1 -genkey -noout -out $@

.key.p8:
	openssl pkcs8 -in $< -inform pem -nocrypt -out $@ -topk8

clean:
	rm -fr $(CLEANFILES)
