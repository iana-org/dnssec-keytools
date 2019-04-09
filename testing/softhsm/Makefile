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

P11MODULE?=		/usr/lib/softhsm/libsofthsm2.so
PKCS11TOOL=		env $(SOFTHSM_ENV) pkcs11-tool --module $(P11MODULE) --login --pin $(SOFTHSM_PIN)

KEYS=			rsa2048-1.key rsa2048-2.key ecp256-1.key ecp256-2.key
KEYS_PKCS8=		rsa2048-1.p8 rsa2048-2.p8 ecp256-1.p8 ecp256-2.p8

CLEANFILES=		*.p8 *.key softhsm.initialized $(TOKENDIR) $(SOFTHSM_CONF)

LABEL_TOKEN_0=		"SoftHSM-0"
LABEL_TOKEN_1=		"SoftHSM-1"
LABEL_TOKEN_2=		"SoftHSM-2"

.SUFFIXES:		.p8 .key


softhsm: $(STATUSFILE)

keys: $(KEYS)

$(SOFTHSM_CONF):
	echo "directories.tokendir = $(TOKENDIR)" > $@
	echo "objectstore.backend = file" >> $@
	echo "log.level = DEBUG" >> $@
	echo "slots.removable = false" >> $@

# fill slot 0 with both *-1.key & *-2.key
# fill slot 1 with *-1.key only
# fill slot 2 with *-2.key only
$(STATUSFILE): $(SOFTHSM_CONF) $(TOKENDIR) $(KEYS_PKCS8)
	rm -fr $(TOKENDIR)/*
	$(SOFTHSM_BIN) $(SOFTHSM_INIT) --free --label $(LABEL_TOKEN_0)
	$(SOFTHSM_BIN) $(SOFTHSM_INIT) --free --label $(LABEL_TOKEN_1)
	$(SOFTHSM_BIN) $(SOFTHSM_INIT) --free --label $(LABEL_TOKEN_2)
	$(SOFTHSM_BIN) $(SOFTHSM_IMPORT) --import rsa2048-1.p8 --token $(LABEL_TOKEN_0) --id 01 --label RSA1
	$(SOFTHSM_BIN) $(SOFTHSM_IMPORT) --import rsa2048-2.p8 --token $(LABEL_TOKEN_0) --id 02 --label RSA2
	$(SOFTHSM_BIN) $(SOFTHSM_IMPORT) --import rsa2048-1.p8 --token $(LABEL_TOKEN_1) --id 01 --label RSA1x
	$(SOFTHSM_BIN) $(SOFTHSM_IMPORT) --import rsa2048-2.p8 --token $(LABEL_TOKEN_2) --id 02 --label RSA2x
	$(SOFTHSM_BIN) $(SOFTHSM_IMPORT) --import ecp256-1.p8 --token $(LABEL_TOKEN_0) --id 03 --label EC1
	$(SOFTHSM_BIN) $(SOFTHSM_IMPORT) --import ecp256-2.p8 --token $(LABEL_TOKEN_0) --id 04 --label EC2
	$(SOFTHSM_BIN) $(SOFTHSM_IMPORT) --import ecp256-1.p8 --token $(LABEL_TOKEN_1) --id 03 --label EC1x
	$(SOFTHSM_BIN) $(SOFTHSM_IMPORT) --import ecp256-2.p8 --token $(LABEL_TOKEN_2) --id 04 --label EC2x
	touch $(STATUSFILE)

inventory:
	$(SOFTHSM_BIN) --show-slots

keylist:
	$(PKCS11TOOL) --list-token-slots || true
	$(PKCS11TOOL) --list-objects --token-label $(LABEL_TOKEN_0)
	$(PKCS11TOOL) --list-objects --token-label $(LABEL_TOKEN_1)
	$(PKCS11TOOL) --list-objects --token-label $(LABEL_TOKEN_2)

$(TOKENDIR):
	mkdir $@

rsa2048-1.p8: rsa2048-1.key
rsa2048-2.p8: rsa2048-2.key
ecp256-1.p8: ecp256-2.key
ecp256-2.p8: ecp256-2.key

rsa2048-1.key:
	openssl genrsa 2048 > $@

rsa2048-2.key:
	openssl genrsa 2048 > $@

ecp256-1.key:
	openssl ecparam -name prime256v1 -genkey -noout -out $@

ecp256-2.key:
	openssl ecparam -name prime256v1 -genkey -noout -out $@

.key.p8:
	openssl pkcs8 -in $< -inform pem -nocrypt -out $@ -topk8

clean:
	rm -fr $(CLEANFILES)
