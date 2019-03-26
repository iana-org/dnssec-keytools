SOFTHSM_SO_PIN=		1234567890
SOFTHSM_PIN =		123456
SOFTHSM_ENV=		SOFTHSM2_CONF=./softhsm.conf
SOFTHSM_INIT=		--init-token \
			--so-pin $(SOFTHSM_SO_PIN) \
			--pin $(SOFTHSM_PIN)
SOFTHSM_IMPORT=		--pin $(SOFTHSM_PIN)
SOFTHSM_BIN=		env $(SOFTHSM_ENV) softhsm2-util

STATUSFILE=		softhsm.initialized
TOKENS=			tokens

CLEANFILES=	*.p8 softhsm.initialized $(TOKENS)

.SUFFIXES:	.p8 .key


softhsm: $(STATUSFILE)

# fill slot 0 with both rsa2048-1.key & rsa2048-2.key
# fill slot 1 with rsa2048-1.key only
# fill slot 2 with rsa2048-2.key only
$(STATUSFILE): $(TOKENS) rsa2048-1.p8 rsa2048-2.p8
	$(SOFTHSM_BIN) $(SOFTHSM_INIT) --free --label "SoftHSM-0"
	$(SOFTHSM_BIN) $(SOFTHSM_INIT) --free --label "SoftHSM-1"
	$(SOFTHSM_BIN) $(SOFTHSM_INIT) --free --label "SoftHSM-2"
	$(SOFTHSM_BIN) $(SOFTHSM_IMPORT) --import rsa2048-1.p8 --token "SoftHSM-0" --id 01 --label KEY1 
	$(SOFTHSM_BIN) $(SOFTHSM_IMPORT) --import rsa2048-2.p8 --token "SoftHSM-0" --id 02 --label KEY2 
	$(SOFTHSM_BIN) $(SOFTHSM_IMPORT) --import rsa2048-1.p8 --token "SoftHSM-1" --id 01 --label KEY1 
	$(SOFTHSM_BIN) $(SOFTHSM_IMPORT) --import rsa2048-2.p8 --token "SoftHSM-2" --id 02 --label KEY2
	touch $(STATUSFILE)

inventory:
	$(SOFTHSM_BIN) --show-slots

$(TOKENS):
	mkdir $@

rsa2048-1.p8: rsa2048-1.key
rsa2048-2.p8: rsa2048-2.key

.key.p8:
	openssl pkcs8 -in $< -inform pem -nocrypt -out $@ -topk8

clean:
	rm -fr $(CLEANFILES)
