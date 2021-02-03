NEW_CERT=	openssl req -new -x509 -newkey rsa:2048 -nodes -days 30


server: wksr.crt wksr.key ca.crt
	env FLASK_ENV=development kskm-wksr --debug --port 8443

certs: wksr.crt client.crt

wksr.crt:
	$(NEW_CERT) -keyout wksr.key -out wksr.crt -subj '/CN=wksr-server'

wksr.key: wksr.key

client.crt:
	$(NEW_CERT) -keyout client.key -out client.crt -subj '/CN=wksr-client'
	openssl x509 -in client.crt -outform der | openssl sha256
	cp client.crt ca.crt

client.key: client.crt

ca.crt: client.crt

upload:
	curl --verbose --insecure --cert client.crt --key client.key \
		-F "ksr=@ksr.xml" https://127.0.0.1:8443/upload

clean:
	rm -f ksr.*.xml

realclean:
	rm -f wksr.crt wksr.key ca.crt client.crt client.key
