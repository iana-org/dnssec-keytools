NEW_CERT=	openssl req -new -x509 -newkey rsa:2048 -nodes -days 30


server: wksr.crt wksr.key ca.crt
	env FLASK_ENV=development kskm-wksr --debug

certs:
	$(NEW_CERT) -keyout wksr.key -out wksr.crt -subj '/CN=wksr-server'
	$(NEW_CERT) -keyout client.key -out client.crt -subj '/CN=wksr-client'
	cp client.crt ca.crt

upload:
	curl --verbose --insecure --cert client.crt --key client.key \
		-F "ksr=@ksr.xml" https://127.0.0.1:8443/upload

clean:
	rm -f ksr.*.xml
