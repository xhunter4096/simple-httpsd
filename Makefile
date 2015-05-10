
all:
	#openssl genrsa -out private-key.pem 2048
	#openssl req -new -x509 -key private-key.pem -out ca.pem -days 1024
	#gcc -Wall simple-httpsd.c -o simple-httpsd -lssl
	gcc -Wall simple-httpsd.c -o simple-httpsd -lssl -lcrypto -lpthread
clean:
	rm -rf simple-httpsd
