@rem Credit to https://github.com/Aim4kill/Bug_OldProtoSSL 

@echo off

rem Create CA
openssl req -nodes -new -md5 -x509 -days 28124 -keyout ca-key.pem -out ca-cert.crt -subj "/OU=Online Technology Group/O=Electronic Arts, Inc./L=Redwood City/ST=California/C=US/CN=OTG3 Certificate Authority"

rem Create certificate request and key
openssl req -nodes -new -keyout key.pem -out cert.csr -subj "/CN=gosredirector.ea.com/OU=Global Online Studio/O=Electronic Arts, Inc./ST=California/C=US"

rem Create the certificate
openssl x509 -req -in cert.csr -CA ca-cert.crt -CAkey ca-key.pem -outform der -out cert.der -days 10000 -md5

rem Remove completed certificate request file
del cert.csr

rem Remove unused ca files (Comment these lines if you want them)
del ca-key.pem
del ca-cert.crt

