@rem Credit to https://github.com/Aim4kill/Bug_OldProtoSSL 
@echo off


rem Certificate Authority name
set CA_NAME=OTG3

rem Certificate name
set C_NAME=gosredirector

rem Modified der file name, that will be used later
set MOD_NAME=gosredirector_mod


rem Create private key for the Certificate Authority
openssl genrsa -aes128 -out %CA_NAME%.key.pem -passout pass:123456 1024
openssl rsa -in %CA_NAME%.key.pem -out %CA_NAME%.key.pem -passin pass:123456

rem Create the certificate of the Certificate Authority
openssl req -new -md5 -x509 -days 28124 -key %CA_NAME%.key.pem -out %CA_NAME%.crt -subj "/OU=Online Technology Group/O=Electronic Arts, Inc./L=Redwood City/ST=California/C=US/CN=OTG3 Certificate Authority"

rem ------------Certificate Authority created, now we can create Certificate------------

rem Create private key for the Certificate
openssl genrsa -aes128 -out %C_NAME%.key.pem -passout pass:123456 1024
openssl rsa -in %C_NAME%.key.pem -out %C_NAME%.key.pem -passin pass:123456

rem Create certificate signing request of the certificate
openssl req -new -key %C_NAME%.key.pem -out %C_NAME%.csr -subj "/CN=gosredirector.ea.com/OU=Global Online Studio/O=Electronic Arts, Inc./ST=California/C=US"

rem Create the certificate
openssl x509 -req -in %C_NAME%.csr -CA %CA_NAME%.crt -CAkey %CA_NAME%.key.pem -CAcreateserial -out %C_NAME%.crt -days 10000 -md5

rem ------------Certificate created, now export it to .der format so we can modify it------------
openssl x509 -outform der -in %C_NAME%.crt -out %C_NAME%.der

echo Der file exported, now patch it manually
pause

