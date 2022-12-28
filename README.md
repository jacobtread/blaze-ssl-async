# ⚙️Blaze SSL Async

![License](https://img.shields.io/github/license/jacobtread/blaze-ssl-async?style=for-the-badge)
![Cargo Version](https://img.shields.io/crates/v/blaze-ssl-async?style=for-the-badge)
![Cargo Downloads](https://img.shields.io/crates/d/blaze-ssl-async?style=for-the-badge)


> 📌**IMPORTANT**📌 If you're here looking for a security focused SSL library this is not it check out
> [rustls (https://github.com/rustls/rustls)](https://github.com/rustls/rustls) This 
> library exists to fill a legacy need for EA games that depend upon the 
> gosredirector.ea.com service

This is the async implementation of Blaze-SSL (Using tokio) if you would like a sync version you can
find that [Here](https://github.com/jacobtread/blaze-ssl) 

## ❔ What

This is a bare minimum implementation of the SSLv3 protocol it implements only the specific server logic
required by the gosredirector.ea.com server. This implementation only implements the TLS_RSA_WITH_RC4_128_SHA
and TLS_RSA_WITH_RC4_128_MD5 cipher suites and only uses the cert.pem and key.pem as the certificate and private
key when used as a server

## ❔ Why 

This SSL implementation is to provide the bare minimum SSL implementation required for the
initial redirect portion of the Mass Effect 3 multiplayer protocol when the client reaches 
out to gosredirector.ea.com. The client refuses to use any other protocols or cipher suites 
and in order to use SSLv3 and these cipher suites you either have to modify Registry keys
(In the case of Schannel) or compile a custom version of OpenSSL; Which isn't very practical
or intuitive for emulating these servers.

## 🧾 License

The MIT License (MIT)

Copyright (c) 2022 Jacobtread

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.