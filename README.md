# SSTP-CLIENT

---

## Background

SSTP is Microsoft's Remote Access Solution (RAS) for PPP over SSL. It can be used instead of PPTP or L2TP, and is available for Windows Vista/7 connecting to a Windows 2008 Server. For further information on SSTP, see the Wikipedia article:

- https://en.wikipedia.org/wiki/Secure_Socket_Tunneling_Protocol


## What is SSTP-CLIENT

SSTP-CLIENT is an SSTP client for Linux. It establishes an SSTP connection to a Windows 2008 Server. The software aims for command-line and configuration compatibility with the `pptp-client` software.


## Features

- Establish a SSTP connection to a remote Windows 2008 server
- Async PPP support (works with most distributions)
- Similar command-line handling as `pptp-client` for easy integration
- IPv6 support
- Basic HTTP proxy support
- Certificate handling and verification
- SSTP plugin integration with NetworkManager v0.9 (available as a separate package)


## SSTP-CLIENT on Ubuntu

Example integration steps for Ubuntu/Debian:

1. Specify your MSCHAP password in `/etc/ppp/chap-secrets`

   Example entry:

   ```text
   SSTP-TEST\\JonDoe  sstp-test   'testme1234!'    *
   ```

2. Create a connect script in `/etc/ppp/peers/sstp-test`, similar to the example in `./support` (replace user-name as appropriate)
3. Start the script with: `pon sstp-test`


## Future

We plan to provide SSTP server functionality in the future. The code has been refactored to make this achievable. See `TODO` for desired features.


## Help Wanted

Contributions are welcome — see `TODO` for a list of wanted features. If you can help, please contact the maintainer.


## Compiling

Make sure development tools and headers are available. This project depends on PPP, libevent and OpenSSL.

Example on Debian/Ubuntu:

```bash
sudo apt-get install ppp-dev libevent-dev libssl-dev
./configure --disable-ppp-plugin && make -j$(nproc)
```


## Important Links

- How to setup SSTP on Windows 2008 Server (Microsoft technet):
  https://technet.microsoft.com/en-us/library/cc731352(WS.10).aspx
- SSTP specification: https://msdn.microsoft.com/en-us/library/cc247338(v=prot.10).aspx
- PPTP client reference (similarities): http://pptpclient.sourceforge.net/
- OpenSSL examples: http://www.rtfm.com/openssl-examples/


## Other related software required

- OpenSSL (https://www.openssl.org)
- PPPD (http://ppp.samba.org)
- libevent (https://libevent.org)