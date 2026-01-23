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

   Note: If you start `sstpc` with `--password`, the client will write the password to a temporary file and pass it to `pppd` using the `file <tmpfile>` option (see `src/sstp-pppd.c`). In that case `/etc/ppp/chap-secrets` may be unused. The temporary file is removed on cleanup, but ensure your system umask/permissions are secure and that the file is not left accessible to other users.

2. Create a connect script in `/etc/ppp/peers/sstp-test`, similar to the example in `./support` (replace user-name as appropriate)
3. Start the script with: `pon sstp-test`


### macOS → Windows Server 2022 (note)

On macOS, the shipped `pppd` may not support EAP/MSCHAPv2 inside EAP (EAP-MSCHAPv2). If your Windows Server uses that EAP method you can often connect by forcing PPP to refuse EAP and negotiate MS-CHAPv2 instead.

Example (sanitised) command that successfully connected to a Windows Server 2022 in our tests:

```bash
# remove old pppd logfile then start sstpc (replace placeholders)
rm -rf pppd.log && sudo src/sstpc \
  --user 'DOMAIN\\user' \
  --password '<your-password>' \
  --debug --log-stdout --log-level 3 \
  server.example.domain.tld \
  -- debug refuse-eap logfile pppd.log
```

Notes:
- The `--` separates sstpc options from options passed to `pppd` (here: `debug`, `refuse-eap`, `logfile pppd.log`).
- Use `refuse-eap` to work around lack of EAP‑MSCHAPv2 support in the system `pppd` — it forces PPP to negotiate MS‑CHAPv2. Also add `require-mschap-v2` in pppd options if you want to require v2.
- Check `pppd.log` (or the file you configured with `logfile`) to inspect PPP negotiation messages and troubleshoot authentication issues.
- Make sure `/etc/ppp/chap-secrets` contains an entry matching the expected server name (or use `*` for the server field) and that its permissions are `600`.

EAP + MPPE proxy (new)

- You can now enable sstp-client to act as an EAP+MPPE proxy with `--eap-auth`. When enabled, sstp-client handles EAP (EAP‑MSCHAPv2) negotiation and MPPE encryption/decryption itself and presents a clear PPP stream to the local `pppd` process.
- Usage: add `--eap-auth` to your `sstpc` command line. Example:

```bash
sudo src/sstpc --eap-auth --user 'DOMAIN\\user' --password '<pwd>' --debug --log-stdout server.example.tld -- debug logfile pppd.log
```

Notes:
- Initial implementation supports direct **EAP‑MSCHAPv2** and **MPPE**. PEAP/TTLS (EAP inside TLS) is not supported yet.
- The MPPE implementation is functional for typical servers but does not yet implement advanced rekeying optimizations — please report interoperability issues.
- This feature reuses algorithms and concepts from pppd (GPL‑2), see source attribution in the codebase.



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