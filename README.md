# Windows Webauthn/fido2 key remover
A simple tool to remove WebAuthn credentials from windows.

Unfortunately, Windows does not have a built in interface to remove fido2 platform keys.
This console apps makes it easy to remove webauthn keys from windows hello.

In case you want to add more domains for domain detection (relying party), just create a file `domains.csv` in the same folder and list the domains without the hash. The hashes are calculated automatically.


[Download the latest release](https://github.com/passwordless/webauthn-fido2-key-remover/releases) or build from source yourself.

![Screenshot](https://user-images.githubusercontent.com/357283/118789707-56c01980-b895-11eb-925d-7cabcaed2408.png)

![Gif recording](https://user-images.githubusercontent.com/357283/118731547-55610380-b839-11eb-8ead-d9d2ab5bb289.gif)
