# XelSSH — an SSH-2 / SFTP client in pure Pascal

About 3,700 lines, no DLLs, no OpenSSL, no libssh. Cryptography comes from XelSSL.

## Features

| | |
|---|---|
| Key exchange | curve25519-sha256 (+ @libssh.org), ecdh-sha2-nistp256/384/521 |
| Host keys | ssh-ed25519, ecdsa-sha2-nistp256/384/521, rsa-sha2-512/256 |
| Ciphers | chacha20-poly1305@openssh.com, aes256/128-gcm@openssh.com, aes256/128-ctr (AES-GCM preferred when the CPU has AES-NI) |
| MACs (CTR only) | hmac-sha2-256/512, hmac-sha2-256/512-etm@openssh.com |
| Protocol | strict KEX (Terrapin mitigation), ext-info (server-sig-algs), server-initiated rekeying, flow control |
| Server key check | known_hosts (hashed `\|1\|` entries, `[host]:port`, wildcards, negation, `@revoked`), pinned `SHA256:` fingerprint; policies strict / accept-new / any |
| Authentication | password, keyboard-interactive (answered with the password), public key: Ed25519, RSA (rsa-sha2-512 / rsa-sha2-256, chosen from the server's server-sig-algs), ECDSA P-256/384/521 |
| Key files | OpenSSH format (`openssh-key-v1`), plain or passphrase-protected (bcrypt_pbkdf + aes256-ctr / aes128-ctr / aes256-gcm); unencrypted PEM: PKCS#1 RSA, SEC1 EC, PKCS#8 RSA/EC/Ed25519. Every loaded key is checked (public part matches the private one) |
| Signing | RSA: CRT with base and exponent blinding; ECDSA: constant-time k*G from XelSSL, blinded inversion; every signature is verified before it is sent |
| Channels | session, exec (stdout / stderr / exit code), subsystems |
| SFTP | version 3: list, stat/lstat, get/put, pipelined upload/download with short-read handling, mkdir/rmdir/remove, rename (posix-rename@openssh.com for atomic overwrite), chmod, times, symlink/readlink, limits@openssh.com |

## Limitations

- client only, no port forwarding, no interactive shell/pty, no agent;
- no certificates (`*-cert-v01@openssh.com`), no FIDO keys (`sk-*`), no DSA, no SHA-1 `ssh-rsa` signatures;
- encrypted PEM keys (`Proc-Type: 4,ENCRYPTED`, `ENCRYPTED PRIVATE KEY`) must be converted first: `ssh-keygen -p -f key`;
- no zlib compression, no legacy algorithms (CBC, SHA-1, diffie-hellman-group*, ssh-rsa with SHA-1);
- the client never initiates a rekey (servers do it, OpenSSH by default after ~1 GB or 1 hour);
- tested on Windows against OpenSSH 9.6 and Rebex SSH; the Unix code paths have not been run yet.

## Files

| Unit | Contents |
|---|---|
| XelSshEd25519 | Ed25519 signing and verification (RFC 8032) |
| XelSshBcrypt | bcrypt_pbkdf (OpenSSH key encryption) |
| XelSshKeys | key files (OpenSSH, PEM, PKCS#8), fingerprints, known_hosts, SSH wire helpers |
| XelSshSign | user key signatures: Ed25519, RSA PKCS#1 v1.5, ECDSA |
| XelSshClient | transport, authentication, channels, exec (`TSshClient`) |
| XelSshSftp | SFTP v3 client (`TSftpClient`) |

## Usage

```pascal
uses XelSshKeys, XelSshClient, XelSshSftp;

var ssh: TSshClient; sftp: TSftpClient; err: RawByteString; code: Integer;
begin
  ssh := TSshClient.Create;               // Policy = hkAcceptNew, ~/.ssh/known_hosts
  try
    if not ssh.ConnectTcp('example.com', 22) then raise Exception.Create(ssh.LastError);
    if not ssh.AuthKey('user', LoadOpenSshPrivateKeyFile('id_ed25519', 'passphrase')) then
      raise Exception.Create(ssh.LastError);  // or ssh.AuthPassword('user', 'secret')
    WriteLn(ssh.Exec('uname -a', err, code));
    sftp := TSftpClient.Create(ssh);
    try
      sftp.UploadFile('local.bin', '/tmp/remote.bin');
      sftp.DownloadFile('/tmp/remote.bin', 'copy.bin');
    finally
      sftp.Free;
    end;
  finally
    ssh.Free;
  end;
end;
```

`TSshClient` can also run over any transport: `SetTransport(Send, Recv)` + `Connect`.
SFTP errors raise `ESftpError` (with the SFTP status in `Code`), transport errors `ESshError`.

## Tests

Transfer speed (Windows → WSL2 VM address, 300 MB, aes128-gcm with AES-NI): about
830–910 MB/s upload and 1 070–1 280 MB/s download; OpenSSH's own client inside the
same VM gets about 740 MB/s from that server. Packets are built, encrypted and decrypted
in place (no copies between the socket buffer and the SFTP data), the socket buffers are
4 MB, and SFTP data is written straight from the channel buffer into the file.

Parallel transfers: `SftpParallelDownload` / `SftpParallelUpload` split one file into
parts that go over several SSH connections at once (the main one and extra ones from a
factory function, each part in its own thread with its own connection; the connection
set-ups overlap). OpenSSH serves every connection with its own process, so the server
side uses several cores too. 1 GB to the WSL VM:

| connections | 1 | 2 | 4 | 8 |
|---|---|---|---|---|
| download | 1 280 MB/s | 1 940 | 2 780 | 2 370 |
| upload | 790 MB/s | 1 210 | 1 880 | 1 640 |

One extra connection costs about 60 ms (key exchange, authentication, the server process),
so files below 8 MB stay on one connection. 
the extra connections are pinned to the host key of the first one.

`ReadAhead` (default `raAuto`): a reader thread receives, authenticates and decrypts
packets while the caller handles the previous ones. It pays off when decryption is the
expensive part — aes128-ctr + HMAC downloads 550 → 650 MB/s — but with hardware AES-GCM
the hand-off between threads costs as much as it saves, so `raAuto` uses it only for
CTR + HMAC or when the CPU has no AES instructions. `raOn` / `raOff` force it. It needs
the built-in socket and more than one CPU (on Unix the program must use `cthreads`).
Through the WSL `localhost` relay every client is slower (it is the relay, not the
protocol). Ed25519 uses the field arithmetic of
XelSSL (`XelSslFe25519`, with its x86-64 addition) and verifies with one shared
doubling chain; `t_ed25519` runs with and without the assembler additions.

## License

MIT — see [LICENSE](LICENSE), which also credits the authors of the code this
library builds on.
