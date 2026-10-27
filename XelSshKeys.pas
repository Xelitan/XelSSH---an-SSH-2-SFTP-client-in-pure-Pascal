// XelSSH - keys: private key files - OpenSSH format (openssh-key-v1; unencrypted or
// aes256-ctr / aes128-ctr / aes256-gcm@openssh.com with bcrypt KDF) and unencrypted
// PEM (PKCS#1 RSA, SEC1 EC, PKCS#8 RSA/EC/Ed25519); key types Ed25519, RSA and
// ECDSA P-256/384/521 (every loaded key is checked for consistency), public key blobs,
// SHA256 fingerprints, base64, and known_hosts files (plain and hashed |1| entries,
// [host]:port, wildcard patterns, negation, @revoked).
// License: MIT.
unit XelSshKeys;

{$mode objfpc}{$H+}{$Q-}{$R-}
{$modeswitch advancedrecords}

interface

uses
  SysUtils, Classes;

type
  TSshPrivateKey = record
    KeyType: string;        // 'ssh-ed25519', 'ssh-rsa', 'ecdsa-sha2-nistp256/384/521'
    Seed: TBytes;           // Ed25519: 32-byte private seed
    Pub: TBytes;            // Ed25519: 32-byte public key; ECDSA: point 04||X||Y
    D: TBytes;              // ECDSA: private scalar (coordinate length); RSA: private exponent
    N, E, P, Q, IQmp: TBytes;  // RSA: modulus, public exponent, primes, q^-1 mod p
    Curve: string;          // ECDSA: 'nistp256', 'nistp384' or 'nistp521'
    Comment: string;
  end;

  TKnownHostsResult = (khUnknown, khMatch, khMismatch, khRevoked);

function Base64Encode(const B: TBytes; Pad: Boolean = True): string;
function Base64Decode(const S: string): TBytes;

// Reads a private key (text of the key file: OpenSSH format or unencrypted PEM).
// Raises an exception with a readable message (wrong passphrase, unsupported key
// type or cipher...).
function LoadOpenSshPrivateKey(const Text: RawByteString; const Passphrase: string): TSshPrivateKey;
function LoadOpenSshPrivateKeyFile(const FileName, Passphrase: string): TSshPrivateKey;

// Public key blob for an Ed25519 key: string "ssh-ed25519" + string pub.
function Ed25519Blob(const Pub: TBytes): TBytes;
// Public key blob of any supported private key (as in the .pub file / authorized_keys).
function SshPublicKeyBlob(const Key: TSshPrivateKey): TBytes;
// "SHA256:..." fingerprint of a public key blob (as shown by ssh-keygen -l).
function SshFingerprint(const Blob: TBytes): string;

// known_hosts lookup for Host:Port and the server key (type + blob).
function KnownHostsCheck(const FileName, Host: string; Port: Integer;
  const KeyType: string; const Blob: TBytes): TKnownHostsResult;
// Appends "host keytype base64" (creates the file and its directory if needed).
procedure KnownHostsAdd(const FileName, Host: string; Port: Integer;
  const KeyType: string; const Blob: TBytes);
// Default known_hosts path: ~/.ssh/known_hosts (%USERPROFILE%\.ssh\known_hosts on Windows).
function DefaultKnownHostsFile: string;

// SSH wire format helpers
function SshString(const B: TBytes): TBytes;
function SshStr(const S: RawByteString): TBytes;
function SshU32(V: UInt32): TBytes;
function SshMpint(const B: TBytes): TBytes;    // unsigned big-endian -> SSH mpint

implementation

uses XelSslHash, XelSslAes, XelSslBigNum, XelSslEcdh, XelSshBcrypt, XelSshEd25519;

procedure KeyError(const Msg: string);
begin
  raise Exception.Create('XelSSH: ' + Msg);
end;

const
  B64: string = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function Base64Encode(const B: TBytes; Pad: Boolean): string;
var i, n: Integer; v: UInt32;
begin
  Result := '';
  i := 0; n := Length(B);
  while i + 2 < n do
  begin
    v := (UInt32(B[i]) shl 16) or (UInt32(B[i + 1]) shl 8) or B[i + 2];
    Result := Result + B64[(v shr 18) + 1] + B64[((v shr 12) and 63) + 1] +
      B64[((v shr 6) and 63) + 1] + B64[(v and 63) + 1];
    Inc(i, 3);
  end;
  if n - i = 1 then
  begin
    v := UInt32(B[i]) shl 16;
    Result := Result + B64[(v shr 18) + 1] + B64[((v shr 12) and 63) + 1];
    if Pad then Result := Result + '==';
  end
  else if n - i = 2 then
  begin
    v := (UInt32(B[i]) shl 16) or (UInt32(B[i + 1]) shl 8);
    Result := Result + B64[(v shr 18) + 1] + B64[((v shr 12) and 63) + 1] + B64[((v shr 6) and 63) + 1];
    if Pad then Result := Result + '=';
  end;
end;

function Base64Decode(const S: string): TBytes;
var i, n, idx, bits: Integer; acc: UInt32;
begin
  SetLength(Result, Length(S) * 3 div 4 + 3);
  n := 0; acc := 0; bits := 0;
  for i := 1 to Length(S) do
  begin
    idx := Pos(S[i], B64);
    if idx = 0 then Continue;               // whitespace, '=' and line breaks
    acc := (acc shl 6) or UInt32(idx - 1);
    Inc(bits, 6);
    if bits >= 8 then
    begin
      Dec(bits, 8);
      Result[n] := Byte(acc shr bits);
      Inc(n);
    end;
  end;
  SetLength(Result, n);
end;

function SshU32(V: UInt32): TBytes;
begin
  Result := TBytes.Create(Byte(V shr 24), Byte(V shr 16), Byte(V shr 8), Byte(V));
end;

function SshString(const B: TBytes): TBytes;
begin
  Result := Concat(SshU32(Length(B)), B);
end;

function SshStr(const S: RawByteString): TBytes;
begin
  Result := SshString(BytesOf(S));
end;

function StripZeros(const B: TBytes): TBytes;
var i: Integer;
begin
  i := 0;
  while (i < Length(B)) and (B[i] = 0) do Inc(i);
  Result := Copy(B, i, Length(B) - i);
end;

function SshMpint(const B: TBytes): TBytes;
var t: TBytes;
begin
  t := StripZeros(B);
  if (Length(t) > 0) and (t[0] >= $80) then t := Concat(TBytes.Create(0), t);
  Result := SshString(t);
end;

// curve name ('nistp256'...) -> XelSSL curve; False if unsupported
function CurveOf(const Name: string; out C: TEcdhCurve): Boolean;
begin
  Result := True;
  if Name = 'nistp256' then C := ecdhP256
  else if Name = 'nistp384' then C := ecdhP384
  else if Name = 'nistp521' then C := ecdhP521
  else Result := False;
end;

// left-pads a big-endian number to Len bytes (fails if it does not fit)
function PadTo(const B: TBytes; Len: Integer): TBytes;
var t: TBytes;
begin
  t := StripZeros(B);
  if Length(t) > Len then KeyError('invalid key (number too large)');
  SetLength(Result, Len - Length(t));
  if Length(Result) > 0 then FillChar(Result[0], Length(Result), 0);
  Result := Concat(Result, t);
end;

// Checks that the private and public parts of a key belong together.
procedure CheckKey(var K: TSshPrivateKey);
var c: TEcdhCurve; d, n: TBig; pub: TBytes;
begin
  if K.KeyType = 'ssh-ed25519' then
  begin
    if (Length(K.Seed) <> 32) or (Length(K.Pub) <> 32) then KeyError('invalid Ed25519 key');
    if not SameBytesCT(Ed25519PublicKey(K.Seed), K.Pub) then KeyError('invalid Ed25519 key (public part does not match)');
  end
  else if K.KeyType = 'ssh-rsa' then
  begin
    K.N := StripZeros(K.N); K.E := StripZeros(K.E); K.D := StripZeros(K.D);
    K.P := StripZeros(K.P); K.Q := StripZeros(K.Q); K.IQmp := StripZeros(K.IQmp);
    if (Length(K.N) < 128) then KeyError('RSA keys shorter than 1024 bits are not supported');
    if (Length(K.N) > 1024) then KeyError('RSA keys longer than 8192 bits are not supported');
    if (Length(K.E) = 0) or (Length(K.E) > 8) or (Length(K.P) = 0) or (Length(K.Q) = 0) or (Length(K.D) = 0) then
      KeyError('invalid RSA key');
    if BigCmp(BigMul(BigFromBytes(K.P), BigFromBytes(K.Q)), BigFromBytes(K.N)) <> 0 then
      KeyError('invalid RSA key (n <> p*q)');
    // q^-1 mod p is recomputed - some files have it wrong or missing
    K.IQmp := BigToBytes(BigModInvPrime(BigMod(BigFromBytes(K.Q), BigFromBytes(K.P)), BigFromBytes(K.P)));
  end
  else if Copy(K.KeyType, 1, 11) = 'ecdsa-sha2-' then
  begin
    if not CurveOf(K.Curve, c) or (K.KeyType <> 'ecdsa-sha2-' + K.Curve) then
      KeyError('unsupported ECDSA curve "' + K.Curve + '"');
    K.D := PadTo(K.D, EcdhCoordLen(c));
    d := BigFromBytes(K.D);
    n := BigFromBytes(EcdhOrder(c));
    if BigIsZero(d) or (BigCmp(d, n) >= 0) then KeyError('invalid ECDSA key');
    try
      pub := EcdhPublicOf(c, K.D);
    except
      KeyError('invalid ECDSA key');
    end;
    if (Length(K.Pub) > 0) and not SameBytesCT(pub, K.Pub) then KeyError('invalid ECDSA key (public part does not match)');
    K.Pub := pub;
  end
  else
    KeyError('unsupported key type "' + K.KeyType + '" (supported: ssh-ed25519, ssh-rsa, ecdsa-sha2-nistp256/384/521)');
end;

function SshPublicKeyBlob(const Key: TSshPrivateKey): TBytes;
begin
  if Key.KeyType = 'ssh-ed25519' then Result := Ed25519Blob(Key.Pub)
  else if Key.KeyType = 'ssh-rsa' then Result := Concat(SshStr('ssh-rsa'), SshMpint(Key.E), SshMpint(Key.N))
  else if Copy(Key.KeyType, 1, 11) = 'ecdsa-sha2-' then
    Result := Concat(SshStr(Key.KeyType), SshStr(Key.Curve), SshString(Key.Pub))
  else
    KeyError('unsupported key type "' + Key.KeyType + '"');
end;

type
  TBuf = record
    B: TBytes; P: Integer;
    function U32: UInt32;
    function Str: TBytes;
    function Text: string;
  end;

function TBuf.U32: UInt32;
begin
  if P + 4 > Length(B) then raise Exception.Create('XelSSH: truncated key data');
  Result := (UInt32(B[P]) shl 24) or (UInt32(B[P + 1]) shl 16) or (UInt32(B[P + 2]) shl 8) or B[P + 3];
  Inc(P, 4);
end;

function TBuf.Str: TBytes;
var n: UInt32;
begin
  n := U32;
  if n > UInt32(Length(B) - P) then raise Exception.Create('XelSSH: truncated key data');
  Result := Copy(B, P, n);
  Inc(P, n);
end;

function TBuf.Text: string;
var t: TBytes;
begin
  t := Str;
  SetString(Result, PAnsiChar(@t[0]), Length(t));
  if Length(t) = 0 then Result := '';
end;

// AES-CTR with a full 128-bit big-endian counter (OpenSSH style)
procedure AesCtr(const Key, IV: TBytes; var Data: TBytes);
var k: TAesKey; ctr, ks: array[0..15] of Byte; i, j, n: Integer;
begin
  AesSetKey(k, Key);
  Move(IV[0], ctr[0], 16);
  i := 0;
  while i < Length(Data) do
  begin
    AesEncryptBlocks(k, @ctr[0], @ks[0], 1);
    n := 16; if Length(Data) - i < n then n := Length(Data) - i;
    for j := 0 to n - 1 do Data[i + j] := Data[i + j] xor ks[j];
    Inc(i, 16);
    for j := 15 downto 0 do
    begin
      Inc(ctr[j]);
      if ctr[j] <> 0 then Break;
    end;
  end;
  FillChar(k, SizeOf(k), 0);
end;

// ---- PEM / DER (unencrypted PKCS#1, SEC1 and PKCS#8 keys) ----

type
  TDer = record
    B: TBytes; P, Stop: Integer;
    procedure Init(const X: TBytes);
    function More: Boolean;
    function Peek: Integer;
    function Read(Tag: Integer): TBytes;     // contents of the next element (must have Tag)
    function Int: TBytes;                     // INTEGER, unsigned, without leading zeros
  end;

procedure TDer.Init(const X: TBytes); begin B := X; P := 0; Stop := Length(X); end;
function TDer.More: Boolean; begin Result := P < Stop; end;
function TDer.Peek: Integer; begin if P < Stop then Result := B[P] else Result := -1; end;

function TDer.Read(Tag: Integer): TBytes;
var len, nb, i: Integer;
begin
  if (P + 2 > Stop) or (B[P] <> Tag) then KeyError('invalid PEM key (unexpected DER structure)');
  Inc(P);
  len := B[P]; Inc(P);
  if len >= $80 then
  begin
    nb := len and $7F;
    if (nb = 0) or (nb > 3) or (P + nb > Stop) then KeyError('invalid PEM key (bad DER length)');
    len := 0;
    for i := 1 to nb do begin len := (len shl 8) or B[P]; Inc(P); end;
  end;
  if P + len > Stop then KeyError('invalid PEM key (truncated)');
  Result := Copy(B, P, len);
  Inc(P, len);
end;

function TDer.Int: TBytes;
begin
  Result := StripZeros(Read($02));
end;

const
  OID_RSA: array[0..8] of Byte = ($2A, $86, $48, $86, $F7, $0D, $01, $01, $01);
  OID_EC: array[0..6] of Byte = ($2A, $86, $48, $CE, $3D, $02, $01);
  OID_ED25519: array[0..2] of Byte = ($2B, $65, $70);
  OID_P256: array[0..7] of Byte = ($2A, $86, $48, $CE, $3D, $03, $01, $07);
  OID_P384: array[0..4] of Byte = ($2B, $81, $04, $00, $22);
  OID_P521: array[0..4] of Byte = ($2B, $81, $04, $00, $23);

function OidIs(const O: TBytes; const Ref: array of Byte): Boolean;
begin
  Result := (Length(O) = Length(Ref)) and CompareMem(@O[0], @Ref[0], Length(Ref));
end;

function CurveFromOid(const O: TBytes): string;
begin
  if OidIs(O, OID_P256) then Result := 'nistp256'
  else if OidIs(O, OID_P384) then Result := 'nistp384'
  else if OidIs(O, OID_P521) then Result := 'nistp521'
  else KeyError('unsupported EC curve in the key');
end;

// PKCS#1 RSAPrivateKey
procedure ParseRsaDer(const Der: TBytes; var K: TSshPrivateKey);
var R, S: TDer;
begin
  R.Init(Der);
  S.Init(R.Read($30));
  S.Int;                                         // version
  K.KeyType := 'ssh-rsa';
  K.N := S.Int; K.E := S.Int; K.D := S.Int; K.P := S.Int; K.Q := S.Int;
  S.Int; S.Int;                                  // d mod (p-1), d mod (q-1)
  K.IQmp := S.Int;
end;

// SEC1 ECPrivateKey; Curve = from the PKCS#8 header ('' = must be inside)
procedure ParseEcDer(const Der: TBytes; const Curve: string; var K: TSshPrivateKey);
var R, S, T: TDer; bits: TBytes;
begin
  R.Init(Der);
  S.Init(R.Read($30));
  S.Int;                                         // version 1
  K.D := S.Read($04);
  K.Curve := Curve;
  while S.More do
    case S.Peek of
      $A0: begin T.Init(S.Read($A0)); K.Curve := CurveFromOid(T.Read($06)); end;
      $A1:
        begin
          T.Init(S.Read($A1));
          bits := T.Read($03);
          if (Length(bits) > 1) and (bits[0] = 0) then K.Pub := Copy(bits, 1, Length(bits) - 1);
        end;
    else
      Break;
    end;
  if K.Curve = '' then KeyError('EC key without a curve');
  K.KeyType := 'ecdsa-sha2-' + K.Curve;
end;

function LoadPemKey(const Text: RawByteString): TSshPrivateKey;
var
  label_, body: string; p, e, q: Integer; der, alg, inner: TBytes; R, S, A, T: TDer;
begin
  Result := Default(TSshPrivateKey);
  p := Pos('-----BEGIN ', Text);
  q := Pos('-----', Copy(Text, p + 11, 80));
  if q = 0 then KeyError('invalid PEM key');
  label_ := Copy(Text, p + 11, q - 1);
  e := Pos('-----END ' + label_ + '-----', Text);
  if e = 0 then KeyError('invalid PEM key (no END line)');
  body := Copy(Text, p + 11 + q + 4, e - (p + 11 + q + 4));
  if (Pos('ENCRYPTED', label_) > 0) or (Pos('Proc-Type:', body) > 0) then
    KeyError('encrypted PEM keys are not supported - convert the key to the OpenSSH format with: ssh-keygen -p -f <key file>');
  der := Base64Decode(body);
  if label_ = 'RSA PRIVATE KEY' then ParseRsaDer(der, Result)
  else if label_ = 'EC PRIVATE KEY' then ParseEcDer(der, '', Result)
  else if label_ = 'PRIVATE KEY' then
  begin
    // PKCS#8: SEQUENCE { version, AlgorithmIdentifier, OCTET STRING key, ... }
    R.Init(der);
    S.Init(R.Read($30));
    S.Int;
    A.Init(S.Read($30));
    alg := A.Read($06);
    inner := S.Read($04);
    if OidIs(alg, OID_RSA) then ParseRsaDer(inner, Result)
    else if OidIs(alg, OID_EC) then ParseEcDer(inner, CurveFromOid(A.Read($06)), Result)
    else if OidIs(alg, OID_ED25519) then
    begin
      T.Init(inner);
      Result.KeyType := 'ssh-ed25519';
      Result.Seed := T.Read($04);
      if Length(Result.Seed) <> 32 then KeyError('invalid Ed25519 key');
      Result.Pub := Ed25519PublicKey(Result.Seed);
    end
    else KeyError('unsupported key algorithm in the PKCS#8 key');
  end
  else if label_ = 'OPENSSH PRIVATE KEY' then KeyError('invalid OpenSSH key')
  else KeyError('unsupported key file ("' + label_ + '")');
  Wipe(der); Wipe(inner);
  CheckKey(Result);
end;

function LoadOpenSshPrivateKey(const Text: RawByteString; const Passphrase: string): TSshPrivateKey;
const
  BeginTag = '-----BEGIN OPENSSH PRIVATE KEY-----';
  EndTag = '-----END OPENSSH PRIVATE KEY-----';
  Magic = 'openssh-key-v1'#0;
var
  p, e, nkeys, keyLen, ivLen: Integer; raw, sec, kdfopt, kd, plain, tag: TBytes;
  R, K, S: TBuf; cipher, kdf, ktype: string; salt: TBytes; rounds, check1, check2: UInt32; g: TGcmKey;
begin
  Result := Default(TSshPrivateKey);
  p := Pos(BeginTag, Text);
  e := Pos(EndTag, Text);
  if (p = 0) or (e <= p) then
  begin
    if Pos('-----BEGIN', Text) > 0 then Exit(LoadPemKey(Text));
    KeyError('not a private key file');
  end;
  raw := Base64Decode(Copy(Text, p + Length(BeginTag), e - p - Length(BeginTag)));
  if (Length(raw) < Length(Magic)) or not CompareMem(@raw[0], PAnsiChar(Magic), Length(Magic)) then
    raise Exception.Create('XelSSH: invalid OpenSSH key header');
  R.B := raw; R.P := Length(Magic);
  cipher := R.Text;
  kdf := R.Text;
  kdfopt := R.Str;
  nkeys := R.U32;
  if nkeys <> 1 then raise Exception.Create('XelSSH: key files with several keys are not supported');
  R.Str;                                         // public key blob (repeated inside)
  sec := R.Str;
  if cipher = 'none' then
    plain := sec
  else
  begin
    if kdf <> 'bcrypt' then raise Exception.Create('XelSSH: unsupported key KDF "' + kdf + '"');
    if Passphrase = '' then raise Exception.Create('XelSSH: the key is encrypted - a passphrase is required');
    K.B := kdfopt; K.P := 0;
    salt := K.Str;
    rounds := K.U32;
    if (rounds < 1) or (rounds > 10000) then raise Exception.Create('XelSSH: invalid bcrypt rounds');
    if (cipher = 'aes256-ctr') or (cipher = 'aes256-gcm@openssh.com') then keyLen := 32
    else if cipher = 'aes128-ctr' then keyLen := 16
    else raise Exception.Create('XelSSH: unsupported key cipher "' + cipher + '"');
    if cipher = 'aes256-gcm@openssh.com' then ivLen := 12 else ivLen := 16;
    kd := BcryptPbkdf(BytesOf(Passphrase), salt, rounds, keyLen + ivLen);
    if cipher = 'aes256-gcm@openssh.com' then
    begin
      // the 16-byte tag follows the encrypted section in the outer buffer
      tag := Copy(raw, R.P, 16);
      if Length(tag) <> 16 then raise Exception.Create('XelSSH: truncated key data');
      GcmSetKey(g, Copy(kd, 0, keyLen));
      if not GcmOpen(g, Copy(kd, keyLen, 12), nil, Concat(sec, tag), plain) then
        raise Exception.Create('XelSSH: wrong passphrase for the key');
    end
    else
    begin
      plain := Copy(sec);
      AesCtr(Copy(kd, 0, keyLen), Copy(kd, keyLen, 16), plain);
    end;
    Wipe(kd);
  end;
  S.B := plain; S.P := 0;
  check1 := S.U32;
  check2 := S.U32;
  if check1 <> check2 then raise Exception.Create('XelSSH: wrong passphrase for the key');
  ktype := S.Text;
  Result.KeyType := ktype;
  if ktype = 'ssh-ed25519' then
  begin
    Result.Pub := S.Str;
    kd := S.Str;                                // seed (32) || public key (32)
    if (Length(Result.Pub) <> 32) or (Length(kd) <> 64) then KeyError('invalid Ed25519 key');
    Result.Seed := Copy(kd, 0, 32);
  end
  else if ktype = 'ssh-rsa' then
  begin
    Result.N := S.Str; Result.E := S.Str; Result.D := S.Str;
    Result.IQmp := S.Str; Result.P := S.Str; Result.Q := S.Str;
  end
  else if Copy(ktype, 1, 11) = 'ecdsa-sha2-' then
  begin
    Result.Curve := S.Text;
    Result.Pub := S.Str;
    Result.D := S.Str;
  end
  else
    KeyError('unsupported key type "' + ktype + '" (supported: ssh-ed25519, ssh-rsa, ecdsa-sha2-nistp256/384/521)');
  Result.Comment := S.Text;
  Wipe(kd); Wipe(plain);
  CheckKey(Result);
end;

function LoadOpenSshPrivateKeyFile(const FileName, Passphrase: string): TSshPrivateKey;
var fs: TFileStream; s: RawByteString;
begin
  if not FileExists(FileName) then raise Exception.Create('XelSSH: key file not found: ' + FileName);
  try
    fs := TFileStream.Create(FileName, fmOpenRead or fmShareDenyNone);
  except
    raise Exception.Create('XelSSH: cannot read the key file ' + FileName);
  end;
  try
    SetLength(s, fs.Size);
    if fs.Size > 0 then fs.ReadBuffer(s[1], fs.Size);
  finally
    fs.Free;
  end;
  Result := LoadOpenSshPrivateKey(s, Passphrase);
end;

function Ed25519Blob(const Pub: TBytes): TBytes;
begin
  Result := Concat(SshStr('ssh-ed25519'), SshString(Pub));
end;

function SshFingerprint(const Blob: TBytes): string;
begin
  Result := 'SHA256:' + Base64Encode(Hash(haSHA256, Blob), False);
end;

// ---- known_hosts ----

function DefaultKnownHostsFile: string;
var home: string;
begin
  {$IFDEF MSWINDOWS}
  home := GetEnvironmentVariable('USERPROFILE');
  {$ELSE}
  home := GetEnvironmentVariable('HOME');
  {$ENDIF}
  Result := IncludeTrailingPathDelimiter(home) + '.ssh' + PathDelim + 'known_hosts';
end;

function HostKeyName(const Host: string; Port: Integer): string;
begin
  if Port = 22 then Result := LowerCase(Host)
  else Result := '[' + LowerCase(Host) + ']:' + IntToStr(Port);
end;

// '*' and '?' wildcards
function WildMatch(const Pat, S: string): Boolean;
  function M(pi, si: Integer): Boolean;
  begin
    while pi <= Length(Pat) do
    begin
      if Pat[pi] = '*' then
      begin
        while (pi <= Length(Pat)) and (Pat[pi] = '*') do Inc(pi);
        if pi > Length(Pat) then Exit(True);
        while si <= Length(S) do
        begin
          if M(pi, si) then Exit(True);
          Inc(si);
        end;
        Exit(False);
      end;
      if si > Length(S) then Exit(False);
      if (Pat[pi] <> '?') and (LowerCase(Pat[pi]) <> LowerCase(S[si])) then Exit(False);
      Inc(pi); Inc(si);
    end;
    Result := si > Length(S);
  end;
begin
  Result := M(1, 1);
end;

// does a host pattern field (comma-separated, possibly hashed) match the name?
function HostFieldMatches(const Field, Name: string): Boolean;
var parts: TStringArray; i: Integer; p, salt, h: string; neg: Boolean; sb, hb: TBytes;
begin
  Result := False;
  if Copy(Field, 1, 3) = '|1|' then
  begin
    parts := Copy(Field, 4, MaxInt).Split(['|']);
    if Length(parts) <> 2 then Exit;
    salt := parts[0]; h := parts[1];
    sb := Base64Decode(salt); hb := Base64Decode(h);
    Exit(SameBytesCT(Hmac(haSHA1, sb, BytesOf(Name)), hb));
  end;
  parts := Field.Split([',']);
  for i := 0 to High(parts) do
  begin
    p := parts[i];
    neg := (p <> '') and (p[1] = '!');
    if neg then Delete(p, 1, 1);
    if WildMatch(p, Name) then
    begin
      if neg then Exit(False);        // negated match excludes the host
      Result := True;
    end;
  end;
end;

function KnownHostsCheck(const FileName, Host: string; Port: Integer;
  const KeyType: string; const Blob: TBytes): TKnownHostsResult;
var L: TStringList; i: Integer; line, name, marker: string; f: TStringArray; key: TBytes;
begin
  Result := khUnknown;
  if not FileExists(FileName) then Exit;
  name := HostKeyName(Host, Port);
  L := TStringList.Create;
  try
    L.LoadFromFile(FileName);
    for i := 0 to L.Count - 1 do
    begin
      line := Trim(L[i]);
      if (line = '') or (line[1] = '#') then Continue;
      f := line.Split([' ', #9], TStringSplitOptions.ExcludeEmpty);
      marker := '';
      if (Length(f) > 0) and (f[0] <> '') and (f[0][1] = '@') then
      begin
        marker := LowerCase(f[0]);
        f := Copy(f, 1, Length(f) - 1);
      end;
      if Length(f) < 3 then Continue;
      if marker = '@cert-authority' then Continue;
      if not HostFieldMatches(f[0], name) then Continue;
      key := Base64Decode(f[2]);
      if marker = '@revoked' then
      begin
        if SameBytesCT(key, Blob) then Exit(khRevoked);
        Continue;
      end;
      if f[1] <> KeyType then Continue;
      if SameBytesCT(key, Blob) then Result := khMatch
      else if Result <> khMatch then Result := khMismatch;
    end;
  finally
    L.Free;
  end;
end;

procedure KnownHostsAdd(const FileName, Host: string; Port: Integer;
  const KeyType: string; const Blob: TBytes);
var fs: TFileStream; line: RawByteString; dir: string; lastByte: Byte;
begin
  dir := ExtractFileDir(FileName);
  if (dir <> '') and not DirectoryExists(dir) then ForceDirectories(dir);
  line := HostKeyName(Host, Port) + ' ' + KeyType + ' ' + Base64Encode(Blob) + #10;
  if FileExists(FileName) then
  begin
    fs := TFileStream.Create(FileName, fmOpenReadWrite or fmShareDenyWrite);
    if fs.Size > 0 then
    begin
      fs.Position := fs.Size - 1;
      fs.ReadBuffer(lastByte, 1);
      if lastByte <> 10 then line := #10 + line;
    end;
    fs.Position := fs.Size;
  end
  else
    fs := TFileStream.Create(FileName, fmCreate);
  try
    fs.WriteBuffer(line[1], Length(line));
  finally
    fs.Free;
  end;
end;

end.
