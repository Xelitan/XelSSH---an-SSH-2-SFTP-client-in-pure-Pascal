// XelSSH - signatures made with the user's private key (publickey authentication):
// ssh-ed25519, rsa-sha2-512 / rsa-sha2-256 (PKCS#1 v1.5) and ecdsa-sha2-nistp256/384/521.
//
// RSA: CRT with base blinding (random r, m * r^e) and exponent blinding
// (d mod (p-1) + k * (p-1) with a random 64-bit k), because the big number code of
// XelSSL is not constant time. ECDSA: k*G with the constant-time ladder of XelSslEcdh,
// random k, and the modular inversion done on k*b for a random b.
// Every signature is verified before it is returned (protection against faults).
// License: MIT.
unit XelSshSign;

{$mode objfpc}{$H+}{$Q-}{$R-}

interface

uses
  SysUtils, XelSslHash, XelSshKeys;

// Signature algorithm for the key. ServerSigAlgs = the server's "server-sig-algs"
// list ('' = unknown). Raises an exception if the server accepts no usable algorithm.
function SshSignAlgorithm(const Key: TSshPrivateKey; const ServerSigAlgs: string): string;
// SSH signature blob of Data: string algorithm + string signature.
function SshSign(const Key: TSshPrivateKey; const Alg: string; const Data: TBytes): TBytes;

// raw primitives (exported for tests)
function RsaSignPkcs1(const Key: TSshPrivateKey; Alg: THashAlg; const Data: TBytes): TBytes;
procedure EcdsaSignRaw(const Key: TSshPrivateKey; const Data: TBytes; out R, S: TBytes);

implementation

uses XelSslBigNum, XelSslEcdh, XelSslPk, XelSslRandom, XelSshEd25519;

procedure SignError(const Msg: string);
begin
  raise Exception.Create('XelSSH: ' + Msg);
end;

function StripZerosOf(const B: TBytes): TBytes;
var i: Integer;
begin
  i := 0;
  while (i < Length(B)) and (B[i] = 0) do Inc(i);
  Result := Copy(B, i, Length(B) - i);
end;

function NameIn(const Name, List: string): Boolean;
var a: TStringArray; i: Integer;
begin
  a := List.Split([',']);
  for i := 0 to High(a) do if Trim(a[i]) = Name then Exit(True);
  Result := False;
end;

function SshSignAlgorithm(const Key: TSshPrivateKey; const ServerSigAlgs: string): string;
begin
  if Key.KeyType = 'ssh-rsa' then
  begin
    // the SHA-1 "ssh-rsa" signature is not supported; servers without ext-info
    // (OpenSSH before 7.2) get rsa-sha2-512 anyway
    if (ServerSigAlgs = '') or NameIn('rsa-sha2-512', ServerSigAlgs) then Result := 'rsa-sha2-512'
    else if NameIn('rsa-sha2-256', ServerSigAlgs) then Result := 'rsa-sha2-256'
    else
      SignError('the server accepts RSA keys only with SHA-1 signatures (ssh-rsa), which are not supported');
  end
  else
    Result := Key.KeyType;
end;

// ---- RSA ----

function RandomBig(const Below: TBig): TBig;      // uniform-ish in [2, Below-1]
var n: Integer;
begin
  n := (BigBits(Below) + 7) div 8 + 8;
  repeat
    Result := BigMod(BigFromBytes(RandomBytes(n)), Below);
  until BigBits(Result) > 1;
end;

function DigestInfo(Alg: THashAlg): TBytes;
begin
  case Alg of
    haSHA256: Result := TBytes.Create($30, $31, $30, $0D, $06, $09, $60, $86, $48, $01, $65, $03, $04, $02, $01,
      $05, $00, $04, $20);
    haSHA512: Result := TBytes.Create($30, $51, $30, $0D, $06, $09, $60, $86, $48, $01, $65, $03, $04, $02, $03,
      $05, $00, $04, $40);
  else
    SignError('unsupported RSA signature hash');
  end;
end;

function RsaSignPkcs1(const Key: TSshPrivateKey; Alg: THashAlg; const Data: TBytes): TBytes;
var
  n, e, d, p, q, iqmp, m, r, rp, rq, mb, dp, dq, sp, sq, h, s, rinv, one, p1, q1, kb: TBig;
  t, em: TBytes; k, i: Integer;
begin
  n := BigFromBytes(Key.N); e := BigFromBytes(Key.E); d := BigFromBytes(Key.D);
  p := BigFromBytes(Key.P); q := BigFromBytes(Key.Q); iqmp := BigFromBytes(Key.IQmp);
  k := Length(StripZerosOf(Key.N));
  // EMSA-PKCS1-v1_5: 00 01 FF..FF 00 DigestInfo H
  t := Concat(DigestInfo(Alg), Hash(Alg, Data));
  if k < Length(t) + 11 then SignError('the RSA key is too short for this hash');
  SetLength(em, k);
  em[0] := 0; em[1] := 1;
  for i := 2 to k - Length(t) - 2 do em[i] := $FF;
  em[k - Length(t) - 1] := 0;
  Move(t[0], em[k - Length(t)], Length(t));
  m := BigFromBytes(em);

  one := BigFromInt(1);
  p1 := BigSub(p, one); q1 := BigSub(q, one);
  // base blinding: mb = m * r^e mod n
  repeat
    r := RandomBig(n);
    rp := BigMod(r, p); rq := BigMod(r, q);
  until not BigIsZero(rp) and not BigIsZero(rq);
  mb := BigModMul(m, BigModExp(r, e, n), n);
  // exponent blinding: dp + kb*(p-1), dq + kb*(q-1)
  kb := BigFromBytes(RandomBytes(8));
  dp := BigAdd(BigMod(d, p1), BigMul(kb, p1));
  kb := BigFromBytes(RandomBytes(8));
  dq := BigAdd(BigMod(d, q1), BigMul(kb, q1));
  sp := BigModExp(BigMod(mb, p), dp, p);
  sq := BigModExp(BigMod(mb, q), dq, q);
  // CRT: s = sq + q * (iqmp * (sp - sq) mod p)
  h := BigModMul(iqmp, BigModSub(sp, BigMod(sq, p), p), p);
  s := BigAdd(sq, BigMul(h, q));
  // unblind: r^-1 mod n, also through CRT
  rp := BigModInvPrime(rp, p);
  rq := BigModInvPrime(rq, q);
  h := BigModMul(iqmp, BigModSub(rp, BigMod(rq, p), p), p);
  rinv := BigAdd(rq, BigMul(h, q));
  s := BigModMul(s, rinv, n);
  if BigCmp(BigModExp(s, e, n), m) <> 0 then SignError('RSA signature self-check failed');
  Result := BigToBytes(s, k);
end;

// ---- ECDSA ----

function CurveOfKey(const Key: TSshPrivateKey; out C: TEcdhCurve; out Alg: THashAlg): Boolean;
begin
  Result := True;
  if Key.Curve = 'nistp256' then begin C := ecdhP256; Alg := haSHA256; end
  else if Key.Curve = 'nistp384' then begin C := ecdhP384; Alg := haSHA384; end
  else if Key.Curve = 'nistp521' then begin C := ecdhP521; Alg := haSHA512; end
  else Result := False;
end;

function DerInt(const V: TBytes): TBytes;
var t: TBytes;
begin
  t := StripZerosOf(V);
  if Length(t) = 0 then t := TBytes.Create(0);
  if t[0] >= $80 then t := Concat(TBytes.Create(0), t);
  Result := Concat(TBytes.Create(2, Length(t)), t);
end;

function DerSig(const R, S: TBytes): TBytes;
var body: TBytes;
begin
  body := Concat(DerInt(R), DerInt(S));
  if Length(body) < 128 then Result := Concat(TBytes.Create($30, Length(body)), body)
  else Result := Concat(TBytes.Create($30, $81, Length(body)), body);
end;

procedure EcdsaSignRaw(const Key: TSshPrivateKey; const Data: TBytes; out R, S: TBytes);
var
  c: TEcdhCurve; ha: THashAlg; n, z, d, k, b, rr, ss, kinv, w: TBig; h, kb, pt: TBytes; nb, len: Integer;
  cid: TEcCurveId;
begin
  if not CurveOfKey(Key, c, ha) then SignError('unsupported ECDSA curve');
  n := BigFromBytes(EcdhOrder(c));
  len := EcdhCoordLen(c);
  h := Hash(ha, Data);
  z := BigFromBytes(h);
  nb := BigBits(n);
  if Length(h) * 8 > nb then z := BigShr(z, Length(h) * 8 - nb);
  z := BigMod(z, n);
  d := BigFromBytes(Key.D);
  repeat
    EcdhKeyPair(c, kb, pt);                         // random k and k*G (constant time)
    k := BigFromBytes(kb);
    rr := BigMod(BigFromBytes(Copy(pt, 1, len)), n);
    if BigIsZero(rr) then Continue;
    // s = (k*b)^-1 * b * (z + r*d)  - the inversion never sees k itself
    b := RandomBig(n);
    kinv := BigModInvPrime(BigModMul(k, b, n), n);
    w := BigModAdd(BigModMul(b, z, n), BigModMul(rr, BigModMul(b, d, n), n), n);
    ss := BigModMul(kinv, w, n);
  until not BigIsZero(ss);
  R := BigToBytes(rr); S := BigToBytes(ss);
  case c of
    ecdhP256: cid := ecP256;
    ecdhP384: cid := ecP384;
  else cid := ecP521;
  end;
  if not EcdsaVerify(cid, Key.Pub, h, DerSig(R, S)) then SignError('ECDSA signature self-check failed');
  Wipe(kb);
end;

function SshSign(const Key: TSshPrivateKey; const Alg: string; const Data: TBytes): TBytes;
var sig, r, s: TBytes;
begin
  if Key.KeyType = 'ssh-ed25519' then
  begin
    if Alg <> 'ssh-ed25519' then SignError('signature algorithm does not match the key');
    sig := Ed25519Sign(Key.Seed, Key.Pub, Data);
  end
  else if Key.KeyType = 'ssh-rsa' then
  begin
    if Alg = 'rsa-sha2-512' then sig := RsaSignPkcs1(Key, haSHA512, Data)
    else if Alg = 'rsa-sha2-256' then sig := RsaSignPkcs1(Key, haSHA256, Data)
    else SignError('unsupported RSA signature algorithm "' + Alg + '"');
  end
  else if Copy(Key.KeyType, 1, 11) = 'ecdsa-sha2-' then
  begin
    if Alg <> Key.KeyType then SignError('signature algorithm does not match the key');
    EcdsaSignRaw(Key, Data, r, s);
    sig := Concat(SshMpint(r), SshMpint(s));
  end
  else
    SignError('unsupported key type "' + Key.KeyType + '"');
  Result := Concat(SshStr(Alg), SshString(sig));
end;

end.
