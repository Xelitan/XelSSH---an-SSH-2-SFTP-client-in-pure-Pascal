// XelSSH - Ed25519 signatures (RFC 8032): key generation, signing, verification.
// Extended twisted Edwards coordinates (X, Y, Z, T); field arithmetic from XelSslFe25519
// (Pascal, or its x86-64 addition). Key generation and signing use a constant-time
// ladder with branch-free swaps; verification (public data only) computes s*B - h*A
// with one shared doubling chain (Straus). Curve constants (d, sqrt(-1), base point,
// group order L) are derived from their definitions at startup; reduction mod L after
// TweetNaCl (Bernstein et al., public domain). Verification rejects non-canonical S
// (S >= L), as RFC 8032 requires.
// License: MIT.
unit XelSshEd25519;

{$mode objfpc}{$H+}{$Q-}{$R-}

interface

uses
  SysUtils;

// Public key (32 bytes) for a 32-byte seed (the private key).
function Ed25519PublicKey(const Seed: TBytes): TBytes;
// Signature (64 bytes) of Msg with a 32-byte seed; Pub = the matching public key.
function Ed25519Sign(const Seed, Pub, Msg: TBytes): TBytes;
function Ed25519Verify(const Pub, Msg, Sig: TBytes): Boolean;

implementation

uses XelSslHash, XelSslBigNum, XelSslFe25519;

type
  TPt = array[0..3] of TFe;      // X, Y, Z, T
  TBytes32 = array[0..31] of Byte;

var
  // constants as 32-byte little-endian numbers (converted per operation, see Consts)
  DB, D2B, SqrtM1B, BXB, BYB: TBytes32;
  LBytes: array[0..31] of Int64;

type
  TConsts = record
    D, D2, SqrtM1, BX, BY: TFe;
  end;

// the constants in the field representation selected by FeSelect
procedure Consts(out C: TConsts);
begin
  FeFromBytes(C.D, @DB[0]);
  FeFromBytes(C.D2, @D2B[0]);
  FeFromBytes(C.SqrtM1, @SqrtM1B[0]);
  FeFromBytes(C.BX, @BXB[0]);
  FeFromBytes(C.BY, @BYB[0]);
end;

function FeEqual(const a, b: TFe): Boolean;
var x, y: TBytes32; i: Integer; d: Byte;
begin
  FeToBytes(@x[0], a);
  FeToBytes(@y[0], b);
  d := 0;
  for i := 0 to 31 do d := d or (x[i] xor y[i]);
  Result := d = 0;
end;

// ---- points ----

procedure PtZero(out p: TPt);
begin
  FeZero(p[0]); FeOne(p[1]); FeOne(p[2]); FeZero(p[3]);
end;

// p := p + q (unified formula, also correct for p = q)
procedure PtAdd(var p: TPt; const q: TPt; const C: TConsts);
var a, b, cc, dd, e, f, g, h, t: TFe;
begin
  FeSub(a, p[1], p[0]); FeSub(t, q[1], q[0]); FeMul(a, a, t);
  FeAdd(b, p[0], p[1]); FeAdd(t, q[0], q[1]); FeMul(b, b, t);
  FeMul(cc, p[3], q[3]); FeMul(cc, cc, C.D2);
  FeMul(dd, p[2], q[2]); FeAdd(dd, dd, dd);
  FeSub(e, b, a); FeSub(f, dd, cc); FeAdd(g, dd, cc); FeAdd(h, b, a);
  FeMul(p[0], e, f); FeMul(p[1], h, g); FeMul(p[2], g, f); FeMul(p[3], e, h);
end;

// p := 2p (doubling for a = -1: 4 multiplications + 4 squarings)
procedure PtDouble(var p: TPt);
var a, b, cc, e, f, g, h, t: TFe;
begin
  FeSq(a, p[0]);                               // A = X^2
  FeSq(b, p[1]);                               // B = Y^2
  FeSq(cc, p[2]); FeAdd(cc, cc, cc);           // C = 2 Z^2
  FeAdd(t, p[0], p[1]); FeSq(e, t);
  FeSub(e, e, a); FeSub(e, e, b);              // E = (X + Y)^2 - A - B
  FeSub(g, b, a);                              // G = -A + B
  FeSub(f, g, cc);                             // F = G - C
  FeNeg(h, a); FeSub(h, h, b);                 // H = -A - B
  FeMul(p[0], e, f); FeMul(p[1], g, h); FeMul(p[3], e, h); FeMul(p[2], f, g);
end;

procedure PtSwap(var p, q: TPt; b: Integer);
var i: Integer;
begin
  for i := 0 to 3 do FeCSwap(p[i], q[i], b);
end;

procedure PtNeg(var p: TPt);
begin
  FeNeg(p[0], p[0]);
  FeNeg(p[3], p[3]);
end;

procedure PtPack(out r: TBytes; const p: TPt);
var tx, ty, zi: TFe;
begin
  FeInv(zi, p[2]);
  FeMul(tx, p[0], zi);
  FeMul(ty, p[1], zi);
  SetLength(r, 32);
  FeToBytes(@r[0], ty);
  r[31] := r[31] xor (FeIsNegative(tx) shl 7);
end;

procedure PtBase(out q: TPt; const C: TConsts);
begin
  q[0] := C.BX; q[1] := C.BY; FeOne(q[2]);
  FeMul(q[3], C.BX, C.BY);
end;

// p := s * B with a constant-time ladder (secret scalars)
procedure ScalarBase(out p: TPt; const s: array of Byte; const C: TConsts);
var i, b: Integer; q: TPt;
begin
  PtBase(q, C);
  PtZero(p);
  for i := 255 downto 0 do
  begin
    b := (s[i shr 3] shr (i and 7)) and 1;
    PtSwap(p, q, b);
    PtAdd(q, p, C);                            // q := p + q
    PtDouble(p);                               // p := 2p
    PtSwap(p, q, b);
  end;
end;

// p := s1 * P1 + s2 * P2 for public scalars (Straus: one doubling chain)
procedure DoubleScalar(out p: TPt; const s1: array of Byte; const P1: TPt; const s2: array of Byte;
  const P2: TPt; const C: TConsts);
var i, b1, b2: Integer; both: TPt;
begin
  both := P1;
  PtAdd(both, P2, C);
  PtZero(p);
  for i := 255 downto 0 do
  begin
    PtDouble(p);
    b1 := (s1[i shr 3] shr (i and 7)) and 1;
    b2 := (s2[i shr 3] shr (i and 7)) and 1;
    if (b1 = 1) and (b2 = 1) then PtAdd(p, both, C)
    else if b1 = 1 then PtAdd(p, P1, C)
    else if b2 = 1 then PtAdd(p, P2, C);
  end;
end;

// point from its encoding; False if not on the curve
function Unpack(out r: TPt; const p: TBytes; const C: TConsts): Boolean;
var t, chk, num, den, den2, den4, den6, one, zero: TFe;
begin
  Result := False;
  FeOne(one); FeZero(zero);
  r[2] := one;
  FeFromBytes(r[1], @p[0]);
  FeSq(num, r[1]);
  FeMul(den, num, C.D);
  FeSub(num, num, one);                        // y^2 - 1
  FeAdd(den, one, den);                        // d y^2 + 1
  FeSq(den2, den);
  FeSq(den4, den2);
  FeMul(den6, den4, den2);
  FeMul(t, den6, num);
  FeMul(t, t, den);
  FePow22523(t, t);
  FeMul(t, t, num);
  FeMul(t, t, den);
  FeMul(t, t, den);
  FeMul(r[0], t, den);
  FeSq(chk, r[0]);
  FeMul(chk, chk, den);
  if not FeEqual(chk, num) then FeMul(r[0], r[0], C.SqrtM1);
  FeSq(chk, r[0]);
  FeMul(chk, chk, den);
  if not FeEqual(chk, num) then Exit;
  if FeIsNegative(r[0]) <> (p[31] shr 7) then FeNeg(r[0], r[0]);
  FeMul(r[3], r[0], r[1]);
  Result := True;
end;

// ---- scalars mod L ----

procedure ModL(out r: TBytes; var x: array of Int64);
var carry: Int64; i, j: Integer;
begin
  for i := 63 downto 32 do
  begin
    carry := 0;
    j := i - 32;
    while j < i - 12 do
    begin
      x[j] := x[j] + carry - 16 * x[i] * LBytes[j - (i - 32)];
      carry := SarInt64(x[j] + 128, 8);
      x[j] := x[j] - (carry shl 8);
      Inc(j);
    end;
    x[j] := x[j] + carry;
    x[i] := 0;
  end;
  carry := 0;
  for j := 0 to 31 do
  begin
    x[j] := x[j] + carry - SarInt64(x[31], 4) * LBytes[j];
    carry := SarInt64(x[j], 8);
    x[j] := x[j] and 255;
  end;
  for j := 0 to 31 do x[j] := x[j] - carry * LBytes[j];
  SetLength(r, 32);
  for i := 0 to 31 do
  begin
    x[i + 1] := x[i + 1] + SarInt64(x[i], 8);
    r[i] := Byte(x[i] and 255);
  end;
end;

function Reduce(const h: TBytes): TBytes;     // 64-byte hash -> scalar mod L
var x: array[0..63] of Int64; i: Integer;
begin
  for i := 0 to 63 do x[i] := h[i];
  ModL(Result, x);
end;

function Clamped(const Seed: TBytes): TBytes;  // SHA-512(seed) with clamped lower half
begin
  Result := Hash(haSHA512, Seed);
  Result[0] := Result[0] and 248;
  Result[31] := (Result[31] and 127) or 64;
end;

function Ed25519PublicKey(const Seed: TBytes): TBytes;
var d: TBytes; p: TPt; C: TConsts;
begin
  if Length(Seed) <> 32 then raise Exception.Create('XelSSH Ed25519: seed must be 32 bytes');
  FeSelect;
  Consts(C);
  d := Clamped(Seed);
  ScalarBase(p, d[0..31], C);
  PtPack(Result, p);
  Wipe(d);
end;

function Ed25519Sign(const Seed, Pub, Msg: TBytes): TBytes;
var d, r, h, rp, s: TBytes; p: TPt; x: array[0..63] of Int64; i, j: Integer; C: TConsts;
begin
  if (Length(Seed) <> 32) or (Length(Pub) <> 32) then raise Exception.Create('XelSSH Ed25519: bad key');
  FeSelect;
  Consts(C);
  d := Clamped(Seed);
  r := Reduce(Hash(haSHA512, Concat(Copy(d, 32, 32), Msg)));
  ScalarBase(p, r[0..31], C);
  PtPack(rp, p);
  h := Reduce(Hash(haSHA512, Concat(rp, Pub, Msg)));
  for i := 0 to 63 do x[i] := 0;
  for i := 0 to 31 do x[i] := r[i];
  for i := 0 to 31 do
    for j := 0 to 31 do
      x[i + j] := x[i + j] + Int64(h[i]) * d[j];
  ModL(s, x);
  Result := Concat(rp, s);
  Wipe(d); Wipe(r);
end;

function Ed25519Verify(const Pub, Msg, Sig: TBytes): Boolean;
var a, b, p: TPt; h, t, s: TBytes; i: Integer; C: TConsts;
begin
  Result := False;
  if (Length(Pub) <> 32) or (Length(Sig) <> 64) then Exit;
  // S must be canonical (S < L)
  s := Copy(Sig, 32, 32);
  for i := 31 downto 0 do
  begin
    if s[i] < LBytes[i] then Break;
    if s[i] > LBytes[i] then Exit;
    if i = 0 then Exit;                         // S = L
  end;
  FeSelect;
  Consts(C);
  if not Unpack(a, Pub, C) then Exit;
  PtNeg(a);                                     // -A
  h := Reduce(Hash(haSHA512, Concat(Copy(Sig, 0, 32), Pub, Msg)));
  PtBase(b, C);
  DoubleScalar(p, s, b, h, a, C);               // s*B - h*A must equal R
  PtPack(t, p);
  Result := SameBytesCT(t, Copy(Sig, 0, 32));
end;

// ---- constants from their definitions ----

procedure FromBig(out o: TBytes32; const v: TBig);
var b: TBytes; i: Integer;
begin
  b := BigToBytes(v, 32);
  for i := 0 to 31 do o[i] := b[31 - i];
end;

procedure InitConstants;
var p, dd, i2, y, u, v, x, l: TBig; lb: TBytes; i: Integer;
begin
  p := BigSub(BigShr(BigFromHex('1' + StringOfChar('0', 64)), 1), BigFromInt(19));   // 2^255 - 19
  // d = -121665 / 121666
  dd := BigModMul(BigSub(p, BigFromInt(121665)), BigModInvPrime(BigFromInt(121666), p), p);
  FromBig(DB, dd);
  FromBig(D2B, BigModAdd(dd, dd, p));
  // sqrt(-1) = 2^((p-1)/4)
  i2 := BigModExp(BigFromInt(2), BigShr(BigSub(p, BigFromInt(1)), 2), p);
  FromBig(SqrtM1B, i2);
  // base point: y = 4/5, x = sqrt((y^2-1)/(d y^2+1)), even
  y := BigModMul(BigFromInt(4), BigModInvPrime(BigFromInt(5), p), p);
  u := BigModSub(BigModMul(y, y, p), BigFromInt(1), p);
  v := BigModAdd(BigModMul(dd, BigModMul(y, y, p), p), BigFromInt(1), p);
  x := BigModMul(u, BigModInvPrime(v, p), p);
  x := BigModExp(x, BigShr(BigAdd(p, BigFromInt(3)), 3), p);              // candidate root
  if BigCmp(BigModMul(x, x, p), BigModMul(u, BigModInvPrime(v, p), p)) <> 0 then
    x := BigModMul(x, i2, p);
  if BigBit(x, 0) = 1 then x := BigSub(p, x);
  FromBig(BXB, x);
  FromBig(BYB, y);
  // L = 2^252 + 27742317777372353535851937790883648493
  l := BigAdd(BigShr(BigFromHex('1' + StringOfChar('0', 64)), 4),
    BigFromHex('14def9dea2f79cd65812631a5cf5d3ed'));
  lb := BigToBytes(l, 32);
  for i := 0 to 31 do LBytes[i] := lb[31 - i];
end;

initialization
  InitConstants;
end.
