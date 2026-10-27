// XelSSH - SSH-2 client: transport (RFC 4253), user authentication (RFC 4252) and
// connection protocol (RFC 4254).
//
// Key exchange: curve25519-sha256 (RFC 8731), ecdh-sha2-nistp256/384/521 (RFC 5656),
//               strict KEX (Terrapin mitigation), ext-info, server-initiated rekeying.
// Host keys:    ssh-ed25519, ecdsa-sha2-nistp256/384/521, rsa-sha2-512/256;
//               checked against an expected fingerprint and/or known_hosts.
// Ciphers:      chacha20-poly1305@openssh.com, aes256/128-gcm@openssh.com,
//               aes256/128-ctr with hmac-sha2-256/512(-etm@openssh.com).
// Auth:         password, keyboard-interactive (answered with the password),
//               publickey with Ed25519, RSA (rsa-sha2-512/256) and ECDSA keys.
// Channels:     sessions with flow control, exec, subsystems (sftp).
// Read-ahead:   after authentication a reader thread can receive, authenticate and decrypt
//               packets while the caller handles the previous ones (ReadAhead; by default
//               only when decryption is the expensive part: CTR + HMAC, or no AES hardware).
//
// Cryptography comes from XelSSL. License: MIT.
unit XelSshClient;

{$mode objfpc}{$H+}{$Q-}{$R-}
{$modeswitch advancedrecords}

interface

uses
  SysUtils, Classes, SyncObjs, ssockets, XelSslHash, XelSshKeys;

const
  SSH_READ_AHEAD_SLOTS = 64;            // decrypted packets queued by the reader thread

type
  TSshSendFn = function(const Buf; Len: Integer): Integer of object;   // bytes sent, <=0 = error
  TSshRecvFn = function(var Buf; Len: Integer): Integer of object;     // bytes read, 0 = EOF, <0 = error

  ESshError = class(Exception);

  // how an unknown server key is treated (a changed key is always rejected)
  THostKeyPolicy = (hkStrict,      // only keys from known_hosts / the expected fingerprint
                    hkAcceptNew,   // unknown hosts are trusted on first use and added to known_hosts
                    hkAny);        // NO verification (insecure, testing only)

  TCipherKind = (ckNone, ckChaCha, ckGcm, ckCtr);

  // reader thread: raAuto = only when decryption is expensive (CTR + HMAC, or no AES
  // hardware); with hardware AES-GCM the hand-off costs more than it saves
  TSshReadAhead = (raAuto, raOn, raOff);

  TSshDir = record
    Kind: TCipherKind;
    Key, IV, MacKey: TBytes;
    MacAlg: THashAlg;
    MacLen: Integer;
    Etm: Boolean;
    Aes: Pointer;           // ^TAesKey (CTR) or ^TGcmKey (GCM)
    KMain, KHdr: TBytes;    // ChaCha20: payload key, length key
    Ctr: array[0..15] of Byte;
    Seq: UInt32;
  end;

  TSshChannel = class
  public
    LocalId, RemoteId: UInt32;
    RemoteWindow, RemoteMaxPacket: UInt32;
    LocalWindow: UInt32;
    InBuf: TBytes;          // received data not yet consumed: InBuf[InPos .. InLen - 1]
    InPos, InLen: Integer;
    ErrData: TBytes;        // extended data 1 (stderr)
    Eof, Closed, CloseSent: Boolean;
    ExitStatus: Integer;
    ReplyPending: Integer;  // 0 = none, 1 = waiting, 2 = success, 3 = failure
    OpenState: Integer;     // 0 = waiting, 1 = open, 2 = failed
    OpenError: string;
  end;

  TSshClient = class
  private
    FSend: TSshSendFn;
    FRecv: TSshRecvFn;
    FSock: TInetSocket;
    FIn: TBytes;                 // received bytes FIn[FInPos .. FInLen - 1]
    FInPos, FInLen: Integer;
    FOut: TBytes;                // the packet being sent (built and encrypted in place)
    FWr, FRd: TSshDir;
    FClientVersion, FServerVersion: string;
    FSessionId: TBytes;
    FStrict, FInitialKex, FExtInfo: Boolean;
    FServerSigAlgs: string;
    FLastError: string;
    FHostKeyType, FHostKeyFp: string;
    FHostKeyBlob: TBytes;
    FKexAlg, FCipherC2S, FCipherS2C, FMacC2S: string;
    FChannels: TList;
    FNextChannel: UInt32;
    FBanner: string;
    FConnected, FAuthenticated, FUserAuthService: Boolean;
    FServerKexInit: TBytes;      // a KEXINIT received during the session (rekey)
    // read-ahead: the reader thread owns FIn/FRd while it runs; packets go through a ring
    FReader: TThread;
    FRaLock: TCriticalSection;
    FRaNotEmpty, FRaNotFull, FRaKeysEv: PRTLEvent;
    FRaSlots: array[0..SSH_READ_AHEAD_SLOTS - 1] of TBytes;
    FRaLens: array[0..SSH_READ_AHEAD_SLOTS - 1] of Integer;
    FRaHead, FRaTail: Int64;     // packets taken / queued
    FRaHeld: Boolean;            // the main thread is using the slot at FRaHead
    FRaFailed, FRaStop, FRaKeysReady: Boolean;
    FRaConsWaiting, FRaProdWaiting: Boolean;   // a side sleeps on its event (signal only then)
    FRaErr: string;
    function SockSend(const Buf; Len: Integer): Integer;
    function SockRecv(var Buf; Len: Integer): Integer;
    procedure RawSend(const B: TBytes);
    procedure RawSendP(P: PByte; Len: Integer);
    procedure RawEnsure(N: Integer);
    function RawRead(N: Integer): TBytes;
    function ReadLine: string;
    procedure SendPacket(const Payload: TBytes);
    procedure SendPacketP(P1: PByte; L1: Integer; P2: PByte; L2: Integer);
    procedure RecvPacketDirect(out P: PByte; out Len: Integer);
    procedure RecvPacketView(out P: PByte; out Len: Integer);
    function RecvPacket: TBytes;
    procedure StartReader;
    procedure StopReader;
    procedure ReaderLoop;
    procedure OnChannelData(Ch: TSshChannel; Code: UInt32; P: PByte; N: Integer);
    procedure ProcessOne;
    function NextMessage: TBytes;
    function HandleGeneric(const M: TBytes): Boolean;
    procedure DoKex(const ServerKexInitIn: TBytes);
    procedure SetupDir(var D: TSshDir; const Cipher, Mac: string; const K, H: TBytes; Hash_: THashAlg;
      const IvC, KeyC, MacC: AnsiChar);
    procedure CheckHostKey;
    function FindChannel(Id: UInt32): TSshChannel;
    procedure WaitChannel(Ch: TSshChannel; Cond: Integer);
    function AuthKbdInteractive(const User, Password: string): Boolean;
    function AuthResult(var Partial: Boolean): Boolean;
  public
    Host: string;                 // used for known_hosts and messages
    Port: Integer;
    Policy: THostKeyPolicy;       // default hkAcceptNew
    KnownHostsFile: string;       // default ~/.ssh/known_hosts; '' = do not use
    ExpectedFingerprint: string;  // "SHA256:..." - if set, the server key must match it
    Timeout: Integer;             // ms, for the built-in socket (default 30000)
    // algorithm preference lists (comma-separated); may be narrowed, but only to supported names
    KexAlgorithms, HostKeyAlgorithms, Ciphers, Macs: string;
    // receive and decrypt in a separate thread after authentication (default raAuto; used
    // only with the built-in socket and more than one CPU)
    ReadAhead: TSshReadAhead;
    constructor Create;
    destructor Destroy; override;
    // Connects using the built-in TCP socket (Host/Port) - or call Connect after setting callbacks.
    function ConnectTcp(const AHost: string; APort: Integer = 22): Boolean;
    procedure SetTransport(ASend: TSshSendFn; ARecv: TSshRecvFn);
    function Connect: Boolean;
    function AuthPassword(const User, Password: string): Boolean;
    function AuthKey(const User: string; const Key: TSshPrivateKey): Boolean;
    function OpenSession: TSshChannel;
    function ChannelRequest(Ch: TSshChannel; const ReqType: string; const Extra: TBytes; WantReply: Boolean): Boolean;
    procedure ChannelWrite(Ch: TSshChannel; const Data: TBytes);
    procedure ChannelWriteP(Ch: TSshChannel; P: PByte; Len: Integer);
    // Zero-copy access to received channel data: Fill waits until N bytes are buffered
    // (exception if the channel closes first); Peek points at them (valid until the next
    // call that receives packets); Consume drops N bytes.
    procedure ChannelFill(Ch: TSshChannel; N: Integer);
    function ChannelAvailable(Ch: TSshChannel): Integer;
    function ChannelPeek(Ch: TSshChannel): PByte;
    procedure ChannelConsume(Ch: TSshChannel; N: Integer);
    // Blocks until data (returns bytes), end of data (0) or an error (exception).
    function ChannelRead(Ch: TSshChannel; MaxLen: Integer; out Data: TBytes): Integer;
    procedure ChannelSendEof(Ch: TSshChannel);
    procedure ChannelClose(Ch: TSshChannel);
    // Runs a command; returns stdout (stderr in StdErr), exit code in ExitCode.
    function Exec(const Command: string; out StdErr: RawByteString; out ExitCode: Integer): RawByteString;
    procedure Disconnect;
    property LastError: string read FLastError;
    property ServerVersion: string read FServerVersion;
    property HostKeyType: string read FHostKeyType;
    property HostKeyFingerprint: string read FHostKeyFp;
    property KexAlgorithm: string read FKexAlg;
    property CipherAlgorithm: string read FCipherC2S;
    property MacAlgorithm: string read FMacC2S;
    property Banner: string read FBanner;
    property Connected: Boolean read FConnected;
    property Authenticated: Boolean read FAuthenticated;
  end;

implementation

uses sockets, XelSslAes, XelSslChaCha, XelSslX25519, XelSslEcdh, XelSslPk, XelSslRandom, XelSshEd25519, XelSshSign;

const
  SSH_MSG_DISCONNECT = 1; SSH_MSG_IGNORE = 2; SSH_MSG_UNIMPLEMENTED = 3; SSH_MSG_DEBUG = 4;
  SSH_MSG_SERVICE_REQUEST = 5; SSH_MSG_SERVICE_ACCEPT = 6; SSH_MSG_EXT_INFO = 7;
  SSH_MSG_KEXINIT = 20; SSH_MSG_NEWKEYS = 21; SSH_MSG_KEX_ECDH_INIT = 30; SSH_MSG_KEX_ECDH_REPLY = 31;
  SSH_MSG_USERAUTH_REQUEST = 50; SSH_MSG_USERAUTH_FAILURE = 51; SSH_MSG_USERAUTH_SUCCESS = 52;
  SSH_MSG_USERAUTH_BANNER = 53; SSH_MSG_USERAUTH_INFO_REQUEST = 60; SSH_MSG_USERAUTH_INFO_RESPONSE = 61;
  SSH_MSG_GLOBAL_REQUEST = 80; SSH_MSG_REQUEST_FAILURE = 82;
  SSH_MSG_CHANNEL_OPEN = 90; SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91; SSH_MSG_CHANNEL_OPEN_FAILURE = 92;
  SSH_MSG_CHANNEL_WINDOW_ADJUST = 93; SSH_MSG_CHANNEL_DATA = 94; SSH_MSG_CHANNEL_EXTENDED_DATA = 95;
  SSH_MSG_CHANNEL_EOF = 96; SSH_MSG_CHANNEL_CLOSE = 97; SSH_MSG_CHANNEL_REQUEST = 98;
  SSH_MSG_CHANNEL_SUCCESS = 99; SSH_MSG_CHANNEL_FAILURE = 100;

  DEF_KEX_ALGS = 'curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521';
  DEF_HOSTKEY_ALGS = 'ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256';
  DEF_CIPHERS = 'chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes128-ctr';
  // with AES-NI + PCLMULQDQ, AES-GCM is several times faster than ChaCha20
  DEF_CIPHERS_AESNI = 'aes128-gcm@openssh.com,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr,aes128-ctr';
  DEF_MACS = 'hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512';
  WINDOW_SIZE = 2 * 1024 * 1024;
  MAX_PACKET = 32768;
  MAX_PACKET_LEN = 256 * 1024;

// ---- wire format ----

type
  TRd = record
    B: TBytes; P: Integer;
    procedure Init(const X: TBytes; Start: Integer = 0);
    function Left: Integer;
    function U8: Byte;
    function U32: UInt32;
    function U64: QWord;
    function Bool: Boolean;
    function Str: TBytes;
    function Text: string;
    function Mpint: TBytes;         // unsigned big-endian, no leading zeros
  end;

procedure Bad(const Msg: string);
begin
  raise ESshError.Create(Msg);
end;

procedure TRd.Init(const X: TBytes; Start: Integer); begin B := X; P := Start; end;
function TRd.Left: Integer; begin Result := Length(B) - P; end;
function TRd.U8: Byte; begin if P >= Length(B) then Bad('XelSSH: truncated message'); Result := B[P]; Inc(P); end;
function TRd.U32: UInt32;
begin
  if P + 4 > Length(B) then Bad('XelSSH: truncated message');
  Result := (UInt32(B[P]) shl 24) or (UInt32(B[P + 1]) shl 16) or (UInt32(B[P + 2]) shl 8) or B[P + 3];
  Inc(P, 4);
end;
function TRd.U64: QWord; begin Result := QWord(U32) shl 32; Result := Result or U32; end;
function TRd.Bool: Boolean; begin Result := U8 <> 0; end;
function TRd.Str: TBytes;
var n: UInt32;
begin
  n := U32;
  if n > UInt32(Left) then Bad('XelSSH: truncated message');
  Result := Copy(B, P, n);
  Inc(P, n);
end;
function TRd.Text: string;
var t: TBytes;
begin
  t := Str;
  if Length(t) = 0 then Result := '' else SetString(Result, PAnsiChar(@t[0]), Length(t));
end;
function TRd.Mpint: TBytes;
begin
  Result := Str;
  while (Length(Result) > 0) and (Result[0] = 0) do Delete(Result, 0, 1);
end;

function U8b(V: Byte): TBytes; begin Result := TBytes.Create(V); end;
function BoolB(V: Boolean): TBytes; begin if V then Result := U8b(1) else Result := U8b(0); end;

function U64b(V: QWord): TBytes;
begin
  Result := Concat(SshU32(UInt32(V shr 32)), SshU32(UInt32(V)));
end;

function Cat(const Parts: array of TBytes): TBytes;
var i, n: Integer;
begin
  n := 0;
  for i := 0 to High(Parts) do Inc(n, Length(Parts[i]));
  SetLength(Result, n);
  n := 0;
  for i := 0 to High(Parts) do
    if Length(Parts[i]) > 0 then
    begin
      Move(Parts[i][0], Result[n], Length(Parts[i]));
      Inc(n, Length(Parts[i]));
    end;
end;

function NameIn(const Name, List: string): Boolean;
var a: TStringArray; i: Integer;
begin
  a := List.Split([',']);
  for i := 0 to High(a) do if a[i] = Name then Exit(True);
  Result := False;
end;

// first client algorithm also supported by the server
function Negotiate(const Client, Server, What: string): string;
var a: TStringArray; i: Integer;
begin
  a := Client.Split([',']);
  for i := 0 to High(a) do
    if NameIn(a[i], Server) then Exit(a[i]);
  raise ESshError.CreateFmt('XelSSH: no common %s algorithm (server offers: %s)', [What, Server]);
end;

// ---- client ----

constructor TSshClient.Create;
begin
  inherited Create;
  FChannels := TList.Create;
  Policy := hkAcceptNew;
  KnownHostsFile := DefaultKnownHostsFile;
  Port := 22;
  Timeout := 30000;
  KexAlgorithms := DEF_KEX_ALGS; HostKeyAlgorithms := DEF_HOSTKEY_ALGS;
  if AesHardwareAvailable then Ciphers := DEF_CIPHERS_AESNI else Ciphers := DEF_CIPHERS;
  Macs := DEF_MACS;
  SetLength(FIn, 256 * 1024);
  ReadAhead := raAuto;
  FRaLock := TCriticalSection.Create;
  FRaNotEmpty := RTLEventCreate;
  FRaNotFull := RTLEventCreate;
  FRaKeysEv := RTLEventCreate;
end;

destructor TSshClient.Destroy;
var i: Integer;
begin
  try if FConnected then Disconnect; except end;
  StopReader;
  RTLEventDestroy(FRaNotEmpty);
  RTLEventDestroy(FRaNotFull);
  RTLEventDestroy(FRaKeysEv);
  FRaLock.Free;
  for i := 0 to FChannels.Count - 1 do TObject(FChannels[i]).Free;
  FChannels.Free;
  if FWr.Aes <> nil then FreeMem(FWr.Aes);
  if FRd.Aes <> nil then FreeMem(FRd.Aes);
  FreeAndNil(FSock);
  inherited Destroy;
end;

function TSshClient.SockSend(const Buf; Len: Integer): Integer;
begin
  if FSock = nil then Exit(-1);
  try Result := FSock.Write(Buf, Len); except Result := -1; end;
end;

function TSshClient.SockRecv(var Buf; Len: Integer): Integer;
begin
  if FSock = nil then Exit(-1);
  try Result := FSock.Read(Buf, Len); except Result := -1; end;
end;

procedure TSshClient.SetTransport(ASend: TSshSendFn; ARecv: TSshRecvFn);
begin
  FSend := ASend; FRecv := ARecv;
end;

function TSshClient.ConnectTcp(const AHost: string; APort: Integer): Boolean;
var one: LongInt;
begin
  Result := False;
  Host := AHost; Port := APort;
  StopReader;
  FreeAndNil(FSock);
  try
    FSock := TInetSocket.Create(AHost, APort);
    if Timeout > 0 then FSock.IOTimeout := Timeout;
    // small requests (SFTP reads, window adjusts) must not wait for delayed ACKs
    one := 1;
    fpsetsockopt(FSock.Handle, IPPROTO_TCP, TCP_NODELAY, @one, SizeOf(one));
    // large socket buffers: fewer system calls and a full window on fast links
    one := 4 * 1024 * 1024;
    fpsetsockopt(FSock.Handle, SOL_SOCKET, SO_RCVBUF, @one, SizeOf(one));
    fpsetsockopt(FSock.Handle, SOL_SOCKET, SO_SNDBUF, @one, SizeOf(one));
  except
    on E: Exception do
    begin
      FLastError := Format('cannot connect to %s:%d (%s)', [AHost, APort, E.Message]);
      Exit;
    end;
  end;
  SetTransport(@SockSend, @SockRecv);
  Result := Connect;
end;

procedure TSshClient.RawSendP(P: PByte; Len: Integer);
var off, n: Integer;
begin
  if not Assigned(FSend) then Bad('XelSSH: not connected');
  off := 0;
  while off < Len do
  begin
    n := FSend(P[off], Len - off);
    if n <= 0 then Bad('XelSSH: connection lost (send failed)');
    Inc(off, n);
  end;
end;

procedure TSshClient.RawSend(const B: TBytes);
begin
  if Length(B) > 0 then RawSendP(@B[0], Length(B));
end;

// makes N unread bytes available at FIn[FInPos] (reads as much as the socket gives)
procedure TSshClient.RawEnsure(N: Integer);
var got: Integer;
begin
  if FInLen - FInPos >= N then Exit;
  if not Assigned(FRecv) then Bad('XelSSH: not connected');
  if FInPos + N > Length(FIn) then
  begin
    if FInLen > FInPos then Move(FIn[FInPos], FIn[0], FInLen - FInPos);
    Dec(FInLen, FInPos); FInPos := 0;
    if N > Length(FIn) then SetLength(FIn, N + 65536);
  end;
  while FInLen - FInPos < N do
  begin
    got := FRecv(FIn[FInLen], Length(FIn) - FInLen);
    if got <= 0 then Bad('XelSSH: connection closed by the server');
    Inc(FInLen, got);
  end;
end;

function TSshClient.RawRead(N: Integer): TBytes;
begin
  RawEnsure(N);
  Result := Copy(FIn, FInPos, N);
  Inc(FInPos, N);
end;

function TSshClient.ReadLine: string;
var b: TBytes;
begin
  Result := '';
  repeat
    b := RawRead(1);
    if b[0] = 10 then Break;
    if b[0] <> 13 then Result := Result + Chr(b[0]);
    if Length(Result) > 1024 then Bad('XelSSH: server identification line too long');
  until False;
end;

// ---- packets ----

// AES-CTR in place; the key stream is made 64 blocks at a time
procedure CtrXorP(var D: TSshDir; P: PByte; Len: Integer);
var ks: array[0..1023] of Byte; i, j, n, blocks: Integer;
begin
  while Len > 0 do
  begin
    blocks := (Len + 15) div 16;
    if blocks > 64 then blocks := 64;
    for i := 0 to blocks - 1 do
    begin
      Move(D.Ctr[0], ks[16 * i], 16);
      for j := 15 downto 0 do
      begin
        Inc(D.Ctr[j]);
        if D.Ctr[j] <> 0 then Break;
      end;
    end;
    AesEncryptBlocks(PAesKey(D.Aes)^, @ks[0], @ks[0], blocks);
    n := blocks * 16;
    if n > Len then n := Len;
    for i := 0 to n - 1 do P[i] := P[i] xor ks[i];
    Inc(P, n); Dec(Len, n);
  end;
  FillChar(ks, SizeOf(ks), 0);
end;

function Be32Of(P: PByte): UInt32; inline;
begin
  Result := (UInt32(P[0]) shl 24) or (UInt32(P[1]) shl 16) or (UInt32(P[2]) shl 8) or P[3];
end;

procedure PutBe32(P: PByte; V: UInt32); inline;
begin
  P[0] := Byte(V shr 24); P[1] := Byte(V shr 16); P[2] := Byte(V shr 8); P[3] := Byte(V);
end;

function ChaNonce(Seq: UInt32): TBytes;
begin
  Result := Concat(TBytes.Create(0, 0, 0, 0), U64b(Seq));
end;

procedure IncGcmIv(var IV: TBytes);
var j: Integer;
begin
  for j := 11 downto 4 do
  begin
    Inc(IV[j]);
    if IV[j] <> 0 then Break;
  end;
end;

// payload = P1[0..L1) followed by P2[0..L2); the packet is built in FOut and encrypted there
procedure TSshClient.SendPacketP(P1: PByte; L1: Integer; P2: PByte; L2: Integer);
var
  block, padLen, total, macLen, size, plen: Integer; o: PByte; pad, mac, nonce: TBytes;
  pk: array[0..31] of Byte; seqb: array[0..3] of Byte;
begin
  plen := L1 + L2;
  if FWr.Kind in [ckCtr, ckGcm] then block := 16 else block := 8;
  // lengths: AEAD/ETM exclude the 4-byte length from the padding calculation
  if (FWr.Kind in [ckChaCha, ckGcm]) or FWr.Etm then
    padLen := block - ((1 + plen) mod block)
  else
    padLen := block - ((5 + plen) mod block);
  if padLen < 4 then Inc(padLen, block);
  total := 1 + plen + padLen;
  case FWr.Kind of
    ckChaCha, ckGcm: macLen := 16;
    ckCtr: macLen := FWr.MacLen;
  else macLen := 0;
  end;
  size := 4 + total + macLen;
  if Length(FOut) < size then SetLength(FOut, size + 4096);
  o := @FOut[0];
  PutBe32(o, total);
  o[4] := padLen;
  if L1 > 0 then Move(P1^, o[5], L1);
  if L2 > 0 then Move(P2^, o[5 + L1], L2);
  pad := RandomBytes(padLen);
  Move(pad[0], o[5 + plen], padLen);
  case FWr.Kind of
    ckChaCha:
      begin
        nonce := ChaNonce(FWr.Seq);
        ChaCha20Xor(FWr.KHdr, nonce, 0, o, o, 4);
        ChaCha20Xor(FWr.KMain, nonce, 1, o + 4, o + 4, total);
        FillChar(pk, 32, 0);
        ChaCha20Xor(FWr.KMain, nonce, 0, @pk[0], @pk[0], 32);
        Poly1305MacP(@pk[0], o, 4 + total, o + 4 + total);
      end;
    ckGcm:
      begin
        GcmSealP(PGcmKey(FWr.Aes)^, @FWr.IV[0], o, 4, o + 4, total, o + 4 + total);
        IncGcmIv(FWr.IV);
      end;
    ckCtr:
      begin
        PutBe32(@seqb[0], FWr.Seq);
        if FWr.Etm then
        begin
          CtrXorP(FWr, o + 4, total);
          mac := HmacP(FWr.MacAlg, FWr.MacKey, @seqb[0], 4, o, 4 + total);
        end
        else
        begin
          mac := HmacP(FWr.MacAlg, FWr.MacKey, @seqb[0], 4, o, 4 + total);
          CtrXorP(FWr, o, 4 + total);
        end;
        Move(mac[0], o[4 + total], macLen);
      end;
  end;
  RawSendP(o, size);
  FWr.Seq := FWr.Seq + 1;
end;

procedure TSshClient.SendPacket(const Payload: TBytes);
begin
  if Length(Payload) > 0 then SendPacketP(@Payload[0], Length(Payload), nil, 0)
  else SendPacketP(nil, 0, nil, 0);
end;

// Next packet, authenticated and decrypted in place in FIn; P/Len = the payload, valid
// until the next read. Runs in the reader thread when read-ahead is active.
procedure TSshClient.RecvPacketDirect(out P: PByte; out Len: Integer);
var
  len_, macLen, padLen: UInt32; q: PByte; lenB: array[0..3] of Byte; nonce, mac: TBytes;
  pk, tag: array[0..31] of Byte; seqb: array[0..3] of Byte; i: Integer; d: Byte;
begin
  case FRd.Kind of
    ckChaCha, ckGcm: macLen := 16;
    ckCtr: macLen := FRd.MacLen;
  else macLen := 0;
  end;
  PutBe32(@seqb[0], FRd.Seq);
  case FRd.Kind of
    ckNone:
      begin
        RawEnsure(4);
        len_ := Be32Of(@FIn[FInPos]);
        if (len_ < 5) or (len_ > MAX_PACKET_LEN) then Bad('XelSSH: invalid packet length');
        RawEnsure(4 + len_);
      end;
    ckChaCha:
      begin
        RawEnsure(4);
        nonce := ChaNonce(FRd.Seq);
        ChaCha20Xor(FRd.KHdr, nonce, 0, @FIn[FInPos], @lenB[0], 4);
        len_ := Be32Of(@lenB[0]);
        if (len_ < 8) or (len_ > MAX_PACKET_LEN) or (len_ mod 8 <> 0) then Bad('XelSSH: invalid packet length');
        RawEnsure(4 + len_ + 16);
        q := @FIn[FInPos];
        FillChar(pk, 32, 0);
        ChaCha20Xor(FRd.KMain, nonce, 0, @pk[0], @pk[0], 32);
        Poly1305MacP(@pk[0], q, 4 + len_, @tag[0]);
        d := 0;
        for i := 0 to 15 do d := d or (tag[i] xor q[4 + len_ + i]);
        if d <> 0 then Bad('XelSSH: packet authentication failed (MAC error)');
        ChaCha20Xor(FRd.KMain, nonce, 1, q + 4, q + 4, len_);
      end;
    ckGcm:
      begin
        RawEnsure(4);
        len_ := Be32Of(@FIn[FInPos]);
        if (len_ < 16) or (len_ > MAX_PACKET_LEN) or (len_ mod 16 <> 0) then Bad('XelSSH: invalid packet length');
        RawEnsure(4 + len_ + 16);
        q := @FIn[FInPos];
        if not GcmOpenP(PGcmKey(FRd.Aes)^, @FRd.IV[0], q, 4, q + 4, len_, q + 4 + len_) then
          Bad('XelSSH: packet authentication failed (MAC error)');
        IncGcmIv(FRd.IV);
      end;
    ckCtr:
      if FRd.Etm then
      begin
        RawEnsure(4);
        len_ := Be32Of(@FIn[FInPos]);
        if (len_ < 16) or (len_ > MAX_PACKET_LEN) or (len_ mod 16 <> 0) then Bad('XelSSH: invalid packet length');
        RawEnsure(4 + len_ + macLen);
        q := @FIn[FInPos];
        mac := HmacP(FRd.MacAlg, FRd.MacKey, @seqb[0], 4, q, 4 + len_);
        d := 0;
        for i := 0 to Integer(macLen) - 1 do d := d or (mac[i] xor q[4 + len_ + UInt32(i)]);
        if d <> 0 then Bad('XelSSH: packet authentication failed (MAC error)');
        CtrXorP(FRd, q + 4, len_);
      end
      else
      begin
        RawEnsure(16);
        CtrXorP(FRd, @FIn[FInPos], 16);
        len_ := Be32Of(@FIn[FInPos]);
        if (len_ < 12) or (len_ > MAX_PACKET_LEN) or ((len_ + 4) mod 16 <> 0) then Bad('XelSSH: invalid packet length');
        RawEnsure(4 + len_ + macLen);
        q := @FIn[FInPos];
        CtrXorP(FRd, q + 16, len_ + 4 - 16);
        mac := HmacP(FRd.MacAlg, FRd.MacKey, @seqb[0], 4, q, 4 + len_);
        d := 0;
        for i := 0 to Integer(macLen) - 1 do d := d or (mac[i] xor q[4 + len_ + UInt32(i)]);
        if d <> 0 then Bad('XelSSH: packet authentication failed (MAC error)');
      end;
  end;
  q := @FIn[FInPos];
  Inc(FInPos, 4 + len_ + macLen);             // the bytes stay until the next RawEnsure
  FRd.Seq := FRd.Seq + 1;
  padLen := q[4];
  if (padLen < 4) or (padLen + 1 >= len_) then Bad('XelSSH: invalid packet padding');
  P := q + 5;
  Len := len_ - 1 - padLen;
end;

// ---- read-ahead ----

type
  TSshReader = class(TThread)
  private
    FOwner: TSshClient;
  protected
    procedure Execute; override;
  end;

procedure TSshReader.Execute;
begin
  FOwner.ReaderLoop;
end;

// reader thread: packets are decrypted and copied to free slots of the ring
procedure TSshClient.ReaderLoop;
var p: PByte; n, slot: Integer; full, stop, ready, wake: Boolean;
begin
  try
    repeat
      RecvPacketDirect(p, n);
      // wait for a free slot
      repeat
        FRaLock.Enter;
        full := FRaTail - FRaHead >= SSH_READ_AHEAD_SLOTS;
        stop := FRaStop;
        FRaProdWaiting := full;
        FRaLock.Leave;
        if stop then Exit;
        if not full then Break;
        RTLEventWaitFor(FRaNotFull, 200);
      until False;
      slot := FRaTail mod SSH_READ_AHEAD_SLOTS;
      if Length(FRaSlots[slot]) < n then SetLength(FRaSlots[slot], n + 1024);
      if n > 0 then Move(p^, FRaSlots[slot][0], n);
      FRaLens[slot] := n;
      FRaLock.Enter;
      FRaKeysReady := False;
      Inc(FRaTail);
      wake := FRaConsWaiting;
      FRaLock.Leave;
      if wake then RTLEventSetEvent(FRaNotEmpty);
      // after NEWKEYS the next packets use keys that the main thread sets up (DoKex)
      if (n > 0) and (p^ = SSH_MSG_NEWKEYS) then
        repeat
          FRaLock.Enter;
          ready := FRaKeysReady;
          stop := FRaStop;
          FRaLock.Leave;
          if stop then Exit;
          if ready then Break;
          RTLEventWaitFor(FRaKeysEv, 200);
        until False;
    until False;
  except
    on E: Exception do
    begin
      FRaLock.Enter;
      FRaFailed := True;
      FRaErr := E.Message;
      FRaLock.Leave;
      RTLEventSetEvent(FRaNotEmpty);
    end;
  end;
end;

procedure TSshClient.StartReader;
var t: TSshReader;
begin
  if (FReader <> nil) or (ReadAhead = raOff) or (FSock = nil) or (TThread.ProcessorCount < 2) then Exit;
  if (ReadAhead = raAuto) and (FRd.Kind <> ckCtr) and AesHardwareAvailable then Exit;
  FRaHead := 0; FRaTail := 0; FRaHeld := False;
  FRaFailed := False; FRaStop := False; FRaKeysReady := False; FRaErr := '';
  FRaConsWaiting := False; FRaProdWaiting := False;
  RTLEventResetEvent(FRaNotEmpty); RTLEventResetEvent(FRaNotFull); RTLEventResetEvent(FRaKeysEv);
  // without thread support (e.g. a Unix program without cthreads) packets are read directly
  try
    t := TSshReader.Create(True);
  except
    Exit;
  end;
  t.FOwner := Self;
  t.FreeOnTerminate := False;
  FReader := t;
  t.Start;
end;

// stops the reader thread; the socket is shut down for reading, so the connection is
// unusable afterwards (called when disconnecting)
procedure TSshClient.StopReader;
var i: Integer;
begin
  if FReader = nil then Exit;
  FRaLock.Enter;
  FRaStop := True;
  FRaLock.Leave;
  RTLEventSetEvent(FRaNotFull);
  RTLEventSetEvent(FRaKeysEv);
  if FSock <> nil then fpshutdown(FSock.Handle, 2);   // unblocks a pending recv
  FReader.WaitFor;
  FreeAndNil(FReader);
  for i := 0 to High(FRaSlots) do FRaSlots[i] := nil;
end;

// next packet: from the reader thread's queue, or read directly
procedure TSshClient.RecvPacketView(out P: PByte; out Len: Integer);
var avail, failed, wake: Boolean; slot, spin: Integer; err: string;
begin
  if FReader = nil then
  begin
    RecvPacketDirect(P, Len);
    Exit;
  end;
  // the previous packet's slot is free again
  if FRaHeld then
  begin
    FRaLock.Enter;
    Inc(FRaHead);
    wake := FRaProdWaiting;
    FRaLock.Leave;
    FRaHeld := False;
    if wake then RTLEventSetEvent(FRaNotFull);
  end;
  spin := 0;
  repeat
    FRaLock.Enter;
    avail := FRaTail > FRaHead;
    failed := FRaFailed;
    err := FRaErr;
    // sleep only after a short spin: the next packet is usually close
    FRaConsWaiting := not avail and not failed and (spin >= 64);
    FRaLock.Leave;
    if avail then Break;
    if failed then Bad(err);
    if spin < 64 then begin Inc(spin); ThreadSwitch; end
    else RTLEventWaitFor(FRaNotEmpty, 1000);
  until False;
  slot := FRaHead mod SSH_READ_AHEAD_SLOTS;
  FRaHeld := True;
  P := @FRaSlots[slot][0];
  Len := FRaLens[slot];
end;

function TSshClient.RecvPacket: TBytes;
var p: PByte; n: Integer;
begin
  RecvPacketView(p, n);
  SetLength(Result, n);
  if n > 0 then Move(p^, Result[0], n);
end;

// ---- messages ----

function DisconnectText(const M: TBytes): string;
var R: TRd; code: UInt32;
begin
  R.Init(M, 1);
  code := R.U32;
  Result := Format('the server disconnected (%d): %s', [code, R.Text]);
end;

// Transport-level messages handled anywhere; returns True if the message was consumed.
function TSshClient.HandleGeneric(const M: TBytes): Boolean;
var R: TRd; n, i: UInt32; name, val: string; ch: TSshChannel; want: Boolean; rtype: string;
    add, rid, code: UInt32; data: TBytes;
begin
  Result := True;
  case M[0] of
    SSH_MSG_IGNORE, SSH_MSG_DEBUG, SSH_MSG_UNIMPLEMENTED:
      if FInitialKex and FStrict then Bad('XelSSH: unexpected message during strict key exchange');
    SSH_MSG_DISCONNECT:
      begin
        FConnected := False;
        Bad('XelSSH: ' + DisconnectText(M));
      end;
    SSH_MSG_EXT_INFO:
      begin
        R.Init(M, 1);
        n := R.U32;
        for i := 1 to n do
        begin
          name := R.Text; val := R.Text;
          if name = 'server-sig-algs' then FServerSigAlgs := val;
        end;
      end;
    SSH_MSG_KEXINIT:
      DoKex(M);                                         // server-initiated rekey
    SSH_MSG_GLOBAL_REQUEST:
      begin
        R.Init(M, 1);
        R.Text;
        if R.Bool then SendPacket(U8b(SSH_MSG_REQUEST_FAILURE));
      end;
    SSH_MSG_CHANNEL_WINDOW_ADJUST:
      begin
        R.Init(M, 1);
        ch := FindChannel(R.U32);
        add := R.U32;
        if ch <> nil then ch.RemoteWindow := ch.RemoteWindow + add;
      end;
    SSH_MSG_CHANNEL_DATA, SSH_MSG_CHANNEL_EXTENDED_DATA:
      begin
        R.Init(M, 1);
        ch := FindChannel(R.U32);
        if M[0] = SSH_MSG_CHANNEL_EXTENDED_DATA then code := R.U32 else code := 0;
        data := R.Str;
        if (ch <> nil) and (Length(data) > 0) then OnChannelData(ch, code, @data[0], Length(data));
      end;
    SSH_MSG_CHANNEL_EOF:
      begin
        R.Init(M, 1);
        ch := FindChannel(R.U32);
        if ch <> nil then ch.Eof := True;
      end;
    SSH_MSG_CHANNEL_CLOSE:
      begin
        R.Init(M, 1);
        ch := FindChannel(R.U32);
        if ch <> nil then
        begin
          ch.Eof := True; ch.Closed := True;
          if not ch.CloseSent then
          begin
            SendPacket(Concat(U8b(SSH_MSG_CHANNEL_CLOSE), SshU32(ch.RemoteId)));
            ch.CloseSent := True;
          end;
        end;
      end;
    SSH_MSG_CHANNEL_REQUEST:
      begin
        R.Init(M, 1);
        ch := FindChannel(R.U32);
        rtype := R.Text;
        want := R.Bool;
        if (ch <> nil) and (rtype = 'exit-status') then ch.ExitStatus := Integer(R.U32);
        if want and (ch <> nil) then SendPacket(Concat(U8b(SSH_MSG_CHANNEL_FAILURE), SshU32(ch.RemoteId)));
      end;
    SSH_MSG_CHANNEL_SUCCESS, SSH_MSG_CHANNEL_FAILURE:
      begin
        R.Init(M, 1);
        ch := FindChannel(R.U32);
        if (ch <> nil) and (ch.ReplyPending = 1) then
          if M[0] = SSH_MSG_CHANNEL_SUCCESS then ch.ReplyPending := 2 else ch.ReplyPending := 3;
      end;
    SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
      begin
        R.Init(M, 1);
        ch := FindChannel(R.U32);
        if ch <> nil then
        begin
          ch.RemoteId := R.U32;
          ch.RemoteWindow := R.U32;
          ch.RemoteMaxPacket := R.U32;
          ch.OpenState := 1;
        end;
      end;
    SSH_MSG_CHANNEL_OPEN_FAILURE:
      begin
        R.Init(M, 1);
        ch := FindChannel(R.U32);
        rid := R.U32;
        if ch <> nil then
        begin
          ch.OpenState := 2;
          ch.OpenError := Format('channel open failed (%d): %s', [rid, R.Text]);
        end;
      end;
    SSH_MSG_CHANNEL_OPEN:
      begin
        // the client accepts no channels opened by the server
        R.Init(M, 1);
        R.Text;
        rid := R.U32;
        SendPacket(Cat([U8b(SSH_MSG_CHANNEL_OPEN_FAILURE), SshU32(rid), SshU32(1),
          SshStr('not supported'), SshStr('')]));
      end;
  else
    Result := False;
  end;
end;

// N bytes of data for a channel: stdout (Code 0) to InBuf, stderr (Code 1) to ErrData
procedure TSshClient.OnChannelData(Ch: TSshChannel; Code: UInt32; P: PByte; N: Integer);
var need: Integer;
begin
  if UInt32(N) > Ch.LocalWindow then Bad('XelSSH: the server exceeded the channel window');
  Ch.LocalWindow := Ch.LocalWindow - UInt32(N);
  if Code = 0 then
  begin
    if Ch.InPos = Ch.InLen then begin Ch.InPos := 0; Ch.InLen := 0; end;
    need := Ch.InLen + N;
    if need > Length(Ch.InBuf) then
    begin
      if Ch.InPos > 0 then
      begin
        Move(Ch.InBuf[Ch.InPos], Ch.InBuf[0], Ch.InLen - Ch.InPos);
        Dec(Ch.InLen, Ch.InPos); Ch.InPos := 0;
        need := Ch.InLen + N;
      end;
      if need > Length(Ch.InBuf) then
      begin
        if need < 2 * Length(Ch.InBuf) then need := 2 * Length(Ch.InBuf);
        if need < 65536 then need := 65536;
        SetLength(Ch.InBuf, need);
      end;
    end;
    Move(P^, Ch.InBuf[Ch.InLen], N);
    Inc(Ch.InLen, N);
  end
  else if Code = 1 then
  begin
    SetLength(Ch.ErrData, Length(Ch.ErrData) + N);
    Move(P^, Ch.ErrData[Length(Ch.ErrData) - N], N);
  end;
  // refill the window once half of it is used
  if Ch.LocalWindow < WINDOW_SIZE div 2 then
  begin
    SendPacket(Cat([U8b(SSH_MSG_CHANNEL_WINDOW_ADJUST), SshU32(Ch.RemoteId), SshU32(WINDOW_SIZE - Ch.LocalWindow)]));
    Ch.LocalWindow := WINDOW_SIZE;
  end;
end;

// receives and handles one packet; channel data goes straight from the receive buffer
// into the channel buffer
procedure TSshClient.ProcessOne;
var p: PByte; len: Integer; ch: TSshChannel; n: UInt32; m: TBytes;
begin
  RecvPacketView(p, len);
  if len = 0 then Bad('XelSSH: empty message');
  if (p[0] = SSH_MSG_CHANNEL_DATA) and (len >= 9) then
  begin
    n := Be32Of(p + 5);
    if UInt64(n) + 9 > UInt64(len) then Bad('XelSSH: truncated message');
    ch := FindChannel(Be32Of(p + 1));
    if (ch <> nil) and (n > 0) then OnChannelData(ch, 0, p + 9, n);
    Exit;
  end;
  SetLength(m, len);
  Move(p^, m[0], len);
  if not HandleGeneric(m) then Bad(Format('XelSSH: unexpected message %d', [m[0]]));
end;

// next message that is not handled generically
function TSshClient.NextMessage: TBytes;
begin
  repeat
    Result := RecvPacket;
    if Length(Result) = 0 then Bad('XelSSH: empty message');
  until not HandleGeneric(Result);
end;

// ---- key exchange ----

function BuildKexInit(C: TSshClient; Initial: Boolean): TBytes;
var kex: string;
begin
  kex := C.KexAlgorithms;
  if Initial then kex := kex + ',ext-info-c,kex-strict-c-v00@openssh.com';
  Result := Cat([U8b(SSH_MSG_KEXINIT), RandomBytes(16), SshStr(kex), SshStr(C.HostKeyAlgorithms),
    SshStr(C.Ciphers), SshStr(C.Ciphers), SshStr(C.Macs), SshStr(C.Macs), SshStr('none'), SshStr('none'),
    SshStr(''), SshStr(''), U8b(0), SshU32(0)]);
end;

function KexHash(const Alg: string): THashAlg;
begin
  if Alg = 'ecdh-sha2-nistp384' then Result := haSHA384
  else if Alg = 'ecdh-sha2-nistp521' then Result := haSHA512
  else Result := haSHA256;
end;

// DER SEQUENCE { INTEGER r, INTEGER s } from SSH mpints
function EcdsaDer(const R, S: TBytes): TBytes;
  function DerInt(const V: TBytes): TBytes;
  var t: TBytes;
  begin
    t := Copy(V);
    while (Length(t) > 1) and (t[0] = 0) do Delete(t, 0, 1);
    if Length(t) = 0 then t := U8b(0);
    if t[0] >= $80 then t := Concat(U8b(0), t);
    Result := Cat([U8b(2), U8b(Length(t)), t]);
  end;
var body: TBytes;
begin
  body := Concat(DerInt(R), DerInt(S));
  if Length(body) < 128 then Result := Cat([U8b($30), U8b(Length(body)), body])
  else Result := Cat([U8b($30), U8b($81), U8b(Length(body)), body]);
end;

function VerifyHostSig(const KeyBlob, SigBlob, H: TBytes; const HostKeyAlg: string): Boolean;
var KR, SR, QR: TRd; ktype, salg, curve: string; sig, pub, e, n, rr, ss: TBytes; cv: TEcCurveId; ha: THashAlg;
begin
  Result := False;
  KR.Init(KeyBlob); SR.Init(SigBlob);
  ktype := KR.Text;
  salg := SR.Text;
  sig := SR.Str;
  if salg <> HostKeyAlg then Exit;
  if HostKeyAlg = 'ssh-ed25519' then
  begin
    if ktype <> 'ssh-ed25519' then Exit;
    pub := KR.Str;
    Result := Ed25519Verify(pub, H, sig);
  end
  else if Copy(HostKeyAlg, 1, 11) = 'ecdsa-sha2-' then
  begin
    if ktype <> HostKeyAlg then Exit;
    curve := KR.Text;
    pub := KR.Str;
    if curve = 'nistp256' then begin cv := ecP256; ha := haSHA256; end
    else if curve = 'nistp384' then begin cv := ecP384; ha := haSHA384; end
    else if curve = 'nistp521' then begin cv := ecP521; ha := haSHA512; end
    else Exit;
    QR.Init(sig);
    rr := QR.Mpint; ss := QR.Mpint;
    Result := EcdsaVerify(cv, pub, Hash(ha, H), EcdsaDer(rr, ss));
  end
  else if (HostKeyAlg = 'rsa-sha2-256') or (HostKeyAlg = 'rsa-sha2-512') then
  begin
    if ktype <> 'ssh-rsa' then Exit;
    e := KR.Mpint; n := KR.Mpint;
    if Length(n) < 256 then Exit;                         // RSA keys below 2048 bits rejected
    if HostKeyAlg = 'rsa-sha2-256' then ha := haSHA256 else ha := haSHA512;
    // signatures shorter than the modulus are left-padded with zeros
    while Length(sig) < Length(n) do sig := Concat(U8b(0), sig);
    Result := RsaPkcs1Verify(n, e, ha, Hash(ha, H), sig);
  end;
end;

procedure TSshClient.SetupDir(var D: TSshDir; const Cipher, Mac: string; const K, H: TBytes;
  Hash_: THashAlg; const IvC, KeyC, MacC: AnsiChar);

  function Derive(C: AnsiChar; Len: Integer): TBytes;
  var km: TBytes;
  begin
    Result := Hash(Hash_, Cat([SshMpint(K), H, BytesOf(C), FSessionId]));
    while Length(Result) < Len do
      Result := Concat(Result, Hash(Hash_, Cat([SshMpint(K), H, Result])));
    km := Copy(Result, 0, Len);
    Result := km;
  end;

var keyLen: Integer;
begin
  if D.Aes <> nil then begin FreeMem(D.Aes); D.Aes := nil; end;
  D.Etm := False; D.MacLen := 0;
  if Cipher = 'chacha20-poly1305@openssh.com' then
  begin
    D.Kind := ckChaCha;
    D.Key := Derive(KeyC, 64);
    D.KMain := Copy(D.Key, 0, 32);
    D.KHdr := Copy(D.Key, 32, 32);
  end
  else if (Cipher = 'aes256-gcm@openssh.com') or (Cipher = 'aes128-gcm@openssh.com') then
  begin
    D.Kind := ckGcm;
    if Cipher = 'aes256-gcm@openssh.com' then keyLen := 32 else keyLen := 16;
    D.Key := Derive(KeyC, keyLen);
    D.IV := Derive(IvC, 12);
    D.Aes := AllocMem(SizeOf(TGcmKey));
    GcmSetKey(PGcmKey(D.Aes)^, D.Key);
  end
  else
  begin
    D.Kind := ckCtr;
    if Cipher = 'aes256-ctr' then keyLen := 32 else keyLen := 16;
    D.Key := Derive(KeyC, keyLen);
    D.IV := Derive(IvC, 16);
    Move(D.IV[0], D.Ctr[0], 16);
    D.Aes := AllocMem(SizeOf(TAesKey));
    AesSetKey(PAesKey(D.Aes)^, D.Key);
    D.Etm := Pos('-etm@openssh.com', Mac) > 0;
    if Copy(Mac, 1, 13) = 'hmac-sha2-512' then begin D.MacAlg := haSHA512; D.MacLen := 64; end
    else begin D.MacAlg := haSHA256; D.MacLen := 32; end;
    D.MacKey := Derive(MacC, D.MacLen);
  end;
end;

procedure TSshClient.CheckHostKey;
var r: TKnownHostsResult;
begin
  if ExpectedFingerprint <> '' then
  begin
    if ExpectedFingerprint <> FHostKeyFp then
      Bad(Format('XelSSH: host key fingerprint %s does not match the expected %s - possible man-in-the-middle attack',
        [FHostKeyFp, ExpectedFingerprint]));
    Exit;
  end;
  if Policy = hkAny then Exit;
  if KnownHostsFile = '' then
  begin
    if Policy = hkStrict then Bad('XelSSH: no known_hosts file and no expected fingerprint (strict policy)');
    Exit;
  end;
  r := KnownHostsCheck(KnownHostsFile, Host, Port, FHostKeyType, FHostKeyBlob);
  case r of
    khMatch: ;
    khRevoked: Bad('XelSSH: the host key is marked @revoked in known_hosts');
    khMismatch:
      Bad(Format('XelSSH: HOST KEY CHANGED for %s (now %s %s) - possible man-in-the-middle attack; ' +
        'if the change is legitimate, remove the old entry from %s', [Host, FHostKeyType, FHostKeyFp, KnownHostsFile]));
    khUnknown:
      if Policy = hkAcceptNew then
        KnownHostsAdd(KnownHostsFile, Host, Port, FHostKeyType, FHostKeyBlob)
      else
        Bad(Format('XelSSH: unknown host key for %s (%s %s) - add it to known_hosts or set the expected fingerprint',
          [Host, FHostKeyType, FHostKeyFp]));
  end;
end;

procedure TSshClient.DoKex(const ServerKexInitIn: TBytes);
var
  myKexInit, srvKexInit, m, priv, pub, ks, qs, sigBlob, k, h, ex: TBytes;
  R: TRd; sKex, sHost, sEncC, sEncS, sMacC, sMacS, kexAlg, hostAlg, encC, encS, macCli, macSrv: string;
  ha: THashAlg; cv: TEcdhCurve; follows: Boolean; i: Integer;
begin
  myKexInit := BuildKexInit(Self, FInitialKex);
  SendPacket(myKexInit);
  if Length(ServerKexInitIn) > 0 then srvKexInit := ServerKexInitIn
  else
  begin
    // in strict mode KEXINIT must be the very first packet (checked below via the sequence number)
    repeat
      srvKexInit := RecvPacket;
      if Length(srvKexInit) = 0 then Bad('XelSSH: empty message');
      if srvKexInit[0] = SSH_MSG_KEXINIT then Break;
      if not HandleGeneric(srvKexInit) then Bad('XelSSH: expected KEXINIT');
    until False;
  end;
  R.Init(srvKexInit, 17);
  sKex := R.Text; sHost := R.Text; sEncC := R.Text; sEncS := R.Text; sMacC := R.Text; sMacS := R.Text;
  if not NameIn('none', R.Text) or not NameIn('none', R.Text) then Bad('XelSSH: the server requires compression');
  R.Text; R.Text;
  follows := R.Bool;
  if FInitialKex then
  begin
    FStrict := NameIn('kex-strict-s-v00@openssh.com', sKex);
    if FStrict and (FRd.Seq <> 1) then Bad('XelSSH: strict KEX violated (KEXINIT was not the first packet)');
  end;
  kexAlg := Negotiate(KexAlgorithms, sKex, 'key exchange');
  hostAlg := Negotiate(HostKeyAlgorithms, sHost, 'host key');
  encC := Negotiate(Ciphers, sEncC, 'cipher');
  encS := Negotiate(Ciphers, sEncS, 'cipher');
  macCli := ''; macSrv := '';
  if Pos('ctr', encC) > 0 then macCli := Negotiate(Macs, sMacC, 'MAC');
  if Pos('ctr', encS) > 0 then macSrv := Negotiate(Macs, sMacS, 'MAC');
  // a wrongly guessed first kex packet from the server is ignored
  if follows and ((sKex.Split([','])[0] <> kexAlg) or (sHost.Split([','])[0] <> hostAlg)) then RecvPacket;
  // ECDH
  ha := KexHash(kexAlg);
  if Copy(kexAlg, 1, 10) = 'curve25519' then
  begin
    priv := RandomBytes(32);
    pub := X25519Base(priv);
  end
  else
  begin
    if kexAlg = 'ecdh-sha2-nistp384' then cv := ecdhP384
    else if kexAlg = 'ecdh-sha2-nistp521' then cv := ecdhP521 else cv := ecdhP256;
    EcdhKeyPair(cv, priv, pub);
  end;
  SendPacket(Concat(U8b(SSH_MSG_KEX_ECDH_INIT), SshString(pub)));
  repeat
    m := RecvPacket;
    if (Length(m) > 0) and (m[0] = SSH_MSG_KEX_ECDH_REPLY) then Break;
    if FStrict and FInitialKex then Bad('XelSSH: unexpected message during strict key exchange');
    if (Length(m) = 0) or not HandleGeneric(m) then Bad('XelSSH: expected KEX_ECDH_REPLY');
  until False;
  R.Init(m, 1);
  ks := R.Str; qs := R.Str; sigBlob := R.Str;
  if Copy(kexAlg, 1, 10) = 'curve25519' then
  begin
    if Length(qs) <> 32 then Bad('XelSSH: invalid server key exchange value');
    k := X25519(priv, qs);
    ex := nil;
    for i := 0 to 31 do if k[i] <> 0 then ex := k;
    if ex = nil then Bad('XelSSH: degenerate shared secret');
  end
  else if not EcdhShared(cv, priv, qs, k) then Bad('XelSSH: invalid server key exchange value');
  Wipe(priv);
  h := Hash(ha, Cat([SshStr(FClientVersion), SshStr(FServerVersion), SshString(myKexInit),
    SshString(srvKexInit), SshString(ks), SshString(pub), SshString(qs), SshMpint(k)]));
  // host key: same key across rekeys
  if Length(FSessionId) = 0 then
  begin
    FHostKeyBlob := ks;
    R.Init(ks);
    FHostKeyType := R.Text;
    FHostKeyFp := SshFingerprint(ks);
  end
  else if not SameBytesCT(ks, FHostKeyBlob) then Bad('XelSSH: the host key changed during rekeying');
  if not VerifyHostSig(ks, sigBlob, h, hostAlg) then Bad('XelSSH: invalid host key signature');
  if Length(FSessionId) = 0 then
  begin
    FSessionId := h;
    CheckHostKey;
  end;
  // NEWKEYS
  SendPacket(U8b(SSH_MSG_NEWKEYS));
  SetupDir(FWr, encC, macCli, k, h, ha, 'A', 'C', 'E');
  if FStrict then FWr.Seq := 0;
  repeat
    m := RecvPacket;
    if (Length(m) > 0) and (m[0] = SSH_MSG_NEWKEYS) then Break;
    if FStrict and FInitialKex then Bad('XelSSH: unexpected message during strict key exchange');
    if (Length(m) = 0) or not HandleGeneric(m) then Bad('XelSSH: expected NEWKEYS');
  until False;
  SetupDir(FRd, encS, macSrv, k, h, ha, 'B', 'D', 'F');
  if FStrict then FRd.Seq := 0;
  // the reader thread waits after NEWKEYS until the new keys are in place
  if FReader <> nil then
  begin
    FRaLock.Enter;
    FRaKeysReady := True;
    FRaLock.Leave;
    RTLEventSetEvent(FRaKeysEv);
  end;
  Wipe(k);
  FKexAlg := kexAlg; FCipherC2S := encC; FCipherS2C := encS; FMacC2S := macCli;
  FInitialKex := False;
end;

function TSshClient.Connect: Boolean;
var line: string; n: Integer;
begin
  Result := False;
  FLastError := '';
  if FReader <> nil then begin FLastError := 'XelSSH: already connected'; Exit; end;
  try
    FClientVersion := 'SSH-2.0-XelSSH_1.0';
    RawSend(BytesOf(FClientVersion + #13#10));
    n := 0;
    repeat
      line := ReadLine;
      Inc(n);
      if n > 50 then Bad('XelSSH: no SSH identification from the server');
    until Copy(line, 1, 4) = 'SSH-';
    if (Copy(line, 1, 8) <> 'SSH-2.0-') and (Copy(line, 1, 9) <> 'SSH-1.99-') then
      Bad('XelSSH: unsupported SSH protocol version: ' + line);
    FServerVersion := line;
    FWr := Default(TSshDir); FRd := Default(TSshDir);
    FInitialKex := True;
    FSessionId := nil;
    FAuthenticated := False; FUserAuthService := False;
    DoKex(nil);
    FConnected := True;
    Result := True;
  except
    on E: Exception do FLastError := E.Message;
  end;
end;

// ---- authentication ----

function TSshClient.AuthResult(var Partial: Boolean): Boolean;
var m: TBytes; R: TRd;
begin
  Result := False;
  Partial := False;
  repeat
    m := NextMessage;
    case m[0] of
      SSH_MSG_USERAUTH_SUCCESS:
        begin
          FAuthenticated := True;
          Exit(True);
        end;
      SSH_MSG_USERAUTH_FAILURE:
        begin
          R.Init(m, 1);
          FLastError := 'authentication failed (server allows: ' + R.Text + ')';
          Partial := R.Bool;
          Exit(False);
        end;
      SSH_MSG_USERAUTH_BANNER:
        begin
          R.Init(m, 1);
          FBanner := FBanner + R.Text;
        end;
      SSH_MSG_USERAUTH_INFO_REQUEST:          // (password change request uses the same number)
        begin
          FLastError := 'the server requires a password change or interactive input';
          Exit(False);
        end;
    else
      Bad(Format('XelSSH: unexpected message %d during authentication', [m[0]]));
    end;
  until False;
end;

function ServiceRequest(C: TSshClient): Boolean;
var m: TBytes;
begin
  if not C.FConnected then Bad('XelSSH: not connected');
  if C.FAuthenticated then Bad('XelSSH: already authenticated');
  // the service is requested once; further attempts reuse it
  if C.FUserAuthService then Exit(True);
  C.SendPacket(Concat(U8b(SSH_MSG_SERVICE_REQUEST), SshStr('ssh-userauth')));
  m := C.NextMessage;
  Result := m[0] = SSH_MSG_SERVICE_ACCEPT;
  C.FUserAuthService := Result;
  if not Result then C.FLastError := 'the server refused the ssh-userauth service';
end;

function TSshClient.AuthKbdInteractive(const User, Password: string): Boolean;
var m, resp: TBytes; R: TRd; n, i: UInt32;
begin
  Result := False;
  SendPacket(Cat([U8b(SSH_MSG_USERAUTH_REQUEST), SshStr(User), SshStr('ssh-connection'),
    SshStr('keyboard-interactive'), SshStr(''), SshStr('')]));
  repeat
    m := NextMessage;
    case m[0] of
      SSH_MSG_USERAUTH_SUCCESS: begin FAuthenticated := True; Exit(True); end;
      SSH_MSG_USERAUTH_FAILURE:
        begin
          R.Init(m, 1);
          FLastError := 'authentication failed (server allows: ' + R.Text + ')';
          Exit(False);
        end;
      SSH_MSG_USERAUTH_BANNER:
        begin
          R.Init(m, 1);
          FBanner := FBanner + R.Text;
        end;
      SSH_MSG_USERAUTH_INFO_REQUEST:
        begin
          R.Init(m, 1);
          R.Text; R.Text; R.Text;                       // name, instruction, language
          n := R.U32;
          resp := Concat(U8b(SSH_MSG_USERAUTH_INFO_RESPONSE), SshU32(n));
          for i := 1 to n do
          begin
            R.Text; R.Bool;                              // prompt, echo
            resp := Concat(resp, SshStr(Password));
          end;
          SendPacket(resp);
        end;
    else
      Bad(Format('XelSSH: unexpected message %d during authentication', [m[0]]));
    end;
  until False;
end;

function TSshClient.AuthPassword(const User, Password: string): Boolean;
var partial: Boolean; allowed: string;
begin
  Result := False;
  FLastError := '';
  try
    if not ServiceRequest(Self) then Exit;
    SendPacket(Cat([U8b(SSH_MSG_USERAUTH_REQUEST), SshStr(User), SshStr('ssh-connection'),
      SshStr('password'), BoolB(False), SshStr(Password)]));
    Result := AuthResult(partial);
    if not Result then
    begin
      allowed := FLastError;
      // many servers only offer keyboard-interactive for passwords
      if Pos('keyboard-interactive', allowed) > 0 then Result := AuthKbdInteractive(User, Password);
    end;
  except
    on E: Exception do FLastError := E.Message;
  end;
end;

function TSshClient.AuthKey(const User: string; const Key: TSshPrivateKey): Boolean;
var blob, toSign, sig: TBytes; partial: Boolean; alg: string;
begin
  Result := False;
  FLastError := '';
  try
    if not ServiceRequest(Self) then Exit;
    alg := SshSignAlgorithm(Key, FServerSigAlgs);
    blob := SshPublicKeyBlob(Key);
    toSign := Cat([SshString(FSessionId), U8b(SSH_MSG_USERAUTH_REQUEST), SshStr(User), SshStr('ssh-connection'),
      SshStr('publickey'), BoolB(True), SshStr(alg), SshString(blob)]);
    sig := SshSign(Key, alg, toSign);
    SendPacket(Cat([U8b(SSH_MSG_USERAUTH_REQUEST), SshStr(User), SshStr('ssh-connection'),
      SshStr('publickey'), BoolB(True), SshStr(alg), SshString(blob), SshString(sig)]));
    Result := AuthResult(partial);
  except
    on E: Exception do FLastError := E.Message;
  end;
end;

// ---- channels ----

function TSshClient.FindChannel(Id: UInt32): TSshChannel;
var i: Integer;
begin
  for i := 0 to FChannels.Count - 1 do
    if TSshChannel(FChannels[i]).LocalId = Id then Exit(TSshChannel(FChannels[i]));
  Result := nil;
end;

// processes messages until the condition holds: 1 = open state set, 2 = reply,
// 3 = data/eof available, 4 = remote window > 0 (or closed), 5 = closed
procedure TSshClient.WaitChannel(Ch: TSshChannel; Cond: Integer);
  function Done: Boolean;
  begin
    case Cond of
      1: Result := Ch.OpenState <> 0;
      2: Result := Ch.ReplyPending <> 1;
      3: Result := (Ch.InLen > Ch.InPos) or Ch.Eof or Ch.Closed;
      4: Result := (Ch.RemoteWindow > 0) or Ch.Closed;
    else Result := Ch.Closed;
    end;
  end;
begin
  // one packet at a time, so the condition is re-checked after each handled message
  while not Done do ProcessOne;
end;

function TSshClient.OpenSession: TSshChannel;
var ch: TSshChannel;
begin
  if not FAuthenticated then Bad('XelSSH: not authenticated');
  StartReader;
  ch := TSshChannel.Create;
  ch.LocalId := FNextChannel; Inc(FNextChannel);
  ch.LocalWindow := WINDOW_SIZE;
  FChannels.Add(ch);
  SendPacket(Cat([U8b(SSH_MSG_CHANNEL_OPEN), SshStr('session'), SshU32(ch.LocalId),
    SshU32(WINDOW_SIZE), SshU32(MAX_PACKET)]));
  WaitChannel(ch, 1);
  if ch.OpenState <> 1 then
  begin
    FLastError := ch.OpenError;
    FChannels.Remove(ch);
    ch.Free;
    Bad('XelSSH: ' + FLastError);
  end;
  Result := ch;
end;

function TSshClient.ChannelRequest(Ch: TSshChannel; const ReqType: string; const Extra: TBytes;
  WantReply: Boolean): Boolean;
begin
  if WantReply then Ch.ReplyPending := 1 else Ch.ReplyPending := 0;
  SendPacket(Cat([U8b(SSH_MSG_CHANNEL_REQUEST), SshU32(Ch.RemoteId), SshStr(ReqType), BoolB(WantReply), Extra]));
  if not WantReply then Exit(True);
  WaitChannel(Ch, 2);
  Result := Ch.ReplyPending = 2;
end;

procedure TSshClient.ChannelWriteP(Ch: TSshChannel; P: PByte; Len: Integer);
var off, n: Integer; hdr: array[0..8] of Byte;
begin
  off := 0;
  while off < Len do
  begin
    if Ch.RemoteWindow = 0 then WaitChannel(Ch, 4);
    if Ch.Closed then Bad('XelSSH: the channel was closed by the server');
    n := Len - off;
    if n > Integer(Ch.RemoteMaxPacket) - 64 then n := Integer(Ch.RemoteMaxPacket) - 64;
    if n > MAX_PACKET then n := MAX_PACKET;
    if UInt32(n) > Ch.RemoteWindow then n := Ch.RemoteWindow;
    hdr[0] := SSH_MSG_CHANNEL_DATA;
    PutBe32(@hdr[1], Ch.RemoteId);
    PutBe32(@hdr[5], n);
    SendPacketP(@hdr[0], 9, P + off, n);
    Ch.RemoteWindow := Ch.RemoteWindow - UInt32(n);
    Inc(off, n);
  end;
end;

procedure TSshClient.ChannelWrite(Ch: TSshChannel; const Data: TBytes);
begin
  if Length(Data) > 0 then ChannelWriteP(Ch, @Data[0], Length(Data));
end;

function TSshClient.ChannelRead(Ch: TSshChannel; MaxLen: Integer; out Data: TBytes): Integer;
begin
  if Ch.InLen = Ch.InPos then WaitChannel(Ch, 3);
  Result := Ch.InLen - Ch.InPos;
  if Result > MaxLen then Result := MaxLen;
  SetLength(Data, Result);
  if Result > 0 then Move(Ch.InBuf[Ch.InPos], Data[0], Result);
  Inc(Ch.InPos, Result);
end;

procedure TSshClient.ChannelFill(Ch: TSshChannel; N: Integer);
begin
  while Ch.InLen - Ch.InPos < N do
  begin
    if Ch.Eof or Ch.Closed then Bad('XelSSH: the channel was closed by the server');
    ProcessOne;
  end;
end;

function TSshClient.ChannelAvailable(Ch: TSshChannel): Integer;
begin
  Result := Ch.InLen - Ch.InPos;
end;

function TSshClient.ChannelPeek(Ch: TSshChannel): PByte;
begin
  if Ch.InLen > Ch.InPos then Result := @Ch.InBuf[Ch.InPos] else Result := nil;
end;

procedure TSshClient.ChannelConsume(Ch: TSshChannel; N: Integer);
begin
  Inc(Ch.InPos, N);
  if Ch.InPos > Ch.InLen then Ch.InPos := Ch.InLen;
end;

procedure TSshClient.ChannelSendEof(Ch: TSshChannel);
begin
  if not Ch.Closed then SendPacket(Concat(U8b(SSH_MSG_CHANNEL_EOF), SshU32(Ch.RemoteId)));
end;

procedure TSshClient.ChannelClose(Ch: TSshChannel);
begin
  try
    if not Ch.CloseSent and not Ch.Closed then
    begin
      SendPacket(Concat(U8b(SSH_MSG_CHANNEL_CLOSE), SshU32(Ch.RemoteId)));
      Ch.CloseSent := True;
    end;
    if not Ch.Closed then WaitChannel(Ch, 5);
  finally
    FChannels.Remove(Ch);
    Ch.Free;
  end;
end;

function TSshClient.Exec(const Command: string; out StdErr: RawByteString; out ExitCode: Integer): RawByteString;
var ch: TSshChannel; d: TBytes; outB: TBytesStream;
begin
  Result := ''; StdErr := ''; ExitCode := -1;
  ch := OpenSession;
  try
    ch.ExitStatus := -1;
    if not ChannelRequest(ch, 'exec', SshStr(Command), True) then Bad('XelSSH: the server refused to run the command');
    ChannelSendEof(ch);
    outB := TBytesStream.Create(nil);
    try
      while ChannelRead(ch, MaxInt, d) > 0 do outB.WriteBuffer(d[0], Length(d));
      if not ch.Closed then WaitChannel(ch, 5);
      if outB.Size > 0 then SetString(Result, PAnsiChar(outB.Memory), outB.Size);
    finally
      outB.Free;
    end;
    if Length(ch.ErrData) > 0 then SetString(StdErr, PAnsiChar(@ch.ErrData[0]), Length(ch.ErrData));
    ExitCode := ch.ExitStatus;
  finally
    ChannelClose(ch);
  end;
end;

procedure TSshClient.Disconnect;
begin
  if FConnected then
    try
      SendPacket(Cat([U8b(SSH_MSG_DISCONNECT), SshU32(11), SshStr('bye'), SshStr('')]));
    except
    end;
  FConnected := False;
  FAuthenticated := False;
  FUserAuthService := False;
  StopReader;
  FreeAndNil(FSock);
end;

end.
