// XelSSH - SFTP client (protocol version 3, draft-ietf-secsh-filexfer-02), as used
// by OpenSSH and most servers. Runs on an authenticated TSshClient.
//
// Transfers are pipelined (many READ/WRITE requests in flight); short reads are
// re-requested. OpenSSH extensions used when offered: posix-rename@openssh.com
// (atomic rename that replaces the target) and limits@openssh.com (chunk sizes).
// Paths are byte strings (UTF-8 on practically all servers).
//
// License: MIT.
unit XelSshSftp;

{$mode objfpc}{$H+}{$Q-}{$R-}
{$modeswitch advancedrecords}

interface

uses
  SysUtils, Classes, XelSshClient;

const
  // status codes
  SFTP_OK = 0; SFTP_EOF = 1; SFTP_NO_SUCH_FILE = 2; SFTP_PERMISSION_DENIED = 3; SFTP_FAILURE = 4;
  SFTP_BAD_MESSAGE = 5; SFTP_NO_CONNECTION = 6; SFTP_CONNECTION_LOST = 7; SFTP_OP_UNSUPPORTED = 8;
  // open flags
  SFTP_READ = 1; SFTP_WRITE = 2; SFTP_APPEND = 4; SFTP_CREAT = 8; SFTP_TRUNC = $10; SFTP_EXCL = $20;
  // attribute flags
  SFTP_ATTR_SIZE = 1; SFTP_ATTR_UIDGID = 2; SFTP_ATTR_PERMISSIONS = 4; SFTP_ATTR_ACMODTIME = 8;
  SFTP_ATTR_EXTENDED = $80000000;

type
  ESftpError = class(Exception)
  public
    Code: Integer;          // SFTP status code; -1 = protocol or connection error
    constructor CreateCode(ACode: Integer; const Msg: string);
  end;

  TSftpAttrs = record
    Flags: UInt32;          // which fields are valid (SFTP_ATTR_*)
    Size: Int64;
    Uid, Gid: UInt32;
    Perm: UInt32;           // Unix mode including the file type bits
    ATime, MTime: Int64;    // Unix time
    function IsDir: Boolean;
    function IsLink: Boolean;
    function IsFile: Boolean;
  end;

  TSftpEntry = record
    Name, LongName: string; // LongName = "ls -l" style line from the server
    Attrs: TSftpAttrs;
  end;
  TSftpEntries = array of TSftpEntry;

  // Done bytes, Total bytes (-1 if unknown)
  TSftpProgress = procedure(Done, Total: Int64) of object;

  TSftpClient = class
  private
    FSsh: TSshClient;
    FOwnsSsh: Boolean;
    FCh: TSshChannel;
    FNextId: UInt32;
    FStash: array of TBytes;        // replies received while waiting for another id
    FVersion: Integer;
    FExtensions: TStringList;
    FReadChunk, FWriteChunk, FMaxRequests: Integer;
    procedure SendPkt(Typ: Byte; const Body: TBytes);
    function NewId: UInt32;
    function RecvPkt: TBytes;
    function Request(Typ: Byte; const Body: TBytes): UInt32;
    function WaitReply(Id: UInt32): TBytes;
    function Call(Typ: Byte; const Body: TBytes): TBytes;
    procedure CheckStatus(const P: TBytes; const What: string);
    function ExpectHandle(const P: TBytes; const What: string): TBytes;
    function StatReq(Typ: Byte; const Path: string): TSftpAttrs;
    procedure SetStat(const Path: string; const Attrs: TBytes);
    procedure Init;
    procedure DoDownload(const Remote: string; Dest: TStream; StartOff, Len: Int64; Progress: TSftpProgress);
    procedure DoUpload(Src: TStream; const Remote: string; Mode: Integer; Progress: TSftpProgress;
      StartOff, Len: Int64; Truncate: Boolean);
  public
    // ASsh must be connected and authenticated; starts the "sftp" subsystem.
    constructor Create(ASsh: TSshClient; AOwnsSsh: Boolean = False);
    destructor Destroy; override;
    function HasExtension(const Name: string): Boolean;

    function RealPath(const Path: string): string;           // canonical absolute path ('.' = home)
    function Stat(const Path: string): TSftpAttrs;           // follows symlinks
    function LStat(const Path: string): TSftpAttrs;
    function TryStat(const Path: string; out Attrs: TSftpAttrs): Boolean;   // False if missing
    function Exists(const Path: string): Boolean;
    function ListDir(const Path: string): TSftpEntries;      // without "." and ".."
    procedure MkDir(const Path: string; Mode: Integer = -1);
    procedure RmDir(const Path: string);
    procedure Remove(const Path: string);
    // Overwrite: replace an existing target (atomic with posix-rename@openssh.com)
    procedure Rename(const OldPath, NewPath: string; Overwrite: Boolean = True);
    procedure SetPermissions(const Path: string; Mode: UInt32);
    procedure SetTimes(const Path: string; ATime, MTime: Int64);
    function ReadLink(const Path: string): string;
    procedure Symlink(const LinkPath, TargetPath: string);

    // Remote file -> stream (from the stream's current position).
    procedure Download(const Remote: string; Dest: TStream; Progress: TSftpProgress = nil);
    // Stream (from its current position to the end) -> remote file (created or truncated).
    procedure Upload(Src: TStream; const Remote: string; Mode: Integer = -1; Progress: TSftpProgress = nil);
    procedure DownloadFile(const Remote, Local: string; Progress: TSftpProgress = nil);
    procedure UploadFile(const Local, Remote: string; Progress: TSftpProgress = nil);
    // Byte ranges at absolute offsets (parallel transfers): bytes Off..Off+Len-1 of the
    // remote file go to Dest at the same positions; Src (from Off, Len bytes) goes into an
    // existing remote file at the same offsets (no truncation).
    procedure DownloadRange(const Remote: string; Dest: TStream; Off, Len: Int64; Progress: TSftpProgress = nil);
    procedure UploadRange(Src: TStream; const Remote: string; Off, Len: Int64; Progress: TSftpProgress = nil);
    function GetBytes(const Remote: string): TBytes;
    procedure PutBytes(const Remote: string; const Data: TBytes; Mode: Integer = -1);

    // low level
    function OpenHandle(const Path: string; Flags: UInt32; Mode: Integer = -1): TBytes;
    procedure CloseHandle(const Handle: TBytes);

    property Ssh: TSshClient read FSsh;
    property Version: Integer read FVersion;
    property Extensions: TStringList read FExtensions;      // name=data, as sent by the server
    property ReadChunk: Integer read FReadChunk write FReadChunk;
    property WriteChunk: Integer read FWriteChunk write FWriteChunk;
    property MaxRequests: Integer read FMaxRequests write FMaxRequests;
  end;

function SftpStatusText(Code: Integer): string;

type
  // a new, connected and authenticated SFTP client (for the extra connections); the
  // client should own its SSH connection (freed with it). Called from worker threads,
  // several at once: it must be thread-safe.
  TSftpConnectFn = function: TSftpClient of object;

// One file over Parts connections at once: Main transfers the first part, Parts - 1 more
// clients from Connect the others - each thread opens its own connection, so the
// connection set-ups overlap with each other and with the first part. Small files
// (below 4 MB per part) use fewer parts. The local file is created with its full size
// first; the remote file of an upload is created or truncated first.
procedure SftpParallelDownload(Main: TSftpClient; Connect: TSftpConnectFn; const Remote, Local: string;
  Parts: Integer);
procedure SftpParallelUpload(Main: TSftpClient; Connect: TSftpConnectFn; const Local, Remote: string;
  Parts: Integer; Mode: Integer = -1);

implementation

uses XelSshKeys;

const
  FXP_INIT = 1; FXP_VERSION = 2; FXP_OPEN = 3; FXP_CLOSE = 4; FXP_READ = 5; FXP_WRITE = 6;
  FXP_LSTAT = 7; FXP_FSTAT = 8; FXP_SETSTAT = 9; FXP_OPENDIR = 11; FXP_READDIR = 12;
  FXP_REMOVE = 13; FXP_MKDIR = 14; FXP_RMDIR = 15; FXP_REALPATH = 16; FXP_STAT = 17;
  FXP_RENAME = 18; FXP_READLINK = 19; FXP_SYMLINK = 20;
  FXP_STATUS = 101; FXP_HANDLE = 102; FXP_DATA = 103; FXP_NAME = 104; FXP_ATTRS = 105;
  FXP_EXTENDED = 200; FXP_EXTENDED_REPLY = 201;

  MAX_SFTP_PACKET = 4 * 1024 * 1024;
  DEF_CHUNK = 32768;
  MAX_CHUNK = 255 * 1024;
  IN_FLIGHT = 4 * 1024 * 1024;     // bytes requested ahead in pipelined transfers

  S_IFMT = $F000; S_IFDIR = $4000; S_IFREG = $8000; S_IFLNK = $A000;

type
  TPr = record
    B: TBytes; P: Integer;
    procedure Init(const X: TBytes; Start: Integer);
    function U8: Byte;
    function U32: UInt32;
    function U64: QWord;
    function Str: TBytes;
    function Text: string;
    function Left: Integer;
  end;

procedure Fail(const Msg: string);
begin
  raise ESftpError.CreateCode(-1, Msg);
end;

procedure TPr.Init(const X: TBytes; Start: Integer); begin B := X; P := Start; end;
function TPr.Left: Integer; begin Result := Length(B) - P; end;
function TPr.U8: Byte;
begin
  if P >= Length(B) then Fail('SFTP: truncated reply');
  Result := B[P]; Inc(P);
end;
function TPr.U32: UInt32;
begin
  if P + 4 > Length(B) then Fail('SFTP: truncated reply');
  Result := (UInt32(B[P]) shl 24) or (UInt32(B[P + 1]) shl 16) or (UInt32(B[P + 2]) shl 8) or B[P + 3];
  Inc(P, 4);
end;
function TPr.U64: QWord; begin Result := QWord(U32) shl 32; Result := Result or U32; end;
function TPr.Str: TBytes;
var n: UInt32;
begin
  n := U32;
  if n > UInt32(Left) then Fail('SFTP: truncated reply');
  Result := Copy(B, P, n);
  Inc(P, n);
end;
function TPr.Text: string;
var t: TBytes;
begin
  t := Str;
  if Length(t) = 0 then Result := '' else SetString(Result, PAnsiChar(@t[0]), Length(t));
end;

function U8b(V: Byte): TBytes; begin Result := TBytes.Create(V); end;

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

function ReadAttrs(var R: TPr): TSftpAttrs;
var n, i: UInt32;
begin
  Result := Default(TSftpAttrs);
  Result.Flags := R.U32;
  if Result.Flags and SFTP_ATTR_SIZE <> 0 then Result.Size := Int64(R.U64);
  if Result.Flags and SFTP_ATTR_UIDGID <> 0 then begin Result.Uid := R.U32; Result.Gid := R.U32; end;
  if Result.Flags and SFTP_ATTR_PERMISSIONS <> 0 then Result.Perm := R.U32;
  if Result.Flags and SFTP_ATTR_ACMODTIME <> 0 then begin Result.ATime := R.U32; Result.MTime := R.U32; end;
  if Result.Flags and SFTP_ATTR_EXTENDED <> 0 then
  begin
    n := R.U32;
    for i := 1 to n do begin R.Str; R.Str; end;
  end;
end;

function PermAttrs(Mode: Integer): TBytes;
begin
  if Mode < 0 then Result := SshU32(0)
  else Result := Concat(SshU32(SFTP_ATTR_PERMISSIONS), SshU32(UInt32(Mode) and $FFF));
end;

function SftpStatusText(Code: Integer): string;
begin
  case Code of
    SFTP_OK: Result := 'OK';
    SFTP_EOF: Result := 'end of file';
    SFTP_NO_SUCH_FILE: Result := 'no such file or directory';
    SFTP_PERMISSION_DENIED: Result := 'permission denied';
    SFTP_FAILURE: Result := 'failure';
    SFTP_BAD_MESSAGE: Result := 'bad message';
    SFTP_NO_CONNECTION: Result := 'no connection';
    SFTP_CONNECTION_LOST: Result := 'connection lost';
    SFTP_OP_UNSUPPORTED: Result := 'operation not supported';
  else
    Result := 'error ' + IntToStr(Code);
  end;
end;

// ---- ESftpError ----

constructor ESftpError.CreateCode(ACode: Integer; const Msg: string);
begin
  inherited Create(Msg);
  Code := ACode;
end;

// ---- TSftpAttrs ----

function TSftpAttrs.IsDir: Boolean;
begin
  Result := (Flags and SFTP_ATTR_PERMISSIONS <> 0) and (Perm and S_IFMT = S_IFDIR);
end;

function TSftpAttrs.IsLink: Boolean;
begin
  Result := (Flags and SFTP_ATTR_PERMISSIONS <> 0) and (Perm and S_IFMT = S_IFLNK);
end;

function TSftpAttrs.IsFile: Boolean;
begin
  Result := (Flags and SFTP_ATTR_PERMISSIONS <> 0) and (Perm and S_IFMT = S_IFREG);
end;

// ---- TSftpClient ----

constructor TSftpClient.Create(ASsh: TSshClient; AOwnsSsh: Boolean);
begin
  inherited Create;
  FSsh := ASsh;
  FOwnsSsh := AOwnsSsh;
  FExtensions := TStringList.Create;
  FReadChunk := DEF_CHUNK;
  FWriteChunk := DEF_CHUNK;
  FMaxRequests := 64;
  FNextId := 1;
  Init;
end;

destructor TSftpClient.Destroy;
begin
  if FCh <> nil then
    try FSsh.ChannelClose(FCh); except end;
  FCh := nil;
  FExtensions.Free;
  if FOwnsSsh then FSsh.Free;
  inherited Destroy;
end;

procedure TSftpClient.Init;
var p: TBytes; R: TPr; name, data: string; lim: TPr; mr, mw: QWord;
begin
  if not FSsh.Authenticated then Fail('SFTP: the SSH connection is not authenticated');
  FCh := FSsh.OpenSession;
  if not FSsh.ChannelRequest(FCh, 'subsystem', SshStr('sftp'), True) then
    Fail('SFTP: the server refused the sftp subsystem');
  SendPkt(FXP_INIT, SshU32(3));
  p := RecvPkt;
  if p[0] <> FXP_VERSION then Fail('SFTP: expected VERSION from the server');
  R.Init(p, 1);
  FVersion := R.U32;
  if FVersion < 3 then Fail(Format('SFTP: unsupported protocol version %d', [FVersion]));
  while R.Left > 0 do
  begin
    name := R.Text; data := R.Text;
    FExtensions.Add(name + '=' + data);
  end;
  // larger chunks if the server announces its limits
  if HasExtension('limits@openssh.com') then
  begin
    p := Call(FXP_EXTENDED, SshStr('limits@openssh.com'));
    if p[0] = FXP_EXTENDED_REPLY then
    begin
      lim.Init(p, 5);
      lim.U64;                                     // max packet length
      mr := lim.U64; mw := lim.U64;
      if mr > MAX_CHUNK then mr := MAX_CHUNK;
      if mw > MAX_CHUNK then mw := MAX_CHUNK;
      if mr >= 1024 then FReadChunk := mr;
      if mw >= 1024 then FWriteChunk := mw;
    end;
  end;
end;

function TSftpClient.HasExtension(const Name: string): Boolean;
begin
  Result := FExtensions.IndexOfName(Name) >= 0;
end;

function Be32Of(P: PByte): UInt32; inline;
begin
  Result := (UInt32(P[0]) shl 24) or (UInt32(P[1]) shl 16) or (UInt32(P[2]) shl 8) or P[3];
end;

procedure PutBe32(P: PByte; V: UInt32); inline;
begin
  P[0] := Byte(V shr 24); P[1] := Byte(V shr 16); P[2] := Byte(V shr 8); P[3] := Byte(V);
end;

procedure TSftpClient.SendPkt(Typ: Byte; const Body: TBytes);
var pkt: TBytes;
begin
  SetLength(pkt, 5 + Length(Body));
  PutBe32(@pkt[0], 1 + Length(Body));
  pkt[4] := Typ;
  if Length(Body) > 0 then Move(Body[0], pkt[5], Length(Body));
  FSsh.ChannelWriteP(FCh, @pkt[0], Length(pkt));
end;

// next packet, read straight from the channel buffer (one copy)
function TSftpClient.RecvPkt: TBytes;
var q: PByte; len: UInt32;
begin
  FSsh.ChannelFill(FCh, 4);
  len := Be32Of(FSsh.ChannelPeek(FCh));
  if (len < 1) or (len > MAX_SFTP_PACKET) then Fail('SFTP: invalid packet length');
  FSsh.ChannelFill(FCh, 4 + len);
  q := FSsh.ChannelPeek(FCh);
  SetLength(Result, len);
  Move(q[4], Result[0], len);
  FSsh.ChannelConsume(FCh, 4 + len);
end;

function TSftpClient.NewId: UInt32;
begin
  Result := FNextId;
  Inc(FNextId);
  if FNextId = 0 then FNextId := 1;
end;

function TSftpClient.Request(Typ: Byte; const Body: TBytes): UInt32;
var pkt: TBytes;
begin
  Result := NewId;
  SetLength(pkt, 9 + Length(Body));
  PutBe32(@pkt[0], 5 + Length(Body));
  pkt[4] := Typ;
  PutBe32(@pkt[5], Result);
  if Length(Body) > 0 then Move(Body[0], pkt[9], Length(Body));
  FSsh.ChannelWriteP(FCh, @pkt[0], Length(pkt));
end;

function ReplyId(const P: TBytes): UInt32;
begin
  if Length(P) < 5 then Fail('SFTP: truncated reply');
  Result := (UInt32(P[1]) shl 24) or (UInt32(P[2]) shl 16) or (UInt32(P[3]) shl 8) or P[4];
end;

function TSftpClient.WaitReply(Id: UInt32): TBytes;
var i: Integer;
begin
  for i := 0 to High(FStash) do
    if ReplyId(FStash[i]) = Id then
    begin
      Result := FStash[i];
      Delete(FStash, i, 1);
      Exit;
    end;
  repeat
    Result := RecvPkt;
    if ReplyId(Result) = Id then Exit;
    if Length(FStash) > 1024 then Fail('SFTP: too many unexpected replies');
    Insert(Result, FStash, Length(FStash));
  until False;
end;

function TSftpClient.Call(Typ: Byte; const Body: TBytes): TBytes;
begin
  Result := WaitReply(Request(Typ, Body));
end;

procedure TSftpClient.CheckStatus(const P: TBytes; const What: string);
var R: TPr; code: UInt32; msg: string;
begin
  if P[0] <> FXP_STATUS then Fail('SFTP: unexpected reply ' + IntToStr(P[0]) + ' (' + What + ')');
  R.Init(P, 5);
  code := R.U32;
  if code = SFTP_OK then Exit;
  msg := '';
  if R.Left >= 4 then msg := R.Text;
  if (msg = '') or SameText(msg, SftpStatusText(code)) then msg := SftpStatusText(code);
  raise ESftpError.CreateCode(code, Format('SFTP: %s: %s', [What, msg]));
end;

function TSftpClient.ExpectHandle(const P: TBytes; const What: string): TBytes;
var R: TPr;
begin
  if P[0] = FXP_STATUS then CheckStatus(P, What);
  if P[0] <> FXP_HANDLE then Fail('SFTP: unexpected reply (' + What + ')');
  R.Init(P, 5);
  Result := R.Str;
end;

function TSftpClient.OpenHandle(const Path: string; Flags: UInt32; Mode: Integer): TBytes;
begin
  Result := ExpectHandle(Call(FXP_OPEN, Cat([SshStr(Path), SshU32(Flags), PermAttrs(Mode)])), Path);
end;

procedure TSftpClient.CloseHandle(const Handle: TBytes);
begin
  CheckStatus(Call(FXP_CLOSE, SshString(Handle)), 'close');
end;

function TSftpClient.RealPath(const Path: string): string;
var p: TBytes; R: TPr;
begin
  p := Call(FXP_REALPATH, SshStr(Path));
  if p[0] = FXP_STATUS then CheckStatus(p, Path);
  if p[0] <> FXP_NAME then Fail('SFTP: unexpected reply (realpath)');
  R.Init(p, 5);
  if R.U32 < 1 then Fail('SFTP: empty realpath reply');
  Result := R.Text;
end;

function TSftpClient.StatReq(Typ: Byte; const Path: string): TSftpAttrs;
var p: TBytes; R: TPr;
begin
  p := Call(Typ, SshStr(Path));
  if p[0] = FXP_STATUS then CheckStatus(p, Path);
  if p[0] <> FXP_ATTRS then Fail('SFTP: unexpected reply (stat)');
  R.Init(p, 5);
  Result := ReadAttrs(R);
end;

function TSftpClient.Stat(const Path: string): TSftpAttrs;
begin
  Result := StatReq(FXP_STAT, Path);
end;

function TSftpClient.LStat(const Path: string): TSftpAttrs;
begin
  Result := StatReq(FXP_LSTAT, Path);
end;

function TSftpClient.TryStat(const Path: string; out Attrs: TSftpAttrs): Boolean;
begin
  Attrs := Default(TSftpAttrs);
  try
    Attrs := StatReq(FXP_STAT, Path);
    Result := True;
  except
    on E: ESftpError do
      if E.Code = SFTP_NO_SUCH_FILE then Result := False else raise;
  end;
end;

function TSftpClient.Exists(const Path: string): Boolean;
var a: TSftpAttrs;
begin
  Result := TryStat(Path, a);
end;

function TSftpClient.ListDir(const Path: string): TSftpEntries;
var h, p: TBytes; R: TPr; n, i: UInt32; e: TSftpEntry; cnt: Integer;
begin
  Result := nil; cnt := 0;
  h := ExpectHandle(Call(FXP_OPENDIR, SshStr(Path)), Path);
  try
    repeat
      p := Call(FXP_READDIR, SshString(h));
      if p[0] = FXP_STATUS then
      begin
        R.Init(p, 5);
        if R.U32 = SFTP_EOF then Break;
        CheckStatus(p, Path);
      end;
      if p[0] <> FXP_NAME then Fail('SFTP: unexpected reply (readdir)');
      R.Init(p, 5);
      n := R.U32;
      for i := 1 to n do
      begin
        e.Name := R.Text;
        e.LongName := R.Text;
        e.Attrs := ReadAttrs(R);
        if (e.Name = '.') or (e.Name = '..') then Continue;
        if cnt >= Length(Result) then SetLength(Result, cnt * 2 + 16);
        Result[cnt] := e;
        Inc(cnt);
      end;
    until False;
  finally
    try CloseHandle(h); except end;
  end;
  SetLength(Result, cnt);
end;

procedure TSftpClient.MkDir(const Path: string; Mode: Integer);
begin
  CheckStatus(Call(FXP_MKDIR, Concat(SshStr(Path), PermAttrs(Mode))), Path);
end;

procedure TSftpClient.RmDir(const Path: string);
begin
  CheckStatus(Call(FXP_RMDIR, SshStr(Path)), Path);
end;

procedure TSftpClient.Remove(const Path: string);
begin
  CheckStatus(Call(FXP_REMOVE, SshStr(Path)), Path);
end;

procedure TSftpClient.Rename(const OldPath, NewPath: string; Overwrite: Boolean);
var a: TSftpAttrs;
begin
  if Overwrite and HasExtension('posix-rename@openssh.com') then
  begin
    CheckStatus(Call(FXP_EXTENDED, Cat([SshStr('posix-rename@openssh.com'), SshStr(OldPath), SshStr(NewPath)])),
      OldPath);
    Exit;
  end;
  // plain SFTP v3 rename fails when the target exists
  if Overwrite and (OldPath <> NewPath) and TryStat(NewPath, a) and not a.IsDir then Remove(NewPath);
  CheckStatus(Call(FXP_RENAME, Concat(SshStr(OldPath), SshStr(NewPath))), OldPath);
end;

procedure TSftpClient.SetStat(const Path: string; const Attrs: TBytes);
begin
  CheckStatus(Call(FXP_SETSTAT, Concat(SshStr(Path), Attrs)), Path);
end;

procedure TSftpClient.SetPermissions(const Path: string; Mode: UInt32);
begin
  SetStat(Path, PermAttrs(Mode and $FFF));
end;

procedure TSftpClient.SetTimes(const Path: string; ATime, MTime: Int64);
begin
  SetStat(Path, Cat([SshU32(SFTP_ATTR_ACMODTIME), SshU32(UInt32(ATime)), SshU32(UInt32(MTime))]));
end;

function TSftpClient.ReadLink(const Path: string): string;
var p: TBytes; R: TPr;
begin
  p := Call(FXP_READLINK, SshStr(Path));
  if p[0] = FXP_STATUS then CheckStatus(p, Path);
  if p[0] <> FXP_NAME then Fail('SFTP: unexpected reply (readlink)');
  R.Init(p, 5);
  if R.U32 < 1 then Fail('SFTP: empty readlink reply');
  Result := R.Text;
end;

procedure TSftpClient.Symlink(const LinkPath, TargetPath: string);
begin
  // OpenSSH swapped the arguments relative to the draft; most servers follow OpenSSH
  CheckStatus(Call(FXP_SYMLINK, Concat(SshStr(TargetPath), SshStr(LinkPath))), LinkPath);
end;

// ---- transfers ----

type
  TReadReq = record
    Id: UInt32;
    Off: Int64;
    Len: UInt32;
  end;

procedure TSftpClient.Download(const Remote: string; Dest: TStream; Progress: TSftpProgress);
begin
  DoDownload(Remote, Dest, 0, -1, Progress);
end;

procedure TSftpClient.DownloadRange(const Remote: string; Dest: TStream; Off, Len: Int64; Progress: TSftpProgress);
begin
  Dest.Position := Off;
  DoDownload(Remote, Dest, Off, Len, Progress);
end;

// bytes StartOff.. (Len = -1: to the end) -> Dest at Dest.Position + (offset - StartOff)
procedure TSftpClient.DoDownload(const Remote: string; Dest: TStream; StartOff, Len: Int64; Progress: TSftpProgress);
var
  h, p: TBytes; R: TPr; reqs: array of TReadReq; nreq, i, maxReq: Integer;
  nextOff, base, total, done, endOff: Int64; eof: Boolean; id, code, plen, dlen, typ, n: UInt32; rq: TReadReq;
  err: string; q: PByte;

  procedure Issue(Off: Int64; Len: UInt32);
  begin
    if nreq >= Length(reqs) then SetLength(reqs, nreq * 2 + 8);
    reqs[nreq].Id := Request(FXP_READ, Cat([SshString(h), U64b(QWord(Off)), SshU32(Len)]));
    reqs[nreq].Off := Off;
    reqs[nreq].Len := Len;
    Inc(nreq);
  end;

begin
  h := OpenHandle(Remote, SFTP_READ);
  err := '';
  try
    total := -1;
    try
      p := Call(FXP_FSTAT, SshString(h));
      if p[0] = FXP_ATTRS then
      begin
        R.Init(p, 5);
        with ReadAttrs(R) do if Flags and SFTP_ATTR_SIZE <> 0 then total := Size;
      end;
    except
      on E: ESftpError do if E.Code < 0 then raise;
    end;
    base := Dest.Position - StartOff;
    if Len >= 0 then begin endOff := StartOff + Len; total := Len; end else endOff := -1;
    maxReq := IN_FLIGHT div FReadChunk;
    if maxReq > FMaxRequests then maxReq := FMaxRequests;
    if maxReq < 1 then maxReq := 1;
    reqs := nil; nreq := 0;
    nextOff := StartOff; eof := False; done := 0;
    repeat
      while not eof and (nreq < maxReq) and (err = '') and ((endOff < 0) or (nextOff < endOff)) do
      begin
        n := FReadChunk;
        if (endOff >= 0) and (nextOff + n > endOff) then n := endOff - nextOff;
        Issue(nextOff, n);
        Inc(nextOff, n);
      end;
      if nreq = 0 then Break;
      // header: length, type, request id
      FSsh.ChannelFill(FCh, 9);
      q := FSsh.ChannelPeek(FCh);
      plen := Be32Of(q);
      if (plen < 5) or (plen > MAX_SFTP_PACKET) then Fail('SFTP: invalid packet length');
      typ := q[4];
      id := Be32Of(q + 5);
      i := 0;
      while (i < nreq) and (reqs[i].Id <> id) do Inc(i);
      if i = nreq then Fail('SFTP: reply to an unknown request');
      rq := reqs[i];
      reqs[i] := reqs[nreq - 1];
      Dec(nreq);
      if typ = FXP_DATA then
      begin
        // the data goes from the channel buffer straight into the stream
        FSsh.ChannelFill(FCh, 4 + plen);
        q := FSsh.ChannelPeek(FCh);
        if plen < 9 then Fail('SFTP: truncated reply');
        dlen := Be32Of(q + 9);
        if dlen > plen - 9 then Fail('SFTP: truncated reply');
        if dlen > rq.Len then Fail('SFTP: the server sent more data than requested');
        if (err = '') and (dlen > 0) then
        begin
          Dest.Position := base + rq.Off;
          Dest.WriteBuffer(q[13], dlen);
        end;
        FSsh.ChannelConsume(FCh, 4 + plen);
        if err <> '' then Continue;                  // draining after an error
        if dlen = 0 then begin eof := True; Continue; end;
        Inc(done, dlen);
        if Assigned(Progress) then Progress(done, total);
        // short read: ask again for the rest of this block
        if dlen < rq.Len then Issue(rq.Off + dlen, rq.Len - dlen);
        Continue;
      end;
      p := RecvPkt;
      if err <> '' then Continue;                    // draining after an error
      if p[0] = FXP_STATUS then
      begin
        R.Init(p, 5);
        code := R.U32;
        if code = SFTP_EOF then eof := True
        else
          try
            CheckStatus(p, Remote);
          except
            on E: Exception do err := E.Message;
          end;
      end
      else
        Fail('SFTP: unexpected reply (read)');
    until False;
    Dest.Position := base + StartOff + done;
  finally
    try CloseHandle(h); except end;
  end;
  if err <> '' then raise ESftpError.CreateCode(SFTP_FAILURE, err);
end;

procedure TSftpClient.Upload(Src: TStream; const Remote: string; Mode: Integer; Progress: TSftpProgress);
begin
  DoUpload(Src, Remote, Mode, Progress, 0, -1, True);
end;

procedure TSftpClient.UploadRange(Src: TStream; const Remote: string; Off, Len: Int64; Progress: TSftpProgress);
begin
  Src.Position := Off;
  DoUpload(Src, Remote, -1, Progress, Off, Len, False);
end;

// Src (from its position; Len = -1: to the end) -> the remote file from offset StartOff
procedure TSftpClient.DoUpload(Src: TStream; const Remote: string; Mode: Integer; Progress: TSftpProgress;
  StartOff, Len: Int64; Truncate: Boolean);
var
  h, buf, p: TBytes; off, total, left: Int64; n, pending, maxReq, hdr, want: Integer; srcEof: Boolean; err: string;
  ids: array of UInt32; lens: array of Integer; i: Integer; id: UInt32; acked: Int64;
begin
  if Truncate then h := OpenHandle(Remote, SFTP_WRITE or SFTP_CREAT or SFTP_TRUNC, Mode)
  else h := OpenHandle(Remote, SFTP_WRITE);
  err := '';
  try
    if Len >= 0 then total := Len
    else try total := Src.Size - Src.Position; except total := -1; end;
    left := Len;
    maxReq := IN_FLIGHT div FWriteChunk;
    if maxReq > FMaxRequests then maxReq := FMaxRequests;
    if maxReq < 1 then maxReq := 1;
    // WRITE packet: length, type, id, string handle, uint64 offset, string data
    hdr := 4 + 1 + 4 + 4 + Length(h) + 8 + 4;
    SetLength(buf, hdr + FWriteChunk);
    buf[4] := FXP_WRITE;
    PutBe32(@buf[9], Length(h));
    if Length(h) > 0 then Move(h[0], buf[13], Length(h));
    SetLength(ids, maxReq); SetLength(lens, maxReq);
    off := StartOff; pending := 0; srcEof := False; acked := 0;
    repeat
      while not srcEof and (pending < maxReq) and (err = '') do
      begin
        want := FWriteChunk;
        if (Len >= 0) and (left < want) then want := left;
        if want <= 0 then begin srcEof := True; Break; end;
        n := Src.Read(buf[hdr], want);
        if n <= 0 then begin srcEof := True; Break; end;
        if Len >= 0 then Dec(left, n);
        id := NewId;
        PutBe32(@buf[0], hdr - 4 + n);
        PutBe32(@buf[5], id);
        PutBe32(@buf[13 + Length(h)], UInt32(QWord(off) shr 32));
        PutBe32(@buf[17 + Length(h)], UInt32(off));
        PutBe32(@buf[21 + Length(h)], n);
        FSsh.ChannelWriteP(FCh, @buf[0], hdr + n);
        ids[pending] := id;
        lens[pending] := n;
        Inc(pending);
        Inc(off, n);
      end;
      if pending = 0 then Break;
      p := RecvPkt;
      id := ReplyId(p);
      i := 0;
      while (i < pending) and (ids[i] <> id) do Inc(i);
      if i = pending then Fail('SFTP: reply to an unknown request');
      n := lens[i];
      ids[i] := ids[pending - 1]; lens[i] := lens[pending - 1];
      Dec(pending);
      if err = '' then
        try
          CheckStatus(p, Remote);
          Inc(acked, n);
          if Assigned(Progress) then Progress(acked, total);
        except
          on E: ESftpError do if E.Code < 0 then raise else err := E.Message;
        end;
    until False;
  finally
    // errors such as a full disk may be reported only on close
    if err = '' then CloseHandle(h)
    else try CloseHandle(h); except end;
  end;
  if err <> '' then raise ESftpError.CreateCode(SFTP_FAILURE, err);
end;

procedure TSftpClient.DownloadFile(const Remote, Local: string; Progress: TSftpProgress);
var fs: TFileStream; ok: Boolean;
begin
  fs := TFileStream.Create(Local, fmCreate);
  ok := False;
  try
    Download(Remote, fs, Progress);
    ok := True;
  finally
    fs.Free;
    if not ok then DeleteFile(Local);                // no half-written files
  end;
end;

procedure TSftpClient.UploadFile(const Local, Remote: string; Progress: TSftpProgress);
var fs: TFileStream;
begin
  fs := TFileStream.Create(Local, fmOpenRead or fmShareDenyWrite);
  try
    Upload(fs, Remote, -1, Progress);
  finally
    fs.Free;
  end;
end;

function TSftpClient.GetBytes(const Remote: string): TBytes;
var ms: TBytesStream;
begin
  ms := TBytesStream.Create(nil);
  try
    Download(Remote, ms);
    Result := Copy(ms.Bytes, 0, ms.Size);
  finally
    ms.Free;
  end;
end;

procedure TSftpClient.PutBytes(const Remote: string; const Data: TBytes; Mode: Integer);
var ms: TBytesStream;
begin
  ms := TBytesStream.Create(Data);
  try
    Upload(ms, Remote, Mode);
  finally
    ms.Free;
  end;
end;

// ---- parallel transfers ----

type
  TSftpPartThread = class(TThread)
  public
    Connect: TSftpConnectFn;
    Client: TSftpClient;
    Remote, Local: string;
    Off, Len: Int64;
    IsDownload, Skip: Boolean;      // Skip: never run (cleanup after a failed connection)
    Error: string;
  protected
    procedure Execute; override;
  end;

// one part: its own local file handle, positioned writes / reads
procedure TransferPart(Client: TSftpClient; const Remote, Local: string; Off, Len: Int64; Download: Boolean);
var fs: TFileStream;
begin
  if Download then fs := TFileStream.Create(Local, fmOpenReadWrite or fmShareDenyNone)
  else fs := TFileStream.Create(Local, fmOpenRead or fmShareDenyNone);
  try
    if Download then Client.DownloadRange(Remote, fs, Off, Len)
    else Client.UploadRange(fs, Remote, Off, Len);
  finally
    fs.Free;
  end;
end;

procedure TSftpPartThread.Execute;
begin
  if Skip then Exit;
  try
    Client := Connect();
    TransferPart(Client, Remote, Local, Off, Len, IsDownload);
  except
    on E: Exception do Error := E.Message;
  end;
end;

const
  MIN_PART = 4 * 1024 * 1024;

// parts 1..n-1 in threads (each with its own client from Connect), part 0 here with Main
procedure RunParts(Main: TSftpClient; Connect: TSftpConnectFn; const Remote, Local: string; Size: Int64;
  Parts: Integer; Download: Boolean);
var
  th: array of TSftpPartThread; i: Integer; partLen, off, len: Int64; err: string;
begin
  if Parts > 1 + Size div MIN_PART then Parts := 1 + Size div MIN_PART;
  if Parts < 1 then Parts := 1;
  partLen := (Size + Parts - 1) div Parts;
  partLen := (partLen + 65535) and not Int64(65535);             // whole 64 KB blocks
  SetLength(th, Parts);
  err := '';
  try
    // the extra parts: each thread connects by itself
    for i := 1 to Parts - 1 do
    begin
      off := i * partLen;
      if off >= Size then Break;
      len := partLen;
      if off + len > Size then len := Size - off;
      th[i] := TSftpPartThread.Create(True);
      th[i].FreeOnTerminate := False;
      th[i].Remote := Remote; th[i].Local := Local;
      th[i].Off := off; th[i].Len := len; th[i].IsDownload := Download;
      th[i].Connect := Connect;
    end;
    for i := 1 to Parts - 1 do
      if th[i] <> nil then th[i].Start;
    // part 0 with the main connection
    len := partLen;
    if len > Size then len := Size;
    try
      TransferPart(Main, Remote, Local, 0, len, Download);
    except
      on E: Exception do err := E.Message;
    end;
    for i := 1 to Parts - 1 do
      if (th[i] <> nil) and not th[i].Suspended then
      begin
        th[i].WaitFor;
        if (err = '') and (th[i].Error <> '') then err := th[i].Error;
      end;
  finally
    for i := 1 to Parts - 1 do
      if th[i] <> nil then
      begin
        if th[i].Suspended then
        begin
          // never started (Connect failed for a later part): run it empty
          th[i].Skip := True;
          th[i].Start;
          th[i].WaitFor;
        end;
        try th[i].Client.Free; except end;        // closing a dead connection may fail
        th[i].Free;
      end;
  end;
  if err <> '' then raise ESftpError.CreateCode(SFTP_FAILURE, err);
end;

procedure SftpParallelDownload(Main: TSftpClient; Connect: TSftpConnectFn; const Remote, Local: string;
  Parts: Integer);
var size: Int64; a: TSftpAttrs; fs: TFileStream; ok: Boolean;
begin
  a := Main.Stat(Remote);
  if a.Flags and SFTP_ATTR_SIZE = 0 then Parts := 1;
  size := a.Size;
  if (Parts <= 1) or (size < 2 * MIN_PART) then
  begin
    Main.DownloadFile(Remote, Local);
    Exit;
  end;
  // the local file at its full size, so that the parts can write at their offsets
  fs := TFileStream.Create(Local, fmCreate);
  try
    fs.Size := size;
  finally
    fs.Free;
  end;
  ok := False;
  try
    RunParts(Main, Connect, Remote, Local, size, Parts, True);
    ok := True;
  finally
    if not ok then DeleteFile(Local);
  end;
end;

procedure SftpParallelUpload(Main: TSftpClient; Connect: TSftpConnectFn; const Local, Remote: string;
  Parts: Integer; Mode: Integer);
var size: Int64; h: TBytes; fs: TFileStream;
begin
  fs := TFileStream.Create(Local, fmOpenRead or fmShareDenyWrite);
  try
    size := fs.Size;
  finally
    fs.Free;
  end;
  if (Parts <= 1) or (size < 2 * MIN_PART) then
  begin
    Main.UploadFile(Local, Remote);
    Exit;
  end;
  // create or truncate the remote file once; the parts then write into it
  h := Main.OpenHandle(Remote, SFTP_WRITE or SFTP_CREAT or SFTP_TRUNC, Mode);
  Main.CloseHandle(h);
  RunParts(Main, Connect, Remote, Local, size, Parts, False);
end;

end.
