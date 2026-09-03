; Inno Setup script for the AegisFlow Windows Endpoint Agent (Part 4).
;
; Build sequence:
;   1. Build dist\aegis-agent.exe   (see packaging/aegis-agent.spec)
;   2. Compile this script with Inno Setup 6  ->  Output\AegisFlowAgentSetup.exe
;
; The operator running the installer answers exactly two questions:
; the enrollment token and a display name. Everything else is baked in
; below -- edit these #define lines for a real deployment.

#define MyAppName "AegisFlow Endpoint Agent"
#define MyAppVersion "0.4.0"
#define MyAppPublisher "AegisFlow"
#define ServiceName "AegisFlowAgent"
#define ExeName "aegis-agent.exe"

; --- BAKED-IN DEPLOYMENT SETTINGS (not asked at install time) ---------
; TODO: replace with the real backend URL once HTTPS is set up on the VM.
#define BackendBaseUrl "https://aegisflow.example.org"
#define InstallDir "{autopf}\AegisFlow Agent"
#define DataDir "{commonappdata}\AegisFlow\agent"
; ---------------------------------------------------------------------

[Setup]
AppId={{7F4B1C2E-3A9D-4E71-9C2A-AEG1SFL0W004}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={#InstallDir}
DisableDirPage=yes
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=Output
OutputBaseFilename=AegisFlowAgentSetup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayName={#MyAppName}

[Files]
Source: "..\dist\{#ExeName}"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
; Service account (LocalSystem) + admins only. The config file written
; into here inherits this and is then locked down further at runtime.
Name: "{#DataDir}"; Permissions: admins-full system-full

[Code]
var
  InputPage: TInputQueryWizardPage;

function ConfigPath: String;
begin
  Result := ExpandConstant('{#DataDir}\config.toml');
end;

function ExePath: String;
begin
  Result := ExpandConstant('{app}\{#ExeName}');
end;

procedure InitializeWizard;
begin
  InputPage := CreateInputQueryPage(
    wpSelectDir,
    'AegisFlow enrollment',
    'Connect this machine to the AegisFlow backend',
    'Paste the enrollment token you were given, and choose a name for this ' +
    'endpoint. Both are required.');
  InputPage.Add('Enrollment token:', False);
  InputPage.Add('Display name for this endpoint:', False);
  InputPage.Values[1] := GetComputerNameString();
end;

function TrimStr(const S: String): String;
begin
  Result := S;
  while (Length(Result) > 0) and (Result[1] <= ' ') do Delete(Result, 1, 1);
  while (Length(Result) > 0) and (Result[Length(Result)] <= ' ') do
    Delete(Result, Length(Result), 1);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID = InputPage.ID then
  begin
    if TrimStr(InputPage.Values[0]) = '' then
    begin
      MsgBox('The enrollment token cannot be blank.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
    if TrimStr(InputPage.Values[1]) = '' then
    begin
      MsgBox('The display name cannot be blank.', mbError, MB_OK);
      Result := False;
    end;
  end;
end;

{ Run a command, redirecting stdout+stderr to a temp file, and return
  both the process exit code and the captured text. }
function RunCapture(const CmdLine: String; var Output: String): Integer;
var
  TmpFile: String;
  ResultCode: Integer;
  Lines: TArrayOfString;
  I: Integer;
begin
  TmpFile := ExpandConstant('{tmp}\aegis-run.txt');
  Output := '';
  if not Exec(ExpandConstant('{cmd}'), '/C ' + CmdLine + ' > "' + TmpFile + '" 2>&1',
             '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    Result := -1;
    Exit;
  end;
  if LoadStringsFromFile(TmpFile, Lines) then
    for I := 0 to GetArrayLength(Lines) - 1 do
      Output := Output + Lines[I] + #13#10;
  DeleteFile(TmpFile);
  Result := ResultCode;
end;

function LineValue(const Output, Key: String): String;
var
  P, LineEnd: Integer;
  Rest: String;
begin
  Result := '';
  P := Pos(Key + '=', Output);
  if P = 0 then Exit;
  Rest := Copy(Output, P + Length(Key) + 1, MaxInt);
  LineEnd := Pos(#13, Rest);
  if LineEnd = 0 then LineEnd := Pos(#10, Rest);
  if LineEnd = 0 then LineEnd := Length(Rest) + 1;
  Result := TrimStr(Copy(Rest, 1, LineEnd - 1));
end;

procedure StepWriteConfig;
var
  Output, Cmd: String;
  Code: Integer;
begin
  Cmd := '"' + ExePath + '" write-config' +
         ' --out "' + ConfigPath + '"' +
         ' --base-url "{#BackendBaseUrl}"' +
         ' --token "' + TrimStr(InputPage.Values[0]) + '"' +
         ' --display-name "' + TrimStr(InputPage.Values[1]) + '"' +
         ' --state-dir "' + ExpandConstant('{#DataDir}') + '"' +
         ' --log-file "' + ExpandConstant('{#DataDir}\agent.log') + '"';
  Code := RunCapture(Cmd, Output);
  if Code <> 0 then
    RaiseException('Could not write the agent configuration:'#13#10 + Output);

  { Lock the config down: it holds the token. Break inheritance, grant
    only SYSTEM and Administrators. }
  RunCapture('icacls "' + ConfigPath + '" /inheritance:r ' +
             '/grant:r "*S-1-5-18:F" /grant:r "*S-1-5-32-544:F"', Output);
end;

procedure StepRegisterService;
var
  Output: String;
  Code: Integer;
begin
  Code := RunCapture('"' + ExePath + '" service --startup auto install', Output);
  if (Code <> 0) and (Pos('already installed', Output) = 0) then
    RaiseException('Could not register the Windows service:'#13#10 + Output);

  RunCapture('sc failure {#ServiceName} reset= 86400 ' +
             'actions= restart/60000/restart/60000/restart/120000', Output);
  RunCapture('sc description {#ServiceName} "AegisFlow endpoint event agent"', Output);
end;

procedure StepStartService;
var
  Output: String;
  Code: Integer;
begin
  Code := RunCapture('sc start {#ServiceName}', Output);
  if (Code <> 0) and (Pos('1056', Output) = 0) then  { 1056 = already running }
    MsgBox('The service did not start:'#13#10 + Output +
           #13#10'You can start it later from services.msc.', mbError, MB_OK);
end;

procedure StepEnrollCheck;
var
  Output, Effective, Adjusted, Requested, Msg: String;
  Code: Integer;
begin
  Code := RunCapture('"' + ExePath + '" enroll-check --config "' + ConfigPath + '"', Output);
  Requested := TrimStr(InputPage.Values[1]);
  if Code = 0 then
  begin
    Effective := LineValue(Output, 'EFFECTIVE_NAME');
    Adjusted := LineValue(Output, 'NAME_ADJUSTED');
    if Effective = '' then Effective := Requested;
    Msg := 'The agent is installed and connected to the AegisFlow backend.'#13#10#13#10 +
           'This endpoint is registered as:  ' + Effective;
    if Adjusted = '1' then
      Msg := Msg + #13#10#13#10 +
             'Note: the name "' + Requested + '" was already in use in your ' +
             'organization, so the server assigned "' + Effective + '" instead. ' +
             'Use that name when you look for this machine in AegisFlow.';
    MsgBox(Msg, mbInformation, MB_OK);
  end
  else
  begin
    MsgBox('The agent service is installed, but it could not confirm a ' +
           'connection to the backend:'#13#10#13#10 + Output + #13#10 +
           'The service will keep retrying on its own. Check the token and ' +
           'network, then either wait for it to connect or re-run this installer.',
           mbCriticalError, MB_OK);
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    StepWriteConfig;
    StepRegisterService;
    StepStartService;
    StepEnrollCheck;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Output: String;
begin
  if CurUninstallStep = usUninstall then
  begin
    RunCapture('sc stop {#ServiceName}', Output);
    RunCapture('"' + ExePath + '" service remove', Output);
  end;
end;
