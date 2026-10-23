; Inno Setup script for WinEventAI - one Setup.exe instead of a ZIP.
;
; Saved as UTF-8 WITH byte order mark: the German wizard texts contain
; umlauts, and ISCC only reads the file as UTF-8 when the BOM is there.
;
; Build:  packaging\build.ps1   (calls ISCC with /DAppVersion=<version>)
;
; Why an installer around the one-dir build and not a single packed EXE:
; a one-file EXE unpacks itself to %TEMP% on every start - packer behaviour
; that EDR products flag, slow to start, and it hides the Qt DLLs that the LGPL
; wants replaceable. The installer unpacks ONCE, into a normal program folder.
;
; Why per user (PrivilegesRequired=lowest): installing must not need an admin.
; The program folder lands in %LOCALAPPDATA%\Programs\WinEventAI, the data in
; %LOCALAPPDATA%\WinEventAI. Admin rights are asked for only where they are
; needed - for the Security channel, via "Restart as administrator" in the
; window.

#ifndef AppVersion
  #error AppVersion must be passed: ISCC /DAppVersion=2.3.0 installer.iss
#endif

#define AppName "WinEventAI"
#define AppPublisher "Felix Spiß"
#define AppUrl "https://github.com/Felixitus/WinEventAI"
#define GuiExe "wineventai-gui.exe"

[Setup]
; Fixed for all versions: Windows recognises an update by this id.
AppId={{6B9F0C2A-4E1D-4C8B-9A3F-2D7E5B1C8A40}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppUrl}
AppSupportURL={#AppUrl}/issues
AppUpdatesURL={#AppUrl}/releases
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
LicenseFile=..\LICENSE
SetupIconFile=..\src\wineventai\gui\assets\wineventai.ico
UninstallDisplayIcon={app}\{#GuiExe}
UninstallDisplayName={#AppName}
OutputDir=..\dist
OutputBaseFilename=WinEventAI-Setup-{#AppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ChangesEnvironment=yes
VersionInfoVersion={#AppVersion}
VersionInfoProductName={#AppName}
VersionInfoDescription={#AppName} Setup
VersionInfoCopyright=(c) 2026 {#AppPublisher}, MIT licence

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "german"; MessagesFile: "compiler:Languages\German.isl"

[CustomMessages]
english.DesktopIcon=Create a desktop shortcut
german.DesktopIcon=Verknüpfung auf dem Desktop anlegen
english.AddToPath=Make the command line available (add "wineventai" to PATH)
german.AddToPath=Befehlszeile verfügbar machen ("wineventai" in PATH aufnehmen)
english.Launch=Start WinEventAI now
german.Launch=WinEventAI jetzt starten

[Tasks]
Name: "desktopicon"; Description: "{cm:DesktopIcon}"; Flags: unchecked
Name: "addtopath"; Description: "{cm:AddToPath}"; Flags: unchecked

[InstallDelete]
; An update must not leave libraries of the previous version behind.
Type: filesandordirs; Name: "{app}\_internal"

[Files]
Source: "..\dist\wineventai\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#GuiExe}"; Comment: "Windows event log diagnostics"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#GuiExe}"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Tasks: addtopath; Check: NeedsAddPath(ExpandConstant('{app}'))

[Run]
Filename: "{app}\{#GuiExe}"; Description: "{cm:Launch}"; Flags: nowait postinstall skipifsilent

[Code]
function NeedsAddPath(Dir: string): Boolean;
var
  Current: string;
begin
  if not RegQueryStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', Current) then
  begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Uppercase(Dir) + ';', ';' + Uppercase(Current) + ';') = 0;
end;

procedure RemoveFromPath(Dir: string);
var
  Current, Upper, Needle: string;
  Index: Integer;
begin
  if not RegQueryStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', Current) then
    exit;
  Current := ';' + Current + ';';
  Upper := Uppercase(Current);
  Needle := ';' + Uppercase(Dir) + ';';
  Index := Pos(Needle, Upper);
  if Index = 0 then
    exit;
  Delete(Current, Index, Length(Needle) - 1);
  // Strip the helper semicolons added above.
  if Copy(Current, 1, 1) = ';' then
    Delete(Current, 1, 1);
  if Copy(Current, Length(Current), 1) = ';' then
    Delete(Current, Length(Current), 1);
  RegWriteExpandStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', Current);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  // The data folder %LOCALAPPDATA%\WinEventAI (runs, configuration) is kept on
  // purpose: reports may be evidence. Only the PATH entry is removed.
  if CurUninstallStep = usPostUninstall then
    RemoveFromPath(ExpandConstant('{app}'));
end;
