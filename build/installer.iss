; User-mode installer. No wildcard delete directives and no user-data cleanup.
#ifndef AppVersion
  #error AppVersion must be supplied by the release builder
#endif
#ifndef SourceDir
  #error SourceDir must be supplied by the release builder
#endif
#ifndef OutputDir
  #error OutputDir must be supplied by the release builder
#endif

[Setup]
AppId={{05859F55-E882-46BB-A37B-D6C6E9926C26}
AppName=ReViveX Ransom
AppVersion={#AppVersion}
AppPublisher=陈涛 alan chen
AppPublisherURL=https://www.xtyue.com/
AppSupportURL=https://github.com/tyintech/ReViveX-Ransom/issues
AppUpdatesURL=https://github.com/tyintech/ReViveX-Ransom/releases
DefaultDirName={localappdata}\Programs\ReViveX Ransom
DefaultGroupName=ReViveX Ransom
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir={#OutputDir}
OutputBaseFilename=ReViveX-Ransom-{#AppVersion}-windows-x64-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\ReViveX-Ransom.exe
CloseApplications=no
RestartApplications=no
SetupLogging=yes

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\ReViveX Ransom"; Filename: "{app}\ReViveX-Ransom.exe"
Name: "{userdesktop}\ReViveX Ransom"; Filename: "{app}\ReViveX-Ransom.exe"; Tasks: desktopicon

; No [Run], [UninstallDelete], service, autorun or file association actions.
