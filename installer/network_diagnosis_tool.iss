; Inno Setup Script for Network Diagnosis Tool
; Build with: iscc network_diagnosis_tool.iss

[Setup]
AppName=Network Diagnosis Tool
AppVersion=1.0.0
DefaultDirName={commonpf64}\NetworkDiagnosisTool
DefaultGroupName=Network Diagnosis Tool
OutputDir=.
OutputBaseFilename=NetworkDiagnosisToolInstaller
Compression=lzma
SolidCompression=yes
PrivilegesRequired=admin

[Languages]
Name: "english"; MessagesFile: "compiler:Default.islu"

[Files]
Source: "dist\NetworkDiagnosisTool.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "README.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Network Diagnosis Tool"; Filename: "{app}\NetworkDiagnosisTool.exe"

[Run]
Filename: "{app}\NetworkDiagnosisTool.exe"; Description: "Launch Network Diagnosis Tool"; Flags: nowait postinstall skipifsilent
