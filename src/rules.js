'use strict';

// Each import rule matches function names (case-sensitive, trailing A/W ignored by the regexes).
const IMPORT_RULES = [
  {
    id: 'http',
    text: 'imports HTTP client functions, so it may make HTTP requests',
    funcs: /^(InternetOpen|InternetConnect|InternetReadFile|InternetOpenUrl|HttpOpenRequest|HttpSendRequest|WinHttp\w+|URLDownloadToFile|URLDownloadToCacheFile)/,
  },
  {
    id: 'socket',
    text: 'imports Winsock functions, so it may use network sockets',
    dlls: /^(ws2_32|wsock32)\.dll$/,
  },
  {
    id: 'file',
    text: 'imports file APIs, so it may read, write or delete files',
    funcs: /^(CreateFile|ReadFile|WriteFile|DeleteFile|MoveFile|CopyFile|FindFirstFile|SetFilePointer)/,
  },
  {
    id: 'registry',
    text: 'imports registry APIs, so it may read or modify registry values',
    funcs: /^Reg(Open|Create|Set|Query|Delete|Enum|Close)/,
  },
  {
    id: 'process',
    text: 'imports process-launching APIs, so it may start other programs',
    funcs: /^(CreateProcess|ShellExecute|WinExec|CreateProcessAsUser)/,
  },
  {
    id: 'remote-memory',
    text: 'imports APIs for accessing the memory of other processes; debuggers and system tools use these legitimately, but it suggests the program may inspect or modify other processes',
    funcs: /^(VirtualAllocEx|WriteProcessMemory|ReadProcessMemory|CreateRemoteThread|NtWriteVirtualMemory|QueueUserAPC)/,
  },
  {
    id: 'dynamic',
    text: 'imports LoadLibrary/GetProcAddress, so it may resolve more functions at run time than the import table shows',
    funcs: /^(LoadLibrary|GetProcAddress|LdrLoadDll|LdrGetProcedureAddress)/,
  },
  {
    id: 'crypto',
    text: 'imports cryptography APIs, so it may encrypt, decrypt or hash data',
    funcs: /^(Crypt\w+|BCrypt\w+|NCrypt\w+)/,
  },
  {
    id: 'debugger',
    text: 'imports debugger-detection APIs, so it may check whether it is being debugged',
    funcs: /^(IsDebuggerPresent|CheckRemoteDebuggerPresent|OutputDebugString)/,
  },
  {
    id: 'service',
    text: 'imports service-control APIs, so it may install or run as a Windows service',
    funcs: /^(OpenSCManager|CreateService|StartService|StartServiceCtrlDispatcher|ControlService)/,
  },
  {
    id: 'input-hook',
    text: 'imports keyboard or input hooking APIs, so it may observe keyboard or mouse input',
    funcs: /^(SetWindowsHookEx|GetAsyncKeyState|GetKeyState|GetKeyboardState|RegisterRawInputDevices)/,
  },
  {
    id: 'privilege',
    text: 'imports access-token APIs, so it may inspect or change its own privileges',
    funcs: /^(OpenProcessToken|AdjustTokenPrivileges|LookupPrivilegeValue|DuplicateToken)/,
  },
  {
    id: 'gui',
    text: 'imports window and message APIs, so it likely presents a graphical interface',
    funcs: /^(CreateWindowEx|RegisterClass|GetMessage|DispatchMessage|DialogBox|MessageBox)/,
  },
  {
    id: 'console',
    text: 'imports console APIs, so it may read from or write to a console',
    funcs: /^(WriteConsole|ReadConsole|AllocConsole|GetConsoleMode)/,
  },
];

const STRING_RULES = [
  { kind: 'url', text: 'contains URL-like strings, so it may refer to network locations' },
  { kind: 'ipv4', text: 'contains IPv4-address-like strings (they may also be version numbers), so it may refer to network hosts' },
  { kind: 'registry', text: 'contains registry-path-like strings, so it may refer to registry keys' },
  { kind: 'path', text: 'contains Windows file-path-like strings, so it may refer to specific files or folders' },
  { kind: 'command', text: 'contains names of command interpreters or script hosts, so it may invoke them' },
];

module.exports = { IMPORT_RULES, STRING_RULES };
