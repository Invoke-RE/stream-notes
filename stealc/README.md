## February 25th Stealc

* [Stealc Blog Series](https://blog.lexfo.fr/StealC_malware_analysis_part1.html)
* [Unpac.me Results of Stealc](https://www.unpac.me/results/3fbe1bfa-3981-4924-b731-5d77e83ce7fc)

### String decryption with Binary Ninja

```python
target_func = bv.get_symbol_by_raw_name('mw_decrypt_str').address

def is_call(i, target_addr):
    if(isinstance(i, HighLevelILCall) and i.dest.constant == target_addr):
        return i

def get_callers(target_func):
    call_locations = []
    for caller in bv.get_callers(target_func):
        caller_add = caller.address
        caller_func = bv.get_functions_containing(caller_add)[0]
        for instr in list(caller_func.hlil.instructions):
            for location in instr.traverse(is_call, target_func):
                call_locations.append(location)

    return call_locations

rstrs = {}
callers = get_callers(target_func)
for caller in callers:
    key = caller.params[1]
    ct_len = caller.params[2]
    ct_ptr = caller.params[0]
    
    xor = Transform['XOR']
    ct = bv.read(ct_ptr.constant, ct_len.constant)
    print(f"Decrypting at location: {caller.address:2x} // {key}")
    key = bv.read(key.constant, ct_len.constant)
    pt = xor.encode(ct, {'key':key})
    rstrs[caller.address] = pt

for addr, rstr in rstrs.items():
    print(f"Address: 0x{addr:2x} // PT string: {rstr}")
    bv.set_comment_at(addr, rstr)
```

### Decrypted Strings

```
[ScriptingProvider] Address: 0x40213f // PT string: b'INSERT_KEY_HERE'
[ScriptingProvider] Address: 0x402158 // PT string: b'27'
[ScriptingProvider] Address: 0x402171 // PT string: b'05'
[ScriptingProvider] Address: 0x40218a // PT string: b'20'
[ScriptingProvider] Address: 0x4021a3 // PT string: b'24'
[ScriptingProvider] Address: 0x4021bc // PT string: b'GetProcAddress'
[ScriptingProvider] Address: 0x4021d5 // PT string: b'LoadLibraryA'
[ScriptingProvider] Address: 0x4021ee // PT string: b'lstrcatA'
[ScriptingProvider] Address: 0x402207 // PT string: b'OpenEventA'
[ScriptingProvider] Address: 0x402220 // PT string: b'CreateEventA'
[ScriptingProvider] Address: 0x402239 // PT string: b'CloseHandle'
[ScriptingProvider] Address: 0x402252 // PT string: b'Sleep'
[ScriptingProvider] Address: 0x40226b // PT string: b'GetUserDefaultLangID'
[ScriptingProvider] Address: 0x402284 // PT string: b'VirtualAllocExNuma'
[ScriptingProvider] Address: 0x40229d // PT string: b'VirtualFree'
[ScriptingProvider] Address: 0x4022b6 // PT string: b'GetSystemInfo'
[ScriptingProvider] Address: 0x4022cf // PT string: b'VirtualAlloc'
[ScriptingProvider] Address: 0x4022e8 // PT string: b'HeapAlloc'
[ScriptingProvider] Address: 0x402301 // PT string: b'GetComputerNameA'
[ScriptingProvider] Address: 0x40231a // PT string: b'lstrcpyA'
[ScriptingProvider] Address: 0x402333 // PT string: b'GetProcessHeap'
[ScriptingProvider] Address: 0x40234c // PT string: b'GetCurrentProcess'
[ScriptingProvider] Address: 0x402365 // PT string: b'lstrlenA'
[ScriptingProvider] Address: 0x40237e // PT string: b'ExitProcess'
[ScriptingProvider] Address: 0x402397 // PT string: b'GlobalMemoryStatusEx'
[ScriptingProvider] Address: 0x4023b0 // PT string: b'GetSystemTime'
[ScriptingProvider] Address: 0x4023c9 // PT string: b'SystemTimeToFileTime'
[ScriptingProvider] Address: 0x4023e2 // PT string: b'advapi32.dll'
[ScriptingProvider] Address: 0x4023fb // PT string: b'gdi32.dll'
[ScriptingProvider] Address: 0x402414 // PT string: b'user32.dll'
[ScriptingProvider] Address: 0x40242d // PT string: b'crypt32.dll'
[ScriptingProvider] Address: 0x402446 // PT string: b'ntdll.dll'
[ScriptingProvider] Address: 0x40245f // PT string: b'GetUserNameA'
[ScriptingProvider] Address: 0x402478 // PT string: b'CreateDCA'
[ScriptingProvider] Address: 0x402491 // PT string: b'GetDeviceCaps'
[ScriptingProvider] Address: 0x4024aa // PT string: b'ReleaseDC'
[ScriptingProvider] Address: 0x4024c3 // PT string: b'CryptStringToBinaryA'
[ScriptingProvider] Address: 0x4024dc // PT string: b'sscanf'
[ScriptingProvider] Address: 0x4024f5 // PT string: b'VMwareVMware'
[ScriptingProvider] Address: 0x40250e // PT string: b'HAL9TH'
[ScriptingProvider] Address: 0x402527 // PT string: b'JohnDoe'
[ScriptingProvider] Address: 0x402540 // PT string: b'DISPLAY'
[ScriptingProvider] Address: 0x402559 // PT string: b'%hu/%hu/%hu'
[ScriptingProvider] Address: 0x40259f // PT string: b'http[:]//185[.]172.128.150'
[ScriptingProvider] Address: 0x4025b8 // PT string: b'/c698e1bc8a2f5e6d.php'
[ScriptingProvider] Address: 0x4025d1 // PT string: b'/b7d0cfdb1d966bdd/'
[ScriptingProvider] Address: 0x4025ea // PT string: b'default100'
[ScriptingProvider] Address: 0x402603 // PT string: b'GetEnvironmentVariableA'
[ScriptingProvider] Address: 0x40261c // PT string: b'GetFileAttributesA'
[ScriptingProvider] Address: 0x402635 // PT string: b'GlobalLock'
[ScriptingProvider] Address: 0x40264e // PT string: b'HeapFree'
[ScriptingProvider] Address: 0x402667 // PT string: b'GetFileSize'
[ScriptingProvider] Address: 0x402680 // PT string: b'GlobalSize'
[ScriptingProvider] Address: 0x402699 // PT string: b'CreateToolhelp32Snapshot'
[ScriptingProvider] Address: 0x4026b2 // PT string: b'IsWow64Process'
[ScriptingProvider] Address: 0x4026cb // PT string: b'Process32Next'
[ScriptingProvider] Address: 0x4026e4 // PT string: b'GetLocalTime'
[ScriptingProvider] Address: 0x4026fd // PT string: b'FreeLibrary'
[ScriptingProvider] Address: 0x402716 // PT string: b'GetTimeZoneInformation'
[ScriptingProvider] Address: 0x40272f // PT string: b'GetSystemPowerStatus'
[ScriptingProvider] Address: 0x402748 // PT string: b'GetVolumeInformationA'
[ScriptingProvider] Address: 0x402761 // PT string: b'GetWindowsDirectoryA'
[ScriptingProvider] Address: 0x40277a // PT string: b'Process32First'
[ScriptingProvider] Address: 0x402793 // PT string: b'GetLocaleInfoA'
[ScriptingProvider] Address: 0x4027ac // PT string: b'GetUserDefaultLocaleName'
[ScriptingProvider] Address: 0x4027c5 // PT string: b'GetModuleFileNameA'
[ScriptingProvider] Address: 0x4027de // PT string: b'DeleteFileA'
[ScriptingProvider] Address: 0x4027f7 // PT string: b'FindNextFileA'
[ScriptingProvider] Address: 0x402810 // PT string: b'LocalFree'
[ScriptingProvider] Address: 0x402829 // PT string: b'FindClose'
[ScriptingProvider] Address: 0x402842 // PT string: b'SetEnvironmentVariableA'
[ScriptingProvider] Address: 0x40285b // PT string: b'LocalAlloc'
[ScriptingProvider] Address: 0x402874 // PT string: b'GetFileSizeEx'
[ScriptingProvider] Address: 0x40288d // PT string: b'ReadFile'
[ScriptingProvider] Address: 0x4028a6 // PT string: b'SetFilePointer'
[ScriptingProvider] Address: 0x4028bf // PT string: b'WriteFile'
[ScriptingProvider] Address: 0x4028d8 // PT string: b'CreateFileA'
[ScriptingProvider] Address: 0x4028f1 // PT string: b'FindFirstFileA'
[ScriptingProvider] Address: 0x40290a // PT string: b'CopyFileA'
[ScriptingProvider] Address: 0x402923 // PT string: b'VirtualProtect'
[ScriptingProvider] Address: 0x40293c // PT string: b'GetLogicalProcessorInformationEx'
[ScriptingProvider] Address: 0x402955 // PT string: b'GetLastError'
[ScriptingProvider] Address: 0x40296e // PT string: b'lstrcpynA'
[ScriptingProvider] Address: 0x402987 // PT string: b'MultiByteToWideChar'
[ScriptingProvider] Address: 0x4029a0 // PT string: b'GlobalFree'
[ScriptingProvider] Address: 0x4029b9 // PT string: b'WideCharToMultiByte'
[ScriptingProvider] Address: 0x4029d2 // PT string: b'GlobalAlloc'
[ScriptingProvider] Address: 0x4029eb // PT string: b'OpenProcess'
[ScriptingProvider] Address: 0x402a04 // PT string: b'TerminateProcess'
[ScriptingProvider] Address: 0x402a1d // PT string: b'GetCurrentProcessId'
[ScriptingProvider] Address: 0x402a36 // PT string: b'gdiplus.dll'
[ScriptingProvider] Address: 0x402a4f // PT string: b'ole32.dll'
[ScriptingProvider] Address: 0x402a68 // PT string: b'bcrypt.dll'
[ScriptingProvider] Address: 0x402a81 // PT string: b'wininet.dll'
[ScriptingProvider] Address: 0x402a9a // PT string: b'shlwapi.dll'
[ScriptingProvider] Address: 0x402ab3 // PT string: b'shell32.dll'
[ScriptingProvider] Address: 0x402acc // PT string: b'psapi.dll'
[ScriptingProvider] Address: 0x402ae5 // PT string: b'rstrtmgr.dll'
[ScriptingProvider] Address: 0x402afe // PT string: b'CreateCompatibleBitmap'
[ScriptingProvider] Address: 0x402b17 // PT string: b'SelectObject'
[ScriptingProvider] Address: 0x402b30 // PT string: b'BitBlt'
[ScriptingProvider] Address: 0x402b49 // PT string: b'DeleteObject'
[ScriptingProvider] Address: 0x402b62 // PT string: b'CreateCompatibleDC'
[ScriptingProvider] Address: 0x402b7b // PT string: b'GdipGetImageEncodersSize'
[ScriptingProvider] Address: 0x402b94 // PT string: b'GdipGetImageEncoders'
[ScriptingProvider] Address: 0x402bad // PT string: b'GdipCreateBitmapFromHBITMAP'
[ScriptingProvider] Address: 0x402bc6 // PT string: b'GdiplusStartup'
[ScriptingProvider] Address: 0x402bdf // PT string: b'GdiplusShutdown'
[ScriptingProvider] Address: 0x402bf8 // PT string: b'GdipSaveImageToStream'
[ScriptingProvider] Address: 0x402c11 // PT string: b'GdipDisposeImage'
[ScriptingProvider] Address: 0x402c2a // PT string: b'GdipFree'
[ScriptingProvider] Address: 0x402c43 // PT string: b'GetHGlobalFromStream'
[ScriptingProvider] Address: 0x402c5c // PT string: b'CreateStreamOnHGlobal'
[ScriptingProvider] Address: 0x402c75 // PT string: b'CoUninitialize'
[ScriptingProvider] Address: 0x402c8e // PT string: b'CoInitialize'
[ScriptingProvider] Address: 0x402ca7 // PT string: b'CoCreateInstance'
[ScriptingProvider] Address: 0x402cc0 // PT string: b'BCryptGenerateSymmetricKey'
[ScriptingProvider] Address: 0x402cd9 // PT string: b'BCryptCloseAlgorithmProvider'
[ScriptingProvider] Address: 0x402cf2 // PT string: b'BCryptDecrypt'
[ScriptingProvider] Address: 0x402d0b // PT string: b'BCryptSetProperty'
[ScriptingProvider] Address: 0x402d24 // PT string: b'BCryptDestroyKey'
[ScriptingProvider] Address: 0x402d3d // PT string: b'BCryptOpenAlgorithmProvider'
[ScriptingProvider] Address: 0x402d56 // PT string: b'GetWindowRect'
[ScriptingProvider] Address: 0x402d6f // PT string: b'GetDesktopWindow'
[ScriptingProvider] Address: 0x402d88 // PT string: b'GetDC'
[ScriptingProvider] Address: 0x402da1 // PT string: b'CloseWindow'
[ScriptingProvider] Address: 0x402dba // PT string: b'wsprintfA'
[ScriptingProvider] Address: 0x402dd3 // PT string: b'EnumDisplayDevicesA'
[ScriptingProvider] Address: 0x402dec // PT string: b'GetKeyboardLayoutList'
[ScriptingProvider] Address: 0x402e05 // PT string: b'CharToOemW'
[ScriptingProvider] Address: 0x402e1e // PT string: b'wsprintfW'
[ScriptingProvider] Address: 0x402e37 // PT string: b'RegQueryValueExA'
[ScriptingProvider] Address: 0x402e50 // PT string: b'RegEnumKeyExA'
[ScriptingProvider] Address: 0x402e69 // PT string: b'RegOpenKeyExA'
[ScriptingProvider] Address: 0x402e82 // PT string: b'RegCloseKey'
[ScriptingProvider] Address: 0x402e9b // PT string: b'RegEnumValueA'
[ScriptingProvider] Address: 0x402eb4 // PT string: b'CryptBinaryToStringA'
[ScriptingProvider] Address: 0x402ecd // PT string: b'CryptUnprotectData'
[ScriptingProvider] Address: 0x402ee6 // PT string: b'SHGetFolderPathA'
[ScriptingProvider] Address: 0x402eff // PT string: b'ShellExecuteExA'
[ScriptingProvider] Address: 0x402f18 // PT string: b'InternetOpenUrlA'
[ScriptingProvider] Address: 0x402f31 // PT string: b'InternetConnectA'
[ScriptingProvider] Address: 0x402f4a // PT string: b'InternetCloseHandle'
[ScriptingProvider] Address: 0x402f63 // PT string: b'InternetOpenA'
[ScriptingProvider] Address: 0x402f7c // PT string: b'HttpSendRequestA'
[ScriptingProvider] Address: 0x402f95 // PT string: b'HttpOpenRequestA'
[ScriptingProvider] Address: 0x402fae // PT string: b'InternetReadFile'
[ScriptingProvider] Address: 0x402fc7 // PT string: b'InternetCrackUrlA'
[ScriptingProvider] Address: 0x402fe0 // PT string: b'StrCmpCA'
[ScriptingProvider] Address: 0x402ff9 // PT string: b'StrStrA'
[ScriptingProvider] Address: 0x403012 // PT string: b'StrCmpCW'
[ScriptingProvider] Address: 0x40302b // PT string: b'PathMatchSpecA'
[ScriptingProvider] Address: 0x403044 // PT string: b'GetModuleFileNameExA'
[ScriptingProvider] Address: 0x40305d // PT string: b'RmStartSession'
[ScriptingProvider] Address: 0x403076 // PT string: b'RmRegisterResources'
[ScriptingProvider] Address: 0x40308f // PT string: b'RmGetList'
[ScriptingProvider] Address: 0x4030a8 // PT string: b'RmEndSession'
[ScriptingProvider] Address: 0x4030c1 // PT string: b'sqlite3_open'
[ScriptingProvider] Address: 0x4030da // PT string: b'sqlite3_prepare_v2'
[ScriptingProvider] Address: 0x4030f3 // PT string: b'sqlite3_step'
[ScriptingProvider] Address: 0x40310c // PT string: b'sqlite3_column_text'
[ScriptingProvider] Address: 0x403125 // PT string: b'sqlite3_finalize'
[ScriptingProvider] Address: 0x40313e // PT string: b'sqlite3_close'
[ScriptingProvider] Address: 0x403157 // PT string: b'sqlite3_column_bytes'
[ScriptingProvider] Address: 0x403170 // PT string: b'sqlite3_column_blob'
[ScriptingProvider] Address: 0x403189 // PT string: b'encrypted_key'
[ScriptingProvider] Address: 0x4031a2 // PT string: b'PATH'
[ScriptingProvider] Address: 0x4031bb // PT string: b'C:\\ProgramData\\nss3.dll'
[ScriptingProvider] Address: 0x4031d4 // PT string: b'NSS_Init'
[ScriptingProvider] Address: 0x4031ed // PT string: b'NSS_Shutdown'
[ScriptingProvider] Address: 0x403206 // PT string: b'PK11_GetInternalKeySlot'
[ScriptingProvider] Address: 0x40321f // PT string: b'PK11_FreeSlot'
[ScriptingProvider] Address: 0x403238 // PT string: b'PK11_Authenticate'
[ScriptingProvider] Address: 0x403251 // PT string: b'PK11SDR_Decrypt'
[ScriptingProvider] Address: 0x40326a // PT string: b'C:\\ProgramData\\'
[ScriptingProvider] Address: 0x403283 // PT string: b'SELECT origin_url, username_value, password_value FROM logins'
[ScriptingProvider] Address: 0x40329c // PT string: b'browser: '
[ScriptingProvider] Address: 0x4032b5 // PT string: b'profile: '
[ScriptingProvider] Address: 0x4032ce // PT string: b'url: '
[ScriptingProvider] Address: 0x4032e7 // PT string: b'login: '
[ScriptingProvider] Address: 0x403300 // PT string: b'password: '
[ScriptingProvider] Address: 0x403319 // PT string: b'Opera'
[ScriptingProvider] Address: 0x403332 // PT string: b'OperaGX'
[ScriptingProvider] Address: 0x40334b // PT string: b'Network'
[ScriptingProvider] Address: 0x403364 // PT string: b'cookies'
[ScriptingProvider] Address: 0x40337d // PT string: b'.txt'
[ScriptingProvider] Address: 0x403396 // PT string: b'SELECT HOST_KEY, is_httponly, path, is_secure, (expires_utc/1000000)-11644480800, name, encrypted_value from cookies'
[ScriptingProvider] Address: 0x4033af // PT string: b'TRUE'
[ScriptingProvider] Address: 0x4033c8 // PT string: b'FALSE'
[ScriptingProvider] Address: 0x4033e1 // PT string: b'autofill'
[ScriptingProvider] Address: 0x4033fa // PT string: b'SELECT name, value FROM autofill'
[ScriptingProvider] Address: 0x403413 // PT string: b'history'
[ScriptingProvider] Address: 0x40342c // PT string: b'SELECT url FROM urls LIMIT 1000'
[ScriptingProvider] Address: 0x403445 // PT string: b'cc'
[ScriptingProvider] Address: 0x40345e // PT string: b'SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards'
[ScriptingProvider] Address: 0x403477 // PT string: b'name: '
[ScriptingProvider] Address: 0x403490 // PT string: b'month: '
[ScriptingProvider] Address: 0x4034a9 // PT string: b'year: '
[ScriptingProvider] Address: 0x4034c2 // PT string: b'card: '
[ScriptingProvider] Address: 0x4034db // PT string: b'Cookies'
[ScriptingProvider] Address: 0x4034f4 // PT string: b'Login Data'
[ScriptingProvider] Address: 0x40350d // PT string: b'Web Data'
[ScriptingProvider] Address: 0x403526 // PT string: b'History'
[ScriptingProvider] Address: 0x40353f // PT string: b'logins.json'
[ScriptingProvider] Address: 0x403558 // PT string: b'formSubmitURL'
[ScriptingProvider] Address: 0x403571 // PT string: b'usernameField'
[ScriptingProvider] Address: 0x40358a // PT string: b'encryptedUsername'
[ScriptingProvider] Address: 0x4035a3 // PT string: b'encryptedPassword'
[ScriptingProvider] Address: 0x4035bc // PT string: b'guid'
[ScriptingProvider] Address: 0x4035d5 // PT string: b'SELECT host, isHttpOnly, path, isSecure, expiry, name, value FROM moz_cookies'
[ScriptingProvider] Address: 0x4035ee // PT string: b'SELECT fieldname, value FROM moz_formhistory'
[ScriptingProvider] Address: 0x403607 // PT string: b'SELECT url FROM moz_places LIMIT 1000'
[ScriptingProvider] Address: 0x403620 // PT string: b'cookies.sqlite'
[ScriptingProvider] Address: 0x403639 // PT string: b'formhistory.sqlite'
[ScriptingProvider] Address: 0x403652 // PT string: b'places.sqlite'
[ScriptingProvider] Address: 0x40366b // PT string: b'plugins'
[ScriptingProvider] Address: 0x403684 // PT string: b'Local Extension Settings'
[ScriptingProvider] Address: 0x40369d // PT string: b'Sync Extension Settings'
[ScriptingProvider] Address: 0x4036b6 // PT string: b'IndexedDB'
[ScriptingProvider] Address: 0x4036cf // PT string: b'Opera Stable'
[ScriptingProvider] Address: 0x4036e8 // PT string: b'Opera GX Stable'
[ScriptingProvider] Address: 0x403701 // PT string: b'CURRENT'
[ScriptingProvider] Address: 0x40371a // PT string: b'chrome-extension_'
[ScriptingProvider] Address: 0x403733 // PT string: b'_0.indexeddb.leveldb'
[ScriptingProvider] Address: 0x40374c // PT string: b'Local State'
[ScriptingProvider] Address: 0x403765 // PT string: b'profiles.ini'
[ScriptingProvider] Address: 0x40377e // PT string: b'chrome'
[ScriptingProvider] Address: 0x403797 // PT string: b'opera'
[ScriptingProvider] Address: 0x4037b0 // PT string: b'firefox'
[ScriptingProvider] Address: 0x4037c9 // PT string: b'wallets'
[ScriptingProvider] Address: 0x4037e2 // PT string: b'%08lX%04lX%lu'
[ScriptingProvider] Address: 0x4037fb // PT string: b'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'
[ScriptingProvider] Address: 0x403814 // PT string: b'ProductName'
[ScriptingProvider] Address: 0x40382d // PT string: b'x32'
[ScriptingProvider] Address: 0x403846 // PT string: b'x64'
[ScriptingProvider] Address: 0x40385f // PT string: b'%d/%d/%d %d:%d:%d'
[ScriptingProvider] Address: 0x403878 // PT string: b'HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0'
[ScriptingProvider] Address: 0x403891 // PT string: b'ProcessorNameString'
[ScriptingProvider] Address: 0x4038aa // PT string: b'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall'
[ScriptingProvider] Address: 0x4038c3 // PT string: b'DisplayName'
[ScriptingProvider] Address: 0x4038dc // PT string: b'DisplayVersion'
[ScriptingProvider] Address: 0x4038f5 // PT string: b'Network Info:'
[ScriptingProvider] Address: 0x40390e // PT string: b'\t- IP: IP?'
[ScriptingProvider] Address: 0x403927 // PT string: b'\t- Country: ISO?'
[ScriptingProvider] Address: 0x403940 // PT string: b'System Summary:'
[ScriptingProvider] Address: 0x403959 // PT string: b'\t- HWID: '
[ScriptingProvider] Address: 0x403972 // PT string: b'\t- OS: '
[ScriptingProvider] Address: 0x40398b // PT string: b'\t- Architecture: '
[ScriptingProvider] Address: 0x4039a4 // PT string: b'\t- UserName: '
[ScriptingProvider] Address: 0x4039bd // PT string: b'\t- Computer Name: '
[ScriptingProvider] Address: 0x4039d6 // PT string: b'\t- Local Time: '
[ScriptingProvider] Address: 0x4039ef // PT string: b'\t- UTC: '
[ScriptingProvider] Address: 0x403a08 // PT string: b'\t- Language: '
[ScriptingProvider] Address: 0x403a21 // PT string: b'\t- Keyboards: '
[ScriptingProvider] Address: 0x403a3a // PT string: b'\t- Laptop: '
[ScriptingProvider] Address: 0x403a53 // PT string: b'\t- Running Path: '
[ScriptingProvider] Address: 0x403a6c // PT string: b'\t- CPU: '
[ScriptingProvider] Address: 0x403a85 // PT string: b'\t- Threads: '
[ScriptingProvider] Address: 0x403a9e // PT string: b'\t- Cores: '
[ScriptingProvider] Address: 0x403ab7 // PT string: b'\t- RAM: '
[ScriptingProvider] Address: 0x403ad0 // PT string: b'\t- Display Resolution: '
[ScriptingProvider] Address: 0x403ae9 // PT string: b'\t- GPU:'
[ScriptingProvider] Address: 0x403b02 // PT string: b'User Agents:'
[ScriptingProvider] Address: 0x403b1b // PT string: b'Installed Apps:'
[ScriptingProvider] Address: 0x403b34 // PT string: b'All Users:'
[ScriptingProvider] Address: 0x403b4d // PT string: b'Current User:'
[ScriptingProvider] Address: 0x403b66 // PT string: b'Process List:'
[ScriptingProvider] Address: 0x403b7f // PT string: b'system_info.txt'
[ScriptingProvider] Address: 0x403b98 // PT string: b'freebl3.dll'
[ScriptingProvider] Address: 0x403bb1 // PT string: b'mozglue.dll'
[ScriptingProvider] Address: 0x403bca // PT string: b'msvcp140.dll'
[ScriptingProvider] Address: 0x403be3 // PT string: b'nss3.dll'
[ScriptingProvider] Address: 0x403bfc // PT string: b'softokn3.dll'
[ScriptingProvider] Address: 0x403c15 // PT string: b'vcruntime140.dll'
[ScriptingProvider] Address: 0x403c2e // PT string: b'\\Temp\\'
[ScriptingProvider] Address: 0x403c47 // PT string: b'.exe'
[ScriptingProvider] Address: 0x403c60 // PT string: b'runas'
[ScriptingProvider] Address: 0x403c79 // PT string: b'open'
[ScriptingProvider] Address: 0x403c92 // PT string: b'/c start '
[ScriptingProvider] Address: 0x403cab // PT string: b'%DESKTOP%'
[ScriptingProvider] Address: 0x403cc4 // PT string: b'%APPDATA%'
[ScriptingProvider] Address: 0x403cdd // PT string: b'%LOCALAPPDATA%'
[ScriptingProvider] Address: 0x403cf6 // PT string: b'%USERPROFILE%'
[ScriptingProvider] Address: 0x403d0f // PT string: b'%DOCUMENTS%'
[ScriptingProvider] Address: 0x403d28 // PT string: b'%PROGRAMFILES%'
[ScriptingProvider] Address: 0x403d41 // PT string: b'%PROGRAMFILES_86%'
[ScriptingProvider] Address: 0x403d5a // PT string: b'%RECENT%'
[ScriptingProvider] Address: 0x403d73 // PT string: b'*.lnk'
[ScriptingProvider] Address: 0x403d8c // PT string: b'files'
[ScriptingProvider] Address: 0x403da5 // PT string: b'\\discord\\'
[ScriptingProvider] Address: 0x403dbe // PT string: b'\\Local Storage\\leveldb\\CURRENT'
[ScriptingProvider] Address: 0x403dd7 // PT string: b'\\Local Storage\\leveldb'
[ScriptingProvider] Address: 0x403df0 // PT string: b'\\Telegram Desktop\\'
[ScriptingProvider] Address: 0x403e09 // PT string: b'key_datas'
[ScriptingProvider] Address: 0x403e22 // PT string: b'D877F783D5D3EF8C*'
[ScriptingProvider] Address: 0x403e3b // PT string: b'map*'
[ScriptingProvider] Address: 0x403e54 // PT string: b'A7FDF864FBC10B77*'
[ScriptingProvider] Address: 0x403e6d // PT string: b'A92DAA6EA6F891F2*'
[ScriptingProvider] Address: 0x403e86 // PT string: b'F8806DD0C461824F*'
[ScriptingProvider] Address: 0x403e9f // PT string: b'Telegram'
[ScriptingProvider] Address: 0x403eb8 // PT string: b'Tox'
[ScriptingProvider] Address: 0x403ed1 // PT string: b'*.tox'
[ScriptingProvider] Address: 0x403eea // PT string: b'*.ini'
[ScriptingProvider] Address: 0x403f03 // PT string: b'Password'
[ScriptingProvider] Address: 0x403f1c // PT string: b'Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676\\'
[ScriptingProvider] Address: 0x403f35 // PT string: b'Software\\Microsoft\\Office\\13.0\\Outlook\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676\\'
[ScriptingProvider] Address: 0x403f4e // PT string: b'Software\\Microsoft\\Office\\14.0\\Outlook\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676\\'
[ScriptingProvider] Address: 0x403f67 // PT string: b'Software\\Microsoft\\Office\\15.0\\Outlook\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676\\'
[ScriptingProvider] Address: 0x403f80 // PT string: b'Software\\Microsoft\\Office\\16.0\\Outlook\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676\\'
[ScriptingProvider] Address: 0x403f99 // PT string: b'oftware\\Microsoft\\Windows Messaging Subsystem\\Profiles\\9375CFF0413111d3B88A00104B2A6676\\'
[ScriptingProvider] Address: 0x403fb2 // PT string: b'00000001'
[ScriptingProvider] Address: 0x403fcb // PT string: b'00000002'
[ScriptingProvider] Address: 0x403fe4 // PT string: b'00000003'
[ScriptingProvider] Address: 0x403ffd // PT string: b'00000004'
[ScriptingProvider] Address: 0x404016 // PT string: b'\\Outlook\\accounts.txt'
[ScriptingProvider] Address: 0x40402f // PT string: b'Pidgin'
[ScriptingProvider] Address: 0x404048 // PT string: b'\\.purple\\'
[ScriptingProvider] Address: 0x404061 // PT string: b'accounts.xml'
[ScriptingProvider] Address: 0x40407a // PT string: b'dQw4w9WgXcQ'
[ScriptingProvider] Address: 0x404093 // PT string: b'token: '
[ScriptingProvider] Address: 0x4040ac // PT string: b'Software\\Valve\\Steam'
[ScriptingProvider] Address: 0x4040c5 // PT string: b'SteamPath'
[ScriptingProvider] Address: 0x4040de // PT string: b'\\config\\'
[ScriptingProvider] Address: 0x4040f7 // PT string: b'ssfn*'
[ScriptingProvider] Address: 0x404110 // PT string: b'config.vdf'
[ScriptingProvider] Address: 0x404129 // PT string: b'DialogConfig.vdf'
[ScriptingProvider] Address: 0x404142 // PT string: b'DialogConfigOverlay*.vdf'
[ScriptingProvider] Address: 0x40415b // PT string: b'libraryfolders.vdf'
[ScriptingProvider] Address: 0x404174 // PT string: b'loginusers.vdf'
[ScriptingProvider] Address: 0x40418d // PT string: b'\\Steam\\'
[ScriptingProvider] Address: 0x4041a6 // PT string: b'sqlite3.dll'
[ScriptingProvider] Address: 0x4041bf // PT string: b'browsers'
[ScriptingProvider] Address: 0x4041d8 // PT string: b'done'
[ScriptingProvider] Address: 0x4041f1 // PT string: b'soft'
[ScriptingProvider] Address: 0x40420a // PT string: b'\\Discord\\tokens.txt'
[ScriptingProvider] Address: 0x404223 // PT string: b'/c timeout /t 5 & del /f /q "'
[ScriptingProvider] Address: 0x40423c // PT string: b'" & del "C:\\ProgramData\\*.dll"" & exit'
[ScriptingProvider] Address: 0x404255 // PT string: b'C:\\Windows\\system32\\cmd.exe'
[ScriptingProvider] Address: 0x40426e // PT string: b'https'
[ScriptingProvider] Address: 0x404287 // PT string: b'Content-Type: multipart/form-data; boundary=----'
[ScriptingProvider] Address: 0x4042a0 // PT string: b'POST'
[ScriptingProvider] Address: 0x4042b9 // PT string: b'HTTP/1.1'
[ScriptingProvider] Address: 0x4042d2 // PT string: b'Content-Disposition: form-data; name="'
[ScriptingProvider] Address: 0x4042eb // PT string: b'hwid'
[ScriptingProvider] Address: 0x404304 // PT string: b'build'
[ScriptingProvider] Address: 0x40431d // PT string: b'token'
[ScriptingProvider] Address: 0x404336 // PT string: b'file_name'
[ScriptingProvider] Address: 0x40434f // PT string: b'file'
[ScriptingProvider] Address: 0x404368 // PT string: b'message'
[ScriptingProvider] Address: 0x404381 // PT string: b'ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'
[ScriptingProvider] Address: 0x40439a // PT string: b'screenshot.jpg'
```

## April 15 2025

* eSentire IOC information https://github.com/eSentire/iocs/blob/main/Stealc/stealc_hwid.py
* XOR with global renaming:
```
import re

target_func = bv.get_symbol_by_raw_name('mw_decrypt_str').address

def is_call(i, target_addr):
    if(isinstance(i, HighLevelILCall) and i.dest.constant == target_addr):
        return i

def get_callers(target_func):
    call_locations = []
    for caller in bv.get_callers(target_func):
        caller_add = caller.address
        caller_func = bv.get_functions_containing(caller_add)[0]
        for instr in list(caller_func.hlil.instructions):
            for location in instr.traverse(is_call, target_func):
                call_locations.append(location)

    return call_locations

def rename_global(address, name):
    print(f"Renaming 0x{address:2x} to {name}")
    bv.define_user_symbol(Symbol(
        SymbolType.DataSymbol,
        address,
        name
    ))

def swap_unsafe(name):
    sname = re.sub(r"[\\/:%]+", "_", name)
    return sname

rstrs = {}
callers = get_callers(target_func)
for caller in callers:
    print(f"Decrypting at location: {caller.address:2x}")
    if isinstance(caller.instr.dest, binaryninja.highlevelil.HighLevelILDeref):
        destination_addr = caller.instr.dest.operands[0].constant
        key = caller.params[1]
        ct_len = caller.params[2]
        ct_ptr = caller.params[0]
    
        xor = Transform['XOR']
        ct = bv.read(ct_ptr.constant, ct_len.constant)
        key = bv.read(key.constant, ct_len.constant)
        pt = xor.encode(ct, {'key':key})
        var_name = swap_unsafe(pt.decode('ascii'))
        rename_global(destination_addr, var_name)
        rstrs[caller.address] = pt

for addr, rstr in rstrs.items():
    print(f"Address: 0x{addr:2x} // PT string: {rstr}")
    bv.set_comment_at(addr, rstr)
```

* Renaming globals from function resolution:
```
def rename_global(address, name):
    print(f"Renaming 0x{address:2x} to {name}")
    bv.define_user_symbol(Symbol(
        SymbolType.DataSymbol,
        address,
        name
    ))

func = bv.get_function_at(0x00a36240)
for bb in func.hlil:
    for instr in bb:
        if isinstance(instr, binaryninja.highlevelil.HighLevelILAssign):
            if isinstance(instr.dest, binaryninja.highlevelil.HighLevelILDeref):
                call_txt = instr.operands[1].tokens[0].text
                if(call_txt == 'GetProcAddress'):
                    print(f"Renaming 0x{instr.dest.operands[0].constant:2x} to {instr.operands[1].tokens[4]}")
                    rename_global(instr.dest.operands[0].constant, instr.operands[1].tokens[4].text)
                elif(call_txt == 'LoadLibraryA'):
                    print(f"Renaming 0x{instr.dest.operands[0].constant:2x} to {instr.operands[1].tokens[2]}")
                    rename_global(instr.dest.operands[0].constant, instr.operands[1].tokens[2].text)
```

* Hybrid-Analysis Run: https://www.hybrid-analysis.com/sample/18f53dd06e6d9d5dfe1b60c4834a185a1cf73ba449c349b6b43c753753256f62

## April 22 2025

Analyzed remaining stealer functionality. Stealc will steal:
- Steam
- Tox
- Outlook data
- Monero wallets
- Discord tokens
- Telegram data
- Pidgin data

In addition, it will take a screenshot and has the ability to download and execute additional files in `%APPDATA%\Temp\[ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890]{10}.exe` or DLL.
