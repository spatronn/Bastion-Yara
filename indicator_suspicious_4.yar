rule INDICATOR_SUSPICIOUS_EXE_WMI_EnumerateVideoDevice {
    meta:
        author = "ditekSHen"
        description = "Detects executables attemping to enumerate video devices using WMI"
    strings:
        $q1 = "Select * from Win32_CacheMemory" ascii wide nocase
        $d1 = "{860BB310-5D01-11d0-BD3B-00A0C911CE86}" ascii wide
        $d2 = "{62BE5D10-60EB-11d0-BD3B-00A0C911CE86}" ascii wide
        $d3 = "{55272A00-42CB-11CE-8135-00AA004BB851}" ascii wide
        $d4 = "SYSTEM\\ControlSet001\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\000" ascii wide nocase
        $d5 = "HardwareInformation.AdapterString" ascii wide
        $d6 = "HardwareInformation.qwMemorySize" ascii wide
    condition:
        uint16(0) == 0x5a4d and ((1 of ($q*) and 1 of ($d*)) or 3 of ($d*))
}

rule INDICATOR_SUSPICIOUS_EXE_DcRatBy {
    meta:
        author = "ditekSHen"
        description = "Detects executables containing the string DcRatBy"
    strings:
        $s1 = "DcRatBy" ascii wide
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_SUSPICIOUS_EXE_Anti_WinJail {
    meta:
        author = "ditekSHen"
        description = "Detects executables potentially checking for WinJail sandbox window"
    strings:
        $s1 = "Afx:400000:0" fullword ascii wide
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_SUSPICIOUS_EXE_Anti_OldCopyPaste {
    meta:
        author = "ditekSHen"
        description = "Detects executables potentially checking for WinJail sandbox window"
    strings:
        $s1 = "This file can't run into Virtual Machines" wide
        $s2 = "This file can't run into Sandboxies" wide
        $s3 = "This file can't run into RDP Servers" wide
        $s4 = "Run without emulation" wide
        $s5 = "Run using valid operating system" wide
        $v1 = "SbieDll.dll" fullword wide
        $v2 = "USER" fullword wide
        $v3 = "SANDBOX" fullword wide
        $v4 = "VIRUS" fullword wide
        $v5 = "MALWARE" fullword wide
        $v6 = "SCHMIDTI" fullword wide
        $v7 = "CURRENTUSER" fullword wide
    condition:
        uint16(0) == 0x5a4d and (3 of ($s*) or all of ($v*))
}

rule INDICATOR_SUSPICIOUS_EXE_Go_GoLazagne {
    meta:
        author = "ditekSHen"
        description = "Detects Go executables using GoLazagne"
    strings:
        $s1 = "/goLazagne/" ascii nocase
        $s2 = "Go build ID:" ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_SUSPICIOUS_CSPROJ {
    meta:
        author = "ditekSHen"
        description = "Detects suspicious .CSPROJ files then compiled with msbuild"
    strings:
        $s1 = "ToolsVersion=" ascii
        $s2 = "/developer/msbuild/" ascii
        $x1 = "[DllImport(\"\\x" ascii
        $x2 = "VirtualAlloc(" ascii nocase
        $x3 = "CallWindowProc(" ascii nocase
    condition:
        uint32(0) == 0x6f72503c and (all of ($s*) and 2 of ($x*))
}
rule INDICATOR_SUSPICIOUS_Sandbox_Evasion_FilesComb {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing specific set of files observed in sandob anti-evation, and Emotet"
    strings:
        $s1 = "c:\\take_screenshot.ps1" ascii wide nocase
        $s2 = "c:\\loaddll.exe" ascii wide nocase
        $s3 = "c:\\email.doc" ascii wide nocase
        $s4 = "c:\\email.htm" ascii wide nocase
        $s5 = "c:\\123\\email.doc" ascii wide nocase
        $s6 = "c:\\123\\email.docx" ascii wide nocase
        $s7 = "c:\\a\\foobar.bmp" ascii wide nocase
        $s8 = "c:\\a\\foobar.doc" ascii wide nocase
        $s9 = "c:\\a\\foobar.gif" ascii wide nocase
        $s10 = "c:\\symbols\\aagmmc.pdb" ascii wide nocase
    condition:
         uint16(0) == 0x5a4d and 6 of them
}

rule INDICATOR_SUSPICIOUS_VM_Evasion_VirtDrvComb {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing combination of virtualization drivers"
    strings:
        $p1 = "prleth.sys" ascii wide
        $p2 = "prlfs.sys" ascii wide
        $p3 = "prlmouse.sys" ascii wide
        $p4 = "prlvideo.sys	" ascii wide
        $p5 = "prltime.sys" ascii wide
        $p6 = "prl_pv32.sys" ascii wide
        $p7 = "prl_paravirt_32.sys" ascii wide
        $vb1 = "VBoxMouse.sys" ascii wide
        $vb2 = "VBoxGuest.sys" ascii wide
        $vb3 = "VBoxSF.sys" ascii wide
        $vb4 = "VBoxVideo.sys" ascii wide
        $vb5 = "vboxdisp.dll" ascii wide
        $vb6 = "vboxhook.dll" ascii wide
        $vb7 = "vboxmrxnp.dll" ascii wide
        $vb8 = "vboxogl.dll" ascii wide
        $vb9 = "vboxoglarrayspu.dll" ascii wide
        $vb10 = "vboxoglcrutil.dll" ascii wide
        $vb11 = "vboxoglerrorspu.dll" ascii wide
        $vb12 = "vboxoglfeedbackspu.dll" ascii wide
        $vb13 = "vboxoglpackspu.dll" ascii wide
        $vb14 = "vboxoglpassthroughspu.dll" ascii wide
        $vb15 = "vboxservice.exe" ascii wide
        $vb16 = "vboxtray.exe" ascii wide
        $vb17 = "VBoxControl.exe" ascii wide
        $vp1 = "vmsrvc.sys" ascii wide
        $vp2 = "vpc-s3.sys" ascii wide
        $vw1 = "vmmouse.sys" ascii wide
        $vw2 = "vmnet.sys" ascii wide
        $vw3 = "vmxnet.sys" ascii wide
        $vw4 = "vmhgfs.sys" ascii wide
        $vw5 = "vmx86.sys" ascii wide
        $vw6 = "hgfs.sys" ascii wide
    condition:
         uint16(0) == 0x5a4d and (
             (2 of ($p*) and (2 of ($vb*) or 2 of ($vp*) or 2 of ($vw*))) or
             (2 of ($vb*) and (2 of ($p*) or 2 of ($vp*) or 2 of ($vw*))) or
             (2 of ($vp*) and (2 of ($p*) or 2 of ($vb*) or 2 of ($vw*))) or
             (2 of ($vw*) and (2 of ($p*) or 2 of ($vb*) or 2 of ($vp*)))
         )
}

rule INDICATOR_SUSPICIOUS_EXE_NoneWindowsUA {
    meta:
        author = "ditekSHen"
        description = "Detects Windows executables referencing non-Windows User-Agents"
    strings:
        $ua1 = "Mozilla/5.0 (Macintosh; Intel Mac OS" wide ascii
        $ua2 = "Mozilla/5.0 (iPhone; CPU iPhone OS" ascii wide
        $ua3 = "Mozilla/5.0 (Linux; Android " ascii wide
        $ua4 = "Mozilla/5.0 (PlayStation " ascii wide
        $ua5 = "Mozilla/5.0 (X11; " wide ascii
        $ua6 = "Mozilla/5.0 (Windows Phone " ascii wide
        $ua7 = "Mozilla/5.0 (compatible; MSIE 10.0; Macintosh; Intel Mac OS X 10_7_3; Trident/6.0)" wide ascii
        $ua8 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows Phone OS 7.5; Trident/5.0; IEMobile/9.0)" wide ascii
        $ua9 = "HTC_Touch_3G Mozilla/4.0 (compatible; MSIE 6.0; Windows CE; IEMobile 7.11)" wide ascii
        $ua10 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows Phone OS 7.0; Trident/3.1; IEMobile/7.0; Nokia;N70)" wide ascii
        $ua11 = "Mozilla/5.0 (BlackBerry; U; BlackBerry " wide ascii
        $ua12 = "Mozilla/5.0 (iPad; CPU OS" wide ascii
        $ua13 = "Mozilla/5.0 (iPad; U;" ascii wide
        $ua14 = "Mozilla/5.0 (IE 11.0;" ascii wide
        $ua15 = "Mozilla/5.0 (Android;" ascii wide
        $ua16 = "User-Agent: Internal Wordpress RPC connection" ascii wide
    condition:
         uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_SUSPICIOUS_EXE_TooManyWindowsUA {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing many varying, potentially fake Windows User-Agents"
    strings:
        $ua1 = "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36" ascii wide
        $ua2 = "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.67 Safari/537.36" ascii wide
        $ua3 = "Mozilla/5.0 (Windows NT 5.1; rv:31.0) Gecko/20100101 Firefox/31.0" ascii wide
        $ua4 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:29.0) Gecko/20120101 Firefox/29.0" ascii wide
        $ua5 = "Mozilla/5.0 (Windows NT 6.1; rv:27.3) Gecko/20130101 Firefox/27.3" ascii wide
        $ua6 = "Mozilla/5.0 (Windows; U; MSIE 9.0; WIndows NT 9.0; en-US)" ascii wide
        $ua7 = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)" ascii wide
        $ua8 = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/4.0; InfoPath.2; SV1; .NET CLR 2.0.50727; WOW64)" ascii wide
        $ua9 = "Opera/12.0(Windows NT 5.2;U;en)Presto/22.9.168 Version/12.00" ascii wide
        $ua10 = "Opera/9.80 (Windows NT 6.0) Presto/2.12.388 Version/12.14" ascii wide
        $ua11 = "Mozilla/5.0 (Windows NT 6.0; rv:2.0) Gecko/20100101 Firefox/4.0 Opera 12.14" ascii wide
        $ua12 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0) Opera 12.14" ascii wide
        $ua13 = "Opera/12.80 (Windows NT 5.1; U; en) Presto/2.10.289 Version/12.02" ascii wide
        $ua14 = "Opera/9.80 (Windows NT 6.1; U; es-ES) Presto/2.9.181 Version/12.00" ascii wide
        $ua15 = "Opera/9.80 (Windows NT 5.1; U; zh-sg) Presto/2.9.181 Version/12.00" ascii wide
        $ua16 = "Mozilla/5.0 (Windows NT 6.2) AppleWebKit/535.7 (KHTML, like Gecko) Comodo_Dragon/16.1.1.0 Chrome/16.0.912.63 Safari/535.7" ascii wide
        $ua17 = "Mozilla/5.0 (Windows; U; Windows NT 6.1; tr-TR) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27" ascii wide
    condition:
         uint16(0) == 0x5a4d and 5 of them
}

rule INDICATOR_SUSPICIOUS_VM_Evasion_MACAddrComb {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing virtualization MAC addresses"
    strings:
        $s1 = "00:03:FF" ascii wide nocase
        $s2 = "00:05:69" ascii wide nocase
        $s3 = "00:0C:29" ascii wide nocase
        $s4 = "00:16:3E" ascii wide nocase
        $s5 = "00:1C:14" ascii wide nocase
        $s6 = "00:1C:42" ascii wide nocase
        $s7 = "00:50:56" ascii wide nocase
        $s8 = "08:00:27" ascii wide nocase
    condition:
         uint16(0) == 0x5a4d and 3 of them
}
rule INDICATOR_SUSPICIOUS_EXE_CC_Regex {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing credit card regular expressions"
    strings:
        // Amex / Express Card
        $s1 = "^3[47][0-9]{13}$" ascii wide nocase
        $s2 = "3[47][0-9]{13}$" ascii wide nocase
        $s3 = "37[0-9]{2}\\s[0-9]{4}\\s[0-9]{4}\\s[0-9]{4}" ascii wide nocase
        // BCGlobal
        $s4 = "^(6541|6556)[0-9]{12}$" ascii wide nocase
        // Carte Blanche Card
        $s5 = "^389[0-9]{11}$" ascii wide nocase
        // Diners Club Card
        $s6 = "^3(?:0[0-5]|[68][0-9])[0-9]{11}$" ascii wide nocase
        // Discover Card
        $s7 = "6(?:011|5[0-9]{2})[0-9]{12}$" ascii wide nocase
        $s8 = "6011\\s[0-9]{4}\\s[0-9]{4}\\s[0-9]{4}" ascii wide nocase
        // Insta Payment Card
        $s9 = "^63[7-9][0-9]{13}$" ascii wide nocase
        // JCB Card
        $s10 = "^(?:2131|1800|35\\d{3})\\d{11}$" ascii wide nocase
        // KoreanLocalCard
        $s11 = "^9[0-9]{15}$" ascii wide nocase
        // Laser Card
        $s12 = "^(6304|6706|6709|6771)[0-9]{12,15}$" ascii wide nocase
        // Maestro Card
        $s13 = "^(5018|5020|5038|6304|6759|6761|6763)[0-9]{8,15}$" ascii wide nocase
        // Mastercard
        $s14 = "5[1-5][0-9]{14}$" ascii wide nocase
        // Solo Card
        $s15 = "^(6334|6767)[0-9]{12}|(6334|6767)[0-9]{14}|(6334|6767)[0-9]{15}$" ascii wide nocase
        // Switch Card
        $s16 = "^(4903|4905|4911|4936|6333|6759)[0-9]{12}|(4903|4905|4911|4936|6333|6759)[0-9]{14}|(4903|4905|4911|4936|6333|6759)[0-9]{15}|564182[0-9]{10}|564182[0-9]{12}|564182[0-9]{13}|633110[0-9]{10}|633110[0-9]{12}|633110[0-9]{13}$" ascii wide nocase
        // Union Pay Card
        $s17 = "^(62[0-9]{14,17})$" ascii wide nocase
        // Visa Card
        $s18 = "4[0-9]{12}(?:[0-9]{3})?$" ascii wide nocase
        // Visa Master Card
        $s19 = "^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})$" ascii wide nocase
        $s20 = "4[0-9]{3}\\s[0-9]{4}\\s[0-9]{4}\\s[0-9]{4}" ascii wide nocase
        $a21 = "^[0-9]{4}\\s[0-9]{4}\\s[0-9]{4}\\s[0-9]{4}"ascii wide nocase
    condition:
         (uint16(0) == 0x5a4d and 2 of them) or (4 of them)
}

rule INDICATOR_SUSPICIOUS_EXE_Discord_Regex {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing Discord tokens regular expressions"
    strings:
        $s1 = "[a-zA-Z0-9]{24}\\.[a-zA-Z0-9]{6}\\.[a-zA-Z0-9_\\-]{27}|mfa\\.[a-zA-Z0-9_\\-]{84}" ascii wide nocase
    condition:
         (uint16(0) == 0x5a4d and all of them) or all of them
}

rule INDICATOR_SUSPICIOUS_EXE_References_VPN {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing many VPN software clients. Observed in infosteslers"
    strings:
        $s1 = "\\VPN\\NordVPN" ascii wide nocase
        $s2 = "\\VPN\\OpenVPN" ascii wide nocase
        $s3 = "\\VPN\\ProtonVPN" ascii wide nocase
        $s4 = "\\VPN\\DUC\\" ascii wide nocase
        $s5 = "\\VPN\\PrivateVPN" ascii wide nocase
        $s6 = "\\VPN\\PrivateVPN" ascii wide nocase
        $s7 = "\\VPN\\EarthVPN" ascii wide nocase
    condition:
         uint16(0) == 0x5a4d and 3 of them
}
rule INDICATOR_SUSPICIOUS_EXE_VaultSchemaGUID {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing Windows vault credential objects. Observed in infostealers"
    strings:
        // Windows Secure Note
        $s1 = "2F1A6504-0641-44CF-8BB5-3612D865F2E5" ascii wide
        // Windows Web Password Credential
        $s2 = "3CCD5499-87A8-4B10-A215-608888DD3B55" ascii wide
        // Windows Credential Picker Protector
        $s3 = "154E23D0-C644-4E6F-8CE6-5069272F999F" ascii wide
        // Web Credentials
        $s4 = "4BF4C442-9B8A-41A0-B380-DD4A704DDB28" ascii wide
        // Windows Credentials
        $s5 = "77BC582B-F0A6-4E15-4E80-61736B6F3B29" ascii wide
        // Windows Domain Certificate Credential
        $s6 = "E69D7838-91B5-4FC9-89D5-230D4D4CC2BC" ascii wide
        // Windows Domain Password Credential
        $s7 = "3E0E35BE-1B77-43E7-B873-AED901B6275B" ascii wide
        // Windows Extended Credential
        $s8 = "3C886FF3-2669-4AA2-A8FB-3F6759A77548" ascii wide
    condition:
         uint16(0) == 0x5a4d and 4 of them
}

rule INDICATOR_SUSPICIOUS_AntiVM_UNK01 {
    meta:
        author = "ditekSHen"
        description = "Detects memory artifcats referencing specific combination of anti-VM checks"
    strings:
        $s1 = "vmci.s" fullword ascii wide
        $s2 = "vmmemc" fullword ascii wide
        $s3 = "qemu-ga.exe" fullword ascii wide
        $s4 = "qga.exe" fullword ascii wide
        $s5 = "windanr.exe" fullword ascii wide
        $s6 = "vboxservice.exe" fullword ascii wide
        $s7 = "vboxtray.exe" fullword ascii wide
        $s8 = "vmtoolsd.exe" fullword ascii wide
        $s9 = "prl_tools.exe" fullword ascii wide
        $s10 = "7869.vmt" fullword ascii wide
        $s11 = "qemu" fullword ascii wide
        $s12 = "virtio" fullword ascii wide
        $s13 = "vmware" fullword ascii wide
        $s14 = "vbox" fullword ascii wide
        $s15 = "%systemroot%\\system32\\ntdll.dll" fullword ascii wide
    condition:
         uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_SUSPICIOUS_AntiVM_WMIC {
    meta:
        author = "ditekSHen"
        description = "Detects memory artifcats referencing WMIC commands for anti-VM checks"
    strings:
        $s1 = "wmic process where \"name like '%vmwp%'\"" ascii wide nocase
        $s2 = "wmic process where \"name like '%virtualbox%'\"" ascii wide nocase
        $s3 = "wmic process where \"name like '%vbox%'\"" ascii wide nocase
    condition:
         uint16(0) == 0x5a4d and 2 of them
}

rule INDICATOR_SUSPICIOUS_EnableSMBv1 {
    meta:
        author = "ditekSHen"
        description = "Detects binaries with PowerShell command enabling SMBv1"
    strings:
        $s1 = "Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol" ascii wide nocase
    condition:
         uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_SUSPICIOUS_EnableNetworkDiscovery {
    meta:
        author = "ditekSHen"
        description = "Detects binaries manipulating Windows firewall to enable permissive network discovery"
    strings:
        $s1 = "netsh advfirewall firewall set rule group=\"Network Discovery\" new enable=Yes" ascii wide nocase 
        $s2 = "netsh advfirewall firewall set rule group=\"File and Printer Sharing\" new enable=Yes" ascii wide nocase 
    condition:
         uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_SUSPICIOUS_EXE_References_AuthApps {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing many authentication apps. Observed in information stealers"
    strings:
        $s1 = "WinAuth\\winauth.xml" ascii wide nocase
        $s2 = "Authy Desktop\\Local" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_SUSPICIOUS_EXE_RegKeyComb_RDP {
    meta:
        author = "ditekSHen"
        description = "Detects executables embedding registry key / value combination manipulating RDP / Terminal Services"
    strings:
        // Beginning with Windows Server 2008 and Windows Vista, this policy no longer has any effect
        // https://docs.microsoft.com/en-us/windows/win32/msi/enableadmintsremote
        $r1 = "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer" ascii wide nocase
        $k1 = "EnableAdminTSRemote" fullword ascii wide nocase
        // Whether basic Terminal Services functions are enabled
        $r2 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server" ascii wide nocase
        $k2 = "TSEnabled" fullword ascii wide nocase
        // Terminal Device Driver Attributes
        // Terminal Services hosts and configurations
        $r3 = "SYSTEM\\CurrentControlSet\\Services\\TermDD" ascii wide nocase
        $r4 = "SYSTEM\\CurrentControlSet\\Services\\TermService" ascii wide nocase
        $k3 = "Start" fullword ascii wide nocase
        // Allows or denies connecting to Terminal Services
        $r5 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server" ascii wide nocase
        $k4 = "fDenyTSConnections" fullword ascii wide nocase
        // RDP Port Number
        $r6 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\RDPTcp" ascii wide nocase
        $r7 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\Wds\\rdpwd\\Tds\\tcp" ascii wide nocase
        $r8 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" ascii wide nocase
        $k5 = "PortNumber" fullword ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and 5 of ($r*) and 3 of ($k*)
}
rule INDICATOR_SUSPICIOUS_EXE_Undocumented_WinAPI_Kerberos {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing undocumented kerberos Windows APIs and obsereved in malware"
    strings:
        // Undocumented Kerberos-related functions
        // Reference: https://unit42.paloaltonetworks.com/manageengine-godzilla-nglite-kdcsponge/ (KdcSponge)
        // Reference: https://us-cert.cisa.gov/ncas/current-activity/2021/11/19/updated-apt-exploitation-manageengine-adselfservice-plus
        // New Sample: e391c2d3e8e4860e061f69b894cf2b1ba578a3e91de610410e7e9fa87c07304c
        $kdc1 = "KdcVerifyEncryptedTimeStamp" ascii wide nocase
        $kdc2 = "KerbHashPasswordEx3" ascii wide nocase
        $kdc3 = "KerbFreeKey" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and all of ($kdc*)
}

rule INDICATOR_SUSPICIOUS_EXE_NKN_BCP2P {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing NKN Blockchain P2P network"
    strings:
        $x1 = "/nknorg/nkn-sdk-go." ascii
        $x2 = "://seed.nkn.org" ascii
        $x3 = "/nknorg/nkn/" ascii
        $s1 = ").NewNanoPayClaimer" ascii
        $s2 = ").IncrementAmount" ascii
        $s3 = ").BalanceByAddress" ascii
        $s4 = ").TransferName" ascii
        $s5 = ".GetWsAddr" ascii
        $s6 = ".GetNodeStateContext" ascii
    condition:
        uint16(0) == 0x5a4d and (1 of ($x*) or all of ($s*))
}

rule INDICATOR_SUSPICIOUS_EXE_References_PasswordManagers {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing many Password Manager software clients. Observed in infostealers"
    strings:
        $s1 = "1Password\\" ascii wide nocase
        $s2 = "Dashlane\\" ascii wide nocase
        $s3 = "nordpass*.sqlite" ascii wide nocase
        $s4 = "RoboForm\\" ascii wide nocase
    condition:
         uint16(0) == 0x5a4d and 3 of them
}

rule INDICATOR_SUSPICIOUS_EXE_WirelessNetReccon {
    meta:
        author = "ditekSHen"
        description = "Detects executables with interest in wireless interface using netsh"
    strings:
        $s1 = "netsh wlan show profile" ascii wide nocase
        $s2 = "netsh wlan show profile name=" ascii wide nocase
        $s3 = "netsh wlan show networks mode=bssid" ascii wide nocase
    condition:
         uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_SUSPICIOUS_EXE_References_GitConfData {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing potentially confidential GIT artifacts. Observed in infostealer"
    strings:
        $s1 = "GithubDesktop\\Local Storage" ascii wide nocase
        $s2 = "GitHub Desktop\\Local Storage" ascii wide nocase
        $s3 = ".git-credentials" ascii wide
        $s4 = ".config\\git\\credentials" ascii wide
        $s5 = ".gitconfig" ascii wide
    condition:
         uint16(0) == 0x5a4d and 4 of them
}

rule INDICATOR_SUSPICIOUS_EXE_Reversed {
    meta:
        author = "ditekSHen"
        description = "Detects reversed executables. Observed N-stage drop"
    strings:
        $s1 = "edom SOD ni nur eb tonnac margorp sihT" ascii
    condition:
         uint16(filesize-0x2) == 0x4d5a and $s1
}