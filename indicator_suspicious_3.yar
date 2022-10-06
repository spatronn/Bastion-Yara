rule INDICATOR_SUSPICIOUS_EXE_RawGitHub_URL {
     meta:
        author = "ditekSHen"
        description = "Detects executables containing URLs to raw contents of a Github gist"
    strings:
        $url1 = "https://gist.githubusercontent.com/" ascii wide
        $url2 = "https://raw.githubusercontent.com/" ascii wide
        $raw = "/raw/" ascii wide
    condition:
        uint16(0) == 0x5a4d and (($url1 and $raw) or ($url2))
}

rule INDICATOR_SUSPICIOUS_EXE_RawPaste_URL {
     meta:
        author = "ditekSHen"
        description = "Detects executables (downlaoders) containing URLs to raw contents of a paste"
    strings:
        $u1 = "https://pastebin.com/" ascii wide nocase
        $u2 = "https://paste.ee/" ascii wide nocase
        $u3 = "https://pastecode.xyz/" ascii wide nocase
        $u4 = "https://rentry.co/" ascii wide nocase
        $u5 = "https://paste.nrecom.net/" ascii wide nocase
        $u6 = "https://hastebin.com/" ascii wide nocase
        $u7 = "https://privatebin.info/" ascii wide nocase
        $u8 = "https://penyacom.org/" ascii wide nocase
        $u9 = "https://controlc.com/" ascii wide nocase
        $u10 = "https://tiny-paste.com/" ascii wide nocase
        $u11 = "https://paste.teknik.io/" ascii wide nocase
        $u12 = "https://privnote.com/" ascii wide nocase
        $u13 = "https://hushnote.herokuapp.com/" ascii wide nocase
        $s1 = "/raw/" ascii wide
    condition:
        uint16(0) == 0x5a4d and (1 of ($u*) and all of ($s*))
}

rule INDICATOR_SUSPICIOUS_EXE_RawPaste_Reverse_URL {
     meta:
        author = "ditekSHen"
        description = "Detects executables (downloaders) containing reversed URLs to raw contents of a paste"
    strings:
        $u1 = "/moc.nibetsap//:sptth" ascii wide nocase
        $u2 = "/ee.etsap//:sptth" ascii wide nocase
        $u3 = "/zyx.edocetsap//:sptth" ascii wide nocase
        $u4 = "/oc.yrtner//:sptth" ascii wide nocase
        $u5 = "/ten.mocern.etsap//:sptth" ascii wide nocase
        $u6 = "/moc.nibetsah//:sptth" ascii wide nocase
        $u7 = "/ofni.nibetavirp//:sptth" ascii wide nocase
        $u8 = "/gro.mocaynep//:sptth" ascii wide nocase
        $u9 = "/moc.clortnoc//:sptth" ascii wide nocase
        $u10 = "/moc.etsap-ynit//:sptth" ascii wide nocase
        $u11 = "/oi.kinket.etsap//:sptth" ascii wide nocase
        $u12 = "/moc.etonvirp//:sptth" ascii wide nocase
        $u13 = "/moc.ppaukoreh.etonhsuh//:sptth" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and 1 of ($u*)
}

rule INDICATOR_SUSPICIOUS_PWSH_PasswordCredential_RetrievePassword {
    meta:
        author = "ditekSHen"
        description = "Detects PowerShell content designed to retrieve passwords from host"
    strings:
        $namespace = "Windows.Security.Credentials.PasswordVault" ascii wide nocase
        $method1 = "RetrieveAll()" ascii wide nocase
        $method2 = ".RetrievePassword()" ascii wide nocase
    condition:
       $namespace and 1 of ($method*)
}
rule INDICATOR_SUSPICIOUS_EXE_UACBypass_EnvVarScheduledTasks {
    meta:
        author = "ditekSHen"
        description = "detects Windows exceutables potentially bypassing UAC (ab)using Environment Variables in Scheduled Tasks"
    strings:
        $s1 = "\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup" ascii wide
        $s2 = "\\Environment" ascii wide
        $s3 = "schtasks" ascii wide
        $s4 = "/v windir" ascii wide
    condition:
       all of them
}

rule INDICATOR_SUSPICIOUS_EXE_UACBypass_fodhelper {
    meta:
        author = "ditekSHen"
        description = "detects Windows exceutables potentially bypassing UAC using fodhelper.exe"
    strings:
        $s1 = "\\software\\classes\\ms-settings\\shell\\open\\command" ascii wide nocase
        $s2 = "DelegateExecute" ascii wide
        $s3 = "fodhelper" ascii wide
        $s4 = "ConsentPromptBehaviorAdmin" ascii wide
    condition:
       all of them
}

/*
rule INDICATOR_SUSPICIOUS_EXE_Contains_MD5_Named_DLL {
    meta:
        author = "ditekSHen"
        description = "detects Windows exceutables potentially bypassing UAC using fodhelper.exe"
    strings:
        $s1 = /[a-f0-9]{32}\.dll/ ascii wide nocase
    condition:
       uint16(0) == 0x5a4d and all of them
}
*/

rule INDICATOR_SUSPICIOUS_Finger_Download_Pattern {
    meta:
        author = "ditekSHen"
        description = "Detects files embedding and abusing the finger command for download"
    strings:
        $pat1 = /finger(\.exe)?\s.{1,50}@.{7,10}\|/ ascii wide
        $pat2 = "-Command \"finger" ascii wide
        $ne1 = "Nmap service detection probe list" ascii
    condition:
       not any of ($ne*) and any of ($pat*)
}

rule INDICATOR_SUSPICIOUS_EXE_UACBypass_CMSTPCMD {
    meta:
        author = "ditekSHen"
        description = "Detects Windows exceutables bypassing UAC using CMSTP utility, command line and INF"
    strings:
        $s1 = "c:\\windows\\system32\\cmstp.exe" ascii wide nocase
        $s2 = "taskkill /IM cmstp.exe /F" ascii wide nocase
        $s3 = "CMSTPBypass" fullword ascii
        $s4 = "CommandToExecute" fullword ascii
        $s5 = "RunPreSetupCommands=RunPreSetupCommandsSection" fullword wide
        $s6 = "\"HKLM\", \"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\CMMGR32.EXE\", \"ProfileInstallPath\", \"%UnexpectedError%\", \"\"" fullword wide nocase
    condition:
       uint16(0) == 0x5a4d and 3 of them
}

rule INDICATOR_SUSPICIOUS_JS_WMI_ExecQuery {
    meta:
        author = "ditekSHen"
        description = "Detects JS potentially executing WMI queries"
    strings:
        $ex = ".ExecQuery(" ascii nocase
        $s1 = "GetObject(" ascii nocase
        $s2 = "String.fromCharCode(" ascii nocase
        $s3 = "ActiveXObject(" ascii nocase
        $s4 = ".Sleep(" ascii nocase
    condition:
       ($ex and all of ($s*))
}

rule INDICATOR_SUSPICIOUS_EXE_SandboxUserNames {
    meta:
        author = "ditekSHen"
        description = "Detects executables containing possible sandbox analysis VM usernames"
    strings:
        $s1 = "15pb" fullword ascii wide nocase
        $s2 = "7man2" fullword ascii wide nocase
        $s3 = "stella" fullword ascii wide nocase
        $s4 = "f4kh9od" fullword ascii wide nocase
        $s5 = "willcarter" fullword ascii wide nocase
        $s6 = "biluta" fullword ascii wide nocase
        $s7 = "ehwalker" fullword ascii wide nocase
        $s8 = "hong lee" fullword ascii wide nocase
        $s9 = "joe cage" fullword ascii wide nocase
        $s10 = "jonathan" fullword ascii wide nocase
        $s11 = "kindsight" fullword ascii wide nocase
        $s12 = "malware" fullword ascii wide nocase
        $s13 = "peter miller" fullword ascii wide nocase
        $s14 = "petermiller" fullword ascii wide nocase
        $s15 = "phil" fullword ascii wide nocase
        $s16 = "rapit" fullword ascii wide nocase
        $s17 = "r0b0t" fullword ascii wide nocase
        $s18 = "cuckoo" fullword ascii wide nocase
        $s19 = "vm-pc" fullword ascii wide nocase
        $s20 = "analyze" fullword ascii wide nocase
        $s21 = "roslyn" fullword ascii wide nocase
        $s22 = "vince" fullword ascii wide nocase
        $s23 = "test" fullword ascii wide nocase
        $s24 = "sample" fullword ascii wide nocase
        $s25 = "mcafee" fullword ascii wide nocase
        $s26 = "vmscan" fullword ascii wide nocase
        $s27 = "mallab" fullword ascii wide nocase
        $s28 = "abby" fullword ascii wide nocase
        $s29 = "elvis" fullword ascii wide nocase
        $s30 = "wilbert" fullword ascii wide nocase
        $s31 = "joe smith" fullword ascii wide nocase
        $s32 = "hanspeter" fullword ascii wide nocase
        $s33 = "johnson" fullword ascii wide nocase
        $s34 = "placehole" fullword ascii wide nocase
        $s35 = "tequila" fullword ascii wide nocase
        $s36 = "paggy sue" fullword ascii wide nocase
        $s37 = "klone" fullword ascii wide nocase
        $s38 = "oliver" fullword ascii wide nocase
        $s39 = "stevens" fullword ascii wide nocase
        $s40 = "ieuser" fullword ascii wide nocase
        $s41 = "virlab" fullword ascii wide nocase
        $s42 = "beginer" fullword ascii wide nocase
        $s43 = "beginner" fullword ascii wide nocase
        $s44 = "markos" fullword ascii wide nocase
        $s45 = "semims" fullword ascii wide nocase
        $s46 = "gregory" fullword ascii wide nocase
        $s47 = "tom-pc" fullword ascii wide nocase
        $s48 = "will carter" fullword ascii wide nocase
        $s49 = "angelica" fullword ascii wide nocase
        $s50 = "eric johns" fullword ascii wide nocase
        $s51 = "john ca" fullword ascii wide nocase
        $s52 = "lebron james" fullword ascii wide nocase
        $s53 = "rats-pc" fullword ascii wide nocase
        $s54 = "robot" fullword ascii wide nocase
        $s55 = "serena" fullword ascii wide nocase
        $s56 = "sofynia" fullword ascii wide nocase
        $s57 = "straz" fullword ascii wide nocase
        $s58 = "bea-ch" fullword ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and 10 of them
}

rule INDICATOR_SUSPICIOUS_XML_Liverpool_Downlaoder_UserConfig {
    meta:
        author = "ditekSHen"
        description = "Detects XML files associated with 'Liverpool' downloader containing encoded executables"
    strings:
        $s1 = "<configSections>" ascii nocase
        $s2 = "<value>77 90" ascii nocase
    condition:
       uint32(0) == 0x6d783f3c and all of them
}

rule INDICATOR_SUSPICIOUS_EXE_B64_Encoded_UserAgent {
    meta:
        author = "ditekSHen"
        description = "Detects executables containing base64 encoded User Agent"
    strings:
        $s1 = "TW96aWxsYS81LjAgK" ascii wide
        $s2 = "TW96aWxsYS81LjAgKFdpbmRvd3M" ascii wide
    condition:
        uint16(0) == 0x5a4d and any of them
}

rule INDICATOR_SUSPICIOUS_EXE_WindDefender_AntiEmaulation {
    meta:
        author = "ditekSHen"
        description = "Detects executables containing potential Windows Defender anti-emulation checks"
    strings:
        $s1 = "JohnDoe" fullword ascii wide
        $s2 = "HAL9TH" fullword ascii wide
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_SUSPICIOUS_EXE_attrib {
    meta:
        author = "ditekSHen"
        description = "Detects executables using attrib with suspicious attributes attributes"
    strings:
        $s1 = "attrib +h +r +s" ascii wide
    condition:
        uint16(0) == 0x5a4d and any of them
}

rule INDICATOR_SUSPICIOUS_EXE_ClearMyTracksByProcess {
    meta:
        author = "ditekSHen"
        description = "Detects executables calling ClearMyTracksByProcess"
    strings:
        $s1 = "InetCpl.cpl,ClearMyTracksByProcess" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and any of them
}

rule INDICATOR_SUSPICIOUS_EXE_DotNetProcHook {
    meta:
        author = "ditekSHen"
        description = "Detects executables with potential process hoocking"
    strings:
        $s1 = "UnHook" fullword ascii
        $s2 = "SetHook" fullword ascii
        $s3 = "CallNextHook" fullword ascii
        $s4 = "_hook" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_SUSPICIOUS_EXE_TelegramChatBot {
    meta:
        author = "ditekSHen"
        description = "Detects executables using Telegram Chat Bot"
    strings:
        $s1 = "https://api.telegram.org/bot" ascii wide
        $s2 = "/sendMessage?chat_id=" fullword ascii wide
        $s3 = "Content-Disposition: form-data; name=\"" fullword ascii
        $s4 = "/sendDocument?chat_id=" fullword ascii wide
        $p1 = "/sendMessage" ascii wide
        $p2 = "/sendDocument" ascii wide
        $p3 = "&chat_id=" ascii wide
    condition:
        uint16(0) == 0x5a4d and (2 of ($s*) or (2 of ($p*) and 1 of ($s*)))
}

rule INDICATOR_SUSPICIOUS_EXE_B64_Artifacts {
    meta:
        author = "ditekSHen"
        description = "Detects executables embedding bas64-encoded APIs, command lines, registry keys, etc."
    strings:
        $s1 = "U09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVuXA" ascii wide
        $s2 = "L2Mgc2NodGFza3MgL2" ascii wide
        $s3 = "QW1zaVNjYW5CdWZmZXI" ascii wide
        $s4 = "VmlydHVhbFByb3RlY3Q" ascii wide
    condition:
        uint16(0) == 0x5a4d and 2 of them
}

rule INDICATOR_SUSPICIOUS_EXE_DiscordURL {
    meta:
        author = "ditekSHen"
        description = "Detects executables Discord URL observed in first stage droppers"
    strings:
        $s1 = "https://discord.com/api/webhooks/" ascii wide nocase
        $s2 = "https://cdn.discordapp.com/attachments/" ascii wide nocase
        $s3 = "aHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvd2ViaG9va" ascii wide
        $s4 = "aHR0cHM6Ly9jZG4uZGlzY29yZGFwcC5jb20vYXR0YWNobW" ascii wide
        $s5 = "/skoohbew/ipa/moc.drocsid//:sptth" ascii wide nocase
        $s6 = "/stnemhcatta/moc.ppadrocsid.ndc//:sptth" ascii wide nocase
        $s7 = "av9GaiV2dvkGch9SbvNmLkJ3bjNXak9yL6MHc0RHa" ascii wide
        $s8 = "WboNWY0RXYv02bj5CcwFGZy92YzlGZu4GZj9yL6MHc0RHa" ascii wide
    condition:
        uint16(0) == 0x5a4d and any of them
}
rule INDICATOR_SUSPICIOUS_EXE_RegKeyComb_DisableWinDefender {
    meta:
        author = "ditekSHen"
        description = "Detects executables embedding registry key / value combination indicative of disabling Windows Defedner features"
    strings:
        $r1 = "SOFTWARE\\Policies\\Microsoft\\Windows Defender" ascii wide nocase
        $k1 = "DisableAntiSpyware" ascii wide
        $r2 = "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection" ascii wide nocase
        $k2 = "DisableBehaviorMonitoring" ascii wide
        $k3 = "DisableOnAccessProtection" ascii wide
        $k4 = "DisableScanOnRealtimeEnable" ascii wide
        $r3 = "SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection" ascii wide nocase
        $k5 = "vDisableRealtimeMonitoring" ascii wide
        $r4 = "SOFTWARE\\Microsoft\\Windows Defender\\Spynet" ascii wide nocase
        $k6 = "SpyNetReporting" ascii wide
        $k7 = "SubmitSamplesConsent" ascii wide
        $r5 = "SOFTWARE\\Microsoft\\Windows Defender\\Features" ascii wide nocase
        $k8 = "TamperProtection" ascii wide
        $r6 = "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths" ascii wide nocase
        $k9 = "Add-MpPreference -ExclusionPath \"{0}\"" ascii wide
    condition:
        uint16(0) == 0x5a4d and (1 of ($r*) and 1 of ($k*))
}

rule INDICATOR_SUSPICIOUS_EXE_RegKeyComb_IExecuteCommandCOM {
    meta:
        author = "ditekSHen"
        description = "Detects executables embedding command execution via IExecuteCommand COM object"
    strings:
        $r1 = "Classes\\Folder\\shell\\open\\command" ascii wide nocase
        $k1 = "DelegateExecute" ascii wide
        $s1 = "/EXEFilename \"{0}" ascii wide
        $s2 = "/WindowState \"\"" ascii wide
        $s3 = "/PriorityClass \"\"32\"\" /CommandLine \"" ascii wide
        $s4 = "/StartDirectory \"" ascii wide
        $s5 = "/RunAs" ascii wide
    condition:
        uint16(0) == 0x5a4d and ((1 of ($r*) and 1 of ($k*)) or (all of ($s*)))
}