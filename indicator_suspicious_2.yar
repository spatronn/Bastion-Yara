rule INDICATOR_SUSPICIOUS_EXE_References_CryptoWallets {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing many cryptocurrency mining wallets or apps. Observed in information stealers"
    strings:
        $app1 = "Ethereum" nocase ascii wide
        $app2 = "Bitcoin" nocase ascii wide
        $app3 = "Litecoin" nocase ascii wide
        $app4 = "NavCoin4" nocase ascii wide
        $app5 = "ByteCoin" nocase ascii wide
        $app6 = "PotCoin" nocase ascii wide
        $app7 = "Gridcoin" nocase ascii wide
        $app8 = "VERGE" nocase ascii wide
        $app9 = "DogeCoin" nocase ascii wide
        $app10 = "FlashCoin" nocase ascii wide
        $app11 = "Sia" nocase ascii wide
        $app12 = "Reddcoin" nocase ascii wide
        $app13 = "Electrum" nocase ascii wide
        $app14 = "Emercoin" nocase ascii wide
        $app15 = "Exodus" nocase ascii wide
        $app16 = "BBQCoin" nocase ascii wide
        $app17 = "Franko" nocase ascii wide
        $app18 = "IOCoin" nocase ascii wide
        $app19 = "Ixcoin" nocase ascii wide
        $app20 = "Mincoin" nocase ascii wide
        $app21 = "YACoin" nocase ascii wide
        $app22 = "Zcash" nocase ascii wide
        $app23 = "devcoin" nocase ascii wide
        $app24 = "Dash" nocase ascii wide
        $app25 = "Monero" nocase ascii wide
        $app26 = "Riot Games\\" nocase ascii wide
        $app27 = "qBittorrent\\" nocase ascii wide
        $app28 = "Battle.net\\" nocase ascii wide
        $app29 = "Steam\\" nocase ascii wide
        $app30 = "Valve\\Steam\\" nocase ascii wide
        $app31 = "Anoncoin" nocase ascii wide
        $app32 = "DashCore" nocase ascii wide
        $app33 = "DevCoin" nocase ascii wide
        $app34 = "DigitalCoin" nocase ascii wide
        $app35 = "Electron" nocase ascii wide
        $app36 = "ElectrumLTC" nocase ascii wide
        $app37 = "FlorinCoin" nocase ascii wide
        $app38 = "FrancoCoin" nocase ascii wide
        $app39 = "JAXX" nocase ascii wide
        $app40 = "MultiDoge" ascii wide
        $app41 = "TerraCoin" ascii wide
        $app42 = "Electrum-LTC" ascii wide
        $app43 = "ElectrumG" ascii wide
        $app44 = "Electrum-btcp" ascii wide
        $app45 = "MultiBitHD" ascii wide
        $app46 = "monero-project" ascii wide
        $app47 = "Bitcoin-Qt" ascii wide
        $app48 = "BitcoinGold-Qt" ascii wide
        $app49 = "Litecoin-Qt" ascii wide
        $app50 = "BitcoinABC-Qt" ascii wide
        $app51 = "Exodus Eden" ascii wide
        $app52 = "myether" ascii wide
        $app53 = "factores-Binance" ascii wide
        $app54 = "metamask" ascii wide
        $app55 = "kucoin" ascii wide
        $app56 = "cryptopia" ascii wide
        $app57 = "binance" ascii wide
        $app58 = "hitbtc" ascii wide
        $app59 = "litebit" ascii wide
        $app60 = "coinEx" ascii wide
        $app61 = "blockchain" ascii wide
        $app62 = "\\Armory" ascii wide
        $app63 = "\\Atomic" ascii wide
        $app64 = "\\Bytecoin" ascii wide
        $app65 = "simpleos" ascii wide
        $app66 = "WalletWasabi" ascii wide
        $app67 = "atomic\\" ascii wide
        $app68 = "Guarda\\" ascii wide
        $app69 = "Neon\\" ascii wide
        $app70 = "Blockstream\\" ascii wide
        $app71 = "GreenAddress Wallet\\" ascii wide
        $app72 = "bitpay\\" ascii wide

        $ne1 = "C:\\src\\pgriffais_incubator-w7\\Steam\\main\\src\\external\\libjingle-0.4.0\\talk/base/scoped_ptr.h" fullword wide
        $ne2 = "\"%s\\bin\\%slauncher.exe\" -hproc %x -hthread %x -baseoverlayname %s\\%s" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (not any of ($ne*) and 6 of them)
}

rule INDICATOR_SUSPICIOUS_ClearWinLogs {
    meta:
        author = "ditekSHen"
        description = "Detects executables containing commands for clearing Windows Event Logs"
    strings:
        $cmd1 = "wevtutil.exe clear-log" ascii wide nocase
        $cmd2 = "wevtutil.exe cl " ascii wide nocase
        $cmd3 = ".ClearEventLog()" ascii wide nocase
        $cmd4 = "Foreach-Object {wevtutil cl \"$_\"}" ascii wide nocase
        $cmd5 = "('wevtutil.exe el') DO (call :do_clear" ascii wide nocase
        $cmd6 = "| ForEach { Clear-EventLog $_.Log }" ascii wide nocase
        $cmd7 = "('wevtutil.exe el') DO wevtutil.exe cl \"%s\"" ascii wide nocase
        $cmd8 = "Clear-EventLog -LogName application, system, security" ascii wide nocase
        $t1 = "wevtutil" ascii wide nocase
        $l1 = "cl Application" ascii wide nocase
        $l2 = "cl System" ascii wide nocase
        $l3 = "cl Setup" ascii wide nocase
        $l4 = "cl Security" ascii wide nocase
        $l5 = "sl Security /e:false" ascii wide nocase
        $ne1 = "wevtutil.exe cl Aplicaci" fullword wide
        $ne2 = "wevtutil.exe cl Application /bu:C:\\admin\\backup\\al0306.evtx" fullword wide
        $ne3 = "wevtutil.exe cl Application /bu:C:\\admin\\backups\\al0306.evtx" fullword wide
    condition:
        uint16(0) == 0x5a4d and not any of ($ne*) and ((1 of ($cmd*)) or (1 of ($t*) and 3 of ($l*)))
}

rule INDICATOR_SUSPICIOUS_DisableWinDefender {
    meta:
        author = "ditekSHen"
        description = "Detects executables containing artifcats associated with disabling Widnows Defender"
    strings:
        $reg1 = "SOFTWARE\\Microsoft\\Windows Defender\\Features" ascii wide nocase
        $reg2 = "SOFTWARE\\Policies\\Microsoft\\Windows Defender" ascii wide nocase
        $s1 = "Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true" ascii wide nocase
        $s2 = "Set-MpPreference -DisableArchiveScanning $true" ascii wide nocase
        $s3 = "Set-MpPreference -DisableIntrusionPreventionSystem $true" ascii wide nocase
        $s4 = "Set-MpPreference -DisableScriptScanning $true" ascii wide nocase
        $s5 = "Set-MpPreference -SubmitSamplesConsent 2" ascii wide nocase
        $s6 = "Set-MpPreference -MAPSReporting 0" ascii wide nocase
        $s7 = "Set-MpPreference -HighThreatDefaultAction 6" ascii wide nocase
        $s8 = "Set-MpPreference -ModerateThreatDefaultAction 6" ascii wide nocase
        $s9 = "Set-MpPreference -LowThreatDefaultAction 6" ascii wide nocase
        $s10 = "Set-MpPreference -SevereThreatDefaultAction 6" ascii wide nocase
        $s11 = "Set-MpPreference -EnableControlledFolderAccess Disabled" ascii wide nocase
        $pdb = "\\Disable-Windows-Defender\\obj\\Debug\\Disable-Windows-Defender.pdb" ascii
        $e1 = "Microsoft\\Windows Defender\\Exclusions\\Paths" ascii wide nocase
        $e2 = "Add-MpPreference -Exclusion" ascii wide nocase
        $c1 = "QQBkAGQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgAC0ARQB4AGMAbAB1AHMAaQBvAG4" ascii wide
    condition:
        uint16(0) == 0x5a4d and ((1 of ($reg*) and 1 of ($s*)) or ($pdb) or all of ($e*) or #c1 > 1)
}

rule INDICATOR_SUSPICIOUS_USNDeleteJournal {
    meta:
        author = "ditekSHen"
        description = "Detects executables containing anti-forensic artifcats of deletiing USN change journal. Observed in ransomware"
    strings:
        $cmd1 = "fsutil.exe" ascii wide nocase
        $s1 = "usn deletejournal /D C:" ascii wide nocase
        $s2 = "fsutil.exe usn deletejournal" ascii wide nocase
        $s3 = "fsutil usn deletejournal" ascii wide nocase
        $s4 = "fsutil file setZeroData offset=0" ascii wide nocase
        $ne1 = "fsutil usn readdata C:\\Temp\\sample.txt" wide
        $ne2 = "fsutil transaction query {0f2d8905-6153-449a-8e03-7d3a38187ba1}" wide
        $ne3 = "fsutil resource start d:\\foobar d:\\foobar\\LogDir\\LogBLF::TxfLog d:\\foobar\\LogDir\\LogBLF::TmLog" wide
        $ne4 = "fsutil objectid query C:\\Temp\\sample.txt" wide
    condition:
        uint16(0) == 0x5a4d and (not any of ($ne*) and ((1 of ($cmd*) and 1 of ($s*)) or 1 of ($s*)))
}

rule INDICATOR_SUSPICIOUS_GENInfoStealer {
    meta:
        author = "ditekSHen"
        description = "Detects executables containing common artifcats observed in infostealers"
    strings:
        $f1 = "FileZilla\\recentservers.xml" ascii wide
        $f2 = "FileZilla\\sitemanager.xml" ascii wide
        $f3 = "SOFTWARE\\\\Martin Prikryl\\\\WinSCP 2\\\\Sessions" ascii wide
        $b1 = "Chrome\\User Data\\" ascii wide
        $b2 = "Mozilla\\Firefox\\Profiles" ascii wide
        $b3 = "Software\\Microsoft\\Internet Explorer\\IntelliForms\\Storage2" ascii wide
        $b4 = "Opera Software\\Opera Stable\\Login Data" ascii wide
        $b5 = "YandexBrowser\\User Data\\" ascii wide
        $s1 = "key3.db" nocase ascii wide
        $s2 = "key4.db" nocase ascii wide
        $s3 = "cert8.db" nocase ascii wide
        $s4 = "logins.json" nocase ascii wide
        $s5 = "account.cfn" nocase ascii wide
        $s6 = "wand.dat" nocase ascii wide
        $s7 = "wallet.dat" nocase ascii wide
        $a1 = "username_value" ascii wide
        $a2 = "password_value" ascii wide
        $a3 = "encryptedUsername" ascii wide
        $a4 = "encryptedPassword" ascii wide
        $a5 = "httpRealm" ascii wide
    condition:
        uint16(0) == 0x5a4d and ((2 of ($f*) and 2 of ($b*) and 1 of ($s*) and 3 of ($a*)) or (14 of them))
}

rule INDICATOR_SUSPICIOUS_NTLM_Exfiltration_IPPattern {
    meta:
        author = "ditekSHen"
        description = "Detects NTLM hashes exfiltration patterns in command line and various file types"
    strings:
        // Example (CMD): net use \\1.2.3.4@80\t
        $s1 = /net\suse\s\\\\([0-9]{1,3}\.){3}[0-9]{1,3}@(80|443|445)/ ascii wide
        // Example (PDF): /F (\\\\IP@80\\t)
        $s2 = /\/F\s\(\\\\\\\\([0-9]{1,3}\.){3}[0-9]{1,3}@(80|443|445)/ ascii wide
        // Example (LNK): URL=file://IP@80/t.htm
        $s3 = /URL=file:\/\/([0-9]{1,3}\.){3}[0-9]{1,3}@(80|443|445)/ ascii wide
        // Example (ICO): IconFile=\\IP@80\t.ico
        $s4 = /IconFile=\\\\([0-9]{1,3}\.){3}[0-9]{1,3}@(80|443|445)/ ascii wide
        // Example (DOC, DOCX): Target="file://IP@80/t.dotx"
        $s5 = /Target=\x22:\/\/([0-9]{1,3}\.){3}[0-9]{1,3}@(80|443|445)/ ascii wide
        // Example (Subdoc ??): ///IP@80/t
        $s6 = /\/\/\/([0-9]{1,3}\.){3}[0-9]{1,3}@(80|443|445)/ ascii wide
        // Example (over SSL) - DavWWWRoot keyword actually triggers WebDAV forcibly
        $s7 = /\\\\([0-9]{1,3}\.){3}[0-9]{1,3}@SSL@\d+\\DavWWWRoot/ ascii wide

        // OOXML in addtion to PK magic
        $mso1 = "word/" ascii
        $mso2 = "ppt/" ascii
        $mso3 = "xl/" ascii
        $mso4 = "[Content_Types].xml" ascii
    condition:
        ((uint32(0) == 0x46445025 or (uint16(0) == 0x004c and uint32(4) == 0x00021401) or uint32(0) == 0x00010000 or (uint16(0) == 0x4b50 and 1 of ($mso*))) and 1 of ($s*)) or 1 of ($s*)
}

rule INDICATOR_SUSPICIOUS_PWSH_B64Encoded_Concatenated_FileEXEC {
    meta:
        author = "ditekSHen"
        description = "Detects PowerShell scripts containing patterns of base64 encoded files, concatenation and execution"
    strings:
        $b1 = "::WriteAllBytes(" ascii
        $b2 = "::FromBase64String(" ascii
        $b3 = "::UTF8.GetString(" ascii

        $s1 = "-join" nocase ascii
        $s2 = "[Char]$_"
        $s3 = "reverse" nocase ascii
        $s4 = " += " ascii

        $e1 = "System.Diagnostics.Process" ascii
        $e2 = /StartInfo\.(Filename|UseShellExecute)/ ascii
        $e3 = /-eq\s'\.(exe|dll)'\)/ ascii
        $e4 = /(Get|Start)-(Process|WmiObject)/ ascii
    condition:
        #s4 > 10 and ((3 of ($b*)) or (1 of ($b*) and 2 of ($s*) and 1 of ($e*)) or (8 of them))
}

rule INDICATOR_SUSPICIOUS_PWSH_AsciiEncoding_Pattern {
    meta:
        author = "ditekSHen"
        description = "Detects PowerShell scripts containing ASCII encoded files"
    strings:
        $enc1 = "[char[]]([char]97..[char]122)" ascii
        $enc2 = "[char[]]([char]65..[char]90)" ascii
        $s1 = ".DownloadData($" ascii
        $s2 = "[Net.SecurityProtocolType]::TLS12" ascii
        $s3 = "::WriteAllBytes($" ascii
        $s4 = "::FromBase64String($" ascii
        $s5 = "Get-Random" ascii
    condition:
        1 of ($enc*) and 4 of ($s*) and filesize < 2500KB
}

rule INDICATOR_SUSPICIOUS_JS_Hex_B64Encoded_EXE {
    meta:
        author = "ditekSHen"
        description = "Detects JavaScript files hex and base64 encoded executables"
    strings:
        $s1 = ".SaveToFile" ascii
        $s2 = ".Run" ascii
        $s3 = "ActiveXObject" ascii
        $s4 = "fromCharCode" ascii
        $s5 = "\\x66\\x72\\x6F\\x6D\\x43\\x68\\x61\\x72\\x43\\x6F\\x64\\x65" ascii
        $binary = "\\x54\\x56\\x71\\x51\\x41\\x41" ascii
        $pattern = /[\s\{\(\[=]_0x[0-9a-z]{3,6}/ ascii
    condition:
        $binary and $pattern and 2 of ($s*) and filesize < 2500KB
}

rule INDICATOR_SUSPICIOUS_JS_LocalPersistence {
    meta:
        author = "ditekSHen"
        description = "Detects JavaScript files used for persistence and executable or script execution"
    strings:
        $s1 = "ActiveXObject" ascii
        $s2 = "Shell.Application" ascii
        $s3 = "ShellExecute" ascii

        $ext1 = ".exe" ascii
        $ext2 = ".ps1" ascii
        $ext3 = ".lnk" ascii
        $ext4 = ".hta" ascii
        $ext5 = ".dll" ascii
        $ext6 = ".vb" ascii
        $ext7 = ".com" ascii
        $ext8 = ".js" ascii

        $action = "\"Open\"" ascii
    condition:
       $action and 2 of ($s*) and 1 of ($ext*) and filesize < 500KB
}

rule INDICATOR_SUSPICIOUS_WMIC_Downloader {
    meta:
        author = "ditekSHen"
        description = "Detects files utilizing WMIC for whitelisting bypass and downloading second stage payloads"
    strings:
        $s1 = "WMIC.exe os get /format:\"http" wide
        $s2 = "WMIC.exe computersystem get /format:\"http" wide
        $s3 = "WMIC.exe dcomapp get /format:\"http" wide
        $s4 = "WMIC.exe desktop get /format:\"http" wide
    condition:
        (uint16(0) == 0x004c or uint16(0) == 0x5a4d) and 1 of them
}

rule INDICATOR_SUSPICIOUS_AMSI_Bypass {
    meta:
        author = "ditekSHen"
        description = "Detects AMSI bypass pattern"
    strings:
        $v1_1 = "[Ref].Assembly.GetType(" ascii nocase
        $v1_2 = "System.Management.Automation.AmsiUtils" ascii
        $v1_3 = "GetField(" ascii nocase
        $v1_4 = "amsiInitFailed" ascii
        $v1_5 = "NonPublic,Static" ascii
        $v1_6 = "SetValue(" ascii nocase
    condition:
        5 of them and filesize < 2000KB
}

rule INDICATOR_SUSPICIOUS_EXE_PE_ResourceTuner {
    meta:
        author = "ditekSHen"
        description = "Detects executables with modified PE resources using the unpaid version of Resource Tuner"
    strings:
        $s1 = "Modified by an unpaid evaluation copy of Resource Tuner 2 (www.heaventools.com)" fullword wide
    condition:
        uint16(0) == 0x5a4d and all of them 
}

rule INDICATOR_SUSPICIOUS_EXE_ASEP_REG_Reverse {
    meta:
        author = "ditekSHen"
        description = "Detects file containing reversed ASEP Autorun registry keys"
    strings:
        $s1 = "nuR\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s2 = "ecnOnuR\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s3 = "secivreSnuR\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s4 = "xEecnOnuR\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s5 = "ecnOsecivreSnuR\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s6 = "yfitoN\\nogolniW\\noisreVtnerruC\\TN swodniW\\tfosorciM" ascii wide nocase
        $s7 = "tiniresU\\nogolniW\\noisreVtnerruC\\TN swodniW\\tfosorciM" ascii wide nocase
        $s8 = "nuR\\rerolpxE\\seiciloP\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s9 = "stnenopmoC dellatsnI\\puteS evitcA\\tfosorciM" ascii wide nocase
        $s10 = "sLLD_tinIppA\\swodniW\\noisreVtnerruC\\TN swodniW\\tfosorciM" ascii wide nocase
        $s11 = "snoitpO noitucexE eliF egamI\\noisreVtnerruC\\TN swodniW\\tfosorciM" ascii wide nocase
        $s12 = "llehS\\nogolniW\\noisreVtnerruC\\TN swodniW\\tfosorciM" ascii wide nocase
        $s13 = "daol\\swodniW\\noisreVtnerruC\\TN swodniW\\tfosorciM" ascii wide nocase
        $s14 = "daoLyaleDtcejbOecivreSllehS\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s15 = "nuRotuA\\rossecorP\\dnammoC\\tfosorciM" ascii wide nocase
        $s16 = "putratS\\sredloF llehS resU\\rerolpxE\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s17 = "sllDtreCppA\\reganaM noisseS\\lortnoC\\teSlortnoCtnerruC\\metsyS" ascii wide nocase
        $s18 = "sllDtreCppA\\reganaM noisseS\\lortnoC\\100teSlortnoC\\metsyS" ascii wide nocase
        $s19 = ")tluafeD(\\dnammoC\\nepO\\llehS\\elifexE\\sessalC\\erawtfoS" ascii wide nocase
        $s20 = ")tluafeD(\\dnammoC\\nepO\\llehS\\elifexE\\sessalC\\edoN2346woW\\erawtfoS" ascii wide nocase
    condition:
        1 of them and filesize < 2000KB
}

rule INDICATOR_SUSPICIOUS_EXE_SQLQuery_ConfidentialDataStore {
    meta:
        author = "ditekSHen"
        description = "Detects executables containing SQL queries to confidential data stores. Observed in infostealers"
    strings:
        $select = "select " ascii wide nocase
        $table1 = " from credit_cards" ascii wide nocase
        $table2 = " from logins" ascii wide nocase
        $table3 = " from cookies" ascii wide nocase
        $table4 = " from moz_cookies" ascii wide nocase
        $table5 = " from moz_formhistory" ascii wide nocase
        $table6 = " from moz_logins" ascii wide nocase
        $column1 = "name" ascii wide nocase
        $column2 = "password_value" ascii wide nocase
        $column3 = "encrypted_value" ascii wide nocase
        $column4 = "card_number_encrypted" ascii wide nocase
        $column5 = "isHttpOnly" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and 2 of ($table*) and 2 of ($column*) and $select
}

rule INDICATOR_SUSPICIOUS_References_SecTools {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing many IR and analysis tools"
    strings:
        $s1 = "procexp.exe" nocase ascii wide
        $s2 = "perfmon.exe" nocase ascii wide
        $s3 = "autoruns.exe" nocase ascii wide
        $s4 = "autorunsc.exe" nocase ascii wide
        $s5 = "ProcessHacker.exe" nocase ascii wide
        $s6 = "procmon.exe" nocase ascii wide
        $s7 = "sysmon.exe" nocase ascii wide
        $s8 = "procdump.exe" nocase ascii wide
        $s9 = "apispy.exe" nocase ascii wide
        $s10 = "dumpcap.exe" nocase ascii wide
        $s11 = "emul.exe" nocase ascii wide
        $s12 = "fortitracer.exe" nocase ascii wide
        $s13 = "hookanaapp.exe" nocase ascii wide
        $s14 = "hookexplorer.exe" nocase ascii wide
        $s15 = "idag.exe" nocase ascii wide
        $s16 = "idaq.exe" nocase ascii wide
        $s17 = "importrec.exe" nocase ascii wide
        $s18 = "imul.exe" nocase ascii wide
        $s19 = "joeboxcontrol.exe" nocase ascii wide
        $s20 = "joeboxserver.exe" nocase ascii wide
        $s21 = "multi_pot.exe" nocase ascii wide
        $s22 = "ollydbg.exe" nocase ascii wide
        $s23 = "peid.exe" nocase ascii wide
        $s24 = "petools.exe" nocase ascii wide
        $s25 = "proc_analyzer.exe" nocase ascii wide
        $s26 = "regmon.exe" nocase ascii wide
        $s27 = "scktool.exe" nocase ascii wide
        $s28 = "sniff_hit.exe" nocase ascii wide
        $s29 = "sysanalyzer.exe" nocase ascii wide
        $s30 = "CaptureProcessMonitor.sys" nocase ascii wide
        $s31 = "CaptureRegistryMonitor.sys" nocase ascii wide
        $s32 = "CaptureFileMonitor.sys" nocase ascii wide
        $s33 = "Control.exe" nocase ascii wide
        $s34 = "rshell.exe" nocase ascii wide
        $s35 = "smc.exe" nocase ascii wide
    condition:
         uint16(0) == 0x5a4d and 4 of them
}

rule INDICATOR_SUSPICIOUS_References_SecTools_B64Encoded {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing many base64-encoded IR and analysis tools names"
    strings:
        $s1 = "VGFza21ncg==" ascii wide  // Taskmgr
        $s2 = "dGFza21ncg==" ascii wide  // taskmgr
        $s3 = "UHJvY2Vzc0hhY2tlcg" ascii wide // ProcessHacker
        $s4 = "cHJvY2V4cA" ascii wide  // procexp
        $s5 = "cHJvY2V4cDY0" ascii wide  // procexp64
        $s6 = "aHR0cCBhbmFseXplci" ascii wide // http analyzer
        $s7 = "ZmlkZGxlcg" ascii wide // fiddler
        $s8 = "ZWZmZXRlY2ggaHR0cCBzbmlmZmVy" ascii wide // effetech http sniffer
        $s9 = "ZmlyZXNoZWVw" ascii wide // firesheep
        $s10 = "SUVXYXRjaCBQcm9mZXNzaW9uYWw" ascii wide // IEWatch Professional
        $s11 = "ZHVtcGNhcA" ascii wide // dumpcap
        $s12 = "d2lyZXNoYXJr" ascii wide //wireshark
        $s13 = "c3lzaW50ZXJuYWxzIHRjcHZpZXc" ascii wide // sysinternals tcpview
        $s14 = "TmV0d29ya01pbmVy" ascii wide // NetworkMiner
        $s15 = "TmV0d29ya1RyYWZmaWNWaWV3" ascii wide // NetworkTrafficView
        $s16 = "SFRUUE5ldHdvcmtTbmlmZmVy" ascii wide // HTTPNetworkSniffer
        $s17 = "dGNwZHVtcA" ascii wide // tcpdump
        $s18 = "aW50ZXJjZXB0ZXI" ascii wide // intercepter
        $s19 = "SW50ZXJjZXB0ZXItTkc" ascii wide // Intercepter-NG
        $s20 = "b2xseWRiZw" ascii wide // ollydbg
        $s21 = "eDY0ZGJn" ascii wide // x64dbg
        $s22 = "eDMyZGJn" ascii wide // x32dbg
        $s23 = "ZG5zcHk" ascii wide // dnspy
        $s24 = "ZGU0ZG90" ascii wide // de4dot
        $s25 = "aWxzcHk" ascii wide // ilspy
        $s26 = "ZG90cGVla" ascii wide // dotpeek
        $s27 = "aWRhNjQ" ascii wide // ida64
        $s28 = "UkRHIFBhY2tlciBEZXRlY3Rvcg" ascii wide // RDG Packer Detector
        $s29 = "Q0ZGIEV4cGxvcmVy" ascii wide // CFF Explorer
        $s30 = "UEVpRA" ascii wide // PEiD
        $s31 = "cHJvdGVjdGlvbl9pZA" ascii wide // protection_id
        $s32 = "TG9yZFBF" ascii wide // LordPE
        $s33 = "cGUtc2lldmU=" ascii wide // pe-sieve
        $s34 = "TWVnYUR1bXBlcg" ascii wide // MegaDumper
        $s35 = "VW5Db25mdXNlckV4" ascii wide // UnConfuserEx
        $s36 = "VW5pdmVyc2FsX0ZpeGVy" ascii wide // Universal_Fixer
        $s37 = "Tm9GdXNlckV4" ascii wide // NoFuserEx
    condition:
         uint16(0) == 0x5a4d and 4 of them
}

rule INDICATOR_SUSPICIOUS_References_Sandbox_Artifacts {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing sandbox artifacts"
    strings:
        $s1 = "C:\\agent\\agent.pyw" ascii wide
        $s2 = "C:\\sandbox\\starter.exe" ascii wide
        $s3 = "c:\\ipf\\BDCore_U.dll" ascii wide
        $s4 = "C:\\cwsandbox_manager" ascii wide
        $s5 = "C:\\cwsandbox" ascii wide
        $s6 = "C:\\Stuff\\odbg110" ascii wide
        $s7 = "C:\\gfisandbox" ascii wide
        $s8 = "C:\\Virus Analysis" ascii wide
        $s9 = "C:\\iDEFENSE\\SysAnalyzer" ascii wide
        $s10 = "c:\\gnu\\bin" ascii wide
        $s11 = "C:\\SandCastle\\tools" ascii wide
        $s12 = "C:\\cuckoo\\dll" ascii wide
        $s13 = "C:\\MDS\\WinDump.exe" ascii wide
        $s14 = "C:\\tsl\\Raptorclient.exe" ascii wide
        $s15 = "C:\\guest_tools\\start.bat" ascii wide
        $s16 = "C:\\tools\\aswsnx\\snxcmd.exe" ascii wide
        $s17 = "C:\\Winap\\ckmon.pyw" ascii wide
        $s18 = "c:\\tools\\decodezeus" ascii wide
        $s19 = "c:\\tools\\aswsnx" ascii wide
        $s20 = "C:\\sandbox\\starter.exe" ascii wide
        $s21 = "C:\\Kit\\procexp.exe" ascii wide
        $s22 = "c:\\tracer\\mdare32_0.sys" ascii wide
        $s23 = "C:\\tool\\malmon" ascii wide
        $s24 = "C:\\Samples\\102114\\Completed" ascii wide
        $s25 = "c:\\vmremote\\VmRemoteGuest.exe" ascii wide
        $s26 = "d:\\sandbox_svc.exe" ascii wide
    condition:
        uint16(0) == 0x5a4d and 3 of them
}

rule INDICATOR_SUSPICIOUS_EXE_Embedded_Gzip_B64Encoded_File {
     meta:
        author = "ditekSHen"
        description = "Detects executables containing bas64 encoded gzip files"
    strings:
        $s1 = "H4sIAAAAAAA" ascii wide
        $s2 = "AAAAAAAIs4H" ascii wide
    condition:
        uint16(0) == 0x5a4d and 1 of them
}