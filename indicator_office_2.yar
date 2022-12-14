
rule INDICATOR_RTF_LNK_Shell_Explorer_Execution {
    meta:
        description = "detects RTF files with Shell.Explorer.1 OLE objects with embedded LNK files referencing an executable."
        author = "ditekSHen"
    strings:
        // Shell.Explorer.1 OLE Object CLSID
        $clsid = "c32ab2eac130cf11a7eb0000c05bae0b" ascii nocase
        // LNK Shortcut Header
        $lnk_header = "4c00000001140200" ascii nocase
        // Second Stage Artefacts - http/file
        $http_url = "6800740074007000" ascii nocase
        $file_url = "660069006c0065003a" ascii nocase
    condition:
        uint32(0) == 0x74725c7b and filesize < 1500KB and $clsid and $lnk_header and ($http_url or $file_url)
}

rule INDICATOR_RTF_Forms_HTML_Execution {
    meta:
        description = "detects RTF files with Forms.HTML:Image.1 or Forms.HTML:Submitbutton.1 OLE objects referencing file or HTTP URLs."
        author = "ditekSHen"
    strings:
        // Forms.HTML:Image.1 OLE Object CLSID
        $img_clsid = "12d11255c65ccf118d6700aa00bdce1d" ascii nocase
        // Forms.HTML:Submitbutton.1 Object CLSID
        $sub_clsid = "10d11255c65ccf118d6700aa00bdce1d" ascii nocase
        // Second Stage Artefacts - http/file
        $http_url = "6800740074007000" ascii nocase
        $file_url = "660069006c0065003a" ascii nocase
    condition:
        uint32(0) == 0x74725c7b and filesize < 1500KB and ($img_clsid or $sub_clsid) and ($http_url or $file_url)
}

rule INDICATOR_PUB_MSIEXEC_Remote {
    meta:
        description = "detects VB-enable Microsoft Publisher files utilizing Microsoft Installer to retrieve remote files and execute them"
        author = "ditekSHen"
    strings:
        $s1 = "Microsoft Publisher" ascii
        $s2 = "msiexec.exe" ascii
        $s3 = "Document_Open" ascii
        $s4 = "/norestart" ascii
        $s5 = "/i http" ascii
        $s6 = "Wscript.Shell" fullword ascii
        $s7 = "\\VBE6.DLL#" wide
    condition:
        uint16(0) == 0xcfd0 and 6 of them
}

rule INDICATOR_RTF_Ancalog_Exploit_Builder_Document {
    meta:
        description = "Detects documents generated by Phantom Crypter/Ancalog"
        author = "ditekSHen"
        snort2_sid = "910000-910001"
        snort3_sid = "910000"
        clamav_sig = "INDICATOR.RTF.AncalogExploitBuilderDocument"
    strings:
        $builder1 = "{\\*\\ancalog" ascii
        $builder2 = "\\ancalog" ascii
    condition:
        uint32(0) == 0x74725c7b and 1 of ($builder*)
}

rule INDICATOR_RTF_ThreadKit_Exploit_Builder_Document {
    meta:
        description = "Detects vaiations of RTF documents generated by ThreadKit builder."
        author = "ditekSHen"
    strings:
        // Embedded Objects
        $obj1 = "\\objhtml" ascii
        $obj2 = "\\objdata" ascii
        $obj3 = "\\objupdate" ascii
        $obj4 = "\\objemb" ascii
        $obj5 = "\\objautlink" ascii
        $obj6 = "\\objlink" ascii
        $obj7 = "\\mmath" ascii
        // Patterns
        $pat1 = /\\objupdate\\v[\\\s\n\r]/ ascii
    condition:
        uint32(0) == 0x74725c7b and 2 of ($obj*) and 1 of ($pat*)
}

rule INDICATOR_XML_LegacyDrawing_AutoLoad_Document {
    meta:
        description = "detects AutoLoad documents using LegacyDrawing"
        author = "ditekSHen"
    strings:
        $s1 = "<legacyDrawing r:id=\"" ascii
        $s2 = "<oleObject progId=\"" ascii
        $s3 = "autoLoad=\"true\"" ascii
    condition:
        uint32(0) == 0x6d783f3c and all of ($s*)
}

rule INDICATOR_XML_OLE_AutoLoad_Document {
    meta:
        description = "detects AutoLoad documents using OLE Object"
        author = "ditekSHen"
    strings:
        $s1 = "autoLoad=\"true\"" ascii
        $s2 = "/relationships/oleObject\"" ascii
        $s3 = "Target=\"../embeddings/oleObject" ascii
    condition:
        uint32(0) == 0x6d783f3c and all of ($s*)
}

rule INDICATOR_XML_Squiblydoo_1 {
    meta:
        description = "detects Squiblydoo variants extracted from exploit RTF documents."
        author = "ditekSHen"
    strings:
        $slt = "<scriptlet" ascii
        $ws1 = "CreateObject(\"WScript\" & \".Shell\")" ascii
        $ws2 = "CreateObject(\"WScript.Shell\")" ascii
        $ws3 = "ActivexObject(\"WScript.Shell\")" ascii
        $r1 = "[\"run\"]" nocase ascii
        $r2 = ".run \"cmd" nocase ascii
        $r3 = ".run chr(" nocase ascii
    condition:
        (uint32(0) == 0x4d583f3c or uint32(0) == 0x6d783f3c) and $slt and 1 of ($ws*) and 1 of ($r*)
}

rule INDICATOR_OLE_Suspicious_Reverse {
     meta:
        description = "detects OLE documents containing VB scripts with reversed suspicious strings"
        author = "ditekSHen"
    strings:
        // Uses VB
        $vb = "\\VBE7.DLL" ascii
        // Command-line Execution
        $cmd1 = "CMD C:\\" nocase ascii
        $cmd2 = "CMD /c " nocase ascii
        // Suspicious Keywords
        $kw1 = "]rAHC[" nocase ascii
        $kw2 = "ekOVNI" nocase ascii
        $kw3 = "EcaLPEr" nocase ascii
        $kw4 = "TcEJBO-WEn" nocase ascii
        $kw5 = "eLbAirav-Teg" nocase ascii
        $kw6 = "ReveRSE(" nocase ascii
        $kw7 = "-JOIn" nocase ascii
    condition:
        uint16(0) == 0xcfd0 and $vb and ((1 of ($cmd*) and 1 of ($kw*)) or (2 of ($kw*)))
}

rule INDICATOR_OLE_Suspicious_ActiveX {
    meta:
        description = "detects OLE documents with suspicious ActiveX content"
        author = "ditekSHen"
    strings:
        // Uses VB
        $vb = "\\VBE7.DLL" ascii
        // ActiveX Control Objects > Triggers
        $ax1 = "_Layout" ascii
        $ax2 = "MultiPage1_" ascii
        $ax3 = "_MouseMove" ascii
        $ax4 = "_MouseHover" ascii
        $ax5 = "_MouseLeave" ascii
        $ax6 = "_MouseEnter" ascii
        $ax7 = "ImageCombo21_Change" ascii
        $ax8 = "InkEdit1_GotFocus" ascii
        $ax9 = "InkPicture1_" ascii
        $ax10 = "SystemMonitor1_" ascii
        $ax11 = "WebBrowser1_" ascii
        $ax12 = "_Click" ascii
        // Suspicious Keywords
        $kw1 = "CreateObject" ascii
        $kw2 = "CreateTextFile" ascii
        $kw3 = ".SpawnInstance_" ascii
        $kw4 = "WScript.Shell" ascii
        $kw5 = { 43 68 72 [0-2] 41 73 63 [0-2] 4d 69 64 }    // & Chr(Asc(Mid(
        $kw6 = { 43 68 [0-2] 72 24 28 40 24 28 22 26 48 }    // & Chr$(Val("&H"
        $kw7 = { 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 } // ActiveDocument
    condition:
        uint16(0) == 0xcfd0 and $vb and 1 of ($ax*) and 2 of ($kw*)
}

rule INDICATOR_OLE_Suspicious_MITRE_T1117 {
    meta:
        description = "Detects MITRE technique T1117 in OLE documents"
        author = "ditekSHen"
    strings:
        $s1 = "scrobj.dll" ascii nocase
        $s2 = "regsvr32" ascii nocase
        $s3 = "JyZWdzdnIzMi5leGU" ascii
        $s4 = "HNjcm9iai5kbGw" ascii
    condition:
        uint16(0) == 0xcfd0 and 2 of them
}

rule INDICATOR_OLE_RemoteTemplate {
    meta:
        description = "Detects XML relations where an OLE object is refrencing an external target in dropper OOXML documents"
        author = "ditekSHen"
    strings:
        $olerel = "relationships/oleObject" ascii
        $target1 = "Target=\"http" ascii
        $target2 = "Target=\"file" ascii
        $mode = "TargetMode=\"External" ascii
    condition:
        $olerel and $mode and 1 of ($target*)
}

rule INDICATOR_RTF_MalVer_Objects {
    meta:
        description = "Detects RTF documents with non-standard version and embeding one of the object mostly observed in exploit documents."
        author = "ditekSHen"
    strings:
        // Embedded Objects
        $obj1 = "\\objhtml" ascii
        $obj2 = "\\objdata" ascii
        $obj3 = "\\objupdate" ascii
        $obj4 = "\\objemb" ascii
        $obj5 = "\\objautlink" ascii
        $obj6 = "\\objlink" ascii
    condition:
        uint32(0) == 0x74725c7b and ((not uint8(4) == 0x66 or not uint8(5) == 0x31 or not uint8(6) == 0x5c) and 1 of ($obj*))
}

rule INDICATOR_PPT_MasterMana {
    meta:
        description = "Detects known malicious pattern (MasterMana) in PowerPoint documents."
        author = "ditekSHen"
    strings:
        $a1 = "auto_close" ascii nocase
        $a2 = "autoclose" ascii nocase
        $a3 = "auto_open" ascii nocase
        $a4 = "autoopen" ascii nocase
        $vb1 = "\\VBE7.DLL" ascii
        $vb2 = { 41 74 74 72 69 62 75 74 ?? 65 20 56 42 5f 4e 61 6d ?? 65 }
        $clsid = "000204EF-0000-0000-C000-000000000046" wide nocase
        $i1 = "@j.mp/" ascii wide
        $i2 = "j.mp/" ascii wide
        $i3 = "\\pm.j\\\\:" ascii wide
        $i4 = ".zz.ht/" ascii wide
        $i5 = "/pm.j@" ascii wide
        $i6 = "\\pm.j@" ascii wide
    condition:
        uint16(0) == 0xcfd0 and 1 of ($i*) and $clsid and 1 of ($a*) and 1 of ($vb*)
}

rule INDICATOR_XML_WebRelFrame_RemoteTemplate {
    meta:
        description = "Detects XML web frame relations refrencing an external target in dropper OOXML documents"
        author = "ditekSHen"
    strings:
        $target1 = "/frame\" Target=\"http" ascii nocase
        $target2 = "/frame\" Target=\"file" ascii nocase
        $mode = "TargetMode=\"External" ascii
    condition:
        uint32(0) == 0x6d783f3c and (1 of ($target*) and $mode)
}

rule INDICATOR_PDF_IPDropper {
    meta:
        description = "Detects PDF documents with Action and URL pointing to direct IP address"
        author = "ditekSHen"
    strings:
        $s1 = { 54 79 70 65 20 2f 41 63 74 69 6f 6e 0d 0a 2f 53 20 2f 55 52 49 0d 0a }
        $s2 = /\/URI \(http(s)?:\/\/([0-9]{1,3}\.){3}[0-9]{1,3}\// ascii
    condition:
        uint32(0) == 0x46445025 and all of them
}

rule INDICATOR_OLE_Excel4Macros_DL1 {
    meta:
        author = "ditekSHen"
        description = "Detects OLE Excel 4 Macros documents acting as downloaders"
    strings:
        $s1 = "Macros Excel 4.0" fullword ascii
        $s2 = { 00 4d 61 63 72 6f 31 85 00 }
        $s3 = "http" ascii
        $s4 = "file:" ascii
        //$cmd1 = { 00 (43|63) [0-1] (4d|6d) [0-1] (44|64) 20 }
        //$cmd2 = { (50|70) [0-1] (4f|6f) [0-1] (57|77) [0-1] (45|65) [0-1] (52|72) [0-1] (53|73) [0-1] (48|68) [0-1] (45|65) [0-1] (4c|6c) [0-1] (4c|6c) }
        //$cmd3 = { (57|77) [0-1] (53|73) [0-1] (43|63) [0-1] (52|72) [0-1] (49|69) [0-1] (50|70) [0-1] (54|74) }
        $fa_exe = ".exe" ascii nocase
        $fa_scr = ".scr" ascii nocase
        $fa_dll = ".dll" ascii nocase
        $fa_bat = ".bat" ascii nocase
        $fa_cmd = ".cmd" ascii nocase
        $fa_sct = ".sct" ascii nocase
        $fa_txt = ".txt" ascii nocase
        $fa_psw = ".ps1" ascii nocase
        $fa_py = ".py" ascii nocase
        $fa_js = ".js" ascii nocase
    condition:
        uint16(0) == 0xcfd0 and (3 of ($s*) and 1 of ($fa*))
}

rule INDICATOR_OLE_Excel4Macros_DL2 {
    meta:
        author = "ditekSHen"
        description = "Detects OLE Excel 4 Macros documents acting as downloaders"
    strings:
        $e1 = "Macros Excel 4.0" ascii
        $e2 = { 00 4d 61 63 72 6f 31 85 00 }
        $a1 = { 18 00 17 00 20 00 00 01 07 00 00 00 00 00 00 00 00 00 00 01 3a 00 } // auto-open
        $a2 = { 18 00 17 00 aa 03 00 01 07 00 00 00 00 00 00 00 00 00 00 01 3a 00 } // auto-open
        $a3 = { 18 00 21 00 20 00 00 01 12 00 00 00 00 00 00 00 00 00 01 3a ff }    // auto-open
        $a4 = { 18 00 17 00 20 00 00 01 07 00 00 00 00 00 00 00 00 00 00 02 3a 00 } // auto-close
        $a5 = { 18 00 17 00 aa 03 00 01 07 00 00 00 00 00 00 00 00 00 00 02 3a 00 } // auto-clos
        $a6 = "auto_open" ascii nocase
        $a7 = "auto_close" ascii nocase
        $x1 = "* #,##0" ascii
        $x2 = "=EXEC(CHAR(" ascii
        $x3 = "-w 1 stARt`-s" ascii nocase
        $x4 = ")&CHAR(" ascii
        $x5 = "Reverse" fullword ascii
    condition:
        uint16(0) == 0xcfd0 and (1 of ($e*) and 1 of ($a*) and (#x1 > 3 or 2 of ($x*)))
}

rule INDICATOR_RTF_Embedded_Excel_URLDownloadToFile {
    meta:
        author = "ditekSHen"
        description = "Detects RTF documents that embed Excel documents for detection evation."
    strings:
        // Excel
        $clsid1 = "2008020000000000c000000000000046" ascii nocase
        // Embedded Objects
        $obj1 = "\\objhtml" ascii
        $obj2 = "\\objdata" ascii
        $obj3 = "\\objupdate" ascii
        $obj4 = "\\objemb" ascii
        $obj5 = "\\objautlink" ascii
        $obj6 = "\\objlink" ascii
        // OLE Signature
        $ole1 = { d0 cf 11 e0 a1 b1 1a e1 }
        $ole2 = "d0cf11e0a1b11ae1" ascii nocase
        $ole3 = "64306366313165306131623131616531" ascii
        $ole4 = "640a300a630a660a310a310a650a300a610a310a620a310a310a610a650a31"
        $ole5 = { 64 30 63 66 [0-2] 31 31 65 30 61 31 62 31 31 61 65 31 }
        $ole6 = "D0cf11E" ascii nocase
        // Lib
        $s1 = "55524c446f776e6c6f6164546f46696c6541" ascii nocase // URLDownloadToFile
        $s2 = "55524c4d4f4e" ascii nocase                         // UrlMon
    condition:
        uint32(0) == 0x74725c7b and (1 of ($clsid*) and 1 of ($obj*) and 1 of ($ole*) and 1 of ($s*))
}

rule INDICATOR_OLE_Excel4Macros_DL3 {
    meta:
        author = "ditekSHen"
        description = "Detects OLE Excel 4 Macros documents acting as downloaders"
    strings:
        $a1 = { 18 00 17 00 20 00 00 01 07 00 00 00 00 00 00 00 00 00 00 01 3a 00 } // auto-open
        $a2 = { 18 00 17 00 aa 03 00 01 07 00 00 00 00 00 00 00 00 00 00 01 3a 00 } // auto-open
        $a3 = { 18 00 21 00 20 00 00 01 12 00 00 00 00 00 00 00 00 00 01 3a ff }    // auto-open
        $a4 = { 18 00 17 00 20 00 00 01 07 00 00 00 00 00 00 00 00 00 00 02 3a 00 } // auto-close
        $a5 = { 18 00 17 00 aa 03 00 01 07 00 00 00 00 00 00 00 00 00 00 02 3a 00 } // auto-clos
        $a6 = "auto_open" ascii nocase
        $a7 = "auto_close" ascii nocase
        $s1 = "* #,##0" ascii
        $s2 = "URLMon" ascii
        $s3 = "DownloadToFileA" ascii
        $s4 = "DllRegisterServer" ascii
    condition:
        uint16(0) == 0xcfd0 and 1 of ($a*) and all of ($s*) and #s1 > 3
}

rule INDICATOR_DOC_PhishingPatterns {
    meta:
        author = "ditekSHen"
        description = "Detects OLE, RTF, PDF and OOXML (decompressed) documents with common phishing strings"
    strings:
        $s1 = "PERFORM THE FOLLOWING STEPS TO PERFORM DECRYPTION" ascii nocase
        $s2 = "Enable Editing" ascii nocase
        $s3 = "Enable Content" ascii nocase
        $s4 = "WHY I CANNOT OPEN THIS DOCUMENT?" ascii nocase
        $s5 = "You are using iOS or Android, please use Desktop PC" ascii nocase
        $s6 = "You are trying to view this document using Online Viewer" ascii nocase
        $s7 = "This document was edited in a different version of" ascii nocase
        $s8 = "document are locked and will not" ascii nocase
        $s9 = "until the \"Enable\" button is pressed" ascii nocase
        $s10 = "This document created in online version of Microsoft Office" ascii nocase
        $s11 = "This document created in previous version of Microsoft Office" ascii nocase
        $s12 = "This document protected by Microsoft Office" ascii nocase
        $s13 = "This document encrypted by" ascii nocase
        $s14 = "document created in earlier version of microsoft office" ascii nocase
    condition:
        (uint16(0) == 0xcfd0 or uint32(0) == 0x74725c7b or uint32(0) == 0x46445025 or uint32(0) == 0x6d783f3c) and 2 of them
}

rule INDICATOR_OOXML_Excel4Macros_EXEC {
    meta:
        author = "ditekSHen"
        description = "Detects OOXML (decompressed) documents with Excel 4 Macros XLM macrosheet"
        clamav_sig = "INDICATOR.OOXML.Excel4MacrosEXEC"
    strings:
        $ms = "<xm:macrosheet" ascii nocase
        $s1 = ">FORMULA.FILL(" ascii nocase
        $s2 = ">REGISTER(" ascii nocase
        $s3 = ">EXEC(" ascii nocase
        $s4 = ">RUN(" ascii nocase
    condition:
        uint32(0) == 0x6d783f3c and $ms and (2 of ($s*) or ($s3))
}

rule INDICATOR_OOXML_Excel4Macros_AutoOpenHidden {
    meta:
        author = "ditekSHen"
        description = "Detects OOXML (decompressed) documents with Excel 4 Macros XLM macrosheet auto_open and state hidden"
        clamav_sig = "INDICATOR.OOXML.Excel4MacrosEXEC"
    strings:
        $s1 = "state=\"veryhidden\"" ascii nocase
        $s2 = "<definedName name=\"_xlnm.Auto_Open" ascii nocase
    condition:
        uint32(0) == 0x6d783f3c and all of them
}


/*
rule INDICATOR_OLE_CreateObject_Suspicious_Pattern_1 {
    meta:
        author = "ditekSHen"
        description = "Detects OLE with specific waves of pattern"
    strings:
        $action1 = "document_open" ascii nocase
        $s1 = "CreateTextFile" ascii
        $s2 = "CreateObject" ascii
        // is slowing down scanning
        $pattern = /(\[\w{3,4}\]\w{3,4}){50,100}/ ascii
    condition:
        uint16(0) == 0xcfd0 and 1 of ($action*) and 2 of ($s*) and $pattern
}
*/

// Extend this to include other file types
rule INDICATOR_SUSPICOIUS_RTF_EncodedURL {
    meta:
        author = "ditekSHen"
        description = "Detects executables calling ClearMyTracksByProcess"
    strings:
        $s1 = "\\u-65431?\\u-65419?\\u-65419?\\u-65423?\\u-" ascii wide
        $s2 = "\\u-65432?\\u-65420?\\u-65420?\\u-65424?\\u-" ascii wide
        $s3 = "\\u-65433?\\u-65430?\\u-65427?\\u-65434?\\u-" ascii wide
        $s4 = "\\u-65434?\\u-65431?\\u-65428?\\u-65435?\\u-" ascii wide
    condition:
        uint32(0) == 0x74725c7b and any of them
}

rule INDICATOR_RTF_RemoteTemplate {
    meta:
        author = "ditekSHen"
        description = "Detects RTF documents potentially exploiting CVE-2017-11882"
    strings:
        $s1 = "{\\*\\template http" ascii nocase
        $s2 = "{\\*\\template file" ascii nocase
        $s3 = "{\\*\\template \\u-" ascii nocase
    condition:
      uint32(0) == 0x74725c7b and 1 of them
}
