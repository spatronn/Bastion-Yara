rule INDICATOR_RTF_EXPLOIT_CVE_2017_0199_1 {
    meta:
        description = "Detects RTF documents potentially exploiting CVE-2017-0199"
        author = "ditekSHen"
    strings:
        // URL Moniker
        /* Reduce FPs
        $urlmoniker1 = "e0c9ea79f9bace118c8200aa004ba90b" ascii nocase
        $urlmoniker2 = { 45 30 43 39 45 41 37 39 46 39 42 41 43 45 31 31
                         38 43 38 32 30 30 41 41 30 30 34 42 41 39 30 42 } // HEX + lower-case
        */
        $urlmoniker3 = { 45 0a 30 0a 43 0a 39 0a 45 0a 41 0a 37 0a 39 0a 
                         46 0a 39 0a 42 0a 41 0a 43 0a 45 0a 31 0a 31 0a 
                         38 0a 43 0a 38 0a 32 0a 30 0a 30 0a 41 0a 41 0a 
                         30 0a 30 0a 34 0a 42 0a 41 0a 39 0a 30 0a 42 }    // HEX + lower-case + \x0a manipulation
        $urlmoniker4 = { 45 0d 0a 30 0d 0a 43 0d 0a 39 0d 0a 45 0d 0a 41
                         0d 0a 37 0d 0a 39 0d 0a 46 0d 0a 39 0d 0a 42 0d 
                         0a 41 0d 0a 43 0d 0a 45 0d 0a 31 0d 0a 31 0d 0a
                         38 0d 0a 43 0d 0a 38 0d 0a 32 0d 0a 30 0d 0a 30
                         0d 0a 41 0d 0a 41 0d 0a 30 0d 0a 30 0d 0a 34 0d
                         0a 42 0d 0a 41 0d 0a 39 0d 0a 30 0d 0a 42 }       // HEX + lower-case + \x0d0a manipulation
        /* Reduce FPs
        $urlmoniker5 = { 65 30 63 39 65 61 37 39 66 39 62 61 63 65 31 31
                         38 63 38 32 30 30 61 61 30 30 34 62 61 39 30 62 } // HEX + upper-case
        */
        $urlmoniker6 = { 65 0a 30 0a 63 0a 39 0a 65 0a 61 0a 37 0a 39 0a
                         66 0a 39 0a 62 0a 61 0a 63 0a 65 0a 31 0a 31 0a
                         38 0a 63 0a 38 0a 32 0a 30 0a 30 0a 61 0a 61 0a
                         30 0a 30 0a 34 0a 62 0a 61 0a 39 0a 30 0a 62 }    // HEX + upper-case + \x0a manipulation
        $urlmoniker7 = { 65 0d 0a 30 0d 0a 63 0d 0a 39 0d 0a 65 0d 0a 61
                         0d 0a 37 0d 0a 39 0d 0a 66 0d 0a 39 0d 0a 62 0d
                         0a 61 0d 0a 63 0d 0a 65 0d 0a 31 0d 0a 31 0d 0a
                         38 0d 0a 63 0d 0a 38 0d 0a 32 0d 0a 30 0d 0a 30
                         0d 0a 61 0d 0a 61 0d 0a 30 0d 0a 30 0d 0a 34 0d
                         0a 62 0d 0a 61 0d 0a 39 0d 0a 30 0d 0a 62 }       // HEX + upper-case + \x0d0a manipulation 
        /* is slowing down scanning
        $urlmoniker2 = { 45 [0-2] 30 [0-2] 43 [0-2] 39 [0-2] 45 [0-2] 41 [0-2] 37 [0-2]
                         39 [0-2] 46 [0-2] 39 [0-2] 42 [0-2] 41 [0-2] 43 [0-2] 45 [0-2]
                         31 [0-2] 31 [0-2] 38 [0-2] 43 [0-2] 38 [0-2] 32 [0-2] 30 [0-2]
                         30 [0-2] 41 [0-2] 41 [0-2] 30 [0-2] 30 [0-2] 34 [0-2] 42 [0-2]
                         41 [0-2] 39 [0-2] 30 [0-2] 42 }
        $urlmoniker2 = { 45 [0-2] 30 [0-2] 43 [0-2] 39 [0-2] 45 [0-2] 41 [0-2] 37 [0-2]
                         39 [0-2] 46 [0-2] 39 [0-2] 42 [0-2] 41 [0-2] 43 [0-2] 45 [0-2]
                         31 [0-2] 31 [0-2] 38 [0-2] 43 [0-2] 38 [0-2] 32 [0-2] 30 [0-2]
                         30 [0-2] 41 [0-2] 41 [0-2] 30 [0-2] 30 [0-2] 34 [0-2] 42 [0-2]
                         41 [0-2] 39 [0-2] 30 [0-2] 42 }
        $urlmoniker3 = { 65 [0-2] 30 [0-2] 63 [0-2] 39 [0-2] 65 [0-2] 61 [0-2] 37 [0-2]
                         39 [0-2] 66 [0-2] 39 [0-2] 62 [0-2] 61 [0-2] 63 [0-2] 65 [0-2]
                         31 [0-2] 31 [0-2] 38 [0-2] 63 [0-2] 38 [0-2] 32 [0-2] 30 [0-2]
                         30 [0-2] 61 [0-2] 61 [0-2] 30 [0-2] 30 [0-2] 34 [0-2] 62 [0-2]
                         61 [0-2] 39 [0-2] 30 [0-2] 62 }
        */
        // OLE Signature
        $ole1 = { d0 cf 11 e0 a1 b1 1a e1 }
        $ole2 = "d0cf11e0a1b11ae1" ascii nocase
        $ole3 = "64306366313165306131623131616531" ascii // HEX
        $ole4 = "640a300a630a660a310a310a650a300a610a310a620a310a310a610a650a31" ascii nocase // HEX manipulated
        $ole5 = { 64 0a 30 0a 63 0a 66 0a 31 0a 31 0a 65 0a 30 }
        $ole6 = { 64 0d 0a 30 0d 0a 63 0d 0a 66 0d 0a 31 0d 0a 31 0d 0a 65 0d 0a 30 }
        // Embedded Objects
        $obj1 = "\\objhtml" ascii
        $obj2 = "\\objdata" ascii
        $obj3 = "\\objupdate" ascii
        $obj4 = "\\objemb" ascii
        $obj5 = "\\objautlink" ascii
        $obj6 = "\\objlink" ascii
    condition:
        uint32(0) == 0x74725c7b and 1 of ($urlmoniker*) and 1 of ($ole*) and 1 of ($obj*)
}

rule INDICATOR_RTF_EXPLOIT_CVE_2017_11882_1 {
    meta:
        description = "Detects RTF documents potentially exploiting CVE-2017-11882"
        author = "ditekSHen"
    strings:
        // 0002CE02-0000-0000-C000-000000000046: Equation
        // CVE-2017-11882 or CVE-2018-0802
        $s1 = "02ce020000000000c000000000000046" ascii nocase
        // Root Entry
        $s2 = "52006f006f007400200045006e00740072007900" ascii nocase
        // OLE Signature
        $ole1 = "d0cf11e0a1b11ae1" ascii nocase
        $olex = { (64|44)[0-1]30[0-1](63|43)[0-1](66|46)[0-1]31[0-1]31[0-1](65|45)[0-1]30[0-1](61|41)[0-1]31[0-1](62|42)[0-1]31[0-1]31[0-1](61|41) }
        //$ole2 = { 6430 [0-1] 6366 [0-1] 3131 [0-1] 6530 [0-1] 6131 [0-1] 6231 [0-1] 3161 }
        //$ole3 = { 4430 [0-1] 4346 [0-1] 3131 [0-1] 4530 [0-1] 4131 [0-1] 4231 [0-1] 3141 }
        //$ole4 = { 64[0-1]30[0-1]63[0-1]66[0-1]31[0-1]31[0-1]65[0-1]30[0-1]61[0-1]31[0-1]62[0-1]31[0-1]31[0-1]61 }
        //$ole5 = { 44[0-1]30[0-1]43[0-1]46[0-1]31[0-1]31[0-1]45[0-1]30[0-1]41[0-1]31[0-1]42[0-1]31[0-1]31[0-1]41 }
        // Embedded Objects
        $obj1 = "\\objhtml" ascii
        $obj2 = "\\objdata" ascii
        $obj3 = "\\objupdate" ascii
        $obj4 = "\\objemb" ascii
        $obj5 = "\\objautlink" ascii
        $obj6 = "\\objlink" ascii
    condition:
      uint32(0) == 0x74725c7b and all of ($s*) and 1 of ($ole*) and 2 of ($obj*)
}

rule INDICATOR_RTF_EXPLOIT_CVE_2017_11882_2 {
    meta:
        description = "detects an obfuscated RTF variant documents potentially exploiting CVE-2017-11882"
        author = "ditekSHen"
    strings:
        // 0002CE02-0000-0000-C000-000000000046: Equation
        // CVE-2017-11882 or CVE-2018-0802
        $eq1 = "02ce020000000000c000000000000046" ascii nocase
        $eq2 = "equation." ascii nocase
        $eq3 = "6551754174496f4e2e33" ascii nocase
        // Embedded Objects
        $obj1 = "\\objhtml" ascii
        $obj2 = "\\objdata" ascii
        $obj3 = "\\objupdate" ascii
        $obj4 = "\\objemb" ascii
        $obj5 = "\\objautlink" ascii
        $obj6 = "\\objlink" ascii
        $obj7 = "\\mmath" ascii
        // Shellcode Artefacts
        $s1 = "4c6f61644c696272617279" ascii nocase                // LoadLibrary
        $s2 = "47657450726f6341646472657373" ascii nocase          // GetProcAddress
        $s3 = "55524c446f776e6c6f6164546f46696c65" ascii nocase    // URLDownloadToFile
        $s4 = "5368656c6c45786563757465" ascii nocase              // ShellExecute
        $s5 = "4578697450726f63657373" ascii nocase                // ExitProcess
    condition:
        uint32(0) == 0x74725c7b and 1 of ($eq*) and 1 of ($obj*) and 2 of ($s*)
}

rule INDICATOR_RTF_EXPLOIT_CVE_2017_11882_3 {
    meta:
        description = "detects RTF variant documents potentially exploiting CVE-2018-0802 or CVE-2017-11882"
        author = "ditekSHen"
    strings:
        // Ole10Native
        $ole1 = "4f006c006500310030004e00410054004900760065" ascii nocase
        $ole2 = { (3666|3466) (3663|3463) (3635|3435) 3331 3330 (3665|3465) (3631|3431) (3734|3534) (3639|3439) (3736|3536) (3635|3435) }
        // CVE-2017-11882 or CVE-2018-0802
        // 0002CE02-0000-0000-C000-000000000046: Equation
        $clsid1 = "2ce020000000000c000000000000046" ascii nocase
        $clsid2 = { 32 (43|63) (45|65) 30 32 30 30 30 30 30 30 30 30 30 30 (43|63) 30 30 30 30 30 30 30 30 30 30 30 30 30 34 36 }
        // Root Entry
        $re = "52006f006f007400200045006e00740072007900" ascii nocase
        // Embedded Objects
        $obj1 = "\\objhtml" ascii
        $obj2 = "\\objdata" ascii
        $obj3 = "\\objupdate" ascii
        $obj4 = "\\objemb" ascii
        $obj5 = "\\objautlink" ascii
        $obj6 = "\\objlink" ascii
        $obj7 = "\\mmath" ascii
    condition:
        uint32(0) == 0x74725c7b and (1 of ($ole*) and 1 of ($clsid*) and $re and 1 of ($obj*))
}

rule INDICATOR_RTF_EXPLOIT_CVE_2017_11882_4 {
    meta:
        description = "detects RTF variant documents potentially exploiting CVE-2018-0802 or CVE-2017-11882"
        author = "ditekSHen"
    strings:
        // equation.3 manipulated
        // is slowing down scanning, but good detection rate
        $s1 = { (36|34)[0-2]35[0-2](37|35)[0-2]31[0-2](37|35)[0-2]35[0-2](36|34)[0-2]31[0-2](37|35)[0-2]34[0-2](36|34)[0-2]39[0-2](36|34)[0-2]66[0-2](36|34)[0-2]65[0-2]32[0-2]65[0-2]33[0-2]33 }
        $s2 = { (7d|5c|2b|24)[0-2](37|35)[0-2]31[0-2](37|35)[0-2]35[0-2](36|34)[0-2]31[0-2](37|35)[0-2]34[0-2](36|34)[0-2]39[0-2](36|34)[0-2]66[0-2](36|34)[0-2]65[0-2]32[0-2]65[0-2]33[0-2]33 }
        // NOT slowing down scanning, but FN prone
        // $s3 = { (36|34)[0-1]35[0-1](37|35)[0-1]31[0-1](37|35)[0-1]35[0-1](36|34)[0-1]31[0-1](37|35)[0-1]34[0-1](36|34)[0-1]39[0-1](36|34)[0-1]66[0-1](36|34)[0-1]65[0-1]3265[0-1]3333 }
        //$s4 = { (7d|5c|2b|24)[0-1](37|35)[0-1]31[0-1](37|35)[0-1]35[0-1](36|34)[0-1]31[0-1](37|35)[0-1]34[0-1](36|34)[0-1]39[0-1](36|34)[0-1]66[0-1](36|34)[0-1]65[0-1]3265[0-1]3333 }
        // Embedded Objects
        $obj1 = "\\objhtml" ascii
        $obj2 = "\\objdata" ascii
        $obj3 = "\\objupdate" ascii
        $obj4 = "\\objemb" ascii
        $obj5 = "\\objautlink" ascii
        $obj6 = "\\objlink" ascii
        $obj7 = "\\mmath" ascii
    condition:
        uint32(0) == 0x74725c7b and (1 of ($s*) and 1 of ($obj*))
}    

rule INDICATOR_OLE_EXPLOIT_CVE_2017_11882_1 {
    meta:
        description = "detects OLE documents potentially exploiting CVE-2017-11882"
        author = "ditekSHen"
    strings:
        $s1 = { d0 cf 11 e0 a1 b1 1a e1 }
        $s2 = { 02 ce 02 00 00 00 00 00 c0 00 00 00 00 00 00 46 }
        $s3 = "ole10native" wide nocase
        $s4 = "Root Entry" wide
    condition:
        uint16(0) == 0xcfd0 and all of them
}

rule INDICATOR_RTF_EXPLOIT_CVE_2017_8759_1 {
    meta:
        description = "detects CVE-2017-8759 weaponized RTF documents."
        author = "ditekSHen"
    strings:
        // 00000300-0000-0000-C000-000000000046: OLE2Link
        $clsid1 = { 00 03 00 00 00 00 00 00 c0 00 00 00 00 00 00 46 }
        $clsid2 = { 00 03 00 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
        $clsid3 = "0003000000000000c000000000000046" ascii nocase
        $clsid4 = "4f4c45324c696e6b" ascii nocase // HEX
        $clsid5 = "OLE2Link" ascii nocase
        // OLE Signature
        $ole1 = { d0 cf 11 e0 a1 b1 1a e1 }
        $ole2 = "d0cf11e0a1b11ae1" ascii nocase
        $ole3 = "64306366313165306131623131616531" ascii // HEX
        $ole4 = "640a300a630a660a310a310a650a300a610a310a620a310a310a610a650a31" // HEX manipulated
        // Second Stage Artefacts
        $s1 = "wsdl=http" wide
        $s2 = "METAFILEPICT" ascii
        $s3 = "INCLUDEPICTURE \"http" ascii
        $s4 = "!This program cannot be run in DOS mode" ascii
    condition:
        uint32(0) == 0x74725c7b and 1 of ($clsid*) and 1 of ($ole*) and 2 of ($s*)
}

rule INDICATOR_RTF_EXPLOIT_CVE_2017_8759_2 {
    meta:
        description = "detects CVE-2017-8759 weaponized RTF documents."
        author = "ditekSHen"
    strings:
        // Msxml2.SAXXMLReader.
        // 88D96A0C-F192-11D4-A65F-0040963251E5: Msxml2.SAXXMLReader.6
        $clsid1 = { 88 d9 6a 0c f1 92 11 d4 a6 5f 00 40 96 32 51 e5 } 
        $clsid2 = "88d96a0cf19211d4a65f0040963251e5" ascii nocase
        $clsid3 = "4d73786d6c322e534158584d4c5265616465722e" ascii nocase // HEX
        $clsid4 = "Msxml2.SAXXMLReader." ascii nocase
        // OLE Signature
        $ole1 = { d0 cf 11 e0 a1 b1 1a e1 }
        $ole2 = "d0cf11e0a1b11ae1" ascii nocase
        $ole3 = "64306366313165306131623131616531" ascii // HEX
        $ole4 = "640a300a630a660a310a310a650a300a610a310a620a310a310a610a650a31" // HEX manipulated
        // Embedded Objects
        $obj1 = "\\objhtml" ascii
        $obj2 = "\\objdata" ascii
        $obj3 = "\\objupdate" ascii
        $obj4 = "\\objemb" ascii
        $obj5 = "\\objautlink" ascii
        $obj6 = "\\objlink" ascii
        $obj7 = "\\objclass htmlfile" ascii
        // SOAP Moniker
        $soap1 = "c7b0abec197fd211978e0000f8757e" ascii nocase
    condition:
        uint32(0) == 0x74725c7b and 1 of ($clsid*) and 1 of ($ole*) and (2 of ($obj*) or 1 of ($soap*))
}

rule INDICATOR_RTF_Exploit_Scripting {
    meta:
        description = "detects CVE-2017-8759 or CVE-2017-8570 weaponized RTF documents."
        author = "ditekSHen"
    strings:
        // 00000300-0000-0000-C000-000000000046: OLE2Link
        $clsid1 = { 00 03 00 00 00 00 00 00 c0 00 00 00 00 00 00 46 }
        $clsid2 = "0003000000000000c000000000000046" ascii nocase
        $clsid3 = "4f4c45324c696e6b" ascii nocase
        $clsid4 = "OLE2Link" ascii nocase
        // OLE Signature
        $ole1 = { d0 cf 11 e0 a1 b1 1a e1 }
        $ole2 = "d0cf11e0a1b11ae1" ascii nocase
        $ole3 = "64306366313165306131623131616531" ascii // HEX
        $ole4 = "640a300a630a660a310a310a650a300a610a310a620a310a310a610a650a31" // HEX manipulated
        $ole5 = { 64 30 63 66 [0-2] 31 31 65 30 61 31 62 31 31 61 65 31 }
        $ole6 = "D0cf11E" ascii nocase
        // Embedded Objects
        $obj1 = "\\objhtml" ascii
        $obj2 = "\\objdata" ascii
        $obj3 = "\\objupdate" ascii
        $obj4 = "\\objemb" ascii
        $obj5 = "\\objautlink" ascii
        $obj6 = "\\objlink" ascii
        $obj7 = "\\mmath" ascii
        $obj8 = "\\objclass htmlfile" ascii
        // <scriptlet
        $sct1 = { 33 (43|63) (3533|3733) (3433|3633) (3532|3732) (3439|3639)( 3530|3730) (3534|3734) (3443|3643) (3435|3635) (3534|3734) }
        // wscript.shell
        $sct2 = { (3737|3537) (3733|3533) (3633|3433) (3732|3532) (3639|3439) (3730|3530) (3734|3534) (3245|3265) (3733|3533) (3638|3438) (3635|3435) (3643|3443) (3643|3443) }
    condition:
        uint32(0) == 0x74725c7b and 1 of ($clsid*) and 1 of ($ole*) and 1 of ($obj*) and 1 of ($sct*)
}

rule INDICATOR_RTF_Embedded_Excel_SheetMacroEnabled {
    meta:
        description = "Detects RTF documents embedding an Excel sheet with macros enabled. Observed in exploit followed by dropper behavior"
        author = "ditekSHen"
    strings:
        // Embedded Excel
        $ex1 = "457863656c2e53686565744d6163726f456e61626c65642e" ascii nocase
        $ex2 = "0002083200000000c000000000000046" ascii nocase
        $ex3 = "Excel.SheetMacroEnabled."ascii
        // OLE Signature
        $ole1 = { d0 cf 11 e0 a1 b1 1a e1 }
        $ole2 = "d0cf11e0a1b11ae1" ascii nocase
        $ole3 = "64306366313165306131623131616531" ascii // HEX
        $ole4 = "640a300a630a660a310a310a650a300a610a310a620a310a310a610a650a31" // HEX manipulated
        // Embedded Objects
        $obj1 = "\\objhtml" ascii
        $obj2 = "\\objdata" ascii
        $obj3 = "\\objupdate" ascii
        $obj4 = "\\objemb" ascii
        $obj5 = "\\objautlink" ascii
        $obj6 = "\\objlink" ascii
        $obj7 = "\\mmath" ascii
    condition:
        uint32(0) == 0x74725c7b and (1 of ($ex*) and 1 of ($ole*) and 2 of ($obj*))
}

rule INDICATOR_OLE_MetadataCMD {
    meta:
        description = "Detects OLE documents with Windows command-line utilities commands (certutil, powershell, etc.) stored in the metadata (author, last modified by, etc.)."
        author = "ditekSHen"
    strings:
        // The byte(s) immediately following the anchor "00 00 00 1E 00 00 00" represent 
        // the length of the metadata field. For example: in "00 00 00 1E 00 00 00 08",
        // the "08" is total length of the value of the field, i.e: 8:
        // 00003e00  04 00 00 00 00 00 00 00  1e 00 00 00 >>08 00 00 00  |................|
        // 00003e10  55 73 65 72 00<< 00 00 00  1e 00 00 00 04 00 00 00  |User............|
        // Some variants don't reference the command itself, but following parts 
        $cmd1 = { 00 1E 00 00 00 [1-4] 00 00 (63|43) (6D|4D) (64|44) (00|20) }  // |00 00|cmd|00|
        $cmd2 = { 00 1E 00 00 00 [1-4] 00 00 (6D|4D) (73|53) (68|48) (74|54) (61|41) (00|20) }  // |00 00|mshta|00|
        $cmd3 = { 00 1E 00 00 00 [1-4] 00 00 (77|57) (73|53) (63|43) (72|52) (69|49) (70|50) (74|54) (00|20) }  // |00 00|wscript|00|
        $cmd4 = { 00 1E 00 00 00 [1-4] 00 00 (63|42) (65|45) (72|52) (74|54) (75|55) (74|54) (69|49) (6C|4C) (00|20) } // |00 00|certutil|00|
        $cmd5 = { 00 1E 00 00 00 [1-4] 00 00 (70|50) (6F|4F) (77|57) (65|45) (72|52) (73|43) (68|48) (65|45) (6C|4C) (6C|4C) (00|20) } // |00 00|powershell|00|
        $cmd6 = { 00 1E 00 00 00 [1-4] 00 00 (6E|4E) (65|45) (74|54) 2E (77|57) (65|45) (62|42) (63|43) (6C|4C) (69|49) (65|45) (6E|4E) (74|54) (00|20) } // |00 00|net.webclient|00|
    condition:
        uint16(0) == 0xcfd0 and any of them
}

rule INDICATOR_RTF_MultiExploit_Embedded_Files {
    meta:
        description = "Detects RTF documents potentially exploting multiple vulnerabilities and embeding next stage scripts and/or binaries"
        author = "ditekSHen"
    strings:
        // 0002CE02-0000-0000-C000-000000000046: Equation
        // CVE-2017-11882 or CVE-2018-0802
        $eq1 = "02ce020000000000c000000000000046" ascii nocase
        $eq2 = { 02ce020000000000c000000000000046 }
        // 00000300-0000-0000-C000-000000000046: OLE2Link
        // CVE-2017-0199, CVE-2017-8570, CVE-2017-8759 or CVE-2018-8174
        $ole2link1 = "03000000000000c000000000000046" ascii nocase
        $ole2link2 = { (36|34) (66|46) (36|34) (63|43) (36|34) 35 33 32 (36|34) (63|43) (36|34) 39 (36|34) (65|45) (36|34) (62|42) } // HEX + manipulated
        // Embedded Objects
        $obj1 = "\\objhtml" ascii
        $obj2 = "\\objdata" ascii
        $obj3 = "\\objupdate" ascii
        $obj4 = "\\objemb" ascii
        $obj5 = "\\objautlink" ascii
        $obj6 = "\\mmath" ascii
        // OLE Package Object
        $pkg = { (70|50) (61|41) (63|43) (6b|4b) (61|41) (67|47) (65|45) }
        // Embedded Files Extensions - ASCII
        $emb_exe = { 3265 (3635|3435) (3738|3538) (3635|3435) 3030 }
        $emb_scr = { 3265 (3733|3533) (3633|3433) (3532|3732) 3030 }
        $emb_dll = { 3265 (3634|3434) (3663|3463) (3663|3463) 3030 }
        $emb_doc = { 3265 (3634|3434) (3666|3466) (3633|3433) 3030 }
        $emb_bat = { 3265 (3632|3432) (3631|3431) (3734|3534) 3030 }
        $emb_sct = { 3265 (3733|3533) (3633|3433) (3734|3534) 3030 }
        $emb_txt = { 3265 (3734|3534) (3738|3538) (3734|3534) 3030 }
        $emb_psw = { 3265 (3730|3530) (3733|3533) 313030 }
    condition:
        // Strict: uint32(0) == 0x74725c7b and filesize > 400KB and (1 of ($eq*) or 1 of ($ole2link*)) and $pkg and 2 of ($obj*) and 1 of ($emb*)
        uint32(0) == 0x74725c7b and (1 of ($eq*) or 1 of ($ole2link*)) and $pkg and 2 of ($obj*) and 1 of ($emb*)
}

rule INDICATOR_OLE_ObjectPool_Embedded_Files {
    meta:
        description = "Detects OLE documents with ObjectPool OLE storage and embed suspicous excutable files"
        author = "ditekSHen"
    strings:
        $s1 = "ObjectPool" fullword wide
        $s2 = "Ole10Native" fullword wide
        $s3 = "Root Entry" fullword wide

        $h1 = { 4f 00 62 00 6a 00 65 00 63 00 74 00 50 00 6f 00 6f 00 6c 00 }
        $h2 = { 4f 00 6c 00 65 00 31 00 30 00 4e 00 61 00 74 00 69 00 76 00 65 00 }
        $h3 = { 52 00 6f 00 6f 00 74 00 20 00 45 00 6e 00 74 00 72 00 79 00 }
        // OLE Package Object
        $olepkg = { 00 00 00 0c 00 03 00 00 00 00 00 c0 00 00 00 00 00 00 46 }
        // Embedded Files Extensions - ASCII - Not as reliable as its hex variant
        $fa_exe = ".exe" ascii nocase
        $fa_scr = ".scr" ascii nocase
        $fa_dll = ".dll" ascii nocase
        $fa_bat = ".bat" ascii nocase
        $fa_cmd = ".cmd" ascii nocase
        $fa_sct = ".sct" ascii nocase
        $fa_txt = ".txt" ascii nocase
        $fa_psw = ".ps1" ascii nocase
        // File extensions - Hex > slowing down scanning
        /*
        $fh_exe = { 2e (45|65) (58|78) (45|65) 00 }
        $fh_scr = { 2e (53|73) (43|63) (52|72) 00 }
        $fh_dll = { 2e (44|64) (4c|6c) (4c|6c) 00 }
        $fh_bat = { 2e (42|62) (41|61) (54|74) 00 }
        $fh_cmd = { 2e (43|63) (4d|6d) (44|64) 00 }
        $fh_sct = { 2e (53|73) (43|63) (54|74) 00 }
        $fh_txt = { 2e (54|74) (58|78) (54|74) 00 }
        $fh_psw = { 2e (50|70) (53|73) 31 00 }
        */
    condition:
        uint16(0) == 0xcfd0 and (all of ($s*) or all of ($h*)) and $olepkg and 1 of ($fa*)
}

rule INDICATOR_RTF_Equation_BITSAdmin_Downloader {
    meta:
        description = "Detects RTF documents that references both Microsoft Equation Editor and BITSAdmin. Common exploit + dropper behavior."
        author = "ditekSHen"
        snort2_sid = "910002-910003"
        snort3_sid = "910001"
        clamav_sig = "INDICATOR.RTF.EquationBITSAdminDownloader"
    strings:
        // 0002CE02-0000-0000-C000-000000000046: Equation
        // CVE-2017-11882 or CVE-2018-0802
        $eq = "0200000002CE020000000000C000000000000046" ascii nocase
        // BITSAdmin
        $ba = "6269747361646d696e" ascii nocase
        // Embedded Objects
        $obj1 = "\\objhtml" ascii
        $obj2 = "\\objdata" ascii
        $obj3 = "\\objupdate" ascii
        $obj4 = "\\objemb" ascii
        $obj5 = "\\objautlink" ascii
        $obj6 = "\\objlink" ascii
        $obj7 = "\\mmath" ascii
    condition:
        uint32(0) == 0x74725c7b and (($eq and $ba) and 1 of ($obj*))
}

rule INDICATOR_RTF_Equation_CertUtil_Downloader {
    meta:
        description = "Detects RTF documents that references both Microsoft Equation Editor and CertUtil. Common exploit + dropper behavior."
        author = "ditekSHen"
        snort2_sid = "910006-910007"
        snort3_sid = "910003"
        clamav_sig = "INDICATOR.RTF.EquationCertUtilDownloader"
    strings:
        // 0002CE02-0000-0000-C000-000000000046: Equation
        // CVE-2017-11882 or CVE-2018-0802
        $eq = "0200000002CE020000000000C000000000000046" ascii nocase
        // CertUtil
        $cu = "636572747574696c" ascii nocase
        // Embedded Objects
        $obj1 = "\\objhtml" ascii
        $obj2 = "\\objdata" ascii
        $obj3 = "\\objupdate" ascii
        $obj4 = "\\objemb" ascii
        $obj5 = "\\objautlink" ascii
        $obj6 = "\\objlink" ascii
        $obj7 = "\\mmath" ascii
    condition:
        uint32(0) == 0x74725c7b and (($eq and $cu) and 1 of ($obj*))
}

rule INDICATOR_RTF_Equation_PowerShell_Downloader {
    meta:
        description = "Detects RTF documents that references both Microsoft Equation Editor and PowerShell. Common exploit + dropper behavior."
        author = "ditekSHen"
        snort2_sid = "910004-910005"
        snort3_sid = "910002"
        clamav_sig = "INDICATOR.RTF.EquationPowerShellDownloader"
    strings:
        // 0002CE02-0000-0000-C000-000000000046: Equation
        // CVE-2017-11882 or CVE-2018-0802
        $eq = "0200000002CE020000000000C000000000000046" ascii nocase
        // PowerShell
        $ps = "706f7765727368656c6c" ascii nocase
        // Embedded Objects
        $obj1 = "\\objhtml" ascii
        $obj2 = "\\objdata" ascii
        $obj3 = "\\objupdate" ascii
        $obj4 = "\\objemb" ascii
        $obj5 = "\\objautlink" ascii
        $obj6 = "\\objlink" ascii
        $obj7 = "\\mmath" ascii
    condition:
        uint32(0) == 0x74725c7b and (($ps and $eq) and 1 of ($obj*))
}