import "pe"
rule INDICATOR_EXE_Packed_eXPressor {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with eXPressor"
        snort2_sid = "930043-930048"
        snort3_sid = "930015-930016"
    strings:
        $s1 = "eXPressor_InstanceChecker_" fullword ascii
        $s2 = "This application was packed with an Unregistered version of eXPressor" ascii
        $s3 = ", please visit www.cgsoftlabs.ro" ascii
        $s4 = /eXPr-v\.\d+\.\d+/ ascii
    condition:
        uint16(0) == 0x5a4d and 2 of them or
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name contains ".ex_cod"
            )
        )
}

rule INDICATOR_EXE_Packed_MEW {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with MEW"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == "MEW" or
                pe.sections[i].name == "\x02\xd2u\xdb\x8a\x16\xeb\xd4"
            )
        )
}

rule INDICATOR_EXE_Packed_RLPack {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with RLPACK"
        snort2_sid = "930064-930066"
        snort3_sid = "930023"
    strings:
        $s1 = ".packed" fullword ascii
        $s2 = ".RLPack" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them or
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".RLPack"
            )
        )
}

rule INDICATOR_EXE_Packed_Cassandra {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with Cassandra/CyaX"
    strings:
        $s1 = "AntiEM" fullword ascii wide
        $s2 = "AntiSB" fullword ascii wide
        $s3 = "Antis" fullword ascii wide
        $s4 = "XOR_DEC" fullword ascii wide
        $s5 = "StartInject" fullword ascii wide
        $s6 = "DetectGawadaka" fullword ascii wide
        $c1 = "CyaX-Sharp" ascii wide
        $c2 = "CyaX_Sharp" ascii wide
        $c3 = "CyaX-PNG" ascii wide
        $c4 = "CyaX_PNG" ascii wide
        $pdb = "\\CyaX\\obj\\Debug\\CyaX.pdb" ascii wide
    condition:
        (uint16(0) == 0x5a4d and (4 of ($s*) or 2 of ($c*) or $pdb)) or (7 of them)
}

rule INDICATOR_EXE_Packed_Themida {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with Themida"
        snort2_sid = "930067-930069"
        snort3_sid = "930024"
    strings:
        $s1 = ".themida" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them or
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".themida"
            )
        )
}

rule INDICATOR_EXE_Packed_SilentInstallBuilder {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with Silent Install Builder"
        snort2_sid = "930070-930072"
        snort3_sid = "930025"
    strings:
        $s1 = "C:\\Users\\Operations\\Source\\Workspaces\\Sib\\Sibl\\Release\\Sibuia.pdb" fullword ascii
        $s2 = "->mb!Silent Install Builder Demo Package." fullword wide
    condition:
        uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_EXE_Packed_NyanXCat_CSharpLoader {
    meta:
        author = "ditekSHen"
        description = "Detects .NET executables utilizing NyanX-CAT C# Loader"
        snort2_sid = "930073-930075"
        snort3_sid = "930026"
    strings:
        $s1 = { 00 50 72 6f 67 72 61 6d 00 4c 6f 61 64 65 72 00 4e 79 61 6e 00 }
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_EXE_Packed_Loader {
    meta:
        author = "ditekSHen"
        description = "Detects packed executables observed in Molerats"
    strings:
        $l1 = "loaderx86.dll" fullword ascii
        $l2 = "loaderx86" fullword ascii
        $l3 = "loaderx64.dll" fullword ascii
        $l4 = "loaderx64" fullword ascii
        $s1 = "ImportCall_Zw" wide
        $s2 = "DllInstall" ascii wide
        $s3 = "evb*.tmp" fullword wide
        $s4 = "WARNING ZwReadFileInformation" ascii
        $s5 = "LoadLibrary failed with module " fullword wide
    condition:
        uint16(0) == 0x5a4d and 2 of ($l*) and 4 of ($s*)
}

rule INDICATOR_EXE_Packed_Bonsai {
    meta:
         author = "ditekSHen"
        description = "Detects .NET executables developed using Bonsai"
    strings:
        $bonsai1 = "<Bonsai." ascii
        $bonsai2 = "Bonsai.Properties" ascii
        $bonsai3 = "Bonsai.Core.dll" fullword wide
        $bonsai4 = "Bonsai.Design." wide
    condition:
        uint16(0) == 0x5a4d and 2 of ($bonsai*)
}

/*
Can lead to many FPs?
rule INDICATOR_EXE_Packed_UPolyX {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with UPolyX"
    strings:
        $s1 = { 81 fd 00 fb ff ff 83 d1 ?? 8d 14 2f 83 fd fc 76 ?? 8a 02 42 88 07 47 49 75 }
        $s2 = { e2 ?? ff ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $s3 = { 55 8b ec ?? 00 bd 46 00 8b ?? b9 ?? 00 00 00 80 ?? ?? 51 }
        $s4 = { bb ?? ?? ?? ?? 83 ec 04 89 1c 24 ?? b9 ?? 00 00 00 80 33 }
        $s5 = { e8 00 00 00 00 59 83 c1 07 51 c3 c3 }
        $s6 = { 83 ec 04 89 ?? 24 59 ?? ?? 00 00 00 }
    condition:
        uint16(0) == 0x5a4d and 1 of them and
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name contains "UPX"
            )
        )
}
*/

rule INDICATOR_EXE_Packed_TriumphLoader {
    meta:
        author = "ditekSHen"
        description = "Detects TriumphLoader"
        snort2_sid = "920101"
        snort3_sid = "920099"
        clamav_sig = "INDICATOR.Packed.TriumphLoader"
    strings:
        $id1 = "User-Agent: TriumphLoader" ascii wide
        $id2 = "\\loader\\absent-loader-master\\client\\full\\absentclientfull\\absentclientfull\\absent\\json.hpp" wide
        $id3 = "\\triumphloader\\triumphloaderfiles\\triumph\\json.h" wide
        $s1 = "current == '\\\"'" fullword wide
        $s2 = "00010203040506070809101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263" ascii
        $s3 = "646566676869707172737475767778798081828384858687888990919293949596979899object key" fullword ascii
        $s4 = "endptr == token_buffer.data() + token_buffer.size()" fullword wide
        $s5 = "last - first >= 2 + (-kMinExp - 1) + std::numeric_limits<FloatType>::max_digits10" fullword wide
        $s6 = "p2 <= (std::numeric_limits<std::uint64_t>::max)() / 10" fullword wide
    condition:
        uint16(0) == 0x5a4d and (1 of ($id*) or all of ($s*) or (3 of ($s*) and 1 of ($id*)) or (4 of them and pe.imphash() == "784001f4b755832ae9085d98afc9ce83"))
}

rule INDICATOR_EXE_Packed_LLVMLoader {
    meta:
        author = "ditekSHen"
        description = "Detects LLVM obfuscator/loader"
        clamav_sig = "INDICATOR.Packed.LLVMLoader"
    strings:
        $s1 = "exeLoaderDll_LLVMO.dll" fullword ascii
        $b = { 64 6c 6c 00 53 74 61 72 74 46 75 6e 63 00 00 00
               ?? ?? 00 00 00 00 00 00 00 00 00 ?? 96 01 00 00
               ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00
               00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 00
               00 00 00 00 00 00 00 00 00 00 00 ?? ?? 45 78 69
               74 50 72 6f 63 65 73 73 00 4b 45 52 4e 45 4c 33
               32 2e 64 6c 6c 00 00 00 00 00 00 }
    condition:
        (uint16(0) == 0x5a4d or uint16(0) == 0x0158) and ((pe.exports("StartFunc") and 1 of ($s*)) or all of ($s*) or ($b))
}

rule INDICATOR_EXE_Packed_NoobyProtect {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with NoopyProtect"
    strings:
        $s1 = "NoobyProtect SE" ascii
    condition:
        uint16(0) == 0x5a4d and all of them or
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == "SE"
            )
        )
}

rule INDICATOR_EXE_Packed_nBinder {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with nBinder"
    strings:
        $s1 = "This file was created using nBinder" ascii
        $s2 = "Warning: Contains binded files that may pose a security risk." ascii
        $s3 = "a file created with nBinder" ascii
        $s4 = "name=\"NKProds.nBinder.Unpacker\" type=\"win" ascii
        $s5 = "<description>nBinder Unpacker. www.nkprods.com</description>" ascii
        $s6 = "nBinder Unpacker (C) NKProds" wide
        $s7 = "\\Proiecte\\nBin" ascii
    condition:
        uint16(0) == 0x5a4d and 2 of them
}

rule INDICATOR_EXE_Packed_SmartAssembly {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with SmartAssembly"
    strings:
        $s1 = "PoweredByAttribute" fullword ascii
        $s2 = "SmartAssembly.Attributes" fullword ascii
        $s3 = "Powered by SmartAssembly" ascii
    condition:
        uint16(0) == 0x5a4d and 2 of them
}

rule INDICATOR_EXE_Packed_AgileDotNet {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with Agile.NET / CliSecure"
    strings:
        $x1 = "AgileDotNetRT" fullword ascii
        $x2 = "AgileDotNetRT64" fullword ascii
        $x3 = "<AgileDotNetRT>" fullword ascii
        $x4 = "AgileDotNetRT.dll" fullword ascii
        $x5 = "AgileDotNetRT64.dll" fullword ascii
        $x6 = "get_AgileDotNet" ascii
        $x7 = "useAgileDotNetStackFrames" fullword ascii
        $x8 = "AgileDotNet." ascii
        $x9 = "://secureteam.net/webservices" ascii
        $x10 = "AgileDotNetProtector." ascii
        $s1 = "Callvirt" fullword ascii
        $s2 = "_Initialize64" fullword ascii
        $s3 = "_AtExit64" fullword ascii
        $s4 = "DomainUnload" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (2 of ($x*) or (1 of ($x*) and 2 of ($s*)) or all of ($s*))
}

rule INDICATOR_EXE_Packed_Fody {
    meta:
        author = "ditekSHen"
        description = "Detects executables manipulated with Fody"
    strings:
        $s1 = "ProcessedByFody" fullword ascii wide
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_EXE_Packed_Costura {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with Costura DotNetGuard"
    strings:
        $s1 = "DotNetGuard" fullword ascii
        $s2 = "costura." ascii wide
        $s3 = "AssemblyLoader" fullword ascii wide
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_EXE_Packed_SimplePolyEngine {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with Sality Polymorphic Code Generator or Simple Poly Engine or Sality"
    strings:
        $s1 = "Simple Poly Engine v" ascii
        $b1 = "yrf<[LordPE]" ascii
        $b2 = "Hello world!" fullword wide
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or all of ($b*))
}

rule INDICATOR_EXE_Packed_dotNetProtector {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with dotNetProtector"
    strings:
        $s1 = "dotNetProtector" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_EXE_Packed_DotNetReactor {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with unregistered version of .NET Reactor"
    strings:
        $s1 = "is protected by an unregistered version of Eziriz's\".NET Reactor\"!" wide
        $s2 = "is protected by an unregistered version of .NET Reactor!\" );</script>" wide
    condition:
        uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_EXE_Packed_Dotfuscator {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with Dotfuscator"
    strings:
        $s1 = "DotfuscatorAttribute" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 1 of them
}