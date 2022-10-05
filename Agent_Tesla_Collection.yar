import "pe"

rule MALWARE_Win_AgentTeslaV2 {
    meta:
        author = "ditekSHen"
        description = "AgenetTesla Type 2 Keylogger payload"
    strings:
        $s1 = "get_kbHook" ascii
        $s2 = "GetPrivateProfileString" ascii
        $s3 = "get_OSFullName" ascii
        $s4 = "get_PasswordHash" ascii
        $s5 = "remove_Key" ascii
        $s6 = "FtpWebRequest" ascii
        $s7 = "logins" fullword wide
        $s8 = "keylog" fullword wide
        $s9 = "1.85 (Hash, version 2, native byte-order)" wide

        $cl1 = "Postbox" fullword ascii
        $cl2 = "BlackHawk" fullword ascii
        $cl3 = "WaterFox" fullword ascii
        $cl4 = "CyberFox" fullword ascii
        $cl5 = "IceDragon" fullword ascii
        $cl6 = "Thunderbird" fullword ascii
    condition:
        (uint16(0) == 0x5a4d and 6 of ($s*)) or (6 of ($s*) and 2 of ($cl*))
}

rule MALWARE_Win_AgentTeslaV3 {
    meta:
      author = "ditekSHen"
      description = "AgentTeslaV3 infostealer payload"
    strings:
      $s1 = "get_kbok" fullword ascii
      $s2 = "get_CHoo" fullword ascii
      $s3 = "set_passwordIsSet" fullword ascii
      $s4 = "get_enableLog" fullword ascii
      $s5 = "bot%telegramapi%" wide
      $s6 = "KillTorProcess" fullword ascii 
      $s7 = "GetMozilla" ascii
      $s8 = "torbrowser" wide
      $s9 = "%chatid%" wide
      $s10 = "logins" fullword wide
      $s11 = "credential" fullword wide
      $s12 = "AccountConfiguration+" wide
      $s13 = "<a.+?href\\s*=\\s*([\"'])(?<href>.+?)\\1[^>]*>" fullword wide

      $g1 = "get_Clipboard" fullword ascii
      $g2 = "get_Keyboard" fullword ascii
      $g3 = "get_Password" fullword ascii
      $g4 = "get_CtrlKeyDown" fullword ascii
      $g5 = "get_ShiftKeyDown" fullword ascii
      $g6 = "get_AltKeyDown" fullword ascii

      $m1 = "yyyy-MM-dd hh-mm-ssCookieapplication/zipSCSC_.jpegScreenshotimage/jpeg/log.tmpKLKL_.html<html></html>Logtext/html[]Time" ascii
      $m2 = "%image/jpg:Zone.Identifier\\tmpG.tmp%urlkey%-f \\Data\\Tor\\torrcp=%PostURL%127.0.0.1POST+%2B" ascii
      $m3 = ">{CTRL}</font>Windows RDPcredentialpolicyblobrdgchrome{{{0}}}CopyToComputeHashsha512CopySystemDrive\\WScript.ShellRegReadg401" ascii
      $m4 = "%startupfolder%\\%insfolder%\\%insname%/\\%insfolder%\\Software\\Microsoft\\Windows\\CurrentVersion\\Run%insregname%SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\RunTruehttp" ascii
      $m5 = "\\WindowsLoad%ftphost%/%ftpuser%%ftppassword%STORLengthWriteCloseGetBytesOpera" ascii
    condition:
      (uint16(0) == 0x5a4d and (8 of ($s*) or (6 of ($*) and all of ($g*)))) or (2 of ($m*))
}

rule MALWARE_Win_TeslaRevenge {
    meta:
        author = "ditekSHen"
        description = "Detects TeslaRevenge ransomware"
    strings:
        $s1 = "autospreadifnoav=" ascii wide
        $s2 = "autospread=" ascii wide
        $s3 = "noencryptext=" ascii wide
        $s4 = "teslarvng" wide
        $s5 = "finished encrypting" wide nocase
        $s6 = "net scan" wide nocase
        $s7 = "for /f %%x in ('wevtutil el') do wevtutil cl" ascii
        $s8 = "tasklist | find /i \"SDELETE.exe\"" ascii
        $e1 = "mshta.exe" ascii wide nocase
        $e2 = "sc.exe" ascii wide nocase
        $e3 = "vssadmin.exe" ascii wide nocase
        $e4 = "wbadmin.exe" ascii wide nocase
        $e5 = "cmd.exe" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and (4 of ($s*) or (all of ($e*) and 2 of ($s*)))
}