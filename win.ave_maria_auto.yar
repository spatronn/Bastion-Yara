rule win_ave_maria_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-08-05"
        version = "1"
        description = "Detects win.ave_maria."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ave_maria"
        malpedia_rule_date = "20220805"
        malpedia_hash = "6ec06c64bcfdbeda64eff021c766b4ce34542b71"
        malpedia_version = "20220808"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using YARA-Signator.
     * The code and documentation is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { 33c3 8bce 2345f4 c1c105 33d0 034db8 8b4594 }
            // n = 7, score = 400
            //   33c3                 | xor                 eax, ebx
            //   8bce                 | mov                 ecx, esi
            //   2345f4               | and                 eax, dword ptr [ebp - 0xc]
            //   c1c105               | rol                 ecx, 5
            //   33d0                 | xor                 edx, eax
            //   034db8               | add                 ecx, dword ptr [ebp - 0x48]
            //   8b4594               | mov                 eax, dword ptr [ebp - 0x6c]

        $sequence_1 = { 8bc3 894dfc 33c2 c1c105 33c7 034db4 81c6a1ebd96e }
            // n = 7, score = 400
            //   8bc3                 | mov                 eax, ebx
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   33c2                 | xor                 eax, edx
            //   c1c105               | rol                 ecx, 5
            //   33c7                 | xor                 eax, edi
            //   034db4               | add                 ecx, dword ptr [ebp - 0x4c]
            //   81c6a1ebd96e         | add                 esi, 0x6ed9eba1

        $sequence_2 = { 7411 8ac2 8ad0 3c22 7409 41 8a11 }
            // n = 7, score = 400
            //   7411                 | je                  0x13
            //   8ac2                 | mov                 al, dl
            //   8ad0                 | mov                 dl, al
            //   3c22                 | cmp                 al, 0x22
            //   7409                 | je                  0xb
            //   41                   | inc                 ecx
            //   8a11                 | mov                 dl, byte ptr [ecx]

        $sequence_3 = { 8bf3 3bf0 0f92c1 e8???????? 8b4740 8d4c2410 8d04b0 }
            // n = 7, score = 400
            //   8bf3                 | mov                 esi, ebx
            //   3bf0                 | cmp                 esi, eax
            //   0f92c1               | setb                cl
            //   e8????????           |                     
            //   8b4740               | mov                 eax, dword ptr [edi + 0x40]
            //   8d4c2410             | lea                 ecx, [esp + 0x10]
            //   8d04b0               | lea                 eax, [eax + esi*4]

        $sequence_4 = { 85c0 740a 8b45f0 8906 33c0 40 eb02 }
            // n = 7, score = 400
            //   85c0                 | test                eax, eax
            //   740a                 | je                  0xc
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   8906                 | mov                 dword ptr [esi], eax
            //   33c0                 | xor                 eax, eax
            //   40                   | inc                 eax
            //   eb02                 | jmp                 4

        $sequence_5 = { 8b4e14 e8???????? 894610 85c0 0f84e0000000 51 ba???????? }
            // n = 7, score = 400
            //   8b4e14               | mov                 ecx, dword ptr [esi + 0x14]
            //   e8????????           |                     
            //   894610               | mov                 dword ptr [esi + 0x10], eax
            //   85c0                 | test                eax, eax
            //   0f84e0000000         | je                  0xe6
            //   51                   | push                ecx
            //   ba????????           |                     

        $sequence_6 = { 8bf1 6a10 5b 53 83c710 68???????? 57 }
            // n = 7, score = 400
            //   8bf1                 | mov                 esi, ecx
            //   6a10                 | push                0x10
            //   5b                   | pop                 ebx
            //   53                   | push                ebx
            //   83c710               | add                 edi, 0x10
            //   68????????           |                     
            //   57                   | push                edi

        $sequence_7 = { 51 54 8d4f20 e8???????? 51 51 54 }
            // n = 7, score = 400
            //   51                   | push                ecx
            //   54                   | push                esp
            //   8d4f20               | lea                 ecx, [edi + 0x20]
            //   e8????????           |                     
            //   51                   | push                ecx
            //   51                   | push                ecx
            //   54                   | push                esp

        $sequence_8 = { 6a03 57 6a01 ff7508 ff7604 ff15???????? 894608 }
            // n = 7, score = 400
            //   6a03                 | push                3
            //   57                   | push                edi
            //   6a01                 | push                1
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff7604               | push                dword ptr [esi + 4]
            //   ff15????????         |                     
            //   894608               | mov                 dword ptr [esi + 8], eax

        $sequence_9 = { 56 e8???????? 59 50 8d4b08 e8???????? 8b4d08 }
            // n = 7, score = 400
            //   56                   | push                esi
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   50                   | push                eax
            //   8d4b08               | lea                 ecx, [ebx + 8]
            //   e8????????           |                     
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]

    condition:
        7 of them and filesize < 237568
}