/*
   Yara Rule Set
   Author: SECUINFRA Falcon Team
   Date: 2022-06-23
   Identifier: 0x03-yara_win-Bitter_T-APT-17
   Reference: "https://www.secuinfra.com/en/techtalk/whatever-floats-your-boat-bitter-apt-continues-to-target-bangladesh"
*/

/* Rule Set ----------------------------------------------------------------- */

rule APT_Bitter_Maldoc_Verify {
    
    meta:
        description = "Detects Bitter (T-APT-17) shellcode in oleObject (CVE-2018-0798)"
        author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
        tlp = "WHITE"
        reference = "https://www.secuinfra.com/en/techtalk/whatever-floats-your-boat-bitter-apt-continues-to-target-bangladesh"
        date = "2022-06-01"
        hash0 = "0c7158f9fc2093caf5ea1e34d8b8fffce0780ffd25191fac9c9b52c3208bc450"
        hash1 = "bd0d25194634b2c74188cfa3be6668590e564e6fe26a6fe3335f95cbc943ce1d"
        hash2 = "3992d5a725126952f61b27d43bd4e03afa5fa4a694dca7cf8bbf555448795cd6"

    strings:
        // This rule is meant to be used for verification of a Bitter Maldoc
        // rather than a hunting rule since the oleObject it is matching is
        // compressed in the doc zip
        
        $xor_string0 = "LoadLibraryA" xor
        $xor_string1 = "urlmon.dll" xor
        $xor_string2 = "Shell32.dll" xor
        $xor_string3 = "ShellExecuteA" xor
        $xor_string4 = "MoveFileA" xor    
        $xor_string5 = "CreateDirectoryA" xor
        $xor_string6 = "C:\\Windows\\explorer" xor
        $padding = {000001128341000001128341000001128342000001128342}
    
    condition:
        3 of ($xor_string*)
        and $padding
}

rule APT_Bitter_ZxxZ_Downloader {
    
    meta:
        description = "Detects Bitter (T-APT-17) ZxxZ Downloader"
        author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
        TLP = "WHITE"
        reference = " https://www.secuinfra.com/en/techtalk/whatever-floats-your-boat-bitter-apt-continues-to-target-bangladesh"
        date = "2022-06-01"
        hash0 = "91ddbe011f1129c186849cd4c84cf7848f20f74bf512362b3283d1ad93be3e42"
        hash1 = "90fd32f8f7b494331ab1429712b1735c3d864c8c8a2461a5ab67b05023821787"
        hash2 = "69b397400043ec7036e23c225d8d562fdcd3be887f0d076b93f6fcaae8f3dd61"
        hash3 = "3fdf291e39e93305ebc9df19ba480ebd60845053b0b606a620bf482d0f09f4d3"
        hash4 = "fa0ed2faa3da831976fee90860ac39d50484b20bee692ce7f0ec35a15670fa92"

    strings:
        // old ZxxZ samples / decrypted strings
        $old0 = "MsMp" ascii
        $old1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" ascii
        $old2 = "&&user=" ascii
        $old3 = "DN-S" ascii
        $old4 = "RN_E" ascii
        
        // new ZxxZ samples
        $c2comm0 = "GET /" ascii
        $c2comm1 = "profile" ascii
        $c2comm2 = ".php?" ascii
        $c2comm3 = "data=" ascii
        $c2comm4 = "Update" ascii
        $c2comm5 = "TTT" ascii

    condition:
        uint16(0) == 0x5a4d
        and filesize > 39KB // Size on Disk/1.5
        and filesize < 2MB // Size of Image*1.5
        and (all of ($old*)) or (all of ($c2comm*))
}

import "pe"
import "dotnet"

rule APT_Bitter_Almond_RAT {
    
    meta:
        description = "Detects Bitter (T-APT-17) Almond RAT (.NET)"
        author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
        tlp = "WHITE"
        reference = " https://www.secuinfra.com/en/techtalk/whatever-floats-your-boat-bitter-apt-continues-to-target-bangladesh"
        date = "2022-06-01"
        hash = "55901c2d5489d6ac5a0671971d29a31f4cdfa2e03d56e18c1585d78547a26396"

    strings:
        $function0 = "GetMacid" ascii
        $function1 = "StartCommWithServer" ascii
        $function2 = "sendingSysInfo" ascii

        $dbg0 = "*|END|*" wide
        $dbg1 = "FILE>" wide
        $dbg2 = "[Command Executed Successfully]" wide

    condition:
        uint16(0) == 0x5a4d
        and dotnet.version == "v4.0.30319"
        and filesize > 12KB // Size on Disk/1.5
        and filesize < 68KB // Size of Image*1.5
        and any of ($function*)
        and any of ($dbg*)
}

rule APT_Bitter_PDB_Paths {
    
    meta:
        description = "Detects Bitter (T-APT-17) PDB Paths"
        author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
        tlp = "WHITE"
        reference = "https://www.secuinfra.com/en/techtalk/whatever-floats-your-boat-bitter-apt-continues-to-target-bangladesh"
        date = "2022-06-22"
        hash0 = "55901c2d5489d6ac5a0671971d29a31f4cdfa2e03d56e18c1585d78547a26396"

    strings:
        // Almond RAT
        $pdbPath0 = "C:\\Users\\Window 10 C\\Desktop\\COMPLETED WORK\\" ascii
        $pdbPath1 = "stdrcl\\stdrcl\\obj\\Release\\stdrcl.pdb"

        // found by Qi Anxin Threat Intellingence Center
        // reference: https://mp.weixin.qq.com/s/8j_rHA7gdMxY1_X8alj8Zg
        $pdbPath2 = "g:\\Projects\\cn_stinker_34318\\"
        $pdbPath3 = "renewedstink\\renewedstink\\obj\\Release\\stimulies.pdb"

    condition:
        uint16(0) == 0x5a4d
        and any of ($pdbPath*)
}
