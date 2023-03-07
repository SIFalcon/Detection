import "console"

rule HUNT_RTF_CVE_2023_21716_Mar23
{
	meta:
		author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
		description = "Detects RTF documents with an inflated fonttable. Hunting for CVE-2023-21716"
		reference = "https://www.bleepingcomputer.com/news/security/proof-of-concept-released-for-critical-microsoft-word-rce-bug/"
		date = "2023-03-07"
		tlp = "CLEAR"

	strings:
		$fonttbl_len = /\\fonttbl\{.{1,10}\;\}(\s.{1,10}\}){10,}/

	condition:
		uint32be(0x0) == 0x7B5C7274
		and !fonttbl_len[1] > 256
		// the "console" module requires Yara 4.2.0 or later, comment out the line below for older versions
		and console.log("[!] Inflated fonttable with length: ", !fonttbl_len[1])
}
