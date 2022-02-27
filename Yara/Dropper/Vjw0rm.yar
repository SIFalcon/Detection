
rule DROPPER_Vjw0rm_Stage_1: JavaScript Dropper Vjw0rm {
	meta:
		author = "SECUINFRA Falcon Team"
		reference = "https://bazaar.abuse.ch/browse.php?search=tag%3AVjw0rm"
		date = "19.02.2022"
		version = "0.1"

	strings:
		$a1 = "$$$"
		$a2 = "microsoft.xmldom"
		$a3 = "eval"
		$a4 = "join(\"\")"

	condition:
		(uint16(0) == 0x7566 or uint16(0) == 0x6176 or uint16(0) == 0x0a0d or uint16(0) == 0x660a) 
		and filesize < 60KB 
		and all of ($a*) 
}