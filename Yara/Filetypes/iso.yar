rule SUSP_VBS_in_ISO: VBS ISO {
	meta:
		author = "SECUINFRA Falcon Team"
		description = "Detects ISO files that contain VBS functions"
		date = "13.02.2022"
		reference = "Internal Research"
		version = "v0.2"

	strings:
		$magic = { 43 44 30 30 31 }

		$a1 = { 43 72 65 61 74 65 4F 62 6A 65 63 74 } // CreateObject
		$a2 = { 72 65 70 6C 61 63 65 } // replace 

	condition:
		filesize < 800KB 
		and $magic 
		and 1 of ($a*)
}

rule SUSP_EXE_in_ISO: EXE ISO {
	meta:
		author = "SECUINFRA Falcon Team"
		description = "Detects ISO files that contains an Exe file. Does not need to be malicious"
		date = "19.02.2022"
		reference = "Internal Research"

	strings:
		$magic = { 43 44 30 30 31 }
		$mz = { 4D 5A }

	condition:
		filesize > 100KB 
		and filesize < 800KB 
		and $magic 
		and $mz
}