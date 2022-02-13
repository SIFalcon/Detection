
rule SUSP_VBS_in_ISO: VBS ISO {
	meta:
		author = "SECUINFRA Falcon Team"
		description = "Detects ISO files that contain VBS functions"
		date = "13.02.2022"
		reference = "Internal Research"
		version = "v0.1"

	strings:
		$magic = { 43 44 30 30 31 }

		$a1 = { 43 72 65 61 74 65 4F 62 6A 65 63 74 } // CreateObject
		$a2 = { 52 75 6E } // Run
		$a3 = { 72 65 70 6C 61 63 65 } // replace 

	condition:
		filesize > 500KB and filesize < 800KB and $magic and 1 of ($a*)
}