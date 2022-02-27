

rule SUSP_VBS_Wscript_Shell {
	meta:
		author = "SECUINFRA Falcon Team"
		date = "27.02.2022"
		description = "Detects the definition of 'Wscript.Shell' which is often used by Malware, FPs are possible and commmon"

	strings:
		$wscript = "CreateObject(\"WScript.Shell\")" wide nocase

	condition:
		filesize < 300KB and $wscript
}