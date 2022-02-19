rule DROPPER_Unknown_1 : Dropper HTA {
	meta:
		author = "SECUINFRA Falcon Team"
		hash = "1749f4127bba3f7204710286b1252e14"
		reference = "https://bazaar.abuse.ch/sample/c2bf8931028e0a18eeb8f1a958ade0ab9d64a00c16f72c1a3459f160f0761348/"
		description = "Detects unknown HTA Dropper"
		date = "10.02.2022"

	strings:
		$a1 = "<script type=\"text/vbscript\" LANGUAGE=\"VBScript\" >"
		$a2 = "Function XmlTime(t)"
		$a3 = "C:\\ProgramData\\"
		$a4 = "wscript.exe"
		$a5 = "Array" nocase

		$b = "chr" nocase


	condition:
		filesize < 70KB and all of ($a*) and #b > 7
}