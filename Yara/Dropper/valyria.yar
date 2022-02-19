rule DROPPER_Valyria_Stage_1: JavaScript VBS Valyria{
	meta:
		author = "SECUINFRA Falcon Team"
		reference = "https://bazaar.abuse.ch/sample/c8a8fea3cbe08cd97e56a0e0dbc59a892f8ab1ff3b5217ca3c9b326eeee6ca66/"
		date = "18.02.2022"
		description = "Family was taken from VirusTotal"

	strings:
		$a1 = "<script language=\"vbscript\">"
		$a2 = "<script language=\"javascript\">"

		$b1 = "window.resizeTo(0,0);"
		$b2 = ".Environment"
		$b3 = ".item().Name"
		$b4 = "v4.0.30319"
		$b5 = "v2.0.50727"

		$c1 = "Content Writing.docx"
		$c2 = "eval"

	condition:
		filesize < 600KB and all of ($a*) and 3 of ($b*) and 1 of ($c*)
}
