
rule DROPPER_Asyncrat_VBS_February_2022_1 {
	meta:
		author = "SECUINFRA Falcon Team"
		date = "21.02.2022"
		reference = "https://bazaar.abuse.ch/sample/06cd1e75f05d55ac1ea77ef7bee38bb3b748110b79128dab4c300f1796a2b941/"

	strings:
		$a1 = "http://3.145.46.6/"

		$b1 = "Const HIDDEN_WINDOW = 0"
		$b2 = "GetObject(\"winmgmts:\\\\"

		$c = "replace("

	condition:
		filesize < 10KB and ($a1 or (all of ($b*) and #c > 10))
}