rule DROPPER_WSHRAT_Stage_1 {
	meta:
		author = "SECUINFRA Falcon Team"
		reference = "https://bazaar.abuse.ch/sample/ad24ae27346d930e75283b10d4b949a4986c18dbd5872a91f073334a08169a14/"
		date = "11.02.2022"
		hash = "793eff1b2039727e76fdd04300d44fc6"
		description = "Detects the first stage of WSHRAT as obfuscated JavaScript"

	strings:
		$a1 = "'var {0} = WS{1}teObject(\"ado{2}am\");"

		$b1 = "String[\"prototype\"]"
		$b2 = "this.replace("
		$b3 = "Array.prototype"

	condition:
		filesize < 1500KB and $a1 and #b3 > 3 and #b1 > 2 and $b2
}