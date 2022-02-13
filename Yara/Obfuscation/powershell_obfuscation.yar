rule OBFUS_PowerShell_Execution {
	meta:
		author = "SECUINFRA Falcon Team"
		date = "09.02.2022"
		description = "Detects some variations of obfuscated PowerShell code to execute further PowerShell code"

	strings:
		$a1 = "-nop -w hiddEn -Ep bypass -Enc" ascii nocase
		$a2 = "-noP -sta -w 1 -enc" ascii nocase
		
		$b1 = "SQBFAF"

	condition:
		1 of ($a*) and $b1
}

rule OBFUS_PowerShell_Replace_Tilde {
	meta:
		author = "SECUINFRA Falcon Team"
		date = "10.02.2022"
		description = "Detects usage of Replace to replace tilde. Often observed in obfuscation"
		reference = "https://bazaar.abuse.ch/sample/4c391b57d604c695925938bfc10ceb4673edd64e9655759c2aead9e12b3e17cf/"

	strings:
		$a = ".Replace(\"~\",\"0\")"

	condition:
		$a
}

rule OBFUS_PowerShell_Common_Replace {
	meta:
		author = "SECUINFRA Falcon Team"
		date = "12.02.2022"
		description = "Detects the common usage of replace for obfuscation"

	strings:
		$replace = ".replace(" nocase

	condition:
		filesize < 100KB and #replace > 20
}
