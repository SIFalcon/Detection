

rule SUSP_Websites {
	meta:
		author = "SECUINFRA Falcon Team"
		description = "Detects the reference of suspicious sites that might be used to download further malware"
		version = "0.1"
		date = "17.02.2022"


	strings:
		$pasteee = "https://paste.ee" nocase 
		$pastebin = "https://pastebin.com" nocase

	condition:
		$paste or $pastebin
}