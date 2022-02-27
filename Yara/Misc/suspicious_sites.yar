rule SUSP_Websites {
	meta:
		author = "SECUINFRA Falcon Team"
		description = "Detects the reference of suspicious sites that might be used to download further malware"
		version = "0.2"
		date = "27.02.2022"


	strings:
		$site_1 = "https://paste.ee" nocase 
		$site_2 = "https://pastebin.com" nocase 
		$site_3 = "https://drive.google.com" nocase 
		$site_4 = "cdn.discordapp.com/attachments" nocase 
		$site_5 = "https://transfer.sh" nocase 
		$site_6 = "ngrok.io" nocase

	condition:
		any of ($site_*)
}