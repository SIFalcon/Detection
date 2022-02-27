import "pe"

rule MAL_AsyncRAT_Config_Decryption : rat malware asyncrat {
	meta:
		author = "SECUINFRA Falcon Team"
		date = "27.02.2022"
		description = "Detects AsnycRAT based on it's config decryption routine"

	strings:
		$config_decryption = { 7E [4] 6F [4] 80 [4] 7E [4] 7E [4] 6F [4] 80 [4] 7E [4] 7E [4] 6F [4] 80 [4] 7E }

	condition:
		uint16(0) == 0x5a4d
		and filesize < 200KB
		and pe.imports("mscoree.dll")
		and $config_decryption
}