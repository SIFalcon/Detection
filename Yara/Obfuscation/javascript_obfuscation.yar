
rule OBFUS_JavaScript_WScript_Hex_Strings_Usage {
	meta:
		author = "SECUINFRA Falcon Team"
		date = "12.02.2022"
		description = "Detects the frequent usage of Wscript to get an hex encoded string from an array and interpret it. Used by e.g WSHRAT"

	strings:
		$wscript = "= WScript["

		// first 4 bytes of common strings
		$hex_enc_str1 = "\\x63\\x72\\x65\\x61" // createObject
		$hex_enc_str2 = "\\x73\\x63\\x72\\x69" // scriptName
		$hex_enc_str3 = "\\x71\\x75\\x69\\x74" //quit
		$hex_enc_str4 = "\\x41\\x72\\x67\\x75" // Arguments

	condition:
		#wscript > 30 and 2 of ($hex_enc_str*)
}