rule MAL_AgentTesla_Stage_1 : JavaScript AgentTesla ObfuscatorIO {
	meta:
		author = "SECUINFRA Falcon Team"
		hash = "bd257d674778100639b298ea35550bf3bcb8b518978c502453e9839846f9bbec"
		reference = "https://bazaar.abuse.ch/sample/bd257d674778100639b298ea35550bf3bcb8b518978c502453e9839846f9bbec/"	
		description = "Detects the first stage of AgentTesla (JavaScript)"

	strings:
		$mz = "TVq"
		
		$a1 = ".jar"
		$a2 = "bin.base64"
		$a3 = "appdata"
		$a4 = "skype.exe"

	condition:
		filesize < 500KB and $mz and 3 of ($a*)
}