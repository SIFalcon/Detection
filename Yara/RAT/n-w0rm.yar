rule NW0rm { 
	meta:
		description = "Detect the final RAT dropped by N-W0rm"
		author = "SECUINFRA Falcon Team"
		reference_1 = "https://bazaar.abuse.ch/sample/1b976a1fa26c4118d09cd6b1eaeceafccc783008c22da58d6f5b1b3019fa1ba4/"
		reference_2 = "https://www.virustotal.com/gui/file/afc5a5a1a18f3e65bffa6e3d4e68ed90c102a942156db77ef570c4e8d1394dbc"
		hash = "08587e04a2196aa97a0f939812229d2d"
		date = "03.02.2022"
          
	strings:
		$a1 = "N-W0rm" fullword wide
		$a2 = "N_W0rm" fullword wide
		$a3 = "|NW|" fullword wide
		
		$b1 = "Select * from AntivirusProduct" fullword wide
		$b2 = "ExecutionPolicy Bypass -WindowStyle Hidden -NoExit -File" fullword wide
		$b3 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36" fullwo $b4 = "killer" fullword wide
		$b4 = "nyanmoney02.duckdns.org" fullword wide

	condition:
		uint16(0) == 0x5a4d and 2 of ($a*) and 2 of ($b*)
}
