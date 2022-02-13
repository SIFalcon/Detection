import "pe"

rule MAL_Redline_Certificate_Bosch {
	meta:
		author = "SECUINFRA Falcon Team"
		date = "12.02.2022"
		description = "Detects Certificate used by Redline Stealer"
		reference = "https://bazaar.abuse.ch/sample/60e40ccfc16ca9f36dee7ec2b4e2fc81398ff408bf7cc63fb7ddf0fef1d4b72b"

	condition:
		uint16(0) == 0x5a4d and
		for any i in (0..pe.number_of_signatures) : (
			pe.signatures[i].issuer contains "BOSCH BOSCH SDS-plus Professional 607557501" and
			pe.signatures[i].serial == "72:76:34:57:ef:50:d5:b0:4e:00:b3:74:ab:c6:ff:11"
		)
}

rule MAL_Redline_Certificate_GeForce {
	meta:
		author = "SECUINFRA Falcon Team"
		date = "13.02.2022"
		description = "Detects Certificate used by Redline Stealer"
		reference = "https://bazaar.abuse.ch/sample/f36c1c2f6b6f334be93b72fccb8e46cadd59304dc244b3a5aabecc8f4018eb77"

	condition:
		uint16(0) == 0x5a4d and
		for any i in (0..pe.number_of_signatures) : (
			pe.signatures[i].issuer contains "Palit GeForce RTX 3070 Dual H21 LHR" and
			pe.signatures[i].serial == "11:cd:b5:d5:9d:fb:90:84:45:f3:a7:22:25:47:a4:54"
		)
}