rule RANSOM_ESXiArgs_Ransomware_Encryptor_Feb23
{
	meta:
		author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
		description = "Detects the ESXiArgs Ransomware 'encrypt' binary"
		reference = "https://secuinfra.com/en/techtalk/hide-your-hypervisor-analysis-of-esxiargs-ransomware"
		date = "2023-02-07"
		tlp = "CLEAR"

	strings:
		// Sosemanuk Pseudo-Random Number Generator
        	$sosemanuk_prng = {48 8b 45 f8 48 01 45 e0 48 8b 45 f8 48 29 45 d8 48 8b 45 e8 8b 90 80 00 00 00 48 8b 45 f8 01 c2 48 8b 45 e8 89 90 80 00 00 00}
        
        	// Sosemanuk Multiplication Tables
        	// based on Findcrypt3 rule https://github.com/polymorf/findcrypt-yara/blob/ad165a6b2bd5b56932657b96edffa851b5b00b15/findcrypt3.rules#L1522
        	$sosemanuk_mul_a = {00 00 00 00 13 CF 9F E1 26 37 97 6B 35 F8 08 8A [992] DE 4D 5B B5 CD 82 C4 54 F8 7A CC DE EB B5 53 3F}
        	$sosemanuk_mul_ia = {00 00 00 00 CD 40 0F 18 33 80 1E 30 FE C0 11 28 [992] 1C 65 E2 9E D1 25 ED 86 2F E5 FC AE E2 A5 F3 B6}

        	$interpreter = "/lib64/ld-linux-x86-64.so.2"

        	$debug0 = "encrypt_bytes: too big data"
        	$debug1 = "Progress: %f"

        	$help = "usage: encrypt <public_key> <file_to_encrypt> [<enc_step>] [<enc_size>] [<file_size>]"

	condition:
		uint32be(0x0) == 0x7F454C46
		and all of ($sosemanuk_*)
        	and $interpreter
        	and 2 of ($debug*)
        	and $help
}
