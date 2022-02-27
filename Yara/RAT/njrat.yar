import "pe"

rule MAL_njrat {
	meta:
		author = "SECUINFRA Falcon Team"
		date = "27.02.2022"

		hash_1 = "38928ae157586ec7785121f79ac5f9eb6727eae66aa512d8adf52d9485928126"
		hash_2 = "fcfa50ca0d4dcf2bb6e96e7b7a223138068f2d6a458d2630757e3bcbe0684aaa"
		hash_3 = "fa28ad86ab796c8e18096badc31bcb1719474d268945172d983bb30ded219944"

	strings:
		$mutex_1 = "02ddd2742fd5023579c925948979506c" wide
		$mutex_2 = "f2defcfce1660e18fd445b5dbce27282" wide
		$mutex_3 = "f7d3b79624476341312866012d0bbf19" wide

		$a1 = "\"|'|'|\"" wide
		$a2 = "SEE_MASK_NOZONECHECKS" wide
		
		$b1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide
		$b2 = "netsh firewall" wide
		$b3 = "[ENTER]\\r\\n" wide
		$b4 = "Execute ERROR" wide

	condition:
		uint16(0) == 0x5a4d
		and filesize < 100KB
		and pe.imports("mscoree.dll")
		and pe.imports("avicap32.dll")
		and 1 of ($mutex_*)
		or (
			1 of ($a*)
			and 2 of ($b*)
		)
}