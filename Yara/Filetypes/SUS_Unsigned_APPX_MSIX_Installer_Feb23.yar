rule SUS_Unsigned_APPX_MSIX_Installer_Feb23
{
	meta:
		author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
		description = "Detects suspicious, unsigned Microsoft Windows APPX/MSIX Installer Packages"
		reference = "https://twitter.com/SI_FalconTeam/status/1620500572481945600"
		date = "2023-02-01"
		tlp = "CLEAR"

	strings:
		$s_manifest = "AppxManifest.xml"
		$s_block = "AppxBlockMap.xml"
		$s_peExt = ".exe"

		// we are not looking for signed packages
		$sig = "AppxSignature.p7x"

	condition:
		uint16be(0x0) == 0x504B
		and 2 of ($s*)
		and not $sig
}
