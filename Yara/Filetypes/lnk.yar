rule SUSP_LNK_CMD {
	meta:
		author = "SECUINFRA Falcon Team"
		date = "19.02.2022"
		description = "Detects the reference to cmd.exe inside an lnk file, which is suspicious"
	strings:
		$header = {4c00 0000 0114 0200 0000}
		$cmd = "cmd.exe" ascii wide

	condition:
		filesize < 5KB 
		and ($header at 0) 
		and $cmd
}

rule SUSP_LNK_PowerShell {
	meta:
		author = "SECUINFRA Falcon Team"
		date = "27.02.2022"
		description = "Detects the reference to powershell inside an lnk file, which is suspicious"
	strings:
		$header = {4c00 0000 0114 0200 0000}
		$ps1 = "powershell.exe" ascii wide

	condition:
		filesize < 5KB 
		and ($header at 0) 
		and $ps1
}

rule SUSP_LNK_Staging_Directory {
	meta:
		author = "SECUINFRA Falcon Team"
		date = "27.02.2022"
		description = "Detects typical staging directories being referenced inside lnk files"

	strings:
		$header = {4c00 0000 0114 0200 0000}
		$public = "$env:public" wide

	condition:
		filesize < 20KB
		and ($header at 0)
		and $public

}