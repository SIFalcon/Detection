import "pe"

rule SUSP_Discord_Attachments_URL : pe download {
	meta:
		author = "SECUINFRA Falcon Team"
		date = "19.02.2022"
		description = "Detects a PE file that contains an Discord Attachments URL. This is often used by Malware to download further payloads"
		version = "0.1"

	strings:
		$url = "cdn.discordapp.com/attachments" nocase wide

	condition:
		uint16(0) == 0x5a4d 
		and $url
}

rule SUSP_Ngrok_URL : pe download {
	meta:
		author = "SECUINFRA Falcon Team"
		date = "27.02.2022"
		description = "Detects a PE file that contains an ngrok.io URL. This can be used as C2 channel"

	strings:
		$url = "ngrok.io" nocase wide

	condition:
		uint16(0) == 0x5a4d 
		and $url
}

rule SUSP_Reverse_DOS_header : pe obfuscation {
	meta:
		author = "SECUINFRA Falcon Team"
		date = "19.02.2022"
		description = "Detects an reversed DOS header"

	strings:
		$reversed = "edom SOD ni nur eb tonnac margorp sihT" ascii wide 

	condition:
		filesize < 500KB and $reversed
}

rule SUSP_DOTNET_PE_Download_To_SpecialFolder : dotnet download {
	meta:
		author = "SECUINFRA Falcon Team"
		date = "27.02.2022"
		description = "Detects a .NET Binary that downloads further payload and retrieves a special folder"

	strings:
		$special_folder = "Environment.SpecialFolder" wide

		$webclient = "WebClient()" wide
		$download = ".DownloadFile(" wide

	condition:
		uint16(0) == 0x5a4d 
		and filesize < 100KB 
		and pe.imports("mscoree.dll")
		and $special_folder 
		and $webclient 
		and $download
}

rule SUSP_DOTNET_PE_List_AV : dotnet av {
	meta:
		author = "SECUINFRA Falcon Team"
		date = "27.02.2022"
		description = "Detecs .NET Binary that lists installed AVs"

	strings:
		$mgt_obj_searcher = "\\root\\SecurityCenter2" wide
		$query = "Select * from AntivirusProduct" wide

	condition:
		uint16(0) == 0x5a4d
		and filesize < 200KB
		and pe.imports("mscoree.dll")
		and $mgt_obj_searcher
		and $query
}

rule SUSP_netsh_firewall_command : pe {
	meta:
		author = "SECUINFRA Falcon Team"
		date = "27.02.2022"

	strings:
		$netsh_delete = "netsh firewall delete" wide
		$netsh_add = "netsh firewall add" wide

	condition:
		uint16(0) == 0x5a4d
		and filesize < 100KB
		and ($netsh_delete or $netsh_add)
}