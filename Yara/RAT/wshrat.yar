
rule MAL_WSHRAT : RAT JavaScript WSHRAT {
	meta:
		author = "SECUINFRA Falcon Team"
		date = "12.02.2022"
		description = "Detects the final Payload of WSHART"
		hash = "b7f53ccc492400290016e802e946e526"


	strings:
		$function1 = "runBinder"
		$function2 = "getBinder"
		$function3 = "Base64Encode"
		$function4 = "payloadLuncher"
		$function5 = "getMailRec"
		$function6 = "getHbrowser"
		$function7 = "passgrabber"
		$function8 = "getRDP"
		$function9 = "getUVNC"
		$function10 = "getConfig"
		$function11 = "getKeyLogger"
		$function12 = "enumprocess"
		$function13 = "cmdshell"
		$function14 = "faceMask"
		$function15 = "upload"
		$function16 = "download"
		$function17 = "sitedownloader"
		$function18 = "servicestarter"
		$function19 = "payloadLuncher"
		$function20 = "keyloggerstarter"
		$function21 = "reverserdp"
		$function22 = "reverseproxy" 
		$function23 = "decode_pass"
		$function24 = "disableSecurity"
		$function25 = "installsdk"

		$cmd1 = "osversion = eval(osversion)"
		$cmd2 = "download(cmd[1],cmd[2])"
		$cmd3 = "keyloggerstarter(cmd[1]"
		$cmd4 = "decode_pass(retcmd);"

	condition:
		 filesize < 2MB and 2 of ($cmd*) and 12 of ($function*) 
}