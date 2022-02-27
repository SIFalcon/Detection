
rule SUSP_Scheduled_Tasks_Create_From_Susp_Dir {
	meta:
		author = "SECUINFRA Falcon Team"
		date = "21.02.2022"
		description = "Detects a PowerShell Script that creates a Scheduled Task that runs from an suspicious directory"
		version = "0.1"

	strings:
		$create = "New-ScheduledTaskAction"
		$execute = "-Execute"

		$trigger = "New-ScheduledTaskTrigger"
		$at_param = "-At"

		$register = "Register-ScheduledTask"
		$action = "-Action"

		$path1 = "C:\\ProgramData\\"
		$path2 = "C:\\Windows\\Temp"
		$path3 = "AppData\\Local"

	condition:
		filesize < 30KB and 1 of ($path*) and ($create and $execute) or ($trigger and $at_param) or ($register and $action)
}

rule SUSP_Reverse_Run_Key {
	meta:
		author = "SECUINFRA Falcon Team"
		date = "27.02.2022"
		description = "Detects a Reversed Run Key"

	strings:
		$run = "nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" wide

	condition:
		 filesize < 100KB and $run
}