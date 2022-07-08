import "pe"

rule RANSOM_MedusaLocker_July22 : Ransomware {

   meta:
      author = "SECUINFRA Falcon Team"
      description = "Detects MedusaLocker Ransomware"
      reference = "https://www.cisa.gov/uscert/sites/default/files/publications/AA22-181A_stopransomware_medusalocker.pdf"
      date = "2022-07-08"
      tlp = "WHITE"
      hash0 = "80ca82e3e62514c66250ff91cc28a945758d435665cd36a347bf9fea9278aa48"
      hash1 = "09ac3b065defa5e69db8573ec2d201e3199ad7508ed775174fe76c18f8b9710b"
      hash2 = "bee9de4694ab25b125b95579235d9f8a5ec48658dfd5b7feb78915ee2aacc6ca"
      hash3 = "1ff4ab45cc7b71d22d2433214eed2b7b2344bb1921c97a44c44fe5f3a78f8135"
      hash4 = "af768da08a34ddf503522186a22e65e623491e48754356210cc6798598f85266"

   strings:
      $log0 =  "[LOCKER] Init cryptor is failed" wide
      $log1 =  "[LOCKER] Kill processes" wide
      $log2 =  "[LOCKER] Scan" wide
      $log3 =  "[LOCKER] Already Scan" wide 
      $log4 =  "[LOCKER] Is running" wide
      $log5 =  "[LOCKER] Is already running" wide
      $log6 =  "[LOCKER] Priv: ADMIN" wide
      $log7 =  "[LOCKER] Priv: USER" wide
      $log8 =  "[LOCKER] Init cryptor" wide
      $log9 =  "[LOCKER] Put ID to HTML-code" wide
      $log10 = "[LOCKER] Init cryptor is failed" wide
      $log11 = "[LOCKER] Add to autorun" wide
      $log12 = "[LOCKER] Put ID to HTML-code is failed!" wide
      $log13 = "[LOCKER] Scan hidden devices" wide
      $log14 = "[LOCKER] Stop and delete services" wide
      $log15 = "[LOCKER] Kill processes" wide
      $log16 = "[LOCKER] Remove backups" wide
      $log17 = "[LOCKER] Lock drive " wide
      $log18 = "[LOCKER] Run scanning..." wide
      $log19 = "[LOCKER] Sleep at 60 seconds..." wide

      $mutex = "{8761ABBD-7F85-42EE-B272-A76179687C63}" wide
      $uacbypass0 = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" wide
      $uacbypass1 = "{6EDD6D74-C007-4E75-B76A-E5740995E24C}" wide

      $note0 = "HOW_TO_RECOVER_DATA.html" ascii
      $note1 = "We gathered highly confidential/personal data. These data are currently stored on" ascii
      $note2 = "<b>/!\\ YOUR COMPANY NETWORK HAS BEEN PENETRATED /!\\" ascii
      $note3 = "<!-- !!! dont changing this !!! -->" fullword ascii

      $ext = ".dll,.sys,.ini,.rdp,.encrypted,.exe" ascii
      $services = "Intuit.QuickBooks.FCS,QBCFMonitorService,sqlwriter,msmdsrv,tomcat6,zhudongfangyu" ascii

      $system0 = "wbadmin DELETE SYSTEMSTATEBACKUP -deleteOldest" wide
      $system1 = "vssadmin.exe Delete Shadows /All /Quiet" wide
      $system2 = "bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures" wide
      $system4 = "bcdedit.exe /set {default} recoveryenabled No" wide
      $system5 = "wmic.exe SHADOWCOPY /nointeractive" wide
      
   condition:
      uint16(0) == 0x5a4d
      and pe.imphash() == "1a395bd10b20c116b11c2db5ee44c225"
      and filesize > 450KB // Size on Disk/1.5
      and filesize < 1MB // Size of Image*1.5
      and all of ($log*)
      and $mutex
      and any of ($uacbypass*)
      and 2 of ($note*)
      and $ext and $services
      and 2 of ($system*)
}