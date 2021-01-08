rule MuddyWater_ForeLord_implant {
	meta:
	  description = "Detects MuddyWater ForeLord DNS implant"
      author = "CyberDefenders"
	  reference = "https://www.secureworks.com/blog/business-as-usual-for-iranian-operations-despite-increased-tensions"
	strings:
		$hex1 = { 0F 10 06 0F 11 85 ?? ?? FF FF F3 0F 7E 46 ?? } 
		$hex2 = { C7 46 ?? ?? ?? ?? ?? C7 46 ?? ?? ?? ?? ?? 66 0F D6 }		
		$ip = "8.8.8.8" wide ascii
		$s1 = "0000" wide ascii
		$s2 = "0001" wide ascii
		$s3 = "0002" wide ascii
		$s4 = "lordlordlordlord"
	condition:
		uint16(0) == 0x5a4d and (($ip and 2 of ($s*)) or (#hex1 >= 2 and #hex2 >=2))
}

