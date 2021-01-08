rule MuddyWater_MoriAgent {
	meta:
		description = "Detects MuddyWater MoriAgent backdoor"
		author = "CyberDefenders"
	strings:
		$s1 = "&t=r" wide ascii
		$s2 = "&t=d" wide ascii
		$s3 = "&t=t" wide ascii
		$s4 = "&t=u" wide ascii
		$s5 = "&cv=" wide ascii
		$s6 = "&ch=" wide ascii
		$s7 = "SOfTWARE\\NFC\\" wide ascii
		$s8 = "|x7d873iqq" wide ascii
		$s9 = "ljyfiiwnskt" wide ascii
		$c = "Content-Type: application/json" wide ascii
	condition:
		uint16(0) == 0x5A4D and $c and 3 of ($s*)
}
