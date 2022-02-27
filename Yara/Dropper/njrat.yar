
rule DROPPER_njrat_VBS : vbs njrat dropper {
	meta:
		author = "SECUINFRA Falcon Team"
		date = "27.02.2022"
		reference = "https://bazaar.abuse.ch/sample/daea0b5dfcc3e20b75292df60fe5f0e16a40735254485ff6cc7884697a007c0d/"

	strings:
		$a1 = "[System.Convert]::FromBase64String( $Codigo.replace(" wide
		$a2 = "WDySjnçIJwGnYGadvbOQBvKzlNzWDDgUqgGlLKÇQvvkKPNjaUIdApxgqHTfDLUkfOKsXOKçDcQtltyXDXhNNbGNNPACgAzWRtuLt" wide 

		$b1 = "CreateObject(\"WScript.Shell\")" wide
		$b2 = "\"R\" + \"e\" + \"p\" + \"l\" + \"a\" + \"c\" + \"e\"" wide
		$b3 = "BBBB\" + \"BBBBBBB\" + \"BBBBBBB\" + \"BBBBBBBB" wide
		$b4 = "& DGRP & NvWt & DGRP &" wide
		$b5 = "= ogidoC$" wide

	condition:
		filesize < 300KB
		and (
			(1 of ($a*)) or (2 of ($b*))
		)
}