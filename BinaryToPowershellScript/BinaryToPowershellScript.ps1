function BinaryToPowershellScript {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory=$true)]  [Alias('i')] [String[]] $Inputs,
		[Parameter(Mandatory=$false)] [Alias('o')] [String] $OutputFolder,
		[Parameter(Mandatory=$false)] [Alias('b')] [switch] $Base64=$false,
		[Parameter(Mandatory=$false)] [Alias('d')] [switch] $Decimal=$false,
		[Parameter(Mandatory=$false)] [Alias('h')] [switch] $Hash=$false,
		[Parameter(Mandatory=$false)] [Alias('s')] [switch] $SingleFile=$false,
		[Parameter(Mandatory=$false)] [Alias('r')] [switch] $Recurse=$false,
		[Parameter(Mandatory=$false)] [Alias('p')] [String] $Password
	)

	$global:KEYSIZE = 256

	[System.IO.Directory]::SetCurrentDirectory((Get-Location).Path)
	
	if ([System.String]::IsNullOrEmpty($OutputFolder)) {
		$OutputFolder = (Resolve-Path '.').Path
	}

	$script = CreateScriptHeader $Password
	$outputFile = [System.IO.Path]::Combine($OutputFolder,"SingleScript$(TernaryExpression $Base64 "_base64" '').ps1")
	foreach ($inputFiles in $Inputs)
	{
		$path = [System.IO.Path]::GetDirectoryName($inputFiles)
		foreach ($file in [System.IO.Directory]::GetFiles($path, [System.IO.Path]::GetFileName($inputFiles), (TernaryExpression $Recurse ([System.IO.SearchOption] 'AllDirectories') ([System.IO.SearchOption] 'TopDirectoryOnly'))))
		{
			if (!$singlefile)
			{
				$script = createscriptheader $password
				$outputfile = [System.IO.Path]::combine($outputfolder,"$([System.IO.Path]::getfilename($file).replace(".", "_"))_script$(ternaryexpression $base64 "_base64" '').ps1")
			}
			$additionalText = TernaryExpression (!$SingleFile) "into $outputFile..." ''
			Write-Host "Scripting file $file $additionalText"
			$inputFilesBytes = [System.IO.File]::ReadAllBytes($file)
 			[byte[]] $bytes = TernaryExpression ([System.String]::IsNullOrEmpty($Password)) $inputFilesBytes (EncryptBytes $inputFilesBytes  $Password)
			if ($Base64)
			{
				$b64 = [System.Convert]::ToBase64String($bytes)
				[void] $script.Append("`t[byte[]] `$bytes = [System.Convert]::FromBase64String(`'$b64`')")
			}
			else
			{
				[void] $script.Append("`t[byte[]] `$bytes = ")
				foreach ($b in $bytes)
				{
					if ($Decimal)
					{
						[void] $script.Append("$($b.ToString('D')),")
					}
					else
					{
						[void] $script.Append("0x$($b.ToString('X2')),")
					}
				}
				($script.Length--)
			}
			$hashParameter = TernaryExpression $Hash "`'$(ComputeSha256Hash($inputFilesBytes))`'" ''
			[void] $script.Append("`n`tcreateFile `'$file`' `$bytes `$password $hashParameter`n`n")
			if (!$SingleFile) {
				[void] $script.Append("`}`n`ncreateFiles `'$Password`'`n")
				[System.IO.File]::WriteAllText($outputFile,$script.ToString())
			}
		}
	}
	if ($SingleFile)
	{
		Write-Host "Creating single script file $outputFile..."
		[void] $script.Append("`}`n`ncreateFiles `'$Password`'`n")
		[System.IO.File]::WriteAllText($outputFile,$script.ToString())
	}
}



function TernaryExpression {
    Param (
		[Parameter(Mandatory=$true)] [System.Boolean] $booleanExpression,
		[Parameter(Mandatory=$false)] $TrueExpression,
		[Parameter(Mandatory=$false)] $FalseExpression
	)

	if ($booleanExpression) {
		return ,$TrueExpression
	}
	else {
		return ,$FalseExpression
	}
}


function ComputeSha256Hash
{
	[OutputType([string])]
	param ([Parameter(Mandatory=$true)] [byte[]] $bytes)
	[System.Security.Cryptography.SHA256]$sha256Hash = $null
	try
	{
		$sha256Hash = [System.Security.Cryptography.SHA256]::Create()
		return [System.BitConverter]::ToString($sha256Hash.ComputeHash($bytes)).Replace("-",'')
	}
	finally
	{
		$sha256Hash.Dispose()
	}
}



function EncryptBytes
{
   [OutputType([byte[]])]
    Param (
		[Parameter(Mandatory=$true)] [System.Byte[]] $inputFiles,
		[Parameter(Mandatory=$false)] [System.String] $password
	) 

	$pbkdf2DerivedBytes = (New-Object -TypeName System.Security.Cryptography.Rfc2898DeriveBytes -ArgumentList $password,16,2000)
	$AES = $null
	try
	{
		$AES = [System.Security.Cryptography.Aes]::Create()
		$AES.KeySize = $global:KEYSIZE
		$AES.Key = $pbkdf2DerivedBytes.GetBytes($global:KEYSIZE/8)
		$AES.Mode = [System.Security.Cryptography.CipherMode]::CBC
		$AES.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
		[System.IO.MemoryStream]$memoryStream = $null
		try
		{
			$memoryStream = (New-Object -TypeName System.IO.MemoryStream)
			[System.Security.Cryptography.CryptoStream]$cryptoStream = (New-Object -TypeName System.Security.Cryptography.CryptoStream -ArgumentList $memoryStream,$AES.CreateEncryptor(),([System.Security.Cryptography.CryptoStreamMode] 'Write'))
			$memoryStream.Write($pbkdf2DerivedBytes.Salt,0,16)
			$memoryStream.Write($AES.IV,0,16)
			$cryptoStream.Write($inputFiles,0,$inputFiles.Length)
			$cryptoStream.FlushFinalBlock()
			return ,$memoryStream.ToArray()
		}
		finally
		{
			$memoryStream.Dispose()
		}
	}
	finally
	{
		$AES.Dispose()
	}
}



function CreateScriptHeader
{
	[OutputType([System.Text.StringBuilder])]
    Param (
		[Parameter(Mandatory=$false)] [System.String] $Password
	) 

	$sb = (New-Object -TypeName System.Text.StringBuilder)
	if (![System.String]::IsNullOrEmpty($Password))
	{
		        # uncomment these lines and put them in the decryptBytes function below (row "$Dec = $AES.CreateDecryptor()") to troubleshoot encryption
                #Write-Host ''Password $password''
                #Write-Host ''KEY: $([System.BitConverter]::ToString($AES.Key))''
                #Write-Host ''IV: $([System.BitConverter]::ToString($AES.IV))''
                #Write-Host ''EncryptedData: $([System.BitConverter]::ToString($EncryptedData))''

                # uncomment these lines and put them in the decryptBytes function below (row ",$result") to troubleshoot encryption
                #Write-Host ''DecryptedData: $([System.BitConverter]::ToString($result))''

                [void] $sb.AppendLine(@"
function decryptBytes `{
`t[OutputType([byte[]])]
`tParam (
`t`t[Parameter(Mandatory=`$true)] [System.Byte[]] `$bytes,
`t`t[Parameter(Mandatory=`$true)] [System.String] `$password
`t) 

`t# Split IV and encrypted data
`t`$PBKDF2Salt = New-Object Byte[] 16
`t`$IV = New-Object Byte[] 16
`t`$EncryptedData = New-Object Byte[] (`$bytes.Length-32)
    
`t[System.Array]::Copy(`$bytes, 0, `$PBKDF2Salt, 0, 16)
`t[System.Array]::Copy(`$bytes, 16, `$IV, 0, 16)
`t[System.Array]::Copy(`$bytes, 32, `$EncryptedData, 0, `$bytes.Length-32)

`t# Generate PBKDF2 from Salt and Password
`t`$PBKDF2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(`$password, `$PBKDF2Salt, 2000)

`t# Setup our decryptor
`t`$AES = [Security.Cryptography.Aes]::Create()
`t`$AES.KeySize = $global:KEYSIZE
`t`$AES.Key = `$PBKDF2.GetBytes((global:KEYSIZE/8))
`t`$AES.IV = `$IV
`t`$AES.Mode = [System.Security.Cryptography.CipherMode]::CBC
`t`$AES.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

`t`$Dec = `$AES.CreateDecryptor()

`t`$EncryptedMemoryStream = New-Object System.IO.MemoryStream @(,`$EncryptedData)
`t`$DecryptedMemoryStream = New-Object System.IO.MemoryStream
`t`$CryptoStream = New-Object System.Security.Cryptography.CryptoStream(`$EncryptedMemoryStream, `$Dec, [System.Security.Cryptography.CryptoStreamMode]::Read)

`t`$CryptoStream.CopyTo(`$DecryptedMemoryStream)
	
`t`$result = `$DecryptedMemoryStream.ToArray()

`t,`$result
`}

"@)
	}

	$decryptBytes = TernaryExpression ([System.String]::IsNullOrEmpty($Password)) '' "`$bytes = `$(decryptBytes `$bytes `$password)"
	[void] $sb.AppendLine(@"
function createFile  `{
`tparam (
`t`t[Parameter(Mandatory=`$true)] [String] `$file,
`t`t[Parameter(Mandatory=`$true)] [byte[]] `$bytes,
`t`t[Parameter(Mandatory=`$false)] [String] `$password,
`t`t[Parameter(Mandatory=`$false)] [String] `$hash)
	
`t`$null = New-Item -ItemType Directory -Path ([System.IO.Path]::GetDirectoryName(`$file)) -Force
`t$decryptBytes
`tif (`$global:core) `{ Set-Content -Path `$file -Value `$bytes -AsByteStream -Force `} else `{ Set-Content test.txt -Value `$bytes -Encoding Byte -Force `}

`tif (![System.String]::IsNullOrEmpty(`$hash)) `{
`t`t`$actualHash = (Get-FileHash -Path `$file -Algorithm Sha256).Hash
`t`tif (`$actualHash -ne `$hash) `{
`t`t`tWrite-Error ''Integrity check failed on `$file expected `$hash actual `$actualHash!''
`t`t`}
`t`}

`tWrite-Host ''Created file `$file Length `$(`$bytes.Length)''
`}

"@)
	[void] $sb.Append("function createFiles  `{`n`tparam ([Parameter(Mandatory=$(TernaryExpression ([System.String]::IsNullOrEmpty($Password)) "`$false" "`$true"))] [String] `$password)`n`n")
	[void] $sb.Append("`t`$setContentHelp = (help Set-Content) | Out-String`n`tif (`$setContentHelp.Contains('AsByteStream')) { `$global:core = `$true } else { `$global:core = `$false }`n`n")
	return $sb
}
