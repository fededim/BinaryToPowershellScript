<#
.SYNOPSIS

Sends a string or a text file as keypresses on the keyobard

.DESCRIPTION

You must specift at least either Filename or Keys parameter.
You can also specify an optional Delay in seconds and a WindowTitle to activate before sending the keypresses.

.PARAMETER Filename
Specifies the file name, alternative to Keys parameter

.PARAMETER Keys
Specifies the keys, alternative to Filename parameter

.PARAMETER Delay
Specifies the amount of time in seconds to wait before starting sending the keypresses

.PARAMETER WindowTitle
Specifies the window title to activate before starting sending the keypresses

.INPUTS

None.

.OUTPUTS

None

.EXAMPLE

PS> SendFileOrKeys -f "BinaryToPowershellScript.ps1" -d 10

.EXAMPLE

PS> SendFileOrKeys -k "Write-Host 'Hello how are you ?'" -w "Powershell 7 (x64)"

.EXAMPLE

PS> SendFileOrKeys -k "Write-Host 'Hello how are you ?'"

.LINK

https://github.com/fededim/BinaryToPowershellScript

.NOTES

Implementation of this script is partially borrowed from https://superuser.com/questions/1249976/sendkeys-method-in-powershell.
Remember to set English keyboard, the SendKeys api does not support other keyboards!
#>
function SendFileOrKeys {
 	 [CmdletBinding()]
     param (
         [Parameter(Mandatory=$false)]  [Alias('f')] [String] $Filename,
         [Parameter(Mandatory=$false)]  [Alias('k')] [String] $Keys,
         [Parameter(Mandatory=$false)]  [Alias('d')] [Nullable[int]] $InitialDelay=$null,
         [Parameter(Mandatory=$false)]  [Alias('i')] [int] $IntraChunkDelayMs=200,
         [Parameter(Mandatory=$false)]  [Alias('c')] [int] $ChunkSize=100,
         [Parameter(Mandatory=$false)]  [Alias('w')] [String] $WindowTitle=$null
     )

     [System.IO.Directory]::SetCurrentDirectory((Convert-Path (Get-Location).Path))

     $wshell = New-Object -ComObject wscript.shell;

     If (![System.String]::IsNullOrEmpty($WindowTitle)) {
         $wshell.AppActivate($WindowTitle)
         if ($InitialDelay -eq $null) {
             $InitialDelay = 1
         }
     }

     If ($InitialDelay -ne $null) {
         Start-Sleep $InitialDelay
     }

     If (![System.String]::IsNullOrEmpty($Filename)) {  
        
        $text = (EncodeForSendKeys ([System.IO.File]::ReadAllText($Filename)))
        Set-Content -Path ".\out.txt" -Value $text

        $wshell.SendKeys($text)

        #$keypresses = [System.Text.RegularExpressions.Regex]::Replace([System.IO.File]::ReadAllText($Filename),"[+^%~(){}]", "{`$0}")   
        #Set-Content -Path ".\out.txt" -Value $keypresses

        #for ($i=0;$i -lt $keypresses.Length;$i+=$ChunkSize) {
        #    $wshell.SendKeys($keypresses.Substring($i, [System.Math]::Min($ChunkSize, $keypresses.Length-$i)))
        #    Start-Sleep -Milliseconds $IntraChunkDelayMs
        #}

        #$lines = [System.IO.File]::ReadAllLines($Filename)
        
        #foreach ($line in $lines) {
        #   $wshell.SendKeys((EncodeForSendKeys $line))
        #    Start-Sleep -Milliseconds $IntraChunkDelayMs
        #}
     }
     else {
        $wshell.SendKeys((EncodeForSendKeys $Keys))
     }
}


function EncodeForSendKeys {
    [OutputType([String])]
    param ([String] $string)
    
    $encode = [System.Text.RegularExpressions.Regex]::Replace($string,"[+^%~(){}]", "{`$0}")
    $adjustNewLines = [System.Text.RegularExpressions.Regex]::Replace($encode,"(`r`n|`r|`n)+", " %(096){ENTER}")

    return $adjustNewLines.Replace("`t","{TAB}")
}