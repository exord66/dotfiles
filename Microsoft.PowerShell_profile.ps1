Import-Module -Name posh-git
Import-Module oh-my-posh
Import-Module Get-ChilditemColor
Set-Alias -Name l -Value Get-ChildItemColor
Set-Theme Paradox

Set-Location $Env:USERPROFILE\Desktop

# From @mattifestation
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())

# If the current session is elevated, prefix the prompt with '[Admin]'
if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Set-Item -Path Function:\prompt -Value "`"[Admin] PS $($executionContext.SessionState.Path.CurrentLocation)$('>' * ($nestedPromptLevel + 1)) `""
}

# Alias powershell to not display the annoying logo
function powershell { powershell.exe -NoLogo }

# Parse the Terminal profile
function Get-TerminalProfile {
    [CmdletBinding()]
    param ()

    if (Get-Item -Path Env:\WT_SESSION -ErrorAction SilentlyContinue) {
        $TerminalAppX = Get-AppxPackage -Name 'Microsoft.WindowsTerminal'

        $TerminalProfilePath = "$ENV:LocalAppData\Packages\$($TerminalAppX.PackageFamilyName)\LocalState\profiles.json"

        Write-Verbose "Terminal profile path: $TerminalProfilePath"

        $TerminalProfileText = Get-Content -Path $TerminalProfilePath -Raw

        ConvertFrom-Json -InputObject $TerminalProfileText
    }
}

# Launch an elevated terminal
function Start-ElevatedTerminal {
    $TerminalAppX = Get-AppxPackage -Name 'Microsoft.WindowsTerminal'

    if ($TerminalAppX) {
        Start-Process -FilePath "shell:AppsFolder\$($TerminalAppX.PackageFamilyName)!App" -Verb 'RunAs'
    }
}

# From: https://adsecurity.org/?p=478
function ConvertTo-Base64 {
  param(
    [Parameter(Mandatory = $True)]
    [string]$String
  )
  $Bytes = [System.Text.Encoding]::Unicode.GetBytes($String)
  $EncodedText = [Convert]::ToBase64String($Bytes)
  return $EncodedText
}

function ConvertFrom-Base64 {
  param(
    [Parameter(Mandatory = $True)]
    [string]$String
  )
  $DecodedText = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($String))
  $DecodedText
}

# From: https://blogs.msdn.microsoft.com/luc/2011/01/21/powershell-getting-the-hash-value-for-a-string/
function Get-StringHash {
  param(
    [string]$String,
    [string]$Hash = "SHA256"
  )

  $hasher = switch ($Hash) {
    "SHA512" { new-object System.Security.Cryptography.SHA512Managed }
    "SHA256" { new-object System.Security.Cryptography.SHA256Managed }
    "SHA1" { new-object System.Security.Cryptography.SHA1Managed }
    "MD5" { new-object System.Security.Cryptography.MD5CryptoServiceProvider }
  }

  $toHash = [System.Text.Encoding]::UTF8.GetBytes($string)
  $hashByteArray = $hasher.ComputeHash($toHash)
  foreach ($byte in $hashByteArray) {
    $res += $byte.ToString("x2")
  }
  return $res;
}

function Get-ExternalIPAddress {
  return (New-Object Net.WebClient).DownloadString('http://ifconfig.io/ip').Replace("`n", "")
}

function ConvertTo-ShortPath ($path) {
  $firstSlash = $path.IndexOf("\")
  $drive = $path.Substring(0, $firstSlash)
  $lastSlash = $path.LastIndexOf("\")
  $secondToLastSlash = $path.LastIndexOf("\", $lastSlash - 1)
  $thirdToLastSlash = $path.LastIndexOf("\", $secondToLastSlash - 1)
  $tail = $path.Substring($thirdToLastSlash)
  $shortPath = "$drive\..$tail"
  $shortPath
}

function Split-String {
  param (
    [Parameter(Mandatory = $true)]
    [string]$String,
    [int]$MinLength = 50,
    [int]$MaxLength = 120,
    [string]$VariableName = "data",
    [ValidateSet("PowerShell", "CSharp")]
    $Format = "PowerShell"
  )

  $index = 0
  $length = $String.length

  if ($Format -eq "CSharp") {
    Write-Output "string $VariableName = `"`";"
  }

  while ($index -lt $length) {
    $substringSize = Get-Random -Minimum $MinLength -Maximum $MaxLength
    if (($index + $substringSize) -gt $length) {
      $substringSize = $length - $index
    }
    $subString = $string.substring($index, $substringSize)
    if ($Format -eq "PowerShell") {
      Write-Output "`$$VariableName += `"$subString`""
    }
    if ($Format -eq "CSharp") {
      Write-Output "$VariableName += `"$subString`";"
    }
    $index += $substringSize
  }
}

function Get-WifiCreds {
  $listProfiles = netsh wlan show profiles | Select-String -Pattern "All User Profile" | %{ ($_ -split ":")[-1].Trim() };
  $listProfiles | foreach {
	  $profileInfo = netsh wlan show profiles name=$_ key="clear";
	  $SSID = $profileInfo | Select-String -Pattern "SSID Name" | %{ ($_ -split ":")[-1].Trim() };
	  $Key = $profileInfo | Select-String -Pattern "Key Content" | %{ ($_ -split ":")[-1].Trim() };
	  [PSCustomObject]@{
		  WifiProfileName = $SSID;
		  Password = $Key
	  }
  }
}
