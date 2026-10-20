# PassBundle script access: fetch a credential a script token was granted,
# and decrypt it on this machine. The server never sees what it holds: the
# key comes from the token's seed, which only this script and the admin who
# made the token have. See docs/script-access.md in PassBundle's meta repo.
#
#   Import-Module .\PassBundle.psm1
#   $credential = Get-PassBundleCredential -Item "Domain admin"
#   $apiKey = Get-PassBundleSecret -Item "Backup service" -Field "API key"
#
# The token comes from $env:PASSBUNDLE_TOKEN unless -Token is given. Works in
# Windows PowerShell 5.1 and PowerShell 7, with nothing to install.

Set-StrictMode -Version 3.0
# Any error stops a script rather than letting it go on without its secret.
$ErrorActionPreference = 'Stop'

# Filled in by the server that serves this file.
$script:DefaultServer = '{{SERVER}}'

if ($PSVersionTable.PSVersion.Major -lt 6) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}

# Functions here return byte arrays whole (the leading comma); PowerShell would
# otherwise unroll them into loose objects.
function ConvertFrom-PassBundleBase64Url([string] $Text) {
    $normal = $Text.Replace('-', '+').Replace('_', '/')
    switch ($normal.Length % 4) { 2 { $normal += '==' } 3 { $normal += '=' } }
    , [Convert]::FromBase64String($normal)
}

function ConvertTo-PassBundleBase64Url([byte[]] $Bytes) {
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Get-PassBundleHmac([byte[]] $Key, [byte[]] $Data) {
    $hmac = New-Object System.Security.Cryptography.HMACSHA256 (, $Key)
    try { , $hmac.ComputeHash($Data) } finally { $hmac.Dispose() }
}

# HKDF-SHA256 with no salt (RFC 5869), as the token's keys are derived.
function Get-PassBundleHkdf([byte[]] $Seed, [string] $Info, [int] $Length) {
    [byte[]] $prk = Get-PassBundleHmac -Key ([byte[]]::new(32)) -Data $Seed
    [byte[]] $infoBytes = [Text.Encoding]::UTF8.GetBytes($Info)
    [byte[]] $out = [byte[]]::new($Length)
    [byte[]] $previous = [byte[]]::new(0)
    $written = 0
    for ($counter = 1; $written -lt $Length; $counter++) {
        [byte[]] $previous = Get-PassBundleHmac -Key $prk -Data ([byte[]]($previous + $infoBytes + [byte]$counter))
        $take = [Math]::Min($previous.Length, $Length - $written)
        [Array]::Copy($previous, 0, $out, $written, $take)
        $written += $take
    }
    , $out
}

function Read-PassBundleToken([string] $Token) {
    if ($Token -notmatch '^pbs1_([0-9a-f]{32})_([A-Za-z0-9_-]{43})$') {
        throw 'That isn''t a PassBundle script token (it starts with pbs1_).'
    }
    $hex = $Matches[1]
    $seed = ConvertFrom-PassBundleBase64Url $Matches[2]
    [pscustomobject]@{
        Id      = '{0}-{1}-{2}-{3}-{4}' -f $hex.Substring(0, 8), $hex.Substring(8, 4), $hex.Substring(12, 4), $hex.Substring(16, 4), $hex.Substring(20)
        Secret  = Get-PassBundleHkdf -Seed $seed -Info 'passbundle script auth v1' -Length 32
        Key     = Get-PassBundleHkdf -Seed $seed -Info 'passbundle script key v1' -Length 64
    }
}

# Opens an encrypted string (type 2: AES-256-CBC, then HMAC-SHA256 over the IV
# and ciphertext), refusing it if the MAC doesn't match.
function Unprotect-PassBundleString([string] $Encrypted, [byte[]] $Key) {
    if ($Encrypted -notmatch '^2\.([^|]+)\|([^|]+)\|([^|]+)$') {
        throw 'The server sent something that isn''t a PassBundle copy.'
    }
    $iv = [Convert]::FromBase64String($Matches[1])
    $data = [Convert]::FromBase64String($Matches[2])
    $mac = [Convert]::FromBase64String($Matches[3])
    $encKey = [byte[]]$Key[0..31]
    $macKey = [byte[]]$Key[32..63]
    $expected = Get-PassBundleHmac -Key $macKey -Data ([byte[]]($iv + $data))
    $diff = $expected.Length -bxor $mac.Length
    for ($i = 0; $i -lt [Math]::Min($expected.Length, $mac.Length); $i++) { $diff = $diff -bor ($expected[$i] -bxor $mac[$i]) }
    if ($diff -ne 0) {
        throw 'A copy failed its integrity check. It wasn''t made with this token''s key.'
    }
    $aes = [System.Security.Cryptography.Aes]::Create()
    try {
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $encKey
        $aes.IV = $iv
        $decryptor = $aes.CreateDecryptor()
        [Text.Encoding]::UTF8.GetString($decryptor.TransformFinalBlock($data, 0, $data.Length))
    } finally {
        $aes.Dispose()
    }
}

function Invoke-PassBundleScript([string] $Path, [string] $Token, [string] $Server) {
    if (-not $Token) { $Token = $env:PASSBUNDLE_TOKEN }
    if (-not $Token) { throw 'No token: set $env:PASSBUNDLE_TOKEN or pass -Token.' }
    if (-not $Server) { $Server = if ($env:PASSBUNDLE_SERVER) { $env:PASSBUNDLE_SERVER } else { $script:DefaultServer } }
    $parsed = Read-PassBundleToken $Token
    $headers = @{ Authorization = 'PassBundleScript {0}.{1}' -f $parsed.Id, (ConvertTo-PassBundleBase64Url $parsed.Secret) }
    try {
        $answer = Invoke-RestMethod -Uri ($Server.TrimEnd('/') + '/api/keykeeper/script/' + $Path) -Headers $headers -UseBasicParsing
    } catch {
        $failure = $_.Exception
        $status = $null
        if ($failure.PSObject.Properties['Response'] -and $failure.Response) { $status = [int]$failure.Response.StatusCode }
        switch ($status) {
            401 { throw 'The server refused the token: it was revoked, expired, mistyped, or used from a network it isn''t allowed on.' }
            404 { throw 'This token can''t read that item.' }
            429 { throw 'Too many reads with this token; try again in a minute.' }
            default { throw "Couldn't reach PassBundle at ${Server}: $($failure.Message)" }
        }
    }
    [pscustomobject]@{ Token = $parsed; Answer = $answer }
}

# PowerShell 7's ConvertFrom-Json turns strings that look like dates into
# dates, which would change a password or field that looks like one;
# System.Text.Json keeps every string as written. Windows PowerShell 5.1 has
# no System.Text.Json, and its ConvertFrom-Json leaves such strings alone.
function ConvertFrom-PassBundleJson([string] $Json) {
    if ($PSVersionTable.PSVersion.Major -lt 6) { return $Json | ConvertFrom-Json }
    $document = [System.Text.Json.JsonDocument]::Parse($Json)
    try { ConvertFrom-PassBundleJsonElement $document.RootElement } finally { $document.Dispose() }
}

function ConvertFrom-PassBundleJsonElement($Element) {
    switch ($Element.ValueKind.ToString()) {
        'Object' {
            $object = [ordered]@{}
            foreach ($property in $Element.EnumerateObject()) {
                $object[$property.Name] = ConvertFrom-PassBundleJsonElement $property.Value
            }
            return [pscustomobject]$object
        }
        'Array' { return , @(foreach ($each in $Element.EnumerateArray()) { ConvertFrom-PassBundleJsonElement $each }) }
        'String' { return $Element.GetString() }
        'Number' {
            $whole = [long]0
            if ($Element.TryGetInt64([ref]$whole)) { return $whole }
            return $Element.GetDouble()
        }
        'True' { return $true }
        'False' { return $false }
        default { return $null }
    }
}

# Opens a copy, checking it was made for this token and this item.
function Open-PassBundleCopy($Token, $Entry) {
    $copy = ConvertFrom-PassBundleJson (Unprotect-PassBundleString -Encrypted $Entry.copy -Key $Token.Key)
    if ($copy.token -ne $Token.Id -or $copy.item -ne $Entry.itemId) {
        throw 'The server sent a copy made for another token or item.'
    }
    $copy
}

function Find-PassBundleCopy([string] $Item, [string] $Token, [string] $Server) {
    if ($Item -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
        $reply = Invoke-PassBundleScript -Path ('items/' + $Item.ToLowerInvariant()) -Token $Token -Server $Server
        return Open-PassBundleCopy $reply.Token $reply.Answer
    }
    $reply = Invoke-PassBundleScript -Path 'items' -Token $Token -Server $Server
    $found = @($reply.Answer.data | ForEach-Object { Open-PassBundleCopy $reply.Token $_ } | Where-Object { $_.name -eq $Item })
    if ($found.Count -eq 0) { throw "This token can't read an item named '$Item'." }
    if ($found.Count -gt 1) { throw "This token can read more than one item named '$Item'. Ask for it by its id." }
    $found[0]
}

# A one-time code from a copied secret: a base32 secret, or an otpauth:// address.
function Get-PassBundleTotp([string] $Secret, [DateTimeOffset] $At = [DateTimeOffset]::UtcNow) {
    $digits = 6; $period = 30; $algorithm = 'SHA1'
    if ($Secret -match '^otpauth://') {
        $query = ($Secret -split '\?', 2)[1]
        foreach ($pair in ($query -split '&')) {
            $name, $value = $pair -split '=', 2
            $value = [Uri]::UnescapeDataString([string]$value)
            switch ($name.ToLowerInvariant()) {
                'secret' { $Secret = $value }
                'digits' { $digits = [int]$value }
                'period' { $period = [int]$value }
                'algorithm' { $algorithm = $value.ToUpperInvariant() }
            }
        }
    } elseif ($Secret -match '^steam://') {
        throw 'Steam one-time codes aren''t supported in scripts.'
    }
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
    $bits = ''
    foreach ($c in ($Secret.ToUpperInvariant().Replace(' ', '').TrimEnd('=')).ToCharArray()) {
        $index = $alphabet.IndexOf($c)
        if ($index -lt 0) { throw 'The one-time code secret isn''t base32.' }
        $bits += [Convert]::ToString($index, 2).PadLeft(5, '0')
    }
    $key = [byte[]]::new([Math]::Floor($bits.Length / 8))
    for ($i = 0; $i -lt $key.Length; $i++) { $key[$i] = [Convert]::ToByte($bits.Substring($i * 8, 8), 2) }
    $counter = [long][Math]::Floor($At.ToUnixTimeSeconds() / $period)
    $message = [BitConverter]::GetBytes($counter)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($message) }
    $hmac = switch ($algorithm) {
        'SHA256' { New-Object System.Security.Cryptography.HMACSHA256 (, $key) }
        'SHA512' { New-Object System.Security.Cryptography.HMACSHA512 (, $key) }
        default { New-Object System.Security.Cryptography.HMACSHA1 (, $key) }
    }
    try { $hash = $hmac.ComputeHash($message) } finally { $hmac.Dispose() }
    $offset = $hash[$hash.Length - 1] -band 0xf
    # As ints: shifting a byte in PowerShell keeps it a byte.
    $code = (([int]$hash[$offset] -band 0x7f) -shl 24) -bor ([int]$hash[$offset + 1] -shl 16) -bor ([int]$hash[$offset + 2] -shl 8) -bor [int]$hash[$offset + 3]
    ($code % [int][Math]::Pow(10, $digits)).ToString().PadLeft($digits, '0')
}

<#
.SYNOPSIS
One value a PassBundle script token was granted: username, password, totp (the current one-time code), or a custom field by name.
#>
function Get-PassBundleSecret {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string] $Item,
        [Parameter(Mandatory = $true)] [string] $Field,
        [string] $Token,
        [string] $Server
    )
    $copy = Find-PassBundleCopy -Item $Item -Token $Token -Server $Server
    $has = { param($name) $null -ne $copy.PSObject.Properties[$name] }
    switch ($Field) {
        'username' { if (& $has 'username') { return $copy.username } }
        'password' { if (& $has 'password') { return $copy.password } }
        'totp' { if (& $has 'totp') { return Get-PassBundleTotp $copy.totp } }
        default {
            if ($null -ne $copy.fields -and $null -ne $copy.fields.PSObject.Properties[$Field]) {
                return $copy.fields.$Field
            }
        }
    }
    throw "This token wasn't granted '$Field' of $($copy.name)."
}

<#
.SYNOPSIS
The username and password a PassBundle script token was granted, as a PSCredential.
#>
function Get-PassBundleCredential {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string] $Item,
        [string] $Token,
        [string] $Server
    )
    $copy = Find-PassBundleCopy -Item $Item -Token $Token -Server $Server
    if ($null -eq $copy.PSObject.Properties['username'] -or $null -eq $copy.PSObject.Properties['password']) {
        throw "This token wasn't granted both the username and password of $($copy.name)."
    }
    $password = ConvertTo-SecureString $copy.password -AsPlainText -Force
    New-Object System.Management.Automation.PSCredential ($copy.username, $password)
}

Export-ModuleMember -Function Get-PassBundleSecret, Get-PassBundleCredential
