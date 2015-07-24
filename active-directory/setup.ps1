[CmdletBinding()]
param (
    [String] $domain,
    [String] $tmpFolder,
    [string] $debugAttrOid,
    [string] $debugAttrCn,
    [switch] $help
)

$SCRIPT_NAME = $($MyInvocation.MyCommand.Name);
$SCRIPT_PATH = Split-Path $MyInvocation.MyCommand.Path;

#dont change unless you know what you are doing
$ATTR_OID_TEMPLATE = '1.2.840.113556.1.8000.1.3.6.1.4.1.28553.2.1';
$ATTR_CN = "sp-OTPSecret";

function spUsage() {
echo "`nUsage: $SCRIPT_NAME -domain <DOMAIN> [-tmpFolder <FOLDER>]";
echo @'

    This skript adds a new attribute to your AD to allow
    a TOTP-authentication with a Securepoint UTM.

'@
}

function create_folder() {
    param(
        [string] $path = $null
    )
    if (!$path) {return 1, "no path given"}

    if ((Test-Path $path) -ne $true) {
        $devnull = New-Item $path -type directory
    }

    return 0, "directory created"
}

function sp_write_file() {
    param(
    [string] $file = $null,
    [string] $content = $null,
    [bool] $overwrite = $false,
    [bool] $append = $true
  );

  if (!$file) {return 1, "no filename given"}

  $file = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($file)


  $exists = [System.IO.File]::Exists($file)

    if ($exists -eq $true -and $overwrite -eq $false -and $append -eq $false) {
        return 1, "file does already exist and we wont overwrite it/append to it"
    }

    $pathName = [System.IO.Path]::GetDirectoryName($file)
    $ret, $res = create_folder -path $pathName

    if ($ret -ne 0) {return $ret, $res}

    $sw = new-object System.IO.Streamwriter -ArgumentList $file, $append
    $sw.Write($content);
    $sw.close()

    return 0, $file
}

if ($help -or -not $domain) {
    spUsage;
    exit 0;
}

if ($debugAttrOid) {
    $ATTR_OID_TEMPLATE = $debugAttrOid
}

if ($debugAttrCn) {
    $ATTR_CN = $debugAttrCn
}


Write-Host "We will now execute some checks to see if we can make the required changes."
Write-Host "You need to confirm the actual changes again before they are performed."
Write-Host "NOTE: This skript should always be executed on the serer owning the AD schema master role"

$cont = $false;
$cont = read-host "Continue? [yes/NO]"

if ($cont.ToLower() -ne 'yes') {
    exit 0;
}


$tmpFileName = "$($SCRIPT_NAME)-$($pid).ldf";

if (-not $tmpFolder) {
    $tmpFolder = $env:TEMP;
}

$tmpFile = "$($tmpFolder)\$($tmpFileName)";

write-host  "Try to write in the tmp folder... " -nonewline
$return, $msg = sp_write_file -file $tmpFile -append $false -overwrite $true -content "testwrite"
if ($return -ne 0) {
    write-host $msg -foreground Red;
    exit 1;
}
write-host "OK" -foreground Green

$domainDn = "dc="+$domain.Replace(".", ",dc=");

$schemaLocation = "CN=Schema,CN=Configuration,$domainDn";

write-host  "Let's see if we find the domain-schema-configuration... " -nonewline
try {
    $devnull = Get-ADObject $schemaLocation;
} catch {
    write-host "ERROR" -foreground Red
    write-host "The path to the schema is invalid: $schemaLocation"
    exit 1;
}

write-host "OK" -foreground Green;
write-host "Found schema config: $schemaLocation"


$attrDn = "CN=$ATTR_CN,$schemaLocation"

write-host  "Check availablity of the required DN... " -nonewline
try {
    $devnull = Get-ADObject $attrDn;
    write-host "ERROR" -foreground Red
    write-host "Our DN is already taken: $attrDn"
    write-host "Maybe someone already executed this skript. Exiting."
    exit 1;
} catch {
    write-host "OK" -foreground Green
    write-host "DN is available: $attrDn"
}


$LDIF_TEMPLATE = @'
dn: ###ATTR_DN###
changetype: ntdsSchemaAdd
adminDisplayName: ###ATTR_CN###
attributeID: ###ATTR_OID###
attributeSyntax: 2.5.5.3
cn: ###ATTR_CN###
description: Securepoint TOTP Attribute.
isMemberOfPartialAttributeSet: FALSE
isSingleValued: TRUE
lDAPDisplayName: ###ATTR_CN###
distinguishedName: ###ATTR_DN###
objectCategory: CN=Attribute-Schema,###SCHEMA_LOCATION###
objectClass: attributeSchema
oMSyntax: 27
name: ###ATTR_CN###
searchFlags: 0
showInAdvancedViewOnly: FALSE

DN:
changetype: modify
add: schemaUpdateNow
schemaUpdateNow: 1
-

dn: cn=User,###SCHEMA_LOCATION###
changetype: ntdsSchemaModify
add: mayContain
mayContain: ###ATTR_CN###
-
'@;


$ldifStr = $LDIF_TEMPLATE.Replace("###ATTR_DN###", $attrDn);
$ldifStr = $ldifStr.Replace("###ATTR_CN###", $ATTR_CN);
$ldifStr = $ldifStr.Replace("###ATTR_OID###", $ATTR_OID_TEMPLATE);
$ldifStr = $ldifStr.Replace("###SCHEMA_LOCATION###", $schemaLocation);

$return, $msg = sp_write_file -file $tmpFile -append $false -overwrite $true -content $ldifStr
if ($return -ne 0) {
    write-host $msg -foreground Red;
    exit 1;
}

write-host "`nEverything looks OK until here..."
write-host "`nWARNING!!!" -foreground Yellow
write-host "BY CONTINUING YOU WILL NOW PERMANENTLY CHANGE THE STRUCTURE OF YOUR LDAP-SERVER."
write-host "THIS CANNOT BE UNDONE. PLEASE BACKUP YOUR SERVER BEFORE ANY FURTHER STEPS."
write-host "YOU ARE DOING THIS ON YOUR OWN RISK AND WE DO NOT HAVE ANY RESPONSIBILITY"
write-host "OF ANY KIND FOR ANY LOSS OF DATA OR DAMAGE."
write-host "`nIf you are unsure, follow the manual instructions found in the Technet:"
write-host "    http://social.technet.microsoft.com/wiki/contents/articles/20319.how-to-create-a-custom-attribute-in-active-directory.aspx"
write-host "`nNOTE: This script was created by myself and is not supported by Securepoint!`n`n"

$cont = $false;
$cont = read-host "Type CONTINUE to perform the changes"

if ($cont -ne 'CONTINUE') {
    exit 0;
}

try {
    ldifde -j $tmpFolder -i -f $tmpFile
} catch {

}
