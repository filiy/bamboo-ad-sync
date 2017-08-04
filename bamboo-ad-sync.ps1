aram([switch]$testrun,[switch]$checkusers,[switch]$run)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
#---------------------------------------------------------- 
# LOAD MODULES 
#---------------------------------------------------------- 
Try 
{ 
    Import-Module ActiveDirectory -ErrorAction Stop 
} 
Catch 
{ 
    
    "[ERROR]`t ActiveDirectory Module couldn't be loaded. Script will stop! - " + $date | Out-File $log -Append
} 
#---------------------------------------------------------- 
#LOAD IN VARIABLES 
#---------------------------------------------------------- 
$date = Get-Date
$name = Import-Csv ".\name-map.csv"
$ou="OU=users,OU=test,DC=test,DC=local"
$pass = "admin123!"
$log = ".\log.txt"
$setpass = ConvertTo-SecureString -AsPlainText $pass -force 
#---------------------------------------------------------- 
#LOAD IN USERS FROM BAMBOO HR
#----------------------------------------------------------
$headers = @{}
#API string added into header variable
$headers.Add("Authorization","Basic ")
#Need to specify json in the header to get back psobject variable 
$headers.Add("Accept","application/json")
$apiurl = "https://proceranetworks.bamboohr.com/api/gateway.php/proceranetworks/v1/employees/directory"
#This is the command that will query Bamboo HR and get all the data back into the $result variable 
$result = Invoke-RestMethod -Uri $apiurl -Headers $headers 
#---------------------------------------------------------- 
#MAIN SCRIPT 
#---------------------------------------------------------- 
if ($testrun)
{
    "**Performing test run no users will be created or updated - " + $date + "**"| Out-File $log -Append
    "--------------------------------------------" | Out-File $log -append 
    
    foreach ($x in $result.employees) 
    {
        #maniplate the last and first name strings to create the user name in the format of first letter of first name last name e.g.; flastname 
        $temp = $x.'lastName'.Split('-')[-1].tolower().trimend()
        $sam = $x.'firstName'.Substring(0,1).tolower() + $temp.Split()[-1]

        #user manager details don't come in with the orginal bamboo query so we need to loop through and query each user based on ID and get manager info
        $managerurl = "https://proceranetworks.bamboohr.com/api/gateway.php/proceranetworks/v1/employees/{0}/?fields=supervisor" -f $($x.'id')
        $manager = Invoke-RestMethod -Uri $managerurl -Headers $headers

        #need to convert the manager name into first inital of first name lastname to query AD
        $managertemp = $manager.supervisor.Split('-')[-1].tolower()
        $managersam = $manager.supervisor.Substring(0,1).tolower() + $managertemp.split()[-1]

        $displayname = $($x.displayname).TrimEnd()

        #Check if user exists in AD
        $exists = Get-ADUser -server win2012.test.local -Credential $cred -Filter "displayname -like '$displayname'" -Properties officephone
        
        if($exists)
        {
            "[TESTRUN-UPDATE] Found $($exists.'DistinguishedName') the script will update these details in non-test run:" | Out-File $log -Append
            "`t`t GivenName: $($x.'firstName') `r`n `t`t Surname: $($x.'lastName') `r`n `t`t Department: $($x.'department') `r`n `t`t Title: $($x."jobTitle") `r`n `t`t Description: $($x."jobTitle") `r`n `t`t Display Name: $($x.'displayName') `r`n `t`t Office: $($x.'location') `r`n `t`t Manager: $($manager.'supervisor')" | Out-File $log -Append
            
            if($($x.'workPhone') -ne $null)
            {
                if($exists.OfficePhone -eq $null)
                {
                    "`t`t Office Phone: $($x.'workPhone')" | Out-File $log -Append
                }
                elseif($exists.OfficePhone -ne $null)
                {
                    "`t`t ##Office Phone already set to: $($exists.OfficePhone) skipping update" | Out-File $log -Append
                }
            }
            
            "[TESTRUN-UPDATE] finshed updating user $($x.'DisplayName') in Active Directory" | Out-File $log -append
        }
        if(!$exists)
        {
            $exists2 = Get-ADUser -server win2012.test.local -Credential $cred -Filter "samAccountName -eq '$sam'" -Properties officephone
            if (!$exists2)
            {
                $namemap="off"
                foreach($y in $name)
                {
                    if($y.bamboo -eq $displayname)
                    {
                        "[TESTRUN-SKIP]`t Skipping $displayname user is in the name map file" | Out-File $log -Append
                        $namemap="on"
                    }
                }
                if($namemap -eq "off")
                {
                    "[TESTRUN-CREATE] Could not find $($x.displayName) OR $sam in Active Directory, the script will create user in non-test run:" | Out-File $log -Append
                }
            }
            elseif ($exists2)
            {
                "[TESTRUN-UPDATE] Found $($exists2.'DistinguishedName') the script will update these details in non-test run:" | Out-File $log -Append
                "`t`t GivenName: $($x.'firstName') `r`n `t`t Surname: $($x.'lastName') `r`n `t`t Department: $($x.'department') `r`n `t`t Title: $($x."jobTitle") `r`n `t`t Description: $($x."jobTitle") `r`n `t`t Display Name: $($x.'displayName') `r`n `t`t Office: $($x.'location') `r`n `t`t Email Address: $($x.'workEmail') `r`n `t`t Manager: $($manager.'supervisor')" | Out-File $log -Append
                
                if($($x.'workPhone') -ne $null)
                {
                    if($exists.OfficePhone -eq $null)
                    {
                        "`t`t Office Phone: $($x.'workPhone')" | Out-File $log -Append
                    }
                    elseif($exists.OfficePhone -ne $null)
                    {
                        "`t`t ##Office Phone already set to: $($exists.OfficePhone) skipping update" | Out-File $log -Append
                    }
                }   
                    "[TESTRUN-UPDATE] finshed updating user $($x.'DisplayName') in Active Directory" | Out-File $log -append
            }
        }
    }
}
if ($checkusers)
{   
    "**Checking if users from Bamboo HR exsist in AD - " + $date + "**" | Out-File $log -Append
    foreach ($x in $result.employees) 
    {
        #maniplate the last and first name strings to create the user name in the format of first letter of first name last name e.g.; flastname 
        $temp = $x.'lastName'.Split('-')[-1].tolower().trimend()
        $sam = $x.'firstName'.Substring(0,1).tolower() + $temp.Split()[-1]
        $displayname = $($x.displayname).TrimEnd()

        #Check if user exists in AD
        $exists = Get-ADUser -server win2012.test.local -Credential $cred -Filter "displayname -like '$displayname'"

        foreach($y in $name)
        {
            if($y.bamboo -eq $displayname)
            {
                $exists = $displayname
            }
        }  
        if(!$exists)
        {
            $exists2 = Get-ADUser -server win2012.test.local -Credential $cred -Filter "samAccountName -eq '$sam'"
            
            if (!$exists2)
            {
                "[CHECK-USER]`t Could not find $($x.displayName) OR $sam in Active Directory" | Out-File $log -Append
            }
        }
    }
}
if ($run)
{
    "**Starting to create and update AD users - " + $date + "**" | Out-File $log -Append
    "--------------------------------------------" | Out-File $log -append 
    foreach ($x in $result.employees) 
    {
        #maniplate the last and first name strings to create the user name in the format of first letter of first name last name e.g.; flastname 
        $temp = $x.'lastName'.Split('-')[-1].tolower().trimend()
        $sam = $x.'firstName'.Substring(0,1).tolower() + $temp.Split()[-1]

        #user manager details don't come in with the orginal bamboo query so we need to loop through and query each user based on ID and get manager info
        $managerurl = "https://proceranetworks.bamboohr.com/api/gateway.php/proceranetworks/v1/employees/{0}/?fields=supervisor" -f $($x.'id')
        $manager = Invoke-RestMethod -Uri $managerurl -Headers $headers

        #need to convert the manager name into first inital of first name lastname to query AD
        $managertemp = $manager.supervisor.Split('-')[-1].tolower()
        $managersam = $manager.supervisor.Substring(0,1).tolower() + $managertemp.split()[-1]

        $displayname = $($x.displayname).TrimEnd()

        #Check if user exists in AD
        $exists = Get-ADUser -server win2012.test.local -Credential $cred -filter "displayname -like '$displayname'" -Properties officephone

        if($exists)
        {
            "[INFO-UPDATE]`t Found $($exists.'DistinguishedName') updating  to:" | Out-File $log -Append
            "`t`t GivenName: $($x.'firstName') `r`n `t`t Surname: $($x.'lastName') `r`n `t`t Department: $($x.'department') `r`n `t`t Title: $($x."jobTitle") `r`n `t`t Description: $($x."jobTitle") `r`n `t`t Display Name: $($x.'displayName') `r`n `t`t Office: $($x.'location') `r`n `t`t Manager: $($manager.'supervisor')" | Out-File $log -Append
            set-aduser -server win2012.test.local -Credential $cred -Identity $sam -GivenName $($x.'firstName') -Surname $($x.'lastName') -Department $($x.'department') -Title $($x."jobTitle") -Description $($x."jobTitle")  -Office $($x.'location') -DisplayName $($x.'displayName')
             #User details will not update if it can't find the manager so it's on seperate action
            set-aduser -server win2012.test.local -Credential $cred -Identity $sam -Manager "$managersam" -ErrorAction SilentlyContinue

            if($($x.'workPhone') -ne $null)
            {
                if($exists.OfficePhone -eq $null)
                {
                    "`t`t Office Phone: $($x.'workPhone')" | Out-File $log -Append
                    set-aduser -server win2012.test.local -Credential $cred -Identity $sam -OfficePhone $($x.'workPhone') 
                }
                elseif($exists.OfficePhone -ne $null)
                {
                    "`t`t ##Office Phone already set to: $($exists.OfficePhone) skipping update" | Out-File $log -Append
                }
            }
            
            "[INFO-UPDATE]`t finshed updating user $($x.'DisplayName') in Active Directory - " | Out-File $log -append
        }
        if(!$exists)
        {
            $exists2 = Get-ADUser -server win2012.test.local -Credential $cred -Filter "samAccountName -eq '$sam'" -Properties officephone
            if (!$exists2)
            {
                $namemap="off"
                foreach($y in $name)
                {
                    if($y.bamboo -eq $displayname)
                    {
                        "[TESTRUN-SKIP]`t Skipping $displayname user is in the name map file" | Out-File $log -Append
                        $namemap="on"
                    }
                }
                if($namemap -eq "off")
                {
                    "[INFO-CREATE]`t user $($x.'DisplayName') does not exist in AD creating user" | Out-File $log -append 
                    new-aduser -server win2012.test.local -Credential $cred -name $($x.'displayName') -SamAccountName $sam -GivenName $($x.'firstName') -Surname $($x.'lastName') -Department $($x.'department') -Title $($x."jobTitle") -Description $($x."jobTitle")  -Office $($x.'location') -EmailAddress $($x.'workEmail') -DisplayName $($x.'displayName') -OfficePhone $($x.'workPhone') -AccountPassword $setpass -Enabled $true -Path $ou
                    #User details will not update if it can't find the manager so it's on seperate action
                    set-aduser -Server win2012.test.local -Credential $cred -Identity $sam -Manager "$managersam" -ErrorAction SilentlyContinue
                    "[INFO-CREATE]`t finshed creating user $sam in AD"| Out-File $log -append
                }
            }
            elseif ($exists2)
            {
                "[INFO-UPDATE]`t Found $($exists.'DistinguishedName') updating  to:" | Out-File $log -Append
                "`t`t GivenName: $($x.'firstName') `r`n `t`t Surname: $($x.'lastName') `r`n `t`t Department: $($x.'department') `r`n `t`t Title: $($x."jobTitle") `r`n `t`t Description: $($x."jobTitle") `r`n `t`t Display Name: $($x.'displayName') `r`n `t`t Office: $($x.'location') `r`n `t`t Manager: $($manager.'supervisor')" | Out-File $log -Append
                set-aduser -server win2012.test.local -Credential $cred -Identity $sam -GivenName $($x.'firstName') -Surname $($x.'lastName') -Department $($x.'department') -Title $($x."jobTitle") -Description $($x."jobTitle")  -Office $($x.'location') -DisplayName $($x.'displayName')
                #User details will not update if it can't find the manager so it's on seperate action
                set-aduser -server win2012.test.local -Credential $cred -Identity $sam -Manager "$managersam" -ErrorAction SilentlyContinue

                if($($x.'workPhone') -ne $null)
                {
                    if($exists.OfficePhone -eq $null)
                    {
                        "`t`t Office Phone: $($x.'workPhone')" | Out-File $log -Append
                        set-aduser -server win2012.test.local -Credential $cred -Identity $sam -OfficePhone $($x.'workPhone') 
                    }
                    elseif($exists.OfficePhone -ne $null)
                    {
                        "`t`t ##Office Phone already set to: $($exists.OfficePhone) skipping update" | Out-File $log -Append
                    }
                }
                "[INFO-UPDATE]`t finshed updating user $($x.'DisplayName') in Active Directory - " | Out-File $log -append
            }
        }
    }
}