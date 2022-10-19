<#	
    .NOTES
    ===========================================================================
    Created with: 	VS
    Created on:   	17/10/2022
    Created by:   	Chris Healey
    Organization: 	
    Filename:     	GetRbacAdmins
    Project path:   https://github.com/healeychris/GetRbacAdmins
    ===========================================================================
    .DESCRIPTION
    This script is used to collect all admins that are a member of any Rbac admins groups.
    .NOTES

#>


####### Variable list #######
Clear-Host                                                                                                                       # Clear screen
$Version                                                = "0.1"                                                                  # Version of script
$host.ui.RawUI.WindowTitle                              = 'Azure Admin Role Collector'                                           # Title for Status Bar
$ExportFile                                             = "UsersPermissionReport_$((get-date).ToString('yyyyMMdd_HHmm')).csv"    # Export File name
$CurrentDate                                            = Get-Date                                                               # Curent Date
$DaysNotLoggedIn                                        = "-50"                                                                  # Number of days not logged in
$DatetoFlag                                             = $CurrentDate.AddDays($DaysNotLoggedIn)                                 # Date flagged on user

##### Functions ####

# FUNCTION - WriteTransaction Log function    
function WriteTransactionsLogs  {

    #WriteTransactionsLogs -Task 'Creating folder' -Result information  -ScreenMessage true -ShowScreenMessage true exit #Writes to file and screen, basic display
          
    #WriteTransactionsLogs -Task task -Result Error -ErrorMessage errormessage -ShowScreenMessage true -ScreenMessageColour red -IncludeSysError true #Writes to file and screen and system "error[0]" is recorded
         
    #WriteTransactionsLogs -Task task -Result Error -ErrorMessage errormessage -ShowScreenMessage true -ScreenMessageColour red -IncludeSysError false  #Writes to file and screen but no system "error[0]" is recorded
       
    #WriteTransactionsLogs -Task "Getting Token from Azure AD" -Result information -ErrorMessage "none" -ShowScreenMessage true -ScreenMessageColour GREEN -IncludeSysError False

    [CmdletBinding()]
    param(
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string]$Task,
 
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]
        [ValidateSet('Information','Warning','Error','Completed','Processing')]
        [string]$Result,
 
        [Parameter(ValueFromPipelineByPropertyName)]
        [AllowNull()]
        [string]$ErrorMessage,
    
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]
        [ValidateSet('True','False')]
        [string]$ShowScreenMessage,
 
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]
        [string]$ScreenMessageColour,
 
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$IncludeSysError,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$ExportData
)
 
    process {
 
        # Stores Variables
        $LogsFolder           = 'Logs'
 
        # Date
        $DateNow = Get-Date -f g    
        
        # Error Message
        $SysErrorMessage = $error[0].Exception.message

        # Check of log files exist for this session
        If ($Global:TransactionLog -eq $null) {$Global:TransactionLog = ".\TransactionLog_$((get-date).ToString('yyyyMMdd_HHmm')).csv"}
         
        # Create Directory Structure
        if (! (Test-Path ".\$LogsFolder")) {new-item -path .\ -name ".\$LogsFolder" -type directory | out-null}
 
 
        $TransactionLogScreen = [pscustomobject][ordered]@{}
        $TransactionLogScreen | Add-Member -MemberType NoteProperty -Name "Date"-Value $DateNow 
        $TransactionLogScreen | Add-Member -MemberType NoteProperty -Name "Task" -Value $Task
        $TransactionLogScreen | Add-Member -MemberType NoteProperty -Name "Result" -Value $Result
        $TransactionLogScreen | Add-Member -MemberType NoteProperty -Name "Error" -Value $ErrorMessage
        $TransactionLogScreen | Add-Member -MemberType NoteProperty -Name "SystemError" -Value $SysErrorMessage
        
       
        # Output to screen
       
        if  ($Result -match "Information|Warning" -and $ShowScreenMessage -eq "$true"){
 
        Write-host $TransactionLogScreen.Date  -NoNewline -ForegroundColor GREEN
        Write-host " | " -NoNewline
        Write-Host $TransactionLogScreen.Task  -NoNewline
        Write-host " | " -NoNewline
        Write-host $TransactionLogScreen.Result -ForegroundColor $ScreenMessageColour 
        }
 
       if  ($Result -eq "Error" -and $ShowScreenMessage -eq "$true" -and $IncludeSysError -eq "$false"){
       Write-host $TransactionLogScreen.Date  -NoNewline -ForegroundColor GREEN
       Write-host " | " -NoNewline
       Write-Host $TransactionLogScreen.Task  -NoNewline
       Write-host " | " -NoNewline
       Write-host $TransactionLogScreen.Result -ForegroundColor $ScreenMessageColour -NoNewline 
       Write-host " | " -NoNewline
       Write-Host $ErrorMessage  -ForegroundColor $ScreenMessageColour
       }
 
       if  ($Result -eq "Error" -and $ShowScreenMessage -eq "$true" -and $IncludeSysError -eq "$true"){
       Write-host $TransactionLogScreen.Date  -NoNewline -ForegroundColor GREEN
       Write-host " | " -NoNewline
       Write-Host $TransactionLogScreen.Task  -NoNewline
       Write-host " | " -NoNewline
       Write-host $TransactionLogScreen.Result -ForegroundColor $ScreenMessageColour -NoNewline 
       Write-host " | " -NoNewline
       Write-Host $ErrorMessage -NoNewline -ForegroundColor $ScreenMessageColour
       if (!$SysErrorMessage -eq $null) {Write-Host " | " -NoNewline}
       Write-Host $SysErrorMessage -ForegroundColor $ScreenMessageColour
       Write-Host
       }
   
        # Build PScustomObject
        $TransactionLogFile = [pscustomobject][ordered]@{}
        $TransactionLogFile | Add-Member -MemberType NoteProperty -Name "Date"-Value "$datenow"
        $TransactionLogFile | Add-Member -MemberType NoteProperty -Name "Task"-Value "$task"
        $TransactionLogFile | Add-Member -MemberType NoteProperty -Name "Result"-Value "$result"
        $TransactionLogFile | Add-Member -MemberType NoteProperty -Name "Error"-Value "$ErrorMessage"
        $TransactionLogFile | Add-Member -MemberType NoteProperty -Name "SystemError"-Value "$SysErrorMessage"
 
        # Connect to Database
        $TransactionLogFile | Export-Csv -Path ".\$LogsFolder\$TransactionLog" -Append -NoTypeInformation      
 
 
        # Clear Error Messages
        $error.clear()
    }   
 

}

# FUNCTION -  Check MgGraph Module is installed
function CheckMgGraphModule () {

    WriteTransactionsLogs -Task "Checking Microsoft.Graph Module"  -Result Information -ErrorMessage none -ShowScreenMessage true -ScreenMessageColour GREEN -IncludeSysError false   
    if (Get-Module -ListAvailable -Name Microsoft.Graph) {
        WriteTransactionsLogs -Task "Found Microsoft.Graph Module" -Result Information -ErrorMessage none -ShowScreenMessage true -ScreenMessageColour GREEN -IncludeSysError false    
    } else {
        WriteTransactionsLogs -Task "Failed to locate Microsoft.Graph Module, it needs to be installed" -Result Error -ErrorMessage "Online Module not installed" -ShowScreenMessage true -ScreenMessageColour RED -IncludeSysError false
    }
    #WriteTransactionsLogs -Task "Importing Microsoft.Graph Module"  -Result Information -ErrorMessage none -ShowScreenMessage true -ScreenMessageColour GREEN -IncludeSysError false   
    #Try {Import-Module Microsoft.Graph -ea Stop -WarningAction SilentlyContinue
    #}
    #Catch {WriteTransactionsLogs -Task "Failed Importing Microsoft.Graph Module, it needs to be installed" -Result Error -ErrorMessage "Online Module not installed" -ShowScreenMessage true -ScreenMessageColour RED -IncludeSysError true
    #}
}

# FUNCTION - Connect to Microsoft Graph
function ConnectMgGraph () {

    # Check Connection to 365 or Connect if not already
    try {
        try { Get-MgOrganization -ea stop | Out-Null;  WriteTransactionsLogs -Task "Existing Microsoft.Graph Connection Found" -Result Information -ErrorMessage none -ShowScreenMessage true -ScreenMessageColour GREEN -IncludeSysError false
        Select-MgProfile -Name "beta"
        Connect-MgGraph -Scopes "User.Read.All","Directory.Read.All","AuditLog.Read.All" -ErrorAction Stop | Out-Null
        }
        catch {
               WriteTransactionsLogs -Task "Not Connected to MgGraph" -Result Information -ErrorMessage none -ShowScreenMessage true -ScreenMessageColour GREEN -IncludeSysError false 
               Select-MgProfile -Name "beta"
               Connect-MgGraph -Scopes "User.Read.All","Directory.Read.All","AuditLog.Read.All" -ErrorAction Stop | Out-Null
            }
    }  
    Catch {
        WriteTransactionsLogs -Task "Unable to Connect to Microsoft MgGraph" -Result Error -ErrorMessage "Connect Error" -ShowScreenMessage true -ScreenMessageColour RED -IncludeSysError true 
	    exit
    }

}


# FUNCTION - Check required Permissions for Admin
function CheckPermissions () {
	
	$Permissions = Get-MgContext | select -ExpandProperty scopes
	
	if ($permissions -match 'AuditLog.Read.All') {WriteTransactionsLogs -Task "Admin Passed Permissions Check" -Result Information -ErrorMessage none -ShowScreenMessage true -ScreenMessageColour GREEN -IncludeSysError false}
	Else {WriteTransactionsLogs -Task "Admin Failed Permissions Check" -Result ERROR -ErrorMessage "NotEnoughPermissions-Missing AuditLog.Read.All Required" -ShowScreenMessage true -ScreenMessageColour RED -IncludeSysError false
		Exit
	}
}
	
	

# FUNCTION - Collect Management Directory Roles
function CollectMgRoles () {

    WriteTransactionsLogs -Task "Collecting Mg Directory Roles" -Result Information -ErrorMessage none -ShowScreenMessage true -ScreenMessageColour GREEN -IncludeSysError false 
    Try { $script:roles = Get-MgDirectoryRole}
    catch { WriteTransactionsLogs -Task "Failed Collecting Mg Directory Roles" -Result ERROR -ErrorMessage NoRBacRolesCollected -ShowScreenMessage true -ScreenMessageColour RED -IncludeSysError true 
        exit
    }

}

# FUNCTION - Collect Users Permissions and Sign-in data
function CollectUsersPermissions () {

    WriteTransactionsLogs -Task "Collecting Mg Directory Members Information" -Result Information -ErrorMessage none -ShowScreenMessage true -ScreenMessageColour GREEN -IncludeSysError false     
    # Gets the members from each management group role
    Foreach ($MemberinMgGroup in $script:roles){

        $DirectoryRoleId    = $MemberinMgGroup.id
        $DirectoryRoleName  = $MemberinMgGroup.Displayname 
        
        # Gets the ID of a user assigned to the management Role
        $UserMemberID = Get-MgDirectoryRoleMember -DirectoryRoleId $DirectoryRoleId | Where-Object {$_.AdditionalProperties."@odata.type" -eq '#microsoft.graph.user'}

            # Find the users details based on the ID from the group
            Foreach ($UserIDFound in $UserMemberID.id) {
            #$azureuser = Get-MgUser -UserId $UserIDFound #-Property 'SignInActivity','Identities','UserPrincipalName'

            $SearchUser = "https://graph.microsoft.com/beta/users/$UserIDFound"
            $SearchFilter = '?$select=displayName,userPrincipalName,signInActivity'
            $azureuser = Invoke-MgGraphRequest -Method GET -Uri $SearchUser$SearchFilter

            # Simple strings for output report
            $UPN = $azureuser.UserPrincipalName
            # if signin null state 'Not logged in'
            $SignInDate = $azureuser.SignInActivity.LastSignInDateTime
            if (!($SignInDate)) {$SignInDate = 'Never Signed In'}


            # Check if user has signed in based on a number of days
            if ($SignInDate -lt $DatetoFlag ) {$Investigate = 'Investigate User, User may not require access'}
            Else {$Investigate = 'No'}

            # Create PSobject for Group Data
            $UserData = @()
            $UserData = [pscustomobject][ordered]@{

            'ManagementRole'                            = $DirectoryRoleName
            'UserPrincipalName'                         = $azureuser.UserPrincipalName
            'LastSignInDate'                            = $SignInDate
            'Investigate'                               = $Investigate
            }

            WriteTransactionsLogs -Task "$DirectoryRoleName | $UPN | $SignInDate | $Investigate" -Result Information -ErrorMessage none -ShowScreenMessage true -ScreenMessageColour GREEN -IncludeSysError false     

            # Export data to CSV File
            $UserData | Export-Csv $ExportFile -NoTypeInformation -Append

        }
    }

}

# Function run order
CheckMgGraphModule
ConnectMgGraph
CheckPermissions 
CollectMgRoles
CollectUsersPermissions



