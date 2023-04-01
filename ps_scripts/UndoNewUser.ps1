# Define variables for user to be deleted
$username = "NewUser"

# Delete the user account
Remove-LocalUser -Name $username -Confirm:$false

# Remove user from the list of users authorized to connect to Remote Desktop
$remoteDesktopGroup = "Remote Desktop Users"
Remove-LocalGroupMember -Group $remoteDesktopGroup -Member $username

# Remove registry values to disable auto-logon for new user
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
Remove-ItemProperty -Path $regPath -Name "AutoAdminLogon"
Remove-ItemProperty -Path $regPath -Name "DefaultUserName"
Remove-ItemProperty -Path $regPath -Name "DefaultPassword"
