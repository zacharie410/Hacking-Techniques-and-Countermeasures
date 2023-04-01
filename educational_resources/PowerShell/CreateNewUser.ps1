# Define variables for new user account
$username = "NewUser"
$password = "P@ssw0rd"

# Create a new local user account with administrative privileges
New-LocalUser -Name $username -Password (ConvertTo-SecureString $password -AsPlainText -Force) -AccountNeverExpires -UserMayNotChangePassword
Add-LocalGroupMember -Group "Administrators" -Member $username

# Add new user to the list of users authorized to connect to Remote Desktop
$remoteDesktopGroup = "Remote Desktop Users"
Add-LocalGroupMember -Group $remoteDesktopGroup -Member $username

# Set registry values to enable auto-logon for new user
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
Set-ItemProperty -Path $regPath -Name "AutoAdminLogon" -Value 1
Set-ItemProperty -Path $regPath -Name "DefaultUserName" -Value $username
Set-ItemProperty -Path $regPath -Name "DefaultPassword" -Value $password

Read-Host -Prompt "Press Enter to exit"