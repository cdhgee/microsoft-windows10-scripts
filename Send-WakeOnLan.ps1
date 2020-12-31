[CmdletBinding()]
Param(
  [Parameter(Mandatory = $true, Position = 0)]
  [ValidateNotNullOrEmpty()]
  [string]$MACAddress,
  [Parameter(Mandatory = $false)]
  [string]$IPAddress,
  [Parameter(Mandatory = $false)]
  [ValidateSet("IPv4", "IPv6")]
  [string]$AddressFamily = "IPv4"
)


Function Get-MagicPacket {

  [CmdletBinding()]
  [OutputType([byte[]])]
  Param()

  # Magic packet format:
  # FF FF FF FF FF FF FF (6 bytes), followed by
  # 12 34 56 78 90 AB CD (MAC address) repeated 16 times
  # Total length: 102 (6 + 16 * 6)

  $magicPacket = ("$("ff" * 6)$($MacAddress * 16)" -replace "[-:]", "" -replace "..", "0x`$0 ").TrimEnd()
  [byte[]]($magicPacket -split " ")

}


Function Get-IPAddress {

  [CmdletBinding()]
  [OutputType([System.Net.IPAddress])]
  Param()


  Switch ($AddressFamily) {
    "IPv4" {
      $ip = "255.255.255.255"
    }
    "IPv6" {
      # Link-local all nodes multicast address
      $ip = "ff02::1"
    }
    default {
      throw "Unknown address family"
      exit 1
    }
  }

  If ($null -ne $IPAddress) {
    $ip = $IPAddress
  }

  [System.Net.IPAddress]::Parse($ip)

}

# Create an endpoint for the relevant IP on port 0
# The protocol and port don't really matter because the WOL packet
# is picked up by layer 2, but they're often sent using UDP to port 0.
$endpoint = New-Object System.Net.IPEndPoint((Get-IPAddress), 0)

# Supplying the address family (IPv4/IPv6) is necessary for IPv6 support
$socket = New-Object System.Net.Sockets.UDPClient($endpoint.AddressFamily)

$magicPacket = Get-MagicPacket

$socket.Send($magicPacket, $magicPacket.Length, $endpoint) | Out-Null

#$EncodedText = [Text.Encoding]::ASCII.GetBytes($Message)
#$SendMessage = $Socket.Send($EncodedText, $EncodedText.Length, $EndPoints)
$socket.Close()
