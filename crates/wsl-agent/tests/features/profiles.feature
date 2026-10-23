Feature: Several WireGuard tunnels, one at a time
  As someone with more than one WireGuard server
  I want to keep each config in the app and pick which one to use
  The way the WireGuard app lists its tunnels

  Background:
    Given wg-quick is installed
    And I have imported the WireGuard config "office"
    And I have imported the WireGuard config "home" pointing at "home.example.com"

  Scenario: Both are listed, and the first stays the active one
    Then the status lists the profiles "office, home"
    And the status says "office" is "Ready"

  Scenario: Connecting with the second profile
    When I connect with the profile "home"
    Then the tunnel is up
    And wg-quick brought up the config for "home.example.com"
    And the status says "home" is "Connected"

  Scenario: Switching while connected replaces the tunnel in one step
    Given I am connected
    When I connect with the profile "home"
    Then wg-quick ran "down" and then "up"
    And wg-quick brought up the config for "home.example.com"

  Scenario: The connected profile cannot be deleted from under its tunnel
    Given I am connected
    When I remove the profile "office"
    Then it fails mentioning "disconnect first"

  Scenario: A profile that is not in use can be deleted
    When I remove the profile "home"
    Then the status lists the profiles "office"
