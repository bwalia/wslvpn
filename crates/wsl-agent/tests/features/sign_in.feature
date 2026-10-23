Feature: Signing in before connecting
  As an administrator
  I want people checked against OpsAPI before the VPN lets them connect
  So that access follows the directory, not whoever holds a config file

  Background:
    Given wg-quick is installed

  Rule: An OpsAPI account signs in with email, password and an emailed code

    Background:
      Given the control plane offers the network "Development"
      And the control plane offers OpsAPI sign-in

    Scenario: Signing in with an emailed code, then connecting
      When I sign in with OpsAPI as "alice@example.com" with password "right"
      Then I am asked for the code sent to "alice@example.com"
      When I enter the code "123456"
      Then I am signed in to the VPN as "alice@example.com"
      And this device is registered
      When I connect
      Then the tunnel is up
      And the status mode is "managed"

    Scenario: The password goes to OpsAPI and never to the control plane
      When I sign in with OpsAPI as "alice@example.com" with password "right"
      And I enter the code "123456"
      Then OpsAPI received the password
      And the control plane never saw the password

    Scenario: A workspace with codes turned off signs in at once
      When I sign in with OpsAPI as "bob@example.com" with password "right"
      Then I am signed in to the VPN as "bob@example.com"

    Scenario: A wrong password is reported as such
      When I sign in with OpsAPI as "alice@example.com" with password "wrong"
      Then it fails mentioning "incorrect"
      And I am not signed in

    Scenario: A real OpsAPI account the control plane does not admit
      When I sign in with OpsAPI as "stranger@example.com" with password "right"
      Then it fails mentioning "not allowed to use this VPN"
      And I am not signed in

    Scenario: Someone deprovisioned after signing in cannot connect
      Given I signed in with OpsAPI as "bob@example.com"
      And the control plane will refuse sessions with "opsapi: user not active in directory"
      When I connect
      Then it fails mentioning "access was refused"
      And wg-quick was never run

  Rule: A control plane without OpsAPI sign-in says so

    Scenario: Asking for OpsAPI sign-in where it is not offered
      Given the control plane offers the network "Development"
      When I sign in with OpsAPI as "alice@example.com" with password "right"
      Then it fails mentioning "does not offer OpsAPI sign-in"

  Rule: Configs from the official WireGuard apps work as they are

    Scenario: A config saved by WireGuard for Windows
      Given I have imported a WireGuard config saved on Windows as "office"
      When I connect
      Then the tunnel is up
      And wg-quick brought up the config without a byte order mark or CR characters
