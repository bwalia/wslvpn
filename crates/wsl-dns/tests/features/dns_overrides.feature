Feature: Overriding DNS records the ISP would return
  As someone on the VPN
  I want names I choose to resolve to addresses I choose
  So that I can reach internal services, and pin or block names,
  whatever my ISP's resolver says

  Background:
    Given the ISP's resolver says "intranet.example.com" is "203.0.113.9"
    And the ISP's resolver says "www.example.com" is "93.184.216.34"
    And the ISP's resolver says "intranet.example.com" is "2001:db8::9"

  Scenario: An overridden name resolves to the override, not the ISP's answer
    Given my overrides say "intranet.example.com" is "10.0.0.5"
    When I look up the A record for "intranet.example.com"
    Then I get "10.0.0.5"

  Scenario: A name I have not overridden still resolves through the ISP
    Given my overrides say "intranet.example.com" is "10.0.0.5"
    When I look up the A record for "www.example.com"
    Then I get "93.184.216.34"

  Scenario: An IPv4 override does not leak the ISP's IPv6 address
    Given my overrides say "intranet.example.com" is "10.0.0.5"
    When I look up the AAAA record for "intranet.example.com"
    Then I get no addresses and no error

  Scenario: A wildcard covers every subdomain, and an exact name refines it
    Given my overrides say "*.dev.example.com" is "10.0.1.1"
    And my overrides say "api.dev.example.com" is "10.0.1.2"
    When I look up the A record for "web.dev.example.com"
    Then I get "10.0.1.1"
    When I look up the A record for "api.dev.example.com"
    Then I get "10.0.1.2"

  Scenario: Blocking a name, the way a hosts file does
    Given my overrides say "tracker.example.com" is "0.0.0.0"
    When I look up the A record for "tracker.example.com"
    Then I get "0.0.0.0"

  Scenario: An edit takes effect without restarting the resolver
    Given my overrides say "intranet.example.com" is "10.0.0.5"
    When I look up the A record for "intranet.example.com"
    Then I get "10.0.0.5"
    When I change my overrides so "intranet.example.com" is "10.0.0.6"
    And I look up the A record for "intranet.example.com"
    Then I get "10.0.0.6"

  Scenario: A typo in the overrides does not switch them all off
    Given my overrides say "intranet.example.com" is "10.0.0.5"
    When I look up the A record for "intranet.example.com"
    And I break my overrides file with "not-an-ip intranet.example.com"
    And I look up the A record for "intranet.example.com"
    Then I get "10.0.0.5"

  Scenario: Lookups over TCP get the same answers
    Given my overrides say "intranet.example.com" is "10.0.0.5"
    When I look up the A record for "intranet.example.com" over TCP
    Then I get "10.0.0.5"
    When I look up the A record for "www.example.com" over TCP
    Then I get "93.184.216.34"

  Scenario: With the ISP unreachable, an unknown name fails fast rather than hanging
    Given the ISP's resolver is down
    And my overrides say "intranet.example.com" is "10.0.0.5"
    When I look up the A record for "www.example.com"
    Then the lookup fails with SERVFAIL
    When I look up the A record for "intranet.example.com"
    Then I get "10.0.0.5"
