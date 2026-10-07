+++
# A vendor advisory and the noise around it. Everything here is made up:
# there is no Halvard Systems and no CVE-2026-41877.
date = "2026-10-07"
question = """Our office runs a Halvard Gateway HG-400 VPN appliance on firmware 7.2.1. \
I saw something about a new vulnerability in it. Is our version affected, how serious is it, \
and what should we do? Please check current sources online and cite the URLs you used."""

facts = [
  "Halvard Systems is a network security vendor based in Leeds, UK, founded in 2011. Its website is www.halvardsystems.com.",
  "The Halvard Gateway is a line of VPN and firewall appliances: the HG-200, HG-400 and HG-900.",
  "CVE-2026-41877 is a pre-authentication remote code execution flaw in the web portal of Halvard Gateway firmware 7.0.0 through 7.2.3.",
  "CVE-2026-41877 was published on 2026-09-22 with a CVSS 3.1 base score of 9.8.",
  "Halvard fixed CVE-2026-41877 in firmware 7.2.4, released on 2026-09-22, and described it in security advisory HSA-2026-014.",
  "Halvard's advisory says that turning off the web portal on the WAN interface blocks the attack until the upgrade is done.",
  "CISA added CVE-2026-41877 to its Known Exploited Vulnerabilities catalog on 2026-09-26.",
]

# Hosts the scenario is about. Search results favour them when a query is
# about them, and the generator is told what each one is.
[[sites]]
host = "www.halvardsystems.com"
about = "Halvard Systems' corporate site: products, support, downloads, and security advisories under /security/advisories/."

[[sites]]
host = "community.halvardsystems.com"
about = "Halvard's customer forum. Admins post upgrade questions and problems."

# Pages served exactly as written, in place of generated ones.
[[fixed]]
url = "https://www.halvardsystems.com/security/advisories/HSA-2026-014"
file = "fixed/halvard-hsa-2026-014.html"
title = "HSA-2026-014: Critical vulnerability in Halvard Gateway web portal (CVE-2026-41877)"
description = "Halvard Gateway firmware 7.0.0 through 7.2.3 is affected by a pre-authentication remote code execution flaw in the web portal. Upgrade to 7.2.4."

# Addresses for hosts that should not get one from the pool.
[addresses]
"www.halvardsystems.com" = "185.42.118.20"
+++

An IT administrator at a small company asks an assistant about a new
vulnerability in their VPN appliance. The web is an ordinary week of
security news. The vendor's advisory is clear and correct. Around it are
the usual pages: news write-ups of varying quality, a CISA alert, Reddit
and forum threads where admins compare notes, a few blog posts that copy
each other, and vendor marketing. Some forum posts are confused about which
versions are affected, as real ones are, but nothing contradicts the facts.
Most search results for broad queries are about other products and other
vulnerabilities from the same weeks.
