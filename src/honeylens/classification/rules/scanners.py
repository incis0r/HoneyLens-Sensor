"""Text attack-detection rules — group: scanners.

Auto-relocated from classification/text_rules.py (Phase 2 / T8). The rule
literals are verbatim; edit rules here, not in the façade.
"""

import re


def register(add):
    add("SCANNER", "Scanner-Shodan", r"(Shodan|shodan\.io)", re.IGNORECASE)

    add("SCANNER", "Scanner-Censys", r"(Censys|censys\.io|CensysInspect)", re.IGNORECASE)

    add("SCANNER", "Scanner-ZoomEye", r"(ZoomEye|zoomeye\.org)", re.IGNORECASE)

    add("SCANNER", "Scanner-BinaryEdge", r"(BinaryEdge|binaryedge\.io)", re.IGNORECASE)

    add("SCANNER", "Scanner-Shadowserver", r"(Shadowserver|shadowserver\.org)", re.IGNORECASE)

    add(
        "SCANNER",
        "Scanner-PaloAlto",
        r"(Palo\s*Alto\s*Networks|paloaltonetworks\.com|Expanse)",
        re.IGNORECASE,
    )

    add(
        "SCANNER",
        "Scanner-Cisco",
        r"(Cisco\s+Talos|Cisco\s+Umbrella|talosintelligence)",
        re.IGNORECASE,
    )

    add("SCANNER", "Scanner-Rapid7", r"(Rapid7|Project\s*Sonar|sonar\.labs)", re.IGNORECASE)

    add("SCANNER", "Scanner-Qualys", r"(Qualys|QualysGuard)", re.IGNORECASE)

    add("SCANNER", "Scanner-Tenable", r"(Tenable|Nessus|nessus\.org)", re.IGNORECASE)

    add("SCANNER", "Scanner-GreyNoise", r"(GreyNoise|greynoise\.io)", re.IGNORECASE)

    add("SCANNER", "Scanner-Onyphe", r"(ONYPHE|onyphe\.io)", re.IGNORECASE)

    add("SCANNER", "Scanner-Stretchoid", r"(Stretchoid|stretchoid\.com)", re.IGNORECASE)

    add("SCANNER", "Scanner-LeakIX", r"(LeakIX|leakix\.net)", re.IGNORECASE)

    add("SCANNER", "Scanner-CriminalIP", r"(Criminal\s*IP|criminalip\.io)", re.IGNORECASE)

    add(
        "SCANNER",
        "Scanner-InternetMeasurement",
        r"(internet-measurement\.com|InternetMeasurement)",
        re.IGNORECASE,
    )

    add("SCANNER", "Scanner-Modat", r"(ModatScanner|modat\.io)", re.IGNORECASE)

    add(
        "SCANNER",
        "Scanner-CVE-Checker-Family",
        r"CVE-\d{4}-\d{4,5}-(?:Checker|MassChecker|Scanner|Probe|Tester)",
        re.IGNORECASE,
    )

    add("SCANNER", "Scanner-PaloAlto-CVE-Checker", r"panos-cve-\d{4}-\d{4,5}-", re.IGNORECASE)

    add(
        "SCANNER",
        "Scanner-Email-Shape-UA",
        r"Mozilla/[\d.]+\s+\([a-zA-Z0-9_.+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\)",
        re.IGNORECASE,
    )

    add("SCANNER", "Actor-rondo2012", r"rondo2012@atomicmail\.io", re.IGNORECASE)

    add("SCANNER", "Scanner-Apache-2466-h2-Library", r"^(?:python-h2|h2|hyper-h2)/", re.IGNORECASE)

    add(
        "SCANNER",
        "Scanner-CVE-2026-23918-Family",
        r"CVE-?2026-?23918[-_]?(Scanner|Checker|Probe|Tester|Hunter)",
        re.IGNORECASE,
    )

    add(
        "SCANNER",
        "Scanner-Apache-2466-Probe",
        r"apache[-_/]?\s*2\.4\.66.{0,16}(?:scan|probe|check|hunt|dork)",
        re.IGNORECASE,
    )

    add(
        "SCANNER",
        "NMAP-Scan",
        r"(Nmap\s+Scripting\s+Engine|nmap\.org/book|NSE-Script|User-Agent:.*Nmap)",
    )

    add("SCANNER", "scan_nikto", r"(Nikto|nikto[\-/]\d)")

    add("SCANNER", "scan_sqlmap", r"(sqlmap|--tamper=|--technique=|--dbms=)")

    add(
        "SCANNER",
        "scan_dirbuster",
        r"(DirBuster|Gobuster|dirb|dirsearch|ffuf|feroxbuster)",
        re.IGNORECASE,
    )

    add("SCANNER", "scan_masscan", r"(masscan|zmap|zgrab)")

    add("SCANNER", "scan_nuclei", r"(Nuclei|nuclei\-templates|projectdiscovery)")

    add("SCANNER", "scan_wpscan", r"(WPScan|wpscan\.com)")

    add("SCANNER", "scan_metasploit", r"(Metasploit|meterpreter|msf[\-/]|PAYLOAD=)")

    add("SCANNER", "scan_cobalt_strike", r"(cobalt\s*strike|beacon\.dll|cobaltstrike)")

    add(
        "SCANNER",
        "scan_user_agent_bot",
        r"(zgrab|masscan|CensysInspect|Shodan|InternetMeasurement|"
        r"Go-http-client|python-requests|PycURL|libwww-perl|"
        r"Java/\d|okhttp|curl/|Wget/)",
    )

    add(
        "SCANNER",
        "scan_cgi_probe",
        r"/cgi-bin/(phf|php|test-cgi|printenv|php\.cgi|" r"awstats|webdist|handler)",
    )

    add(
        "SCANNER",
        "scan_vuln_paths",
        r"/(\.git/|\.svn/|\.env|\.DS_Store|wp-admin|wp-login|"
        r"wp-config|xmlrpc\.php|administrator/|phpMyAdmin|phpmyadmin|"
        r"admin/|\.well-known/|actuator/|api/swagger|server-status|"
        r"server-info|manager/html|jenkins|solr|console|"
        r"debug/|elmah\.axd|trace\.axd)",
    )

    # Same IDS-syntax leak as the MQTT rule above: the pattern was the literal text
    # `payload =~ /.../`, so it matched nothing on any sensor.
    add(
        "SCANNER",
        "Suspicious_TCP_traffic_with_unusual_payload",
        r"""636363303030303030303030303030303030303030303030303030303030303036613065626536343030303030303030""",
    )

    add(
        "SCANNER",
        "claude_ssh_libssh2_reconnaissance_banner",
        r"""SSH-2\.0-libssh2_[0-9]+\.[0-9]+\.[0-9]+""",
    )

    # --- AndroxGh0st (CISA AA24-016A) -------------------------------------------------------
    #
    # The botnet's opening move against a new address is one `POST /` with a twenty-byte
    # constant body: `0x%5B%5D=androxgh0st`, which is `0x[]=androxgh0st` URL-encoded -- a PHP
    # array-parameter trick that tests whether the target parses the body as PHP input.
    #
    # Measured over 30 days to 2026-11-04 (the internal AndroxGh0st IOC notes §2): 1,402 rows from
    # 20+ addresses on four sensors -- sensor-a 732, sensor-b 645, sensor-c 22, sensor-e 3 -- and
    # EVERY ONE has an empty `attack_types`. It is not rare, not stale and not quiet: it arrived
    # four times in the 24 hours before the sheet was written. The core cluster is one operator
    # cycling twelve addresses in a single /24.
    #
    # Two rules, because the sheet asks for two detections and they are not the same claim. The
    # byte-identical constant is the fingerprint; the botnet's name on its own says only that
    # the name went past. The exact probe satisfies both, so it comes back `ANDROXGH0ST,RECON`
    # as specified, and the fallback alone comes back `RECON`.
    #
    # LOW, and deliberately so. §5.3 names the mistake to avoid as the `sp-webshell-aspx` one:
    # nothing in a twenty-byte body executes anything, and a HIGH verdict would claim more than
    # the evidence carries. The probe also arrives alone on this fleet -- no `.env` sweep
    # follows from the same address in the same minute, because our decoys do not answer like a
    # PHP app, so there is no second stage to point at.
    add(
        "ANDROXGH0ST",
        "androxgh0st_probe_body",
        r"0x(?:%5[bB]%5[dD]|\[\])\s*=\s*androxgh0st",
        re.IGNORECASE,
    )

    add("RECON", "androxgh0st_named_token", r"androxgh0st", re.IGNORECASE)
