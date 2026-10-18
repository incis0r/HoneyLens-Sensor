"""Text attack-detection rules — group: smb.

Auto-relocated from classification/text_rules.py (Phase 2 / T8). The rule
literals are verbatim; edit rules here, not in the façade.
"""

import re


def register(add):
    add(
        "SMB",
        "smb_impacket_psexec",
        r"(psexec\.py|impacket.*psexec|psexecsvc|RemCom_stdin|RemCom_stdout)",
        re.IGNORECASE,
    )

    add(
        "SMB",
        "smb_impacket_smbexec",
        r"(smbexec\.py|impacket.*smbexec|BTOBTO|execute\.bat)",
        re.IGNORECASE,
    )

    add("SMB", "smb_impacket_wmiexec", r"(wmiexec\.py|impacket.*wmiexec|__\d{10,})", re.IGNORECASE)

    add("SMB", "smb_impacket_atexec", r"(atexec\.py|impacket.*atexec)", re.IGNORECASE)

    add(
        "SMB", "smb_impacket_secretsdump", r"(secretsdump\.py|impacket.*secretsdump)", re.IGNORECASE
    )

    add("SMB", "smb_impacket_ntlmrelayx", r"(ntlmrelayx\.py|impacket.*ntlmrelay)", re.IGNORECASE)

    add("SMB", "smb_crackmapexec", r"(crackmapexec|cme\s+smb|nxc\s+smb)", re.IGNORECASE)

    add("SMB", "smb_smbmap", r"(smbmap|smbclient.*\-L|\-\-shares)", re.IGNORECASE)

    add("SMB", "smb_enum4linux", r"(enum4linux|rpcclient|samrdump)", re.IGNORECASE)

    add(
        "SMB",
        "smb_eternalblue",
        r"(eternalblue|eternal.?blue|ms17.?010|CVE.?2017.?0143|CVE.?2017.?0144)",
        re.IGNORECASE,
    )

    add(
        "SMB",
        "smb_eternalromance",
        r"(eternalromance|eternal.?romance|eternalsynergy|eternalchampion)",
        re.IGNORECASE,
    )

    add("SMB", "smb_doublepulsar", r"(doublepulsar|double.?pulsar)", re.IGNORECASE)

    add("SMB", "smb_shadowbrokers", r"(shadow.?brokers|fuzzbunch|equation.?group)", re.IGNORECASE)

    add("SMB", "smb_admin_share_access", r"(ADMIN\$|C\$|IPC\$|PRINT\$|FAX\$)\\", re.IGNORECASE)

    add(
        "SMB",
        "smb_remote_service_create",
        r"(sc\s+(create|config|start|stop).*\\\\|CreateService|OpenSCManager)",
        re.IGNORECASE,
    )

    add("SMB", "smb_psexec_service", r"(psexecsvc|PSEXEC|paexec|remcom|csexec)", re.IGNORECASE)

    add("SMB", "smb_wmi_lateral", r"(wmic.*\/node:|Win32_Process.*Create|wmiprvse)", re.IGNORECASE)

    add("SMB", "smb_ntlm_relay", r"(ntlm.?relay|smb.?relay|responder|inveigh)", re.IGNORECASE)

    add(
        "SMB",
        "smb_pass_the_hash",
        # "pth" needs word boundaries — bare, it matched the substring inside unrelated text
        # (e.g. an AnyConnect computer-name "jwebspthgm", "pthread", "depth"), tagging HTTP(S)
        # payloads as SMB. There is no SMB protocol to find inside an HTTP body.
        r"(pass.?the.?hash|\bpth\b|mimikatz|sekurlsa|lsadump)",
        re.IGNORECASE,
    )

    add("SMB", "smb_null_session", r"(null.?session|anonymous.?logon|guest.?access)", re.IGNORECASE)

    add("SMB", "smb_brute_force", r"(smb.*brute|hydra.*smb|medusa.*smb|ncrack.*smb)", re.IGNORECASE)

    add(
        "SMB", "smb_share_enum", r"(NetShareEnum|NetShareGetInfo|srvsvc|share.?enum)", re.IGNORECASE
    )

    add(
        "SMB",
        "smb_user_enum",
        r"(NetUserEnum|samr|lsarpc|QueryDisplayInfo|EnumDomainUsers)",
        re.IGNORECASE,
    )

    add("SMB", "smb_session_enum", r"(NetSessionEnum|NetWkstaUserEnum|wkssvc)", re.IGNORECASE)

    add(
        "SMB",
        "smb_signing_disabled",
        r"(signing.?not.?required|smb.?signing.?disabled|RequireSecuritySignature.?false)",
        re.IGNORECASE,
    )

    add("SMB", "smb_smb1_usage", r"(SMBv1|SMB\s*1\.0|CIFS|NT\s*LM\s*0\.12)", re.IGNORECASE)

    add("SMB", "smb_guest_fallback", r"(guest.?fallback|EnableInsecureGuestLogons)", re.IGNORECASE)

    add("SMB", "smb_named_pipe_svcctl", r"(\\pipe\\svcctl|\\svcctl)", re.IGNORECASE)

    add("SMB", "smb_named_pipe_atsvc", r"(\\pipe\\atsvc|\\atsvc)", re.IGNORECASE)

    add("SMB", "smb_named_pipe_samr", r"(\\pipe\\samr|\\samr)", re.IGNORECASE)

    add("SMB", "smb_named_pipe_lsarpc", r"(\\pipe\\lsarpc|\\lsarpc)", re.IGNORECASE)

    add("SMB", "smb_named_pipe_netlogon", r"(\\pipe\\netlogon|\\netlogon)", re.IGNORECASE)

    add("SMB", "smb_named_pipe_winreg", r"(\\pipe\\winreg|\\winreg)", re.IGNORECASE)

    add("SMB", "smb_named_pipe_srvsvc", r"(\\pipe\\srvsvc|\\srvsvc)", re.IGNORECASE)

    add(
        "SMB",
        "smb_named_pipe_spoolss",
        r"(\\pipe\\spoolss|\\spoolss|PrintNightmare)",
        re.IGNORECASE,
    )

    add("SMB", "smb_named_pipe_efsrpc", r"(\\pipe\\efsrpc|\\pipe\\lsass|PetitPotam)", re.IGNORECASE)

    add("SMB", "smb_exe_upload", r"(\\[^\\]+\.(exe|dll|bat|ps1|vbs|cmd)$)", re.IGNORECASE)

    add("SMB", "smb_sam_ntds_access", r"(\\SAM|\\NTDS\.dit|\\SYSTEM|\\SECURITY)", re.IGNORECASE)

    add("SMB", "smb_lsass_dump", r"(lsass\.dmp|procdump.*lsass|comsvcs.*MiniDump)", re.IGNORECASE)

    add("SMB", "smb_nmap_scripts", r"(smb-vuln|smb-enum|smb-os-discovery|smb-brute)", re.IGNORECASE)

    add(
        "SMB",
        "smb_metasploit_scanner",
        r"(smb_version|smb_login|smb_enumshares|smb_enumusers)",
        re.IGNORECASE,
    )

    add("SMB", "smb_smbghost", r"(smbghost|CVE.?2020.?0796|SMBv3.*compression)", re.IGNORECASE)

    add(
        "SMB",
        "smb_printnightmare",
        r"(printnightmare|CVE.?2021.?1675|CVE.?2021.?34527)",
        re.IGNORECASE,
    )

    add("SMB", "smb_petitpotam", r"(petitpotam|CVE.?2021.?36942|efsrpc)", re.IGNORECASE)

    add("SMB", "smb_zerologon", r"(zerologon|CVE.?2020.?1472|netlogon.*crypt)", re.IGNORECASE)

    add("SMB_EXPLOIT_PROBE", "SMB_Command_Execution", r"""smb:445.*cmd.exe""")

    add("RCE", "SMB_Command_Injection", r"""\b(cmd.exe|powershell|wget|Invoke-Expression)\b""")

    add("SMB_EXPLOIT_PROBE", "SMB_SMB_CMD_EXEC", r"""smb:445\s+\w+\s+cmd.exe""")

    add("SMB_EXPLOIT_PROBE", "claude_smb1_trans2_detection", r"""ff534d42.{8}32.{4}""")

    add("SMB_EXPLOIT_PROBE", "claude_smb1_trans2_exploit_detection", r"""ff534d4232.*1807c0""")

    add("SMB_EXPLOIT_PROBE", "claude_smb1_trans2_exploit_vector", r"""ff534d4232.*1807c0""")

    add("SMB_EXPLOIT_PROBE", "claude_smb1_trans2_exploitation_attempt", r"""ff534d42.{8}001807c0""")

    add("SMB_EXPLOIT_PROBE", "claude_smb_eternalblue_trans2_exploit", r"""ff534d42.{8}32.{8}""")

    add("SMB_EXPLOIT_PROBE", "claude_smb_trans2_exploitation_attempt", r"""ff534d42.{8}1807c0""")

    add("SMB_SCAN", "SMB_Custom_Payload", r"""SMB:445.*\x4d\x42.*\x75""")

    add(
        "SMB_SCAN",
        "SMB_Echo_Request_DoS",
        r"""^ff534d427200000000180148000000000000000000000000ffff6c1b00000000000c00024e54204c4d20302e313200$""",
    )

    add("RCE", "SMB_Redirect", r"""\b(start|cmd.exe)(\.|\s)(/c\s)(.*?)(http|www)""")

    add("SMB_SCAN", "SMB_Redirect_Attack", r"""SMB\:445\s+\[.*\]\s+\w+\:\d+\s+\[.*\]""")

    add("SMB_SCAN", "SMB_Traffic", r"""smb:\d+\.\d+\.\d+\s+\w+\s+\w+\s+\w+""")

    add("RCE", "SMB_Traffic_with_Suspicious_Payload", r"""wget.*malicious.*command""")

    add(
        "SMB_SCAN",
        "claude_smb1_eternalblue_reconnaissance",
        r"""ff534d42.{16,32}.*57696e646f7773203230303020323139350057696e646f7773203230303020352e30""",
    )

    add(
        "SMB_SCAN",
        "claude_smb1_external_connection_attempt",
        r"""ff534d42.{8}1807c0.*5c005c00.*5c00490050004300240000""",
    )

    add(
        "SMB_SCAN",
        "claude_smb1_external_enumeration",
        r"""ff534d42.*(?:49004300240000|490050004300240000)""",
    )

    add("SMB_SCAN", "claude_smb1_ipc_share_enumeration", r"""ff534d42.*75.*IPC\$""")

    # No leading `.*`. Under `search()` it matches nothing extra — `search` already scans
    # from every position — but it makes the engine re-scan the payload from each one.
    # Measured on an 8 KB non-matching payload: 2208 ms with it, 0.18 ms without, and
    # identical match/no-match over an SMB corpus plus near-misses and junk.
    add(
        "SMB_SCAN",
        "claude_smb1_legacy_dialect_negotiation",
        r"""SMB.*NT LM 0\.12|SMB.*LANMAN1\.0|SMB.*LM1\.2X002""",
    )

    add(
        "SMB_SCAN",
        "claude_smb1_negotiation_attempt",
        r"""ff534d427[0-9a-f]{2}000000[0-9a-f]{8}[0-9a-f]{8}""",
    )

    add(
        "SMB_SCAN",
        "claude_smb1_reconnaissance_detected",
        r"""ff534d42.{8}75.{16}.*5c005c00.*5c0049005000430024""",
    )

    add(
        "SMB_SCAN",
        "claude_smb_ipc_enumeration_with_replacement_pattern",
        r"""SMB.*\\[0-9.]+\\IPC\$.*ATH_REPLACE""",
    )

    # Leading and trailing `.*` dropped: 1633 ms -> 0.40 ms on 8 KB, same verdicts.
    add(
        "SMB_SCAN",
        "claude_smb_legacy_dialect_negotiation",
        r"""(?i)(NT LM 0\.12|Windows for Workgroups|LANMAN[0-9]\.[0-9])""",
    )

    add(
        "SMB_SCAN",
        "claude_smb_legacy_protocol_negotiation",
        r"""NT LM 0\.12|LANMAN[12]\.[01]|PC NETWORK PROGRAM 1\.0|Windows for Workgroups 3\.1""",
    )

    add(
        "SMB_SCAN",
        "claude_smb_multi_dialect_reconnaissance",
        r"""ff534d42.*4e54204c4d20302e3132.*534d4220322e30303[0-9].*534d4220322e""",
    )

    add("SMB_SCAN", "claude_smb_reconnaissance_short_payload", r"""^[0-9a-fA-F]{8}$""")

    add("SMB_SCAN", "claude_smb_v1_enumeration_ipc_share", r"""ff534d42.*\x49\x50\x43\x24""")

    add("SMB_SCAN", "claude_smb_v1_external_negotiation", r"""\xff\x53\x4d\x42.*NT LM 0\.12""")

    add(
        "SMB_SCAN",
        "claude_smb_v1_external_reconnaissance",
        r"""ff534d42.{16,}(4c414e4d414e|4c4d312e32|4e54204c414e4d414e|4e54204c4d)""",
    )

    add(
        "SMB_SCAN",
        "claude_smb_v1_legacy_dialect_negotiation",
        r"""ff534d42.*?(PC NETWORK PROGRAM|Windows for Workgroups|LANMAN1\.0)""",
    )

    add(
        "SMB_SCAN",
        "claude_smb_v1_negotiation_external",
        r"""ff534d42720000.*4e54204c4d20302e3132""",
    )

    # 636 ms -> 0.17 ms on 8 KB, same verdicts.
    add("SMB_SCAN", "claude_smb_v1_non_standard_port_detection", r"""SMB.*NT LM 0\.12""")
