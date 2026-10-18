"""
honeypots/honeypots_config.py — Per-protocol deception configuration
=====================================================================
Central place for banners, server names, version strings, and fake data
used by all honeypot services. Override any value via .env variables.

Usage:
    from honeylens.honeypots.honeypots_config import get_profile
    p = get_profile("ssh")
    banner = p["banner"]  # "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
"""

from __future__ import annotations

from honeylens.env import env

HONEYPOT_PROFILES = {
    "ssh": {
        "banner": env("HP_SSH_BANNER", "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"),
        "hostname": env("HP_SSH_HOSTNAME", "prod-web-03"),
        "motd": env("HP_SSH_MOTD", "Welcome to Ubuntu 20.04.6 LTS"),
    },
    "http": {
        # CVE-2026-23918 bait: Apache 2.4.66 mod_http2 double-free DoS.
        # Banner advertises both the vulnerable Apache build AND mod_http2 so
        # passive scanners (Shodan/ZoomEye/Google-dork `intext:"Apache/2.4.66" "HTTP/2"`)
        # flag this host. Also emit Upgrade: h2,h2c in the response so the dork's
        # "HTTP/2" substring matches. Active exploit needs TLS+ALPN-h2, which we
        # don't terminate — the handshake itself is the IoC.
        "server_header": env("HP_HTTP_SERVER", "Apache/2.4.66 (Ubuntu) mod_http2/2.0.32"),
        "powered_by": env("HP_HTTP_POWERED_BY", "PHP/7.4.3"),
        "title": env("HP_HTTP_TITLE", "Apache2 Ubuntu Default Page"),
        "hostname": env("HP_HTTP_HOSTNAME", "www.example.com"),
        "upgrade": env("HP_HTTP_UPGRADE", "h2,h2c"),
    },
    "ftp": {
        "banner": env("HP_FTP_BANNER", "220 ProFTPD 1.3.6 Server (Debian)"),
        "hostname": env("HP_FTP_HOSTNAME", "ftp.internal.local"),
    },
    "smtp": {
        "banner": env("HP_SMTP_BANNER", "220 mail.example.com ESMTP Postfix (Ubuntu)"),
        "hostname": env("HP_SMTP_HOSTNAME", "mail.example.com"),
        "domain": env("HP_SMTP_DOMAIN", "example.com"),
    },
    "telnet": {
        "banner": env("HP_TELNET_BANNER", "Ubuntu 20.04.6 LTS"),
        "hostname": env("HP_TELNET_HOSTNAME", "gateway"),
        "login_prompt": env("HP_TELNET_LOGIN", "login: "),
    },
    "mysql": {
        "version": env("HP_MYSQL_VERSION", "5.7.42-0ubuntu0.18.04.1"),
        "server_id": env("HP_MYSQL_SERVER_ID", "mysql-prod-01"),
    },
    "mssql": {
        "version": env("HP_MSSQL_VERSION", "Microsoft SQL Server 2019 (RTM-CU18)"),
        "instance": env("HP_MSSQL_INSTANCE", "MSSQLSERVER"),
        "hostname": env("HP_MSSQL_HOSTNAME", "SQL-PROD-01"),
    },
    "rdp": {
        "hostname": env("HP_RDP_HOSTNAME", "WIN-DC01"),
        "os_version": env("HP_RDP_OS", "Windows Server 2019"),
        "domain": env("HP_RDP_DOMAIN", "CORP"),
    },
    "smb": {
        "hostname": env("HP_SMB_HOSTNAME", "FILESERVER01"),
        "domain": env("HP_SMB_DOMAIN", "WORKGROUP"),
        "os": env("HP_SMB_OS", "Windows Server 2016"),
        "shares": env("HP_SMB_SHARES", "Documents,Backup,IT,Users").split(","),
    },
    "modbus": {
        "device_id": env("HP_MODBUS_DEVICE", "Schneider Electric PM5560"),
        "vendor": env("HP_MODBUS_VENDOR", "Schneider Electric"),
        "product_code": env("HP_MODBUS_PRODUCT", "PM5560"),
        "firmware": env("HP_MODBUS_FW", "3.4.2"),
        "unit_id": int(env("HP_MODBUS_UNIT_ID", "1")),
    },
    "s7comm": {
        "plc_name": env("HP_S7_NAME", "S7-1200 CPU 1214C"),
        "module_type": env("HP_S7_MODULE", "6ES7 214-1AG40-0XB0"),
        "serial": env("HP_S7_SERIAL", "S C-L9E87654321"),
        "firmware": env("HP_S7_FW", "V4.5.2"),
        "plant_id": env("HP_S7_PLANT", "WaterTreatment-PLC03"),
    },
    "mqtt": {
        "broker_name": env("HP_MQTT_BROKER", "Eclipse Mosquitto"),
        "version": env("HP_MQTT_VERSION", "2.0.18"),
        "topics": env(
            "HP_MQTT_TOPICS", "sensors/temp,sensors/humidity,actuators/valve01,plc/status"
        ).split(","),
    },
    "vnc": {
        "desktop_name": env("HP_VNC_DESKTOP", "server01:1 (root)"),
        "version": env("HP_VNC_VERSION", "003.008"),
    },
    "elasticsearch": {
        "cluster_name": env("HP_ES_CLUSTER", "elasticsearch-prod"),
        "node_name": env("HP_ES_NODE", "es-node-01"),
        "version": env("HP_ES_VERSION", "7.17.9"),
    },
    "redis": {
        "version": env("HP_REDIS_VERSION", "6.2.12"),
        "os": env("HP_REDIS_OS", "Linux 5.15.0-76-generic x86_64"),
        "mode": env("HP_REDIS_MODE", "standalone"),
    },
    "ldap": {
        "base_dn": env("HP_LDAP_BASE_DN", "DC=corp,DC=example,DC=com"),
        "domain": env("HP_LDAP_DOMAIN", "corp.example.com"),
        "dc_name": env("HP_LDAP_DC", "DC01.corp.example.com"),
        "org": env("HP_LDAP_ORG", "Example Corporation"),
        "fake_users": env("HP_LDAP_USERS", "admin,jsmith,svc_backup,krbtgt,sql_svc").split(","),
        "fake_groups": env("HP_LDAP_GROUPS", "Domain Admins,IT-Support,HR,Finance,VPN-Users").split(
            ","
        ),
    },
    "adb": {
        "device_model": env("HP_ADB_MODEL", "Pixel 6"),
        "android_ver": env("HP_ADB_ANDROID", "13"),
        "api_level": env("HP_ADB_API", "33"),
        "build": env("HP_ADB_BUILD", "TQ3A.230901.001"),
        "serial": env("HP_ADB_SERIAL", "emulator-5554"),
    },
    "afp": {
        "server_name": env("HP_AFP_NAME", "NAS-Backup-01"),
        "machine_type": env("HP_AFP_TYPE", "Synology DS920+"),
        "shares": env("HP_AFP_SHARES", "backup,photos,documents,media").split(","),
    },
    "cassandra": {
        "cluster_name": env("HP_CASS_CLUSTER", "production-cluster"),
        "dc_name": env("HP_CASS_DC", "dc1"),
        "version": env("HP_CASS_VERSION", "4.1.3"),
    },
    "rsync": {
        "version": env("HP_RSYNC_VERSION", "31.0"),
        "modules": env("HP_RSYNC_MODULES", "backup,www,etc,database-dumps,configs").split(","),
        "motd": env("HP_RSYNC_MOTD", "Welcome to backup.internal.example.com"),
    },
    "dahua": {
        "model": env("HP_DAHUA_MODEL", "DH-XVR5108HS-I3"),
        "firmware": env("HP_DAHUA_FW", "4.003.0000000.1"),
        "serial": env("HP_DAHUA_SERIAL", "6L08B6DPAZ12345"),
        "device_type": env("HP_DAHUA_TYPE", "XVR"),
    },
    "bacnet": {
        "device_name": env("HP_BACNET_NAME", "HVAC-Controller-01"),
        "vendor": env("HP_BACNET_VENDOR", "Johnson Controls"),
        "model": env("HP_BACNET_MODEL", "FX-PCG2611"),
        "location": env("HP_BACNET_LOCATION", "Building A Floor 3"),
        "object_id": int(env("HP_BACNET_OBJECT_ID", "12345")),
    },
    "fox": {
        "hostname": env("HP_FOX_HOSTNAME", "jace-8000"),
        "station_name": env("HP_FOX_STATION", "BMS_Station1"),
        "niagara_version": env("HP_FOX_NIAGARA", "4.10.3.36"),
        "host_id": env("HP_FOX_HOSTID", "Qnx-NPM6E-0000-1A2B-3C4D"),
        "brand_id": env("HP_FOX_BRAND", "vykon"),
        "timezone": env("HP_FOX_TZ", "America/New_York"),
        "vm_uuid": env("HP_FOX_VMUUID", "b8f1c2a0-1d34-4e56-8a90-001122334455"),
    },
    "profinet": {
        "vendor_id": env("HP_PROFINET_VENDOR", "0x002A"),
        "order_id": env("HP_PROFINET_ORDER", "6ES7 515-2AM01-0AB0"),
        "serial": env("HP_PROFINET_SERIAL", "S C-X1V234567"),
        "hw_rev": env("HP_PROFINET_HW", "5"),
        "sw_rev": env("HP_PROFINET_SW", "V2.9.2"),
        "station_name": env("HP_PROFINET_STATION", "plcxb1d0ed"),
    },
    "mms": {
        "vendor": env("HP_MMS_VENDOR", "SIEMENS"),
        "model": env("HP_MMS_MODEL", "SIPROTEC 5"),
        "revision": env("HP_MMS_REV", "V09.40"),
    },
}


def get_profile(protocol: str) -> dict:
    """Get honeypot profile for a protocol. Returns empty dict if not configured."""
    return HONEYPOT_PROFILES.get(protocol, {})
