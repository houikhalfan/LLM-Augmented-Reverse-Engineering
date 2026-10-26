/*
 * sample_01_plain.c  –  SYNTHETIC MALWARE SAMPLE (safe, no real threat)
 * Obfuscation level : NONE  (plain-text IoCs)
 * Simulates        : C2 beacon + registry persistence
 */
#include <stdio.h>
#include <string.h>
#include <windows.h>

static const char *C2_IP     = "203.0.113.42";
static const char *C2_DOMAIN = "c2.malware-sample.test";
static const int   C2_PORT   = 4444;

static const char *REG_PATH  = "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SvcHost32";
static const char *REG_VALUE = "C:\\Windows\\System32\\svchost32.exe";

int beacon_connect(void) {
    printf("[*] Connecting to %s (%s:%d)\n", C2_DOMAIN, C2_IP, C2_PORT);
    return 0;
}

int install_persistence(void) {
    HKEY hKey;
    RegOpenKeyExA(HKEY_CURRENT_USER,
                  "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                  0, KEY_SET_VALUE, &hKey);
    RegSetValueExA(hKey, "SvcHost32", 0, REG_SZ,
                   (BYTE *)REG_VALUE, strlen(REG_VALUE)+1);
    RegCloseKey(hKey);
    return 0;
}

int main(void) {
    install_persistence();
    beacon_connect();
    return 0;
}
