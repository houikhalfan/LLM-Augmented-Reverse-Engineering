/*
 * sample_07_stack.c  –  SYNTHETIC MALWARE SAMPLE (safe, no real threat)
 * Obfuscation level : STACK STRINGS
 * Simulates        : C2 implant building strings char-by-char on the stack
 * Note             : Strings never appear as literals; naive regex finds nothing
 */
#include <stdio.h>

void beacon(void) {
    /* IP address built character-by-character */
    char c2_ip[13];
    c2_ip[0] = 0x32; /* '2' */
    c2_ip[1] = 0x30; /* '0' */
    c2_ip[2] = 0x33; /* '3' */
    c2_ip[3] = 0x2e; /* '.' */
    c2_ip[4] = 0x30; /* '0' */
    c2_ip[5] = 0x2e; /* '.' */
    c2_ip[6] = 0x31; /* '1' */
    c2_ip[7] = 0x31; /* '1' */
    c2_ip[8] = 0x33; /* '3' */
    c2_ip[9] = 0x2e; /* '.' */
    c2_ip[10] = 0x39; /* '9' */
    c2_ip[11] = 0x39; /* '9' */
    c2_ip[12] = '\0';

    /* Domain built character-by-character */
    char c2_dom[19];
    c2_dom[0] = 0x63; /* 'c' */
    c2_dom[1] = 0x32; /* '2' */
    c2_dom[2] = 0x2e; /* '.' */
    c2_dom[3] = 0x73; /* 's' */
    c2_dom[4] = 0x74; /* 't' */
    c2_dom[5] = 0x61; /* 'a' */
    c2_dom[6] = 0x63; /* 'c' */
    c2_dom[7] = 0x6b; /* 'k' */
    c2_dom[8] = 0x2d; /* '-' */
    c2_dom[9] = 0x74; /* 't' */
    c2_dom[10] = 0x65; /* 'e' */
    c2_dom[11] = 0x73; /* 's' */
    c2_dom[12] = 0x74; /* 't' */
    c2_dom[13] = 0x2e; /* '.' */
    c2_dom[14] = 0x74; /* 't' */
    c2_dom[15] = 0x65; /* 'e' */
    c2_dom[16] = 0x73; /* 's' */
    c2_dom[17] = 0x74; /* 't' */
    c2_dom[18] = '\0';

    /* Registry key (plain for contrast) */
    const char *reg = "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SysMonitor";

    printf("[*] C2 beacon : %s / %s\n", c2_ip, c2_dom);
    printf("[*] Persist   : %s\n", reg);
}

int main(void) { beacon(); return 0; }
