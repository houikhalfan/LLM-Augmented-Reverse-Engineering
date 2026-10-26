/*
 * sample_05_xor.c  –  SYNTHETIC MALWARE SAMPLE (safe, no real threat)
 * Obfuscation level : XOR  (key = 0x42)
 * Simulates        : Stage-2 loader with XOR-obfuscated C2
 */
#include <stdio.h>
#include <string.h>

#define XOR_KEY 0x42

/* XOR-encoded IP  – decoded: 203.0.113.11  */
unsigned char enc_ip[] = {0x70, 0x72, 0x71, 0x6c, 0x72, 0x6c, 0x73, 0x73, 0x71, 0x6c, 0x73, 0x73, 0x00};

/* XOR-encoded domain – decoded: stage2.apt-sim.test */
unsigned char enc_dom[] = {0x31, 0x36, 0x23, 0x25, 0x27, 0x70, 0x6c, 0x23, 0x32, 0x36, 0x6f, 0x31, 0x2b, 0x2f, 0x6c, 0x36, 0x27, 0x31, 0x36, 0x00};

/* Registry persistence key (plain) */
static const char *REG_KEY = "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\NetHelper";

void xor_decode(unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; i++) buf[i] ^= XOR_KEY;
}

void stage2_init(void) {
    unsigned char ip[32],  dom[64];
    memcpy(ip,  enc_ip,  sizeof(enc_ip));
    memcpy(dom, enc_dom, sizeof(enc_dom));
    xor_decode(ip,  sizeof(enc_ip)  - 1);
    xor_decode(dom, sizeof(enc_dom) - 1);
    printf("[*] Stage2 C2 : %s / %s\n", (char*)ip, (char*)dom);
    printf("[*] Persist   : %s\n", REG_KEY);
}

int main(void) { stage2_init(); return 0; }
