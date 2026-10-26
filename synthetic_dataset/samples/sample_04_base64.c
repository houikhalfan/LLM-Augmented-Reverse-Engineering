/*
 * sample_04_base64.c  –  SYNTHETIC MALWARE SAMPLE (safe, no real threat)
 * Obfuscation level : BASE64 (all IoCs encoded)
 * Simulates        : Full base64-obfuscated drop server config
 */
#include <stdio.h>
#include <stdlib.h>

/* ALL indicators base64-encoded */
static const char B64_DROP_IP[]   = "MTk4LjUxLjEwMC4zMw==";  /* 198.51.100.33  */
static const char B64_DROP_DOM[]  = "ZHJvcC5leGZpbC1sYWIudGVzdA=="; /* drop.exfil-lab.test */
static const char B64_REG_KEY[]   = "SEtMTVxTb2Z0d2FyZVxNaWNyb3NvZnRcV2luZG93c1xDdXJyZW50VmVyc2lvblxSdW5cVGFza0hvc3Rz"; /* HKLM\Software\Microsoft\Windows\CurrentVersion\Run\TaskHosts */

char *base64_decode(const char *src, size_t *len) {
    (void)src; (void)len; return NULL; /* stub */
}

void drop_payload(void) {
    size_t l;
    char *ip  = base64_decode(B64_DROP_IP,  &l);
    char *dom = base64_decode(B64_DROP_DOM, &l);
    char *key = base64_decode(B64_REG_KEY,  &l);
    printf("[*] Drop server: %s / %s\n", ip, dom);
    printf("[*] Persist at : %s\n", key);
    free(ip); free(dom); free(key);
}

int main(void) { drop_payload(); return 0; }
