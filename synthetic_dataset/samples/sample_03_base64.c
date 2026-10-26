/*
 * sample_03_base64.c  –  SYNTHETIC MALWARE SAMPLE (safe, no real threat)
 * Obfuscation level : BASE64
 * Simulates        : C2 beacon with base64-encoded network indicators
 * Note             : Strings decoded at runtime via base64_decode()
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* base64 alphabet */
static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Encoded IoCs – not readable by naive regex */
static const char ENC_IP[]     = "MjAzLjAuMTEzLjg4";   /* decodes to: 203.0.113.88  */
static const char ENC_DOMAIN[] = "YmVhY29uLmMyLXRlc3QudGVzdA=="; /* decodes to: beacon.c2-test.test */

static const char *REG_PERSIST = "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\UpdaterSvc";  /* registry key (plain) */

char *base64_decode(const char *src, size_t *out_len) {
    /* ... standard base64 decode implementation ... */
    (void)src; (void)out_len;
    return NULL; /* stub */
}

void c2_connect(void) {
    size_t ip_len = 0, dom_len = 0;
    char *ip  = base64_decode(ENC_IP,     &ip_len);
    char *dom = base64_decode(ENC_DOMAIN, &dom_len);
    printf("[*] Decoded C2: %s / %s\n", ip, dom);
    free(ip); free(dom);
}

int main(void) {
    c2_connect();
    return 0;
}
