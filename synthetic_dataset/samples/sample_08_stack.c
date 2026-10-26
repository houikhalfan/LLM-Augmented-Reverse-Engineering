/*
 * sample_08_stack.c  –  SYNTHETIC MALWARE SAMPLE (safe, no real threat)
 * Obfuscation level : STACK STRINGS (all IoCs)
 * Simulates        : Fully stack-string obfuscated exfil agent
 */
#include <stdio.h>

void exfil_agent(void) {
    /* Exfil server IP */
    char exfil_ip[14];
    exfil_ip[0] = 0x31; /* '1' */
    exfil_ip[1] = 0x39; /* '9' */
    exfil_ip[2] = 0x38; /* '8' */
    exfil_ip[3] = 0x2e; /* '.' */
    exfil_ip[4] = 0x35; /* '5' */
    exfil_ip[5] = 0x31; /* '1' */
    exfil_ip[6] = 0x2e; /* '.' */
    exfil_ip[7] = 0x31; /* '1' */
    exfil_ip[8] = 0x30; /* '0' */
    exfil_ip[9] = 0x30; /* '0' */
    exfil_ip[10] = 0x2e; /* '.' */
    exfil_ip[11] = 0x37; /* '7' */
    exfil_ip[12] = 0x37; /* '7' */
    exfil_ip[13] = '\0';

    /* Exfil server domain */
    char exfil_dom[21];
    exfil_dom[0] = 0x65; /* 'e' */
    exfil_dom[1] = 0x78; /* 'x' */
    exfil_dom[2] = 0x66; /* 'f' */
    exfil_dom[3] = 0x69; /* 'i' */
    exfil_dom[4] = 0x6c; /* 'l' */
    exfil_dom[5] = 0x2e; /* '.' */
    exfil_dom[6] = 0x73; /* 's' */
    exfil_dom[7] = 0x74; /* 't' */
    exfil_dom[8] = 0x61; /* 'a' */
    exfil_dom[9] = 0x63; /* 'c' */
    exfil_dom[10] = 0x6b; /* 'k' */
    exfil_dom[11] = 0x2d; /* '-' */
    exfil_dom[12] = 0x6c; /* 'l' */
    exfil_dom[13] = 0x61; /* 'a' */
    exfil_dom[14] = 0x62; /* 'b' */
    exfil_dom[15] = 0x2e; /* '.' */
    exfil_dom[16] = 0x74; /* 't' */
    exfil_dom[17] = 0x65; /* 'e' */
    exfil_dom[18] = 0x73; /* 's' */
    exfil_dom[19] = 0x74; /* 't' */
    exfil_dom[20] = '\0';

    /* Registry persistence key */
    char reg_key[68];
    reg_key[0] = 0x48; /* 'H' */
    reg_key[1] = 0x4b; /* 'K' */
    reg_key[2] = 0x4c; /* 'L' */
    reg_key[3] = 0x4d; /* 'M' */
    reg_key[4] = 0x5c; /* '\' */
    reg_key[5] = 0x53; /* 'S' */
    reg_key[6] = 0x6f; /* 'o' */
    reg_key[7] = 0x66; /* 'f' */
    reg_key[8] = 0x74; /* 't' */
    reg_key[9] = 0x77; /* 'w' */
    reg_key[10] = 0x61; /* 'a' */
    reg_key[11] = 0x72; /* 'r' */
    reg_key[12] = 0x65; /* 'e' */
    reg_key[13] = 0x5c; /* '\' */
    reg_key[14] = 0x4d; /* 'M' */
    reg_key[15] = 0x69; /* 'i' */
    reg_key[16] = 0x63; /* 'c' */
    reg_key[17] = 0x72; /* 'r' */
    reg_key[18] = 0x6f; /* 'o' */
    reg_key[19] = 0x73; /* 's' */
    reg_key[20] = 0x6f; /* 'o' */
    reg_key[21] = 0x66; /* 'f' */
    reg_key[22] = 0x74; /* 't' */
    reg_key[23] = 0x5c; /* '\' */
    reg_key[24] = 0x57; /* 'W' */
    reg_key[25] = 0x69; /* 'i' */
    reg_key[26] = 0x6e; /* 'n' */
    reg_key[27] = 0x64; /* 'd' */
    reg_key[28] = 0x6f; /* 'o' */
    reg_key[29] = 0x77; /* 'w' */
    reg_key[30] = 0x73; /* 's' */
    reg_key[31] = 0x20; /* ' ' */
    reg_key[32] = 0x4e; /* 'N' */
    reg_key[33] = 0x54; /* 'T' */
    reg_key[34] = 0x5c; /* '\' */
    reg_key[35] = 0x43; /* 'C' */
    reg_key[36] = 0x75; /* 'u' */
    reg_key[37] = 0x72; /* 'r' */
    reg_key[38] = 0x72; /* 'r' */
    reg_key[39] = 0x65; /* 'e' */
    reg_key[40] = 0x6e; /* 'n' */
    reg_key[41] = 0x74; /* 't' */
    reg_key[42] = 0x56; /* 'V' */
    reg_key[43] = 0x65; /* 'e' */
    reg_key[44] = 0x72; /* 'r' */
    reg_key[45] = 0x73; /* 's' */
    reg_key[46] = 0x69; /* 'i' */
    reg_key[47] = 0x6f; /* 'o' */
    reg_key[48] = 0x6e; /* 'n' */
    reg_key[49] = 0x5c; /* '\' */
    reg_key[50] = 0x57; /* 'W' */
    reg_key[51] = 0x69; /* 'i' */
    reg_key[52] = 0x6e; /* 'n' */
    reg_key[53] = 0x6c; /* 'l' */
    reg_key[54] = 0x6f; /* 'o' */
    reg_key[55] = 0x67; /* 'g' */
    reg_key[56] = 0x6f; /* 'o' */
    reg_key[57] = 0x6e; /* 'n' */
    reg_key[58] = 0x5c; /* '\' */
    reg_key[59] = 0x55; /* 'U' */
    reg_key[60] = 0x73; /* 's' */
    reg_key[61] = 0x65; /* 'e' */
    reg_key[62] = 0x72; /* 'r' */
    reg_key[63] = 0x69; /* 'i' */
    reg_key[64] = 0x6e; /* 'n' */
    reg_key[65] = 0x69; /* 'i' */
    reg_key[66] = 0x74; /* 't' */
    reg_key[67] = '\0';

    printf("[*] Exfil to : %s / %s\n", exfil_ip, exfil_dom);
    printf("[*] Persist  : %s\n", reg_key);
}

int main(void) { exfil_agent(); return 0; }
