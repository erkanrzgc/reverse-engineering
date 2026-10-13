// Decompiled by reverse-engineering
// Binary: C:\x5CUsers\x5Cerkanrzgc\x5CDesktop\x5Creverse-engineering\x5Cdocs\x5Creviews\x5C2026-10-13-rea\x5Cfixture\x5Csemantic-cases.exe
// Format: PE/EXE
// Architecture: x64
// Entry point: 0x1000
// Runtime hints: none detected

#include <stdint.h>
#include <stddef.h>

// String literals
const char str_2000[] = "REA comparative fixture";
const char str_301B[] = "\342\240\2000\344\200\2000\345\240\2000";
const char str_303F[] = "\347\234\2000\350\254\2000\351\240\2000\352\260\2000\353\250\2000\354\250\2000";
const char str_3064[] = "semantic-cases.exe";
const char str_3077[] = "fixture_conditional";
const char str_308B[] = "fixture_imul";
const char str_3098[] = "fixture_indexed_lea";
const char str_30AC[] = "fixture_movzx";
const char str_30BA[] = "fixture_partial";
const char str_30CA[] = "fixture_string";

// Function declarations
// 0x1000 (export)
uint64_t fixture_conditional(uint64_t rcx);
// 0x100E (export)
uint64_t fixture_imul(uint64_t rcx);
// 0x1012 (export)
uint64_t fixture_partial(void);
// 0x101C (export)
uint64_t fixture_movzx(void);
// 0x1027 (export)
uint64_t fixture_indexed_lea(uint64_t rcx, uint64_t rdx);
// 0x102D (export)
uint64_t fixture_string(void);

// Function implementations
// Function: fixture_conditional at 0x1000 (size: 14 bytes)
uint64_t fixture_conditional(uint64_t rcx) {
    uint64_t rax;
    /* 0x1000: cmp ecx,0 */
    if (((uint32_t)(uint64_t)(uint32_t)rcx == (uint32_t)0)) {
        rax = (uint32_t)0;
        return rax;
    } else {
        rax = (uint32_t)1;
        return rax;
    }
}

// Function: fixture_imul at 0x100E (size: 4 bytes)
uint64_t fixture_imul(uint64_t rcx) {
    uint64_t rax;
    rax = (uint32_t)((uint64_t)(uint32_t)rcx * 7);
    return rax;
}

// Function: fixture_partial at 0x1012 (size: 10 bytes)
uint64_t fixture_partial(void) {
    uint64_t rax;
    rax = 4660;
    rax = ((rax & -256) | (uint64_t)(uint8_t)86);
    return rax;
}

// Function: fixture_movzx at 0x101C (size: 11 bytes)
uint64_t fixture_movzx(void) {
    uint64_t rax;
    rax = 4660;
    rax = (uint32_t)(uint64_t)(uint8_t)rax;
    return rax;
}

// Function: fixture_indexed_lea at 0x1027 (size: 6 bytes)
uint64_t fixture_indexed_lea(uint64_t rcx, uint64_t rdx) {
    uint64_t rax;
    rax = ((rcx + (rdx * 8)) + -8);
    return rax;
}

// Function: fixture_string at 0x102D (size: 467 bytes)
uint64_t fixture_string(void) {
    uint64_t rax;
    rax = 8192;
    return rax;
    /* 0x1035: nop */
    /* 0x1036: nop */
    /* 0x1037: nop */
    /* 0x1038: nop */
    /* 0x1039: nop */
    /* 0x103A: nop */
    /* 0x103B: nop */
    /* 0x103C: nop */
    /* 0x103D: nop */
    /* 0x103E: nop */
    /* 0x103F: nop */
    /* 0x1040: add [rax],al */
    /* 0x1042: add [rax],al */
    /* 0x1044: add [rax],al */
    /* 0x1046: add [rax],al */
    /* 0x1048: add [rax],al */
    /* 0x104A: add [rax],al */
    /* 0x104C: add [rax],al */
    /* 0x104E: add [rax],al */
    /* 0x1050: add [rax],al */
    /* 0x1052: add [rax],al */
    /* 0x1054: add [rax],al */
    /* 0x1056: add [rax],al */
    /* 0x1058: add [rax],al */
    /* 0x105A: add [rax],al */
    /* 0x105C: add [rax],al */
    /* 0x105E: add [rax],al */
    /* 0x1060: add [rax],al */
    /* 0x1062: add [rax],al */
    /* 0x1064: add [rax],al */
    /* 0x1066: add [rax],al */
    /* 0x1068: add [rax],al */
    /* 0x106A: add [rax],al */
    /* 0x106C: add [rax],al */
    /* 0x106E: add [rax],al */
    /* 0x1070: add [rax],al */
    /* 0x1072: add [rax],al */
    /* 0x1074: add [rax],al */
    /* 0x1076: add [rax],al */
    /* 0x1078: add [rax],al */
    /* 0x107A: add [rax],al */
    /* 0x107C: add [rax],al */
    /* 0x107E: add [rax],al */
    /* 0x1080: add [rax],al */
    /* 0x1082: add [rax],al */
    /* 0x1084: add [rax],al */
    /* 0x1086: add [rax],al */
    /* 0x1088: add [rax],al */
    /* 0x108A: add [rax],al */
    /* 0x108C: add [rax],al */
    /* 0x108E: add [rax],al */
    /* 0x1090: add [rax],al */
    /* 0x1092: add [rax],al */
    /* 0x1094: add [rax],al */
    /* 0x1096: add [rax],al */
    /* 0x1098: add [rax],al */
    /* 0x109A: add [rax],al */
    /* 0x109C: add [rax],al */
    /* 0x109E: add [rax],al */
    /* 0x10A0: add [rax],al */
    /* 0x10A2: add [rax],al */
    /* 0x10A4: add [rax],al */
    /* 0x10A6: add [rax],al */
    /* 0x10A8: add [rax],al */
    /* 0x10AA: add [rax],al */
    /* 0x10AC: add [rax],al */
    /* 0x10AE: add [rax],al */
    /* 0x10B0: add [rax],al */
    /* 0x10B2: add [rax],al */
    /* 0x10B4: add [rax],al */
    /* 0x10B6: add [rax],al */
    /* 0x10B8: add [rax],al */
    /* 0x10BA: add [rax],al */
    /* 0x10BC: add [rax],al */
    /* 0x10BE: add [rax],al */
    /* 0x10C0: add [rax],al */
    /* 0x10C2: add [rax],al */
    /* 0x10C4: add [rax],al */
    /* 0x10C6: add [rax],al */
    /* 0x10C8: add [rax],al */
    /* 0x10CA: add [rax],al */
    /* 0x10CC: add [rax],al */
    /* 0x10CE: add [rax],al */
    /* 0x10D0: add [rax],al */
    /* 0x10D2: add [rax],al */
    /* 0x10D4: add [rax],al */
    /* 0x10D6: add [rax],al */
    /* 0x10D8: add [rax],al */
    /* 0x10DA: add [rax],al */
    /* 0x10DC: add [rax],al */
    /* 0x10DE: add [rax],al */
    /* 0x10E0: add [rax],al */
    /* 0x10E2: add [rax],al */
    /* 0x10E4: add [rax],al */
    /* 0x10E6: add [rax],al */
    /* 0x10E8: add [rax],al */
    /* 0x10EA: add [rax],al */
    /* 0x10EC: add [rax],al */
    /* 0x10EE: add [rax],al */
    /* 0x10F0: add [rax],al */
    /* 0x10F2: add [rax],al */
    /* 0x10F4: add [rax],al */
    /* 0x10F6: add [rax],al */
    /* 0x10F8: add [rax],al */
    /* 0x10FA: add [rax],al */
    /* 0x10FC: add [rax],al */
    /* 0x10FE: add [rax],al */
    /* 0x1100: add [rax],al */
    /* 0x1102: add [rax],al */
    /* 0x1104: add [rax],al */
    /* 0x1106: add [rax],al */
    /* 0x1108: add [rax],al */
    /* 0x110A: add [rax],al */
    /* 0x110C: add [rax],al */
    /* 0x110E: add [rax],al */
    /* 0x1110: add [rax],al */
    /* 0x1112: add [rax],al */
    /* 0x1114: add [rax],al */
    /* 0x1116: add [rax],al */
    /* 0x1118: add [rax],al */
    /* 0x111A: add [rax],al */
    /* 0x111C: add [rax],al */
    /* 0x111E: add [rax],al */
    /* 0x1120: add [rax],al */
    /* 0x1122: add [rax],al */
    /* 0x1124: add [rax],al */
    /* 0x1126: add [rax],al */
    /* 0x1128: add [rax],al */
    /* 0x112A: add [rax],al */
    /* 0x112C: add [rax],al */
    /* 0x112E: add [rax],al */
    /* 0x1130: add [rax],al */
    /* 0x1132: add [rax],al */
    /* 0x1134: add [rax],al */
    /* 0x1136: add [rax],al */
    /* 0x1138: add [rax],al */
    /* 0x113A: add [rax],al */
    /* 0x113C: add [rax],al */
    /* 0x113E: add [rax],al */
    /* 0x1140: add [rax],al */
    /* 0x1142: add [rax],al */
    /* 0x1144: add [rax],al */
    /* 0x1146: add [rax],al */
    /* 0x1148: add [rax],al */
    /* 0x114A: add [rax],al */
    /* 0x114C: add [rax],al */
    /* 0x114E: add [rax],al */
    /* 0x1150: add [rax],al */
    /* 0x1152: add [rax],al */
    /* 0x1154: add [rax],al */
    /* 0x1156: add [rax],al */
    /* 0x1158: add [rax],al */
    /* 0x115A: add [rax],al */
    /* 0x115C: add [rax],al */
    /* 0x115E: add [rax],al */
    /* 0x1160: add [rax],al */
    /* 0x1162: add [rax],al */
    /* 0x1164: add [rax],al */
    /* 0x1166: add [rax],al */
    /* 0x1168: add [rax],al */
    /* 0x116A: add [rax],al */
    /* 0x116C: add [rax],al */
    /* 0x116E: add [rax],al */
    /* 0x1170: add [rax],al */
    /* 0x1172: add [rax],al */
    /* 0x1174: add [rax],al */
    /* 0x1176: add [rax],al */
    /* 0x1178: add [rax],al */
    /* 0x117A: add [rax],al */
    /* 0x117C: add [rax],al */
    /* 0x117E: add [rax],al */
    /* 0x1180: add [rax],al */
    /* 0x1182: add [rax],al */
    /* 0x1184: add [rax],al */
    /* 0x1186: add [rax],al */
    /* 0x1188: add [rax],al */
    /* 0x118A: add [rax],al */
    /* 0x118C: add [rax],al */
    /* 0x118E: add [rax],al */
    /* 0x1190: add [rax],al */
    /* 0x1192: add [rax],al */
    /* 0x1194: add [rax],al */
    /* 0x1196: add [rax],al */
    /* 0x1198: add [rax],al */
    /* 0x119A: add [rax],al */
    /* 0x119C: add [rax],al */
    /* 0x119E: add [rax],al */
    /* 0x11A0: add [rax],al */
    /* 0x11A2: add [rax],al */
    /* 0x11A4: add [rax],al */
    /* 0x11A6: add [rax],al */
    /* 0x11A8: add [rax],al */
    /* 0x11AA: add [rax],al */
    /* 0x11AC: add [rax],al */
    /* 0x11AE: add [rax],al */
    /* 0x11B0: add [rax],al */
    /* 0x11B2: add [rax],al */
    /* 0x11B4: add [rax],al */
    /* 0x11B6: add [rax],al */
    /* 0x11B8: add [rax],al */
    /* 0x11BA: add [rax],al */
    /* 0x11BC: add [rax],al */
    /* 0x11BE: add [rax],al */
    /* 0x11C0: add [rax],al */
    /* 0x11C2: add [rax],al */
    /* 0x11C4: add [rax],al */
    /* 0x11C6: add [rax],al */
    /* 0x11C8: add [rax],al */
    /* 0x11CA: add [rax],al */
    /* 0x11CC: add [rax],al */
    /* 0x11CE: add [rax],al */
    /* 0x11D0: add [rax],al */
    /* 0x11D2: add [rax],al */
    /* 0x11D4: add [rax],al */
    /* 0x11D6: add [rax],al */
    /* 0x11D8: add [rax],al */
    /* 0x11DA: add [rax],al */
    /* 0x11DC: add [rax],al */
    /* 0x11DE: add [rax],al */
    /* 0x11E0: add [rax],al */
    /* 0x11E2: add [rax],al */
    /* 0x11E4: add [rax],al */
    /* 0x11E6: add [rax],al */
    /* 0x11E8: add [rax],al */
    /* 0x11EA: add [rax],al */
    /* 0x11EC: add [rax],al */
    /* 0x11EE: add [rax],al */
    /* 0x11F0: add [rax],al */
    /* 0x11F2: add [rax],al */
    /* 0x11F4: add [rax],al */
    /* 0x11F6: add [rax],al */
    /* 0x11F8: add [rax],al */
    /* 0x11FA: add [rax],al */
    /* 0x11FC: add [rax],al */
    /* 0x11FE: add [rax],al */
}

