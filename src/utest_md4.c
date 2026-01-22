#include <stdio.h>
#include <string.h>
#include "md4.h"

int main(void) {
    int fail = 0;
    // test 0, len=0
    const unsigned char *in0 = (const unsigned char*)"";
    const unsigned char exp0[16] = {0x31,0xd6,0xcf,0xe0,0xd1,0x6a,0xe9,0x31,0xb7,0x3c,0x59,0xd7,0xe0,0xc0,0x89,0xc0};
    unsigned char out0[16];
    MD4_CTX ctx0;
    MD4_Init(&ctx0);
    MD4_Update(&ctx0, in0, 0);
    MD4_Final(out0, &ctx0);
    if (memcmp(out0, exp0, 16) != 0) {
        printf("MD4 test 0 FAILED\n");
        fail = 1;
    }
    // test 1, len=3
    const unsigned char *in1 = (const unsigned char*)"abc";
    const unsigned char exp1[16] = {0xa4,0x48,0x01,0x7a,0xaf,0x21,0xd8,0x52,0x5f,0xc1,0x0a,0xe8,0x7a,0xa6,0x72,0x9d};
    unsigned char out1[16];
    MD4_CTX ctx1;
    MD4_Init(&ctx1);
    MD4_Update(&ctx1, in1, 3);
    MD4_Final(out1, &ctx1);
    if (memcmp(out1, exp1, 16) != 0) {
        printf("MD4 test 1 FAILED\n");
        fail = 1;
    }
    // test 2, len=80
    const unsigned char *in2 = (const unsigned char*)"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const unsigned char exp2[16] = {0x72,0x1a,0x93,0xb0,0x51,0x04,0x9c,0x47,0x48,0x7b,0x06,0xa5,0x9a,0xcc,0x7d,0x64};
    unsigned char out2[16];
    MD4_CTX ctx2;
    MD4_Init(&ctx2);
    MD4_Update(&ctx2, in2, 80);
    MD4_Final(out2, &ctx2);
    if (memcmp(out2, exp2, 16) != 0) {
        printf("MD4 test 2 FAILED\n");
        fail = 1;
    }
    // test 3, len=163
    const unsigned char *in3 = (const unsigned char*)"hbVrpoiVgRV5IfLBcbfnoGMbJmTPSIAoCLrZ3aWZkSBvrjn9Wvgfygw2wMqZcUDIh7yfJs1ON43xKmTecQoXsf2o3gyrDO1xkxwnQrS7RPeMOkIUpkDyr7OSJoRu1XXdo0cZuzren68K4TunPFz46PDjqipVJIqVLB5";
    const unsigned char exp3[16] = {0x15,0x31,0xad,0x5e,0xe3,0xa8,0x02,0x2b,0x06,0x58,0xd0,0x6e,0x5e,0xdc,0x2e,0x24};
    unsigned char out3[16];
    MD4_CTX ctx3;
    MD4_Init(&ctx3);
    MD4_Update(&ctx3, in3, 163);
    MD4_Final(out3, &ctx3);
    if (memcmp(out3, exp3, 16) != 0) {
        printf("MD4 test 3 FAILED\n");
        fail = 1;
    }
    // test 4, len=149
    const unsigned char *in4 = (const unsigned char*)"zxoiGFfWd3hjOkYRBMeyyMDHqJ38aRUhR4IWrXPvhsBkDa9U4UqGWlG6g3Ot1OGMmjxWkI9X7H6aMuFbh7x41Ztpdp4K8ffUF0eWIXiiQE8JkqH3MB9n7IWUSmTtzQPxC5HChpoevbLJoLoaeTOdo";
    const unsigned char exp4[16] = {0xc5,0x05,0x95,0x65,0x95,0x4b,0xe0,0x3c,0x7e,0x75,0x6d,0x50,0x9e,0xa9,0xd3,0xbf};
    unsigned char out4[16];
    MD4_CTX ctx4;
    MD4_Init(&ctx4);
    MD4_Update(&ctx4, in4, 149);
    MD4_Final(out4, &ctx4);
    if (memcmp(out4, exp4, 16) != 0) {
        printf("MD4 test 4 FAILED\n");
        fail = 1;
    }
    // test 5, len=17
    const unsigned char *in5 = (const unsigned char*)"5c3veGprQFnIiU74K";
    const unsigned char exp5[16] = {0x03,0xe0,0x77,0xd6,0xcf,0x52,0x19,0xfe,0x47,0x70,0x7d,0xe8,0x2d,0x0e,0x18,0xd7};
    unsigned char out5[16];
    MD4_CTX ctx5;
    MD4_Init(&ctx5);
    MD4_Update(&ctx5, in5, 17);
    MD4_Final(out5, &ctx5);
    if (memcmp(out5, exp5, 16) != 0) {
        printf("MD4 test 5 FAILED\n");
        fail = 1;
    }
    // test 6, len=147
    const unsigned char *in6 = (const unsigned char*)"EpYEZAmggQBwBAD3UdRPPgdzUvZ3gpmmICiBlrDp37eCZ32JgdPI1af7W2pkAFEn3z5dkyayq7YYDsBS9UYJQTFjmsn9dLVIdVuddLEG62Hkd9Gf2leMeR3pzh84KpLMcNfAQLKHu7qnQTupqzi";
    const unsigned char exp6[16] = {0x69,0x6e,0x7f,0x05,0xbf,0xb7,0x22,0xad,0x44,0x4f,0x15,0xbb,0xd2,0xce,0xc5,0x2e};
    unsigned char out6[16];
    MD4_CTX ctx6;
    MD4_Init(&ctx6);
    MD4_Update(&ctx6, in6, 147);
    MD4_Final(out6, &ctx6);
    if (memcmp(out6, exp6, 16) != 0) {
        printf("MD4 test 6 FAILED\n");
        fail = 1;
    }
    // test 7, len=171
    const unsigned char *in7 = (const unsigned char*)"PtDu7W7eaDNKgeInGqi7w4e4pxskC1ITtNZPHaQ0Jt7Qg84iqh4gVJjrsMnTvnRO2qGFq562dfOB1rcavXiOqkVCJTBJahe84S5jIc1xLJjBictx57Y3c5wnRpQgwXJ43ANVj77p3kZZl4AblV7vY7AZQ3VZprkYSgy3c2Eom06";
    const unsigned char exp7[16] = {0x1b,0x1e,0x44,0x8d,0x80,0x6e,0x12,0x4d,0x9e,0x23,0x5e,0xba,0x0e,0xc8,0xc7,0x90};
    unsigned char out7[16];
    MD4_CTX ctx7;
    MD4_Init(&ctx7);
    MD4_Update(&ctx7, in7, 171);
    MD4_Final(out7, &ctx7);
    if (memcmp(out7, exp7, 16) != 0) {
        printf("MD4 test 7 FAILED\n");
        fail = 1;
    }
    // test 8, len=117
    const unsigned char *in8 = (const unsigned char*)"wt0Y3oobQmzvr3e9XrwPGzR1Iv8bh4qlL9qcgMBwUYuBMGhy5KmqcTBaH7ZIRU8VVQmxBe8Q6vNuQ2hU5tGtQAuzSsJimAQ8yRV5lNKtzJ1atsnBYLMPu";
    const unsigned char exp8[16] = {0xe7,0x47,0x87,0x4a,0x28,0x85,0xd2,0x27,0xc9,0xb9,0xdd,0xf1,0x2b,0x05,0xc3,0xa7};
    unsigned char out8[16];
    MD4_CTX ctx8;
    MD4_Init(&ctx8);
    MD4_Update(&ctx8, in8, 117);
    MD4_Final(out8, &ctx8);
    if (memcmp(out8, exp8, 16) != 0) {
        printf("MD4 test 8 FAILED\n");
        fail = 1;
    }
    // test 9, len=119
    const unsigned char *in9 = (const unsigned char*)"CCRnGEY59YVkQfsGQONvf08WpRtoZmjbcpEN2XeDA4OKmTSyFzpjPSa5W3X4gXBolZ9SHDdJp62hDiZDQHJMu8W5CN0U5GB16JC5kV3ECqWp1OrXXHFOprC";
    const unsigned char exp9[16] = {0xcc,0x4f,0xb1,0x13,0x28,0x90,0x2e,0x51,0xe5,0xf5,0xe9,0xcf,0xb2,0xb1,0xd9,0xa9};
    unsigned char out9[16];
    MD4_CTX ctx9;
    MD4_Init(&ctx9);
    MD4_Update(&ctx9, in9, 119);
    MD4_Final(out9, &ctx9);
    if (memcmp(out9, exp9, 16) != 0) {
        printf("MD4 test 9 FAILED\n");
        fail = 1;
    }
    // test 10, len=19
    const unsigned char *in10 = (const unsigned char*)"Tsprvu5IfijoySjTneA";
    const unsigned char exp10[16] = {0xb7,0xbe,0x82,0xa8,0x34,0x57,0xa6,0xe8,0x5a,0xc8,0x33,0x1a,0x4e,0x9c,0xa4,0xcb};
    unsigned char out10[16];
    MD4_CTX ctx10;
    MD4_Init(&ctx10);
    MD4_Update(&ctx10, in10, 19);
    MD4_Final(out10, &ctx10);
    if (memcmp(out10, exp10, 16) != 0) {
        printf("MD4 test 10 FAILED\n");
        fail = 1;
    }
    // test 11, len=104
    const unsigned char *in11 = (const unsigned char*)"vIDAdn1Ay5XL8Sb24WKyEa8wtWy2591AIVVIZM5oForBFbyvQRZzUk1D6iNIb6zLKQbfPBi3DldqyunDuvW4yrW81Aq1fEbVId8woPeX";
    const unsigned char exp11[16] = {0x88,0x5d,0x98,0x59,0x68,0xb1,0x82,0x30,0xe6,0xf2,0x23,0x59,0x47,0x90,0x55,0x0d};
    unsigned char out11[16];
    MD4_CTX ctx11;
    MD4_Init(&ctx11);
    MD4_Update(&ctx11, in11, 104);
    MD4_Final(out11, &ctx11);
    if (memcmp(out11, exp11, 16) != 0) {
        printf("MD4 test 11 FAILED\n");
        fail = 1;
    }
    // test 12, len=166
    const unsigned char *in12 = (const unsigned char*)"cWb8pm1bNjpiEQhK8nDSqXxkMM9VThX0k9tgLb7tKR69yz8TmeLS1OpgSXt2RMZhYKYcwIBQxeGPva2A0FgB9xO51DTjBlUH9PrNZ6IXEDB0ULru2p17fr4CpWDKNQyvbF2ulFnwZqvr4MS4rJaH8mfpUAFJWpSEPTFCYb";
    const unsigned char exp12[16] = {0x87,0x68,0x16,0x69,0xf9,0x7c,0x73,0xd3,0x0d,0x25,0x92,0xf8,0x8d,0x72,0x99,0xe5};
    unsigned char out12[16];
    MD4_CTX ctx12;
    MD4_Init(&ctx12);
    MD4_Update(&ctx12, in12, 166);
    MD4_Final(out12, &ctx12);
    if (memcmp(out12, exp12, 16) != 0) {
        printf("MD4 test 12 FAILED\n");
        fail = 1;
    }
    // test 13, len=23
    const unsigned char *in13 = (const unsigned char*)"sozSptQLxEJHwBVJvwSDrtq";
    const unsigned char exp13[16] = {0xf7,0x22,0x15,0xc4,0x75,0x54,0x2d,0x58,0x37,0x3e,0xd1,0xdb,0x9b,0xd4,0x34,0xab};
    unsigned char out13[16];
    MD4_CTX ctx13;
    MD4_Init(&ctx13);
    MD4_Update(&ctx13, in13, 23);
    MD4_Final(out13, &ctx13);
    if (memcmp(out13, exp13, 16) != 0) {
        printf("MD4 test 13 FAILED\n");
        fail = 1;
    }
    // test 14, len=59
    const unsigned char *in14 = (const unsigned char*)"hUmuhVI8WSlmnVErULWHMsg1msoxltaTIircdJsS8iO3WFg3aKsEECvl9dq";
    const unsigned char exp14[16] = {0xdf,0x29,0x8b,0x9d,0x68,0x77,0x30,0xb2,0x9a,0x59,0xcf,0x6b,0x29,0xe6,0xaf,0x48};
    unsigned char out14[16];
    MD4_CTX ctx14;
    MD4_Init(&ctx14);
    MD4_Update(&ctx14, in14, 59);
    MD4_Final(out14, &ctx14);
    if (memcmp(out14, exp14, 16) != 0) {
        printf("MD4 test 14 FAILED\n");
        fail = 1;
    }
    // test 15, len=122
    const unsigned char *in15 = (const unsigned char*)"h0ezFeKORdjjZK8tfphJWAMMYNoXHyC6Ct3LBtKNdN9Vg8WnOnqQfkplJekaACSMEscosTsS3DeRo7qYYOLQZ7mBhIoPj6r0jedkYtMV0K6sChDStSz8rGIFCf";
    const unsigned char exp15[16] = {0x01,0x1b,0x7f,0x93,0xcd,0x87,0x6a,0xd5,0xef,0xfa,0xe2,0x88,0x27,0xdc,0x6c,0x17};
    unsigned char out15[16];
    MD4_CTX ctx15;
    MD4_Init(&ctx15);
    MD4_Update(&ctx15, in15, 122);
    MD4_Final(out15, &ctx15);
    if (memcmp(out15, exp15, 16) != 0) {
        printf("MD4 test 15 FAILED\n");
        fail = 1;
    }
    // test 16, len=153
    const unsigned char *in16 = (const unsigned char*)"c4BVuMqbfo9R13KL8bWR0rKcWWlEHPC6rlLBO0FfEwAvuQg2kvASFsQ8z0WJcDfuquhXz3G0aQ3IDAdmHxNWFOCWdnrJi7sC4SFhbOMZpTktJaJAfo16hD8hP1jF7TsGTrA1EEpDJjym6MGV4i3erXY2A";
    const unsigned char exp16[16] = {0x6a,0xc3,0xc9,0x2b,0xba,0xcf,0x4f,0xf6,0xe4,0x51,0x1f,0x76,0x19,0xdf,0x02,0xf9};
    unsigned char out16[16];
    MD4_CTX ctx16;
    MD4_Init(&ctx16);
    MD4_Update(&ctx16, in16, 153);
    MD4_Final(out16, &ctx16);
    if (memcmp(out16, exp16, 16) != 0) {
        printf("MD4 test 16 FAILED\n");
        fail = 1;
    }
    // test 17, len=87
    const unsigned char *in17 = (const unsigned char*)"7YGr0asUt1LLQF3jCIEwvJWIyD7u3mSpKyo2XAcuVET6ZyyQY0PjF9ciG9Lv3g32CgH6DaUjA3PjeEYqvNSzPf2";
    const unsigned char exp17[16] = {0x8c,0x8f,0x2b,0x82,0xb8,0xd5,0xc9,0x3b,0x7d,0x58,0x30,0xb4,0xee,0xd8,0x8b,0xf1};
    unsigned char out17[16];
    MD4_CTX ctx17;
    MD4_Init(&ctx17);
    MD4_Update(&ctx17, in17, 87);
    MD4_Final(out17, &ctx17);
    if (memcmp(out17, exp17, 16) != 0) {
        printf("MD4 test 17 FAILED\n");
        fail = 1;
    }
    // test 18, len=84
    const unsigned char *in18 = (const unsigned char*)"2R2Iy9uOT4WF3IcNepOR6soVfBgWOT3gCkSt5bcuYdswxBjpHAKRYlklfN3yNRpF6LjoDOqDqQa5ZD5sRIke";
    const unsigned char exp18[16] = {0x33,0x7b,0xf3,0x0c,0x57,0x8a,0x79,0xfc,0xa1,0x3d,0x4c,0xe9,0x80,0x38,0x01,0xc9};
    unsigned char out18[16];
    MD4_CTX ctx18;
    MD4_Init(&ctx18);
    MD4_Update(&ctx18, in18, 84);
    MD4_Final(out18, &ctx18);
    if (memcmp(out18, exp18, 16) != 0) {
        printf("MD4 test 18 FAILED\n");
        fail = 1;
    }
    // test 19, len=113
    const unsigned char *in19 = (const unsigned char*)"8wLtO9BSqD2tmy2EgpyKwKsSsb1QzraK3RXVd6MVF155sXZoMZwoOmNqRWUXQR1iOg5OPctYCcLxUif6suVAlmiYI4xHG6r1kq608E9ZsV3vZhD9e";
    const unsigned char exp19[16] = {0x57,0x10,0x01,0xfe,0xec,0xba,0x2a,0x80,0xeb,0x62,0x8e,0xd7,0x4c,0x88,0x83,0xf5};
    unsigned char out19[16];
    MD4_CTX ctx19;
    MD4_Init(&ctx19);
    MD4_Update(&ctx19, in19, 113);
    MD4_Final(out19, &ctx19);
    if (memcmp(out19, exp19, 16) != 0) {
        printf("MD4 test 19 FAILED\n");
        fail = 1;
    }
    // test 20, len=36
    const unsigned char *in20 = (const unsigned char*)"W9o3RURz92ZJxfYzaqIhDxRVRqLy0O8xgRoE";
    const unsigned char exp20[16] = {0xf9,0x1b,0xda,0x0d,0x2c,0x18,0x6a,0xc4,0xef,0x32,0xd7,0xcd,0x07,0xae,0x61,0x7b};
    unsigned char out20[16];
    MD4_CTX ctx20;
    MD4_Init(&ctx20);
    MD4_Update(&ctx20, in20, 36);
    MD4_Final(out20, &ctx20);
    if (memcmp(out20, exp20, 16) != 0) {
        printf("MD4 test 20 FAILED\n");
        fail = 1;
    }
    // test 21, len=6
    const unsigned char *in21 = (const unsigned char*)"N48Ju6";
    const unsigned char exp21[16] = {0x86,0x4d,0x78,0xc0,0x3f,0xe5,0x5b,0xb8,0x4a,0x5c,0x4c,0x29,0x75,0x91,0x04,0x52};
    unsigned char out21[16];
    MD4_CTX ctx21;
    MD4_Init(&ctx21);
    MD4_Update(&ctx21, in21, 6);
    MD4_Final(out21, &ctx21);
    if (memcmp(out21, exp21, 16) != 0) {
        printf("MD4 test 21 FAILED\n");
        fail = 1;
    }
    // test 22, len=156
    const unsigned char *in22 = (const unsigned char*)"oPeO0D6StPAhic8ctFhgp4IiyDxQ8VS8IALVUj4APg1FNA88rcSxnCC8p2xgRxI5Pwdzrm9h820DfQnPOMbdYvpiYKne1WJnLn03ovXjY5Mar2jiIqZlhQ3biawYYpLublqdiVAHhVeECXxGLgCGo8NcUY63";
    const unsigned char exp22[16] = {0x85,0x7b,0xe5,0x0d,0xfc,0xdd,0xbe,0x6b,0xf2,0x77,0xb4,0xc8,0x53,0xee,0x49,0xf1};
    unsigned char out22[16];
    MD4_CTX ctx22;
    MD4_Init(&ctx22);
    MD4_Update(&ctx22, in22, 156);
    MD4_Final(out22, &ctx22);
    if (memcmp(out22, exp22, 16) != 0) {
        printf("MD4 test 22 FAILED\n");
        fail = 1;
    }
    // test 23, len=168
    const unsigned char *in23 = (const unsigned char*)"HtDP9bdE2zBRgFT6Ce5fuMjeirNOLJTuyMHsDGMBgYSh2PP4XJU3nBC4oAv0DzAUguBuQqx9jR7Eef1ffBgVVxZiJdL9JJvQhAw3Q8WB36Ud9sMtwgKGnjQEo2gw2JxhWrKoZB2JX0NNRPJbM7Q1SrblrSWt6vwal3jKQzej";
    const unsigned char exp23[16] = {0xdb,0x65,0xbb,0xe2,0x94,0x0d,0xb3,0xf0,0x64,0x6c,0x5b,0xaa,0x06,0x03,0x8e,0x23};
    unsigned char out23[16];
    MD4_CTX ctx23;
    MD4_Init(&ctx23);
    MD4_Update(&ctx23, in23, 168);
    MD4_Final(out23, &ctx23);
    if (memcmp(out23, exp23, 16) != 0) {
        printf("MD4 test 23 FAILED\n");
        fail = 1;
    }
    // test 24, len=189
    const unsigned char *in24 = (const unsigned char*)"ObfVHnyADvkxtUuX8KMf4djkWNdRfrCQBFMCArnWGhwBhsRRLFHQtcozMdant8nXiWqsuhaFVBliyIToGJ1QZwez3VcBbD6e3uKBKzTOAshzb9ukZ8ND1S6xfB2gpBLzHfz3tVvovXkeGOhHGm5XwwU90P0jpgjqmlMjWWPel8XOFDWKWLCR74KPONu3O";
    const unsigned char exp24[16] = {0x39,0x67,0x23,0xff,0x75,0xd0,0x01,0x4b,0x75,0x59,0x16,0x8f,0xbe,0x74,0x36,0xf2};
    unsigned char out24[16];
    MD4_CTX ctx24;
    MD4_Init(&ctx24);
    MD4_Update(&ctx24, in24, 189);
    MD4_Final(out24, &ctx24);
    if (memcmp(out24, exp24, 16) != 0) {
        printf("MD4 test 24 FAILED\n");
        fail = 1;
    }
    // test 25, len=80
    const unsigned char *in25 = (const unsigned char*)"jCeECOtYrLdwGetDCcdx1seP32fNMGyDLJ9YV5cC6ZKPmuMEGj9dCgZ51vTfGPlcpTCCHHNkxx6syAXv";
    const unsigned char exp25[16] = {0x1d,0xad,0x92,0x05,0x8d,0xf0,0x23,0x7b,0xd4,0x71,0xc0,0x4c,0x15,0x51,0x1d,0xcb};
    unsigned char out25[16];
    MD4_CTX ctx25;
    MD4_Init(&ctx25);
    MD4_Update(&ctx25, in25, 80);
    MD4_Final(out25, &ctx25);
    if (memcmp(out25, exp25, 16) != 0) {
        printf("MD4 test 25 FAILED\n");
        fail = 1;
    }
    // test 26, len=173
    const unsigned char *in26 = (const unsigned char*)"MdYOPvevgJRysqU2Q96M3jvfLQj6wt9PSQziMT8ftJyPYv0iQS18VR6HfPQBGxbxtl8nv8XFmoijes2YgGXI1V4HcQv4XNiMyjkl1SXNZ5kUCcAxRUpCNsWVYCoIpt9ZYE51mxR8KCDXsXyGHA9k0mZMi3qdPE3xJ7gT2H2hsfWkr";
    const unsigned char exp26[16] = {0x63,0x5c,0x67,0x3a,0x7d,0xa1,0x20,0xfb,0x1f,0x6d,0x9f,0xd3,0xaa,0x97,0xea,0x62};
    unsigned char out26[16];
    MD4_CTX ctx26;
    MD4_Init(&ctx26);
    MD4_Update(&ctx26, in26, 173);
    MD4_Final(out26, &ctx26);
    if (memcmp(out26, exp26, 16) != 0) {
        printf("MD4 test 26 FAILED\n");
        fail = 1;
    }
    // test 27, len=115
    const unsigned char *in27 = (const unsigned char*)"5Gj1Bf86o0C4w7bAdzGxpyfxobu7g1TPvYjics61ES1iWTECNa5fbqn1jJ8UMHBhXspthdpAOYNDeh15FMIbOGKpTjsBaNwpKAlQQfHxe9HIGYGJby3";
    const unsigned char exp27[16] = {0x3a,0xa4,0x8d,0xd1,0x1b,0xfb,0xe8,0xa9,0xda,0x9d,0x8a,0x6c,0xad,0x42,0x21,0xb3};
    unsigned char out27[16];
    MD4_CTX ctx27;
    MD4_Init(&ctx27);
    MD4_Update(&ctx27, in27, 115);
    MD4_Final(out27, &ctx27);
    if (memcmp(out27, exp27, 16) != 0) {
        printf("MD4 test 27 FAILED\n");
        fail = 1;
    }
    // test 28, len=120
    const unsigned char *in28 = (const unsigned char*)"cOyxqVbwYewpUQOgXLVWvicwIv0Pl1XRDSEOlZieTX8DcsmcYm4cu7tGz0IEqcWPmsw3Xd3PvrhZxB4zVC59yvlFSFx7ZHrZfUBfBM0lIsugfuQstCMTBkSC";
    const unsigned char exp28[16] = {0x85,0x5d,0x09,0x0c,0xba,0xd6,0x1c,0x1a,0xaf,0xee,0x97,0x1c,0x2b,0xeb,0x53,0xe5};
    unsigned char out28[16];
    MD4_CTX ctx28;
    MD4_Init(&ctx28);
    MD4_Update(&ctx28, in28, 120);
    MD4_Final(out28, &ctx28);
    if (memcmp(out28, exp28, 16) != 0) {
        printf("MD4 test 28 FAILED\n");
        fail = 1;
    }
    // test 29, len=89
    const unsigned char *in29 = (const unsigned char*)"CcU36wNBrOY8deQOzxGZVRk8bj2MRYCciepXPxxy8KcMjRC8xxCWeKiHxzuPrp9hbVlFHy6JhqXqTCnNsS6Fmhi2e";
    const unsigned char exp29[16] = {0x14,0xf4,0x3a,0x01,0x60,0xc7,0xf5,0x5e,0x41,0xfa,0x95,0x9a,0x92,0xcf,0x2c,0x16};
    unsigned char out29[16];
    MD4_CTX ctx29;
    MD4_Init(&ctx29);
    MD4_Update(&ctx29, in29, 89);
    MD4_Final(out29, &ctx29);
    if (memcmp(out29, exp29, 16) != 0) {
        printf("MD4 test 29 FAILED\n");
        fail = 1;
    }
    // test 30, len=115
    const unsigned char *in30 = (const unsigned char*)"l5TCfZR92uQwTeJIs5t2kTT7SOlYxGohmYipYFbxJKxDZJiN4fetzTUEHAXA0KeiuPeCDRHwi41XJOLlX9iBG63d1hHjtkku7Tow88H5s2fqmO9JriO";
    const unsigned char exp30[16] = {0x0e,0x34,0x47,0xd9,0xcf,0x2f,0x95,0x5a,0x45,0x3f,0xd8,0x23,0x11,0x03,0x74,0x56};
    unsigned char out30[16];
    MD4_CTX ctx30;
    MD4_Init(&ctx30);
    MD4_Update(&ctx30, in30, 115);
    MD4_Final(out30, &ctx30);
    if (memcmp(out30, exp30, 16) != 0) {
        printf("MD4 test 30 FAILED\n");
        fail = 1;
    }
    // test 31, len=77
    const unsigned char *in31 = (const unsigned char*)"NIfGPkL8LjkQNU5Mv17Kc03bfc8PXKqPnXKANObF4OIsP9tEpZZRztDeSdkCAEDnvMju3TuU3wziW";
    const unsigned char exp31[16] = {0x8d,0x44,0x8d,0xf5,0x51,0xfd,0xa1,0xfc,0x9f,0x45,0x5e,0x23,0xca,0xd9,0x1c,0x7e};
    unsigned char out31[16];
    MD4_CTX ctx31;
    MD4_Init(&ctx31);
    MD4_Update(&ctx31, in31, 77);
    MD4_Final(out31, &ctx31);
    if (memcmp(out31, exp31, 16) != 0) {
        printf("MD4 test 31 FAILED\n");
        fail = 1;
    }
    // test 32, len=94
    const unsigned char *in32 = (const unsigned char*)"GJgupDhrCpjgds8y3NAp935k0u7KUumWkFGDF4tFbf8zGD9pnLwddsFM41PREsIa2gBi4qUxWzxczdKJmxJseyGCWJr0NR";
    const unsigned char exp32[16] = {0x43,0xa2,0x54,0x71,0x4b,0x31,0x33,0x23,0xa1,0xaa,0x5d,0xb5,0x21,0xbb,0x2b,0x23};
    unsigned char out32[16];
    MD4_CTX ctx32;
    MD4_Init(&ctx32);
    MD4_Update(&ctx32, in32, 94);
    MD4_Final(out32, &ctx32);
    if (memcmp(out32, exp32, 16) != 0) {
        printf("MD4 test 32 FAILED\n");
        fail = 1;
    }
    // test 33, len=156
    const unsigned char *in33 = (const unsigned char*)"higzxYvJ8xWjmMGzGccciTvZEHDjM5Giu7NukzNV1tLvG1GIFTKtE0bxvRhALtY5U3SObMEq9PYXLKoUdLEkHOUNX1yj0RpcK8ShmbCuAjASnAGXN6E32VUdTiHnJuQEHyu9lD6IvIwRX3URPZSqNEm9prJt";
    const unsigned char exp33[16] = {0x6a,0xbe,0xbe,0x87,0x52,0x2e,0xd2,0x76,0x0d,0xec,0x34,0x07,0xfb,0xd9,0x62,0x5c};
    unsigned char out33[16];
    MD4_CTX ctx33;
    MD4_Init(&ctx33);
    MD4_Update(&ctx33, in33, 156);
    MD4_Final(out33, &ctx33);
    if (memcmp(out33, exp33, 16) != 0) {
        printf("MD4 test 33 FAILED\n");
        fail = 1;
    }
    // test 34, len=57
    const unsigned char *in34 = (const unsigned char*)"8tXsTnSTFuEwJ77YUrshKRIy5z0w9XZjscs9Tfw7CPqVEnm0Ir7JSrigN";
    const unsigned char exp34[16] = {0x12,0xdd,0x2e,0xa5,0x84,0x59,0xd8,0xfc,0x1d,0x75,0xb1,0x4a,0x0b,0x65,0xed,0xe2};
    unsigned char out34[16];
    MD4_CTX ctx34;
    MD4_Init(&ctx34);
    MD4_Update(&ctx34, in34, 57);
    MD4_Final(out34, &ctx34);
    if (memcmp(out34, exp34, 16) != 0) {
        printf("MD4 test 34 FAILED\n");
        fail = 1;
    }
    // test 35, len=189
    const unsigned char *in35 = (const unsigned char*)"LppdQ5HoOodgAvTEgRXia9J7kAP744EEPmW9susPd6XfPKoIVU27c66lA41l76c1zYFl7V937s4catKMg7vsDPIHF48i2GDrmZhvkUDPqTlaVvYsKRWmlN2O5z0BGufzQgliEu7paqypCWr9vtLUKaqPxSpdQhDtkzRG754TXtShO68sxNoo9iEjDVMxA";
    const unsigned char exp35[16] = {0x21,0x5e,0x04,0xaf,0x8e,0x50,0xa4,0x6d,0xb3,0x25,0xb3,0xbf,0x7b,0xb0,0xd5,0x86};
    unsigned char out35[16];
    MD4_CTX ctx35;
    MD4_Init(&ctx35);
    MD4_Update(&ctx35, in35, 189);
    MD4_Final(out35, &ctx35);
    if (memcmp(out35, exp35, 16) != 0) {
        printf("MD4 test 35 FAILED\n");
        fail = 1;
    }
    // test 36, len=179
    const unsigned char *in36 = (const unsigned char*)"J6EWIZQ0nWpRWM3YfHCHTxe6Khd1J5GmKIjku2HChRnTLFf5GCZdDiGADKdJDRZtUbzq0aVnLecBwSeId75e7EcsAlXiXPUP9Ax5yC366yyfR9Q3IiP3whlIzHiUo1aWbtDRUIBIy0opDwjrm74UWhcZQANX744bpnegMcCMRT3dpVczCoI";
    const unsigned char exp36[16] = {0x54,0x8e,0x47,0x6b,0xa8,0x1b,0xe1,0xae,0xe8,0xc0,0xc8,0xbb,0xd6,0x13,0x37,0x4b};
    unsigned char out36[16];
    MD4_CTX ctx36;
    MD4_Init(&ctx36);
    MD4_Update(&ctx36, in36, 179);
    MD4_Final(out36, &ctx36);
    if (memcmp(out36, exp36, 16) != 0) {
        printf("MD4 test 36 FAILED\n");
        fail = 1;
    }
    // test 37, len=55
    const unsigned char *in37 = (const unsigned char*)"W3XdiGso06UKuKMXR0upt4jQHoAtrdJ8L4V6lORBJFdw8PQyYHuSAAj";
    const unsigned char exp37[16] = {0x07,0xfc,0xef,0x60,0xe8,0x5c,0x50,0xfd,0x05,0xf2,0x39,0xb0,0xec,0x23,0x88,0x14};
    unsigned char out37[16];
    MD4_CTX ctx37;
    MD4_Init(&ctx37);
    MD4_Update(&ctx37, in37, 55);
    MD4_Final(out37, &ctx37);
    if (memcmp(out37, exp37, 16) != 0) {
        printf("MD4 test 37 FAILED\n");
        fail = 1;
    }
    // test 38, len=76
    const unsigned char *in38 = (const unsigned char*)"ylWIEp2ot2TjZD6dJA9AJHiypqnvPf7C2xfIU1mdryRMMc3emZWLUQJnEn36vt96an7m9VhVWE6p";
    const unsigned char exp38[16] = {0x86,0xec,0x89,0x82,0x46,0x44,0x8f,0xbc,0xbd,0xda,0x42,0x6e,0xbb,0xa5,0x9f,0xd0};
    unsigned char out38[16];
    MD4_CTX ctx38;
    MD4_Init(&ctx38);
    MD4_Update(&ctx38, in38, 76);
    MD4_Final(out38, &ctx38);
    if (memcmp(out38, exp38, 16) != 0) {
        printf("MD4 test 38 FAILED\n");
        fail = 1;
    }
    // test 39, len=178
    const unsigned char *in39 = (const unsigned char*)"MTnz6pJuXsyDIPwtqxG4FDgZUEW1u6nxuAcK3oVjbqJ7LLUAsjmvoyK1pFJP8RvqW0F9UPVFDkUYwkiUIFl64IP9dHc12e80QdWaAi1OoeTjanGDxdNOQ7N6EQFbaIJAabHUrIsbG0SRBZ86lg6gHjpmNHq0wrYzfx9zDKpSotR02fP2PW";
    const unsigned char exp39[16] = {0x53,0xe9,0x34,0x2b,0x7b,0xdc,0xbb,0x1e,0x4b,0x50,0x8b,0x3e,0x1d,0x6e,0x38,0xbc};
    unsigned char out39[16];
    MD4_CTX ctx39;
    MD4_Init(&ctx39);
    MD4_Update(&ctx39, in39, 178);
    MD4_Final(out39, &ctx39);
    if (memcmp(out39, exp39, 16) != 0) {
        printf("MD4 test 39 FAILED\n");
        fail = 1;
    }
    // test 40, len=8
    const unsigned char *in40 = (const unsigned char*)"fzyyJEdO";
    const unsigned char exp40[16] = {0xde,0xea,0x52,0x39,0xb9,0x18,0x8c,0x39,0xea,0xdf,0x37,0x97,0x3a,0x0f,0xdc,0x4b};
    unsigned char out40[16];
    MD4_CTX ctx40;
    MD4_Init(&ctx40);
    MD4_Update(&ctx40, in40, 8);
    MD4_Final(out40, &ctx40);
    if (memcmp(out40, exp40, 16) != 0) {
        printf("MD4 test 40 FAILED\n");
        fail = 1;
    }
    // test 41, len=2
    const unsigned char *in41 = (const unsigned char*)"Sk";
    const unsigned char exp41[16] = {0x19,0xff,0xf3,0x94,0x82,0xbe,0x64,0x4f,0x96,0xe2,0xe5,0x99,0x2a,0x4f,0x4d,0x9d};
    unsigned char out41[16];
    MD4_CTX ctx41;
    MD4_Init(&ctx41);
    MD4_Update(&ctx41, in41, 2);
    MD4_Final(out41, &ctx41);
    if (memcmp(out41, exp41, 16) != 0) {
        printf("MD4 test 41 FAILED\n");
        fail = 1;
    }
    // test 42, len=21
    const unsigned char *in42 = (const unsigned char*)"F2BPYvK2g5H6con53S4KE";
    const unsigned char exp42[16] = {0xa3,0x2b,0x87,0x4b,0x1f,0xa4,0x17,0x6b,0x84,0x9c,0x97,0x63,0x21,0x13,0xb2,0x40};
    unsigned char out42[16];
    MD4_CTX ctx42;
    MD4_Init(&ctx42);
    MD4_Update(&ctx42, in42, 21);
    MD4_Final(out42, &ctx42);
    if (memcmp(out42, exp42, 16) != 0) {
        printf("MD4 test 42 FAILED\n");
        fail = 1;
    }
    // test 43, len=69
    const unsigned char *in43 = (const unsigned char*)"c7eR7r5IKQcl72ub9nLjW0T0z7etkKpK12yR5IvyWViYSUfGVwdgBo1evMXN9MzXubOrY";
    const unsigned char exp43[16] = {0x0b,0x42,0x01,0x79,0x63,0x42,0xb1,0x00,0x24,0xf0,0x69,0x15,0xab,0xa6,0xea,0x0f};
    unsigned char out43[16];
    MD4_CTX ctx43;
    MD4_Init(&ctx43);
    MD4_Update(&ctx43, in43, 69);
    MD4_Final(out43, &ctx43);
    if (memcmp(out43, exp43, 16) != 0) {
        printf("MD4 test 43 FAILED\n");
        fail = 1;
    }
    // test 44, len=115
    const unsigned char *in44 = (const unsigned char*)"FowJ8yBlRLQyfXNsZpTefrjyTYOjVyuxgfa8tCxWrgiflBCJJGAgbfwJfMMYu3yasAyXfU5J5pKHkRykirtrFjekBrAtEYexq8pUOFMNmDgita8zv1N";
    const unsigned char exp44[16] = {0x1a,0x6a,0x75,0x66,0x35,0x9e,0xfa,0x3e,0x96,0x81,0xb9,0x7a,0x44,0xfd,0x52,0xba};
    unsigned char out44[16];
    MD4_CTX ctx44;
    MD4_Init(&ctx44);
    MD4_Update(&ctx44, in44, 115);
    MD4_Final(out44, &ctx44);
    if (memcmp(out44, exp44, 16) != 0) {
        printf("MD4 test 44 FAILED\n");
        fail = 1;
    }
    // test 45, len=97
    const unsigned char *in45 = (const unsigned char*)"Z3vCvB003PMituM8SmEul9z9usVSOF9KYpuyr0Yzxh7KmLIlRXJb8UD8TnCZs1Se02YYARFiOtpqQjTBYyeCMELzIG763SAIc";
    const unsigned char exp45[16] = {0x2c,0x7d,0x7f,0x48,0x62,0xc5,0xf1,0xc7,0x87,0x5b,0xc0,0xd7,0xc3,0xd5,0xb8,0x97};
    unsigned char out45[16];
    MD4_CTX ctx45;
    MD4_Init(&ctx45);
    MD4_Update(&ctx45, in45, 97);
    MD4_Final(out45, &ctx45);
    if (memcmp(out45, exp45, 16) != 0) {
        printf("MD4 test 45 FAILED\n");
        fail = 1;
    }
    // test 46, len=92
    const unsigned char *in46 = (const unsigned char*)"S5ZIMO6fgXpQQwkPNcKPRPz9Wv9YBgagqoGVHJLSKoCxzDXRLSGjwbEgsA69fh18UjwtvDYnHEwEgCUSCuetcZThb2vP";
    const unsigned char exp46[16] = {0x05,0xba,0x58,0xb3,0xa2,0x22,0x17,0x4b,0x14,0x9b,0xda,0x10,0xc8,0xb4,0x24,0x2b};
    unsigned char out46[16];
    MD4_CTX ctx46;
    MD4_Init(&ctx46);
    MD4_Update(&ctx46, in46, 92);
    MD4_Final(out46, &ctx46);
    if (memcmp(out46, exp46, 16) != 0) {
        printf("MD4 test 46 FAILED\n");
        fail = 1;
    }
    // test 47, len=27
    const unsigned char *in47 = (const unsigned char*)"RZk7VpHlJkvJB9DoZzOllOQBzbV";
    const unsigned char exp47[16] = {0xfb,0x22,0x49,0x61,0x40,0x43,0xb4,0xbd,0xfa,0x4d,0xe1,0x4d,0xb4,0x99,0xd2,0x49};
    unsigned char out47[16];
    MD4_CTX ctx47;
    MD4_Init(&ctx47);
    MD4_Update(&ctx47, in47, 27);
    MD4_Final(out47, &ctx47);
    if (memcmp(out47, exp47, 16) != 0) {
        printf("MD4 test 47 FAILED\n");
        fail = 1;
    }
    // test 48, len=157
    const unsigned char *in48 = (const unsigned char*)"4mCLByaTnnrWTZYeKgZ3IlxumDhqQ3FH9OuMyNzLhww2DNl0RTZt6NLfRiuhpthlxSjGyAMiKyBlFOIS6P7lJkFsilu1CNd3w8aFim0y9JGPFARFAT1CFkfKbYWoscroIskXDKVXXFJGhKhrXI0xI0WcWUCIn";
    const unsigned char exp48[16] = {0xd1,0xf3,0x65,0xa8,0x9d,0x85,0xcd,0xe0,0x36,0x98,0x9b,0x0d,0xb3,0x28,0x0c,0xfe};
    unsigned char out48[16];
    MD4_CTX ctx48;
    MD4_Init(&ctx48);
    MD4_Update(&ctx48, in48, 157);
    MD4_Final(out48, &ctx48);
    if (memcmp(out48, exp48, 16) != 0) {
        printf("MD4 test 48 FAILED\n");
        fail = 1;
    }
    // test 49, len=108
    const unsigned char *in49 = (const unsigned char*)"gV1PWpt3cCqw30fC3hXZpnZVLSw3TNOBkNiYn0nZdKwIrMIkuTssKr82G5R0gi9WYA6dr3PiS3ipjTu1pW1RzFjKOrOAyCeOY4XfzGVrS74x";
    const unsigned char exp49[16] = {0xda,0xc5,0xe8,0x70,0xb5,0xb2,0x94,0xfb,0xed,0x4c,0x50,0x88,0x2f,0x55,0x6d,0x50};
    unsigned char out49[16];
    MD4_CTX ctx49;
    MD4_Init(&ctx49);
    MD4_Update(&ctx49, in49, 108);
    MD4_Final(out49, &ctx49);
    if (memcmp(out49, exp49, 16) != 0) {
        printf("MD4 test 49 FAILED\n");
        fail = 1;
    }
    // test 50, len=116
    const unsigned char *in50 = (const unsigned char*)"8FuLa3X2UfUDOQSw2eYIzn9B0nFru1svJKiK2FYv5RWdcgOY1Dbh72kCDa9BmS6i4Ptk374rfPxqfxQ5PkdzOtUSWoBPfTganEeiLoHRCaaSv0h3BSiE";
    const unsigned char exp50[16] = {0x0f,0x33,0xc4,0x8e,0x94,0x1d,0x75,0xaf,0x57,0x7f,0x8e,0xf9,0xe1,0xc0,0x6c,0x80};
    unsigned char out50[16];
    MD4_CTX ctx50;
    MD4_Init(&ctx50);
    MD4_Update(&ctx50, in50, 116);
    MD4_Final(out50, &ctx50);
    if (memcmp(out50, exp50, 16) != 0) {
        printf("MD4 test 50 FAILED\n");
        fail = 1;
    }
    // test 51, len=18
    const unsigned char *in51 = (const unsigned char*)"oyfUZggux4tiyX0W3i";
    const unsigned char exp51[16] = {0xf0,0x5c,0xc9,0x8f,0xb7,0x96,0xd2,0x02,0xb8,0x03,0x05,0xd2,0x59,0xff,0x40,0xca};
    unsigned char out51[16];
    MD4_CTX ctx51;
    MD4_Init(&ctx51);
    MD4_Update(&ctx51, in51, 18);
    MD4_Final(out51, &ctx51);
    if (memcmp(out51, exp51, 16) != 0) {
        printf("MD4 test 51 FAILED\n");
        fail = 1;
    }
    // test 52, len=164
    const unsigned char *in52 = (const unsigned char*)"RjeHKaNPkCwUnOVj6ANRC3nf5giWhLUyw9BuYiprPfpJMMUMsX8Sb22Q4tnHMGmVzsPdY5Y9pFyhpFOMeH4ax7uiy31KAxIRlWE9XebLeaqnc7d8YzGsOTGXABSzfOIINjrftfG6nZjIuzLOW1PRPetSBU92pdpf7BhD";
    const unsigned char exp52[16] = {0x72,0xe3,0x5f,0x53,0xd2,0x69,0x5e,0x1a,0x8d,0xc7,0x2e,0x39,0xbe,0x7f,0x8e,0x58};
    unsigned char out52[16];
    MD4_CTX ctx52;
    MD4_Init(&ctx52);
    MD4_Update(&ctx52, in52, 164);
    MD4_Final(out52, &ctx52);
    if (memcmp(out52, exp52, 16) != 0) {
        printf("MD4 test 52 FAILED\n");
        fail = 1;
    }
    // test 53, len=156
    const unsigned char *in53 = (const unsigned char*)"MdtQVQVlhaTiSakF8wHHY0UqkxiVX3rU4hX5bvZBrHeqTKOeFDGxdF2KkxkqXg5KRUhoVGac23apcExy6jl792cJZ6TVPAoupA6Uur0eKxhGR5dloZHc9ze4D3sX2tufJDaxmsKYtVNpDxLFXXmU5IWYpja7";
    const unsigned char exp53[16] = {0x33,0x5d,0x97,0x3b,0xeb,0x63,0x74,0x80,0x53,0xd7,0x5b,0x7e,0x26,0x8f,0x24,0x7b};
    unsigned char out53[16];
    MD4_CTX ctx53;
    MD4_Init(&ctx53);
    MD4_Update(&ctx53, in53, 156);
    MD4_Final(out53, &ctx53);
    if (memcmp(out53, exp53, 16) != 0) {
        printf("MD4 test 53 FAILED\n");
        fail = 1;
    }
    // test 54, len=104
    const unsigned char *in54 = (const unsigned char*)"boIwO1S4a8vaWQy2VUtgnHpAF9djTrfc6o52HAS5xDVfLgGiO0zeLKdBQ9ipsq2u7ZzS1VuuCroe8miXXLgjgkCDuAhIw9XnCtDq2hfk";
    const unsigned char exp54[16] = {0xd4,0x05,0x24,0x4a,0x6e,0x20,0x65,0x8c,0xed,0x23,0x58,0x1d,0xe0,0x1e,0x2b,0xda};
    unsigned char out54[16];
    MD4_CTX ctx54;
    MD4_Init(&ctx54);
    MD4_Update(&ctx54, in54, 104);
    MD4_Final(out54, &ctx54);
    if (memcmp(out54, exp54, 16) != 0) {
        printf("MD4 test 54 FAILED\n");
        fail = 1;
    }
    // test 55, len=175
    const unsigned char *in55 = (const unsigned char*)"t0TSMcn12ujfTp9wzGdRtq0lb8z2CJVJpgDgZYihad1Xoim0zxRO8PfLLq60ebem5PCZif521Zvhc8Ddk7KB0UzFbyRBlwn6lrrC4jcNNNpPsFA4JEdfryiAmP4ZHpOZIYbyYTwEIYFw6KGuyrlbuMob5ZXrdZEHwXLokgpQprI0Y6V";
    const unsigned char exp55[16] = {0x28,0x06,0x8a,0xc4,0x83,0x9f,0x29,0x2c,0xd3,0xb5,0x33,0xfe,0xd4,0x94,0xbc,0x90};
    unsigned char out55[16];
    MD4_CTX ctx55;
    MD4_Init(&ctx55);
    MD4_Update(&ctx55, in55, 175);
    MD4_Final(out55, &ctx55);
    if (memcmp(out55, exp55, 16) != 0) {
        printf("MD4 test 55 FAILED\n");
        fail = 1;
    }
    // test 56, len=14
    const unsigned char *in56 = (const unsigned char*)"W8oK2Zyw712llp";
    const unsigned char exp56[16] = {0xf0,0x5d,0x16,0xbe,0x23,0x82,0x64,0xca,0x83,0x91,0x39,0x3e,0xb3,0x89,0x1f,0x38};
    unsigned char out56[16];
    MD4_CTX ctx56;
    MD4_Init(&ctx56);
    MD4_Update(&ctx56, in56, 14);
    MD4_Final(out56, &ctx56);
    if (memcmp(out56, exp56, 16) != 0) {
        printf("MD4 test 56 FAILED\n");
        fail = 1;
    }
    // test 57, len=151
    const unsigned char *in57 = (const unsigned char*)"uZVSw6LbTSw8KKjK8m1Z4FItlFcfdoMobHEav6NmZivTl6Z23udbjLT6jXh2H3x9exT8QzLgvtuikU8BYO9FPulT9JS47NYwoQL0lytUSsilUa8S8Kz2X9KclMu6Z9NoOKg7FjvVepwukO49f0TQOU4";
    const unsigned char exp57[16] = {0xef,0xbc,0x81,0xf8,0xb3,0xbf,0xcb,0x0e,0xe0,0x03,0x38,0x9b,0xdf,0x4d,0xaa,0x77};
    unsigned char out57[16];
    MD4_CTX ctx57;
    MD4_Init(&ctx57);
    MD4_Update(&ctx57, in57, 151);
    MD4_Final(out57, &ctx57);
    if (memcmp(out57, exp57, 16) != 0) {
        printf("MD4 test 57 FAILED\n");
        fail = 1;
    }
    // test 58, len=85
    const unsigned char *in58 = (const unsigned char*)"CaqnpSewqYgUadyCUAk4AF4ywIyg1EY3KPWRokCeZ2csbuq8gevk4ykUeJ85fvMN5ETbB8PkM4BkdgvnmASJU";
    const unsigned char exp58[16] = {0xf0,0x94,0xda,0x30,0x73,0xaa,0x24,0x33,0x36,0x14,0x32,0x9d,0x34,0xb7,0x94,0x74};
    unsigned char out58[16];
    MD4_CTX ctx58;
    MD4_Init(&ctx58);
    MD4_Update(&ctx58, in58, 85);
    MD4_Final(out58, &ctx58);
    if (memcmp(out58, exp58, 16) != 0) {
        printf("MD4 test 58 FAILED\n");
        fail = 1;
    }
    // test 59, len=186
    const unsigned char *in59 = (const unsigned char*)"IqQstpgdzKJ1FjdxaBfs0QOMEmgbnkOsfE2htYzEF5QqfPIylx4yxlCcqCDqo1rKdjWSQgfQwZIAWLoJd1y0HA9IR37EK4pEtfz52TcGK5HZKRNjh8WCl8knZmicBfRBm0Oj1Mqu6U6ZefyJzJu2rHD63aYSNLHYAhAjjKLLW98g7gKXgYs3I4w4Aq";
    const unsigned char exp59[16] = {0x35,0x2e,0x57,0xa2,0x0e,0x96,0x7c,0x0f,0x45,0x22,0x9a,0x41,0xcd,0xae,0x58,0x6d};
    unsigned char out59[16];
    MD4_CTX ctx59;
    MD4_Init(&ctx59);
    MD4_Update(&ctx59, in59, 186);
    MD4_Final(out59, &ctx59);
    if (memcmp(out59, exp59, 16) != 0) {
        printf("MD4 test 59 FAILED\n");
        fail = 1;
    }
    // test 60, len=98
    const unsigned char *in60 = (const unsigned char*)"PFKMEclrzjNMRSzcz44vSpdVE6r5xbv0Yttr1F2SRg3oitVCX0urUAMPfmCn60AVFWH3x0dGYketTGziX2H4Kblm41m1dpcDd6";
    const unsigned char exp60[16] = {0xdc,0xd9,0x96,0xdd,0x6f,0x2d,0x72,0xf0,0xdd,0xf1,0x9d,0xc6,0x40,0x25,0x94,0x80};
    unsigned char out60[16];
    MD4_CTX ctx60;
    MD4_Init(&ctx60);
    MD4_Update(&ctx60, in60, 98);
    MD4_Final(out60, &ctx60);
    if (memcmp(out60, exp60, 16) != 0) {
        printf("MD4 test 60 FAILED\n");
        fail = 1;
    }
    // test 61, len=92
    const unsigned char *in61 = (const unsigned char*)"Tmrx0DGzO7hRbpxFMCl93ELJwwk15qV1Sfsbydk2KX9n2oPoRnrPAGb3X9XRaE6iPlMZaoqMZ8tT9TPrB5y2wDqnDtRH";
    const unsigned char exp61[16] = {0xfc,0x68,0x45,0x84,0xea,0x49,0x84,0x6a,0xe3,0x44,0x0c,0x65,0x02,0xbe,0x5d,0xf9};
    unsigned char out61[16];
    MD4_CTX ctx61;
    MD4_Init(&ctx61);
    MD4_Update(&ctx61, in61, 92);
    MD4_Final(out61, &ctx61);
    if (memcmp(out61, exp61, 16) != 0) {
        printf("MD4 test 61 FAILED\n");
        fail = 1;
    }
    // test 62, len=159
    const unsigned char *in62 = (const unsigned char*)"zLgaGQ911xJPMMstRgEevrOu3rqPT85PtmjHWp5dZ2ZZMzQuRiUbPFsq6AzyVcLTK0mvUToRIOYE68QwGt2k1Q4JlsgEiVqUZJW6l8R5vPfowoV3tAY4vxqLsD2hEd3OLL8NeE4mGh3RyHtAd32jimvAK56Dju3";
    const unsigned char exp62[16] = {0x38,0xc9,0x7b,0x58,0xcd,0x0a,0x49,0x2d,0xd5,0x2e,0x4b,0x24,0x05,0xd9,0x05,0x9d};
    unsigned char out62[16];
    MD4_CTX ctx62;
    MD4_Init(&ctx62);
    MD4_Update(&ctx62, in62, 159);
    MD4_Final(out62, &ctx62);
    if (memcmp(out62, exp62, 16) != 0) {
        printf("MD4 test 62 FAILED\n");
        fail = 1;
    }
    // test 63, len=183
    const unsigned char *in63 = (const unsigned char*)"lXfFvOluOdaCrnWXkKWkFYWXfiNBOBzB9EyacImUx8a5uW1HmbRaOUpoS4wtigyGLtke0ct8sDUHMHvB4Riv5FwWmk866ZzbooUinUbLGkhxTPYcy4OqXINdMdQgP1bdShACyhJqESjnSROatAQgQHrNMSiA15gGUNhshYgFmMmXq1HmwTAskcJ";
    const unsigned char exp63[16] = {0xd1,0xb3,0xd3,0xfd,0xe9,0x9f,0xaf,0x0e,0xff,0x5a,0x64,0x1a,0xd5,0xa1,0x5e,0xcd};
    unsigned char out63[16];
    MD4_CTX ctx63;
    MD4_Init(&ctx63);
    MD4_Update(&ctx63, in63, 183);
    MD4_Final(out63, &ctx63);
    if (memcmp(out63, exp63, 16) != 0) {
        printf("MD4 test 63 FAILED\n");
        fail = 1;
    }
    // test 64, len=127
    const unsigned char *in64 = (const unsigned char*)"6nS7EvpaaQf6h1KQFj8fXGeUUg5qPoDsqDdg0l3c2sxZRuBVhg2W4ca2iQPkvw5C9Nr4Ufx0vlhzz9Dr1yS2EZAP4ZkhiSUd82kgA6LEZKRClNyXwNb3R41U5iE6Fh4";
    const unsigned char exp64[16] = {0x21,0x66,0x48,0x68,0x4f,0x73,0x94,0x4b,0x99,0xc3,0xd0,0x12,0xf9,0xf5,0x21,0x59};
    unsigned char out64[16];
    MD4_CTX ctx64;
    MD4_Init(&ctx64);
    MD4_Update(&ctx64, in64, 127);
    MD4_Final(out64, &ctx64);
    if (memcmp(out64, exp64, 16) != 0) {
        printf("MD4 test 64 FAILED\n");
        fail = 1;
    }
    // test 65, len=105
    const unsigned char *in65 = (const unsigned char*)"CceqPuaT3RHXVKUKo9Q3vHHSSNgBQUpEwQRPyj10J5NdaP7kG2E2F3keWFupvrdGoJPyz0pfDCZKCf2FCuhFVPbgzAcJJa0fYM9NOt4GJ";
    const unsigned char exp65[16] = {0x98,0x6d,0xef,0x65,0xce,0x5b,0x92,0xbd,0x60,0x28,0x0f,0xb5,0x41,0x22,0xdb,0xeb};
    unsigned char out65[16];
    MD4_CTX ctx65;
    MD4_Init(&ctx65);
    MD4_Update(&ctx65, in65, 105);
    MD4_Final(out65, &ctx65);
    if (memcmp(out65, exp65, 16) != 0) {
        printf("MD4 test 65 FAILED\n");
        fail = 1;
    }
    // test 66, len=52
    const unsigned char *in66 = (const unsigned char*)"PQD8vx0d0o2DvJXNMETQxTChgWQoavw1O9ZsJHxSgc5kFi0TVUAg";
    const unsigned char exp66[16] = {0x3f,0x4d,0xcb,0x1a,0xf5,0x69,0x38,0x8f,0x66,0xb4,0x8a,0x29,0x40,0x88,0x0e,0xbd};
    unsigned char out66[16];
    MD4_CTX ctx66;
    MD4_Init(&ctx66);
    MD4_Update(&ctx66, in66, 52);
    MD4_Final(out66, &ctx66);
    if (memcmp(out66, exp66, 16) != 0) {
        printf("MD4 test 66 FAILED\n");
        fail = 1;
    }
    // test 67, len=65
    const unsigned char *in67 = (const unsigned char*)"Nmmh72znD0YmTvgWAc7O1RLhX5CDQL9Gi9FaHVdJ7B1LE7GX66lSLlU0igyQMM4uG";
    const unsigned char exp67[16] = {0xae,0xd2,0x34,0x29,0x90,0xbf,0x00,0xeb,0x53,0x42,0x99,0x95,0x07,0x8e,0x3f,0xd0};
    unsigned char out67[16];
    MD4_CTX ctx67;
    MD4_Init(&ctx67);
    MD4_Update(&ctx67, in67, 65);
    MD4_Final(out67, &ctx67);
    if (memcmp(out67, exp67, 16) != 0) {
        printf("MD4 test 67 FAILED\n");
        fail = 1;
    }
    // test 68, len=98
    const unsigned char *in68 = (const unsigned char*)"AM6SWprz9vsCZiiAMS4VGt1SJ3uTV7JOnmnNTsRw6RiTP9lGISOuThWwJELK8QTARV51Is42BZaHgbyjdQdmrWYksRqj1dSYsn";
    const unsigned char exp68[16] = {0xa2,0xc4,0x62,0x08,0xfb,0x62,0x8e,0x44,0x6a,0x8e,0x04,0x30,0x22,0xdf,0x2e,0x2d};
    unsigned char out68[16];
    MD4_CTX ctx68;
    MD4_Init(&ctx68);
    MD4_Update(&ctx68, in68, 98);
    MD4_Final(out68, &ctx68);
    if (memcmp(out68, exp68, 16) != 0) {
        printf("MD4 test 68 FAILED\n");
        fail = 1;
    }
    // test 69, len=192
    const unsigned char *in69 = (const unsigned char*)"Icw0CgN3RVJ3oVPJypGYYZSsSQd7yyA9YRu9JdaVqmN3X33C1o6OTTPxWLIVMmXU9msClRel9lVGhycBrJqikL2qavDT7jcj7uMdX7ON1QtFYKJweYTuHo9lHeYGkAIIzfwo4nQvvxsn8WNHEJ0WPahQwCp5PN6Np9cR4uy6Y8hyqIUsb6H0XxGZGCFcs5Pm";
    const unsigned char exp69[16] = {0x7d,0x1d,0xdd,0xc3,0x63,0xdd,0x5f,0xe9,0xb8,0x61,0xb0,0xd8,0x21,0x8d,0xd4,0xd2};
    unsigned char out69[16];
    MD4_CTX ctx69;
    MD4_Init(&ctx69);
    MD4_Update(&ctx69, in69, 192);
    MD4_Final(out69, &ctx69);
    if (memcmp(out69, exp69, 16) != 0) {
        printf("MD4 test 69 FAILED\n");
        fail = 1;
    }
    // test 70, len=82
    const unsigned char *in70 = (const unsigned char*)"Gf8gk9XIIaOenQOXn3RB1gnI1S4VXBP08eVRjbDTvcfedlYqJeK0o6qAyCOzBubyRhIaPUNeWVLcS2ew7G";
    const unsigned char exp70[16] = {0xb3,0x55,0x65,0xcf,0x1b,0x32,0x8d,0x64,0x00,0x4e,0xd0,0xa5,0x6e,0xb3,0x58,0xf8};
    unsigned char out70[16];
    MD4_CTX ctx70;
    MD4_Init(&ctx70);
    MD4_Update(&ctx70, in70, 82);
    MD4_Final(out70, &ctx70);
    if (memcmp(out70, exp70, 16) != 0) {
        printf("MD4 test 70 FAILED\n");
        fail = 1;
    }
    // test 71, len=27
    const unsigned char *in71 = (const unsigned char*)"sYRtMfsW7Cyz0QbEkIoiVzYZ2Is";
    const unsigned char exp71[16] = {0x1f,0x6a,0x4e,0x68,0x05,0xaa,0x54,0xdc,0xa0,0x76,0x29,0xbd,0x34,0x36,0x3c,0x34};
    unsigned char out71[16];
    MD4_CTX ctx71;
    MD4_Init(&ctx71);
    MD4_Update(&ctx71, in71, 27);
    MD4_Final(out71, &ctx71);
    if (memcmp(out71, exp71, 16) != 0) {
        printf("MD4 test 71 FAILED\n");
        fail = 1;
    }
    // test 72, len=162
    const unsigned char *in72 = (const unsigned char*)"jtR469Y3UPx98aJ3JjhcaKMzIJ8ftnVV5UwnA5P2GjkloN1qmhlQZK2d2W7JDPJesQeqgmULF8vwiQPpgsNe5muFCvNQtSLjKKxZu9BkaupYoTVPBr1xiRUv4EDCwXtFJglPMf1r20i5ImqU4OeUe5b2GOb0LLzXLn";
    const unsigned char exp72[16] = {0xbf,0x56,0x2f,0x3e,0xdf,0x37,0x6c,0xf9,0xf5,0x9a,0xaf,0xe7,0x2f,0xcd,0xe8,0x6e};
    unsigned char out72[16];
    MD4_CTX ctx72;
    MD4_Init(&ctx72);
    MD4_Update(&ctx72, in72, 162);
    MD4_Final(out72, &ctx72);
    if (memcmp(out72, exp72, 16) != 0) {
        printf("MD4 test 72 FAILED\n");
        fail = 1;
    }
    // test 73, len=9
    const unsigned char *in73 = (const unsigned char*)"JqI5IEPXj";
    const unsigned char exp73[16] = {0x55,0x3f,0x44,0xd0,0x30,0xb2,0x78,0x48,0x56,0x13,0x38,0x72,0xb9,0x07,0xfc,0x81};
    unsigned char out73[16];
    MD4_CTX ctx73;
    MD4_Init(&ctx73);
    MD4_Update(&ctx73, in73, 9);
    MD4_Final(out73, &ctx73);
    if (memcmp(out73, exp73, 16) != 0) {
        printf("MD4 test 73 FAILED\n");
        fail = 1;
    }
    // test 74, len=93
    const unsigned char *in74 = (const unsigned char*)"zo5XLU2siDGGfzxGaQp29ZNRkWGiCklK8KQ39jVUE8wcoWFoeqxocQnH6YxyE6D4ccPugT9HO1r1VqLIKlyPyxLP51eHq";
    const unsigned char exp74[16] = {0x41,0x8a,0xdd,0x66,0xb0,0xcc,0x0e,0x31,0x61,0xea,0xd0,0xde,0x25,0x08,0x3e,0x15};
    unsigned char out74[16];
    MD4_CTX ctx74;
    MD4_Init(&ctx74);
    MD4_Update(&ctx74, in74, 93);
    MD4_Final(out74, &ctx74);
    if (memcmp(out74, exp74, 16) != 0) {
        printf("MD4 test 74 FAILED\n");
        fail = 1;
    }
    // test 75, len=96
    const unsigned char *in75 = (const unsigned char*)"6oHzw03wFYE4MaG4iCkoeGPrnjlkxMT0hQoAZvUhEREEnLkP1AbpciKLkiOGc5Kjdkq7lH9zMKOb4UUQ0s8fnCME3Eko1AMj";
    const unsigned char exp75[16] = {0x57,0xf2,0x9e,0xd1,0x55,0xc7,0x7a,0x48,0x85,0x5a,0x65,0x7e,0xdc,0xff,0x18,0x3f};
    unsigned char out75[16];
    MD4_CTX ctx75;
    MD4_Init(&ctx75);
    MD4_Update(&ctx75, in75, 96);
    MD4_Final(out75, &ctx75);
    if (memcmp(out75, exp75, 16) != 0) {
        printf("MD4 test 75 FAILED\n");
        fail = 1;
    }
    // test 76, len=149
    const unsigned char *in76 = (const unsigned char*)"0XlNQGqkURv7DMLeoyyigbmH36GRA0jMglE5NMc4YIGWhfEQi5MI0a58XRPBHAx3cSHBo8ZEYXywLZV6W1SKgBiqEXo62fsM4IAqmaTVYaKHhHayPnSZuAxgjBPLqq2IBKxNrRzWnAJYJElxJJEqt";
    const unsigned char exp76[16] = {0x82,0x02,0xc3,0xf3,0xd5,0xa7,0x87,0xd4,0x3a,0x6c,0x37,0x5b,0x09,0x11,0xa1,0x4b};
    unsigned char out76[16];
    MD4_CTX ctx76;
    MD4_Init(&ctx76);
    MD4_Update(&ctx76, in76, 149);
    MD4_Final(out76, &ctx76);
    if (memcmp(out76, exp76, 16) != 0) {
        printf("MD4 test 76 FAILED\n");
        fail = 1;
    }
    // test 77, len=147
    const unsigned char *in77 = (const unsigned char*)"wXTzVi23QhVoCYS8kgnGzYvZJNSRTdky9OaZf0jE7MBfeqoxfMcUy7zNPHsT9Md8X0lOFCam2Q7ZHsmcYMGHSoNkRcxpPakfrXzwQzzLmHaVTe6fJsU1J6Lww90roM9mD7zKaqlAGgJeGsv8hZG";
    const unsigned char exp77[16] = {0x3e,0xc4,0xb3,0x6f,0x14,0xd3,0x21,0xa6,0x86,0xbe,0xa8,0x92,0x52,0x72,0x4f,0xdf};
    unsigned char out77[16];
    MD4_CTX ctx77;
    MD4_Init(&ctx77);
    MD4_Update(&ctx77, in77, 147);
    MD4_Final(out77, &ctx77);
    if (memcmp(out77, exp77, 16) != 0) {
        printf("MD4 test 77 FAILED\n");
        fail = 1;
    }
    // test 78, len=65
    const unsigned char *in78 = (const unsigned char*)"4I0YKqSC9yKEXpWv9XDRD5L3bEhqeyOYoRSoZuA9wHIaS1qpsfzRV0veJ7lEuwn5K";
    const unsigned char exp78[16] = {0x34,0x3c,0x8c,0x7c,0x7e,0x9c,0xb0,0x16,0xd5,0x82,0xe6,0xc3,0x87,0xec,0x24,0xdf};
    unsigned char out78[16];
    MD4_CTX ctx78;
    MD4_Init(&ctx78);
    MD4_Update(&ctx78, in78, 65);
    MD4_Final(out78, &ctx78);
    if (memcmp(out78, exp78, 16) != 0) {
        printf("MD4 test 78 FAILED\n");
        fail = 1;
    }
    // test 79, len=68
    const unsigned char *in79 = (const unsigned char*)"l8VR76mFVmpVp3qnom1p1NwjXgh6fR9QFNaW2I9c2ExNuF545K3rFlW6GrzoWKidHZBE";
    const unsigned char exp79[16] = {0xb6,0x5d,0xfa,0xfa,0xe7,0xed,0x82,0x01,0x89,0x28,0x4a,0x9e,0x9e,0xd2,0x3d,0x84};
    unsigned char out79[16];
    MD4_CTX ctx79;
    MD4_Init(&ctx79);
    MD4_Update(&ctx79, in79, 68);
    MD4_Final(out79, &ctx79);
    if (memcmp(out79, exp79, 16) != 0) {
        printf("MD4 test 79 FAILED\n");
        fail = 1;
    }
    // test 80, len=138
    const unsigned char *in80 = (const unsigned char*)"cGwz3RXlDhSHDuSaaRnyLguxN3qlJqprE9NvxlFBnASWxx2zrClKiKRo0gUrZpJB2ymjZ9VjEZalAFi52OHIUuYFtqJ2KdzgSkdn0qE1OgCVvqxxJJ7ZqwbAhw3R9MmKKPPIlXswuR";
    const unsigned char exp80[16] = {0x01,0x75,0x38,0x71,0xa8,0xac,0x5c,0x10,0x95,0x61,0xc8,0x12,0x9c,0xeb,0x81,0x7b};
    unsigned char out80[16];
    MD4_CTX ctx80;
    MD4_Init(&ctx80);
    MD4_Update(&ctx80, in80, 138);
    MD4_Final(out80, &ctx80);
    if (memcmp(out80, exp80, 16) != 0) {
        printf("MD4 test 80 FAILED\n");
        fail = 1;
    }
    // test 81, len=130
    const unsigned char *in81 = (const unsigned char*)"FXVC4fyNsDO9j3kOZ7vAONKz26efkvouuPsTrMPzr4CX38xVLH9CAkl2biUpQq8VSVfnkzgge74EJdbXzHWfgqNjfP74ytopVsCOiiH1kbcQw36u3ED3I7rJCi8SIlLMDO";
    const unsigned char exp81[16] = {0x3e,0xf7,0x91,0x3e,0x2d,0xb5,0x63,0xa8,0x41,0x12,0xf0,0x7d,0x4a,0x8b,0x67,0x93};
    unsigned char out81[16];
    MD4_CTX ctx81;
    MD4_Init(&ctx81);
    MD4_Update(&ctx81, in81, 130);
    MD4_Final(out81, &ctx81);
    if (memcmp(out81, exp81, 16) != 0) {
        printf("MD4 test 81 FAILED\n");
        fail = 1;
    }
    // test 82, len=191
    const unsigned char *in82 = (const unsigned char*)"O4KBHOOIt6wEIoZfCtxAqjtaaH0W2iwsEIaS7F8WEtaXBZsMoYaJxmA4JBzpkTVPy1yoqfBOpHWZ6NZSRrsPVIZrAm2elishODNCrSNFmubjdIblgsriTCUaofjaFnvAtYZFxDSYcvf1W8jdrXzeIElm51q0y1ahXTpyXCpVcmDVXgHQnEyR9t7ukOUcV7J";
    const unsigned char exp82[16] = {0xf0,0x08,0x6b,0x9e,0x44,0x6f,0xd9,0x3a,0x5b,0x25,0x08,0xb2,0x87,0x48,0x6f,0x2d};
    unsigned char out82[16];
    MD4_CTX ctx82;
    MD4_Init(&ctx82);
    MD4_Update(&ctx82, in82, 191);
    MD4_Final(out82, &ctx82);
    if (memcmp(out82, exp82, 16) != 0) {
        printf("MD4 test 82 FAILED\n");
        fail = 1;
    }
    // test 83, len=133
    const unsigned char *in83 = (const unsigned char*)"hqEOtmx4d3QnhpOBuakYrLhzYpacLYSESMjxXfpkFfRNv7WOddwPjSIYgiFouJYPWwZ5CUmbSywUiq5cFTCJsISFmKlIwuUDr31M63JkeHjCs0qIxDaXOGyUl4bN2xXNpuUeQ";
    const unsigned char exp83[16] = {0x82,0xd2,0xe9,0xae,0xe7,0x4f,0xc3,0xd0,0xf6,0xfd,0xaf,0x9d,0xb9,0xfb,0xe9,0x5e};
    unsigned char out83[16];
    MD4_CTX ctx83;
    MD4_Init(&ctx83);
    MD4_Update(&ctx83, in83, 133);
    MD4_Final(out83, &ctx83);
    if (memcmp(out83, exp83, 16) != 0) {
        printf("MD4 test 83 FAILED\n");
        fail = 1;
    }
    // test 84, len=137
    const unsigned char *in84 = (const unsigned char*)"0ymHRFXJjNsuAPuhgHQec18il3cmgFmgcKP1yQFHNSLqdxoMTea76nPF741fDZOdxJV84A0xYTd0NrHcUe1te8n9HggUoIymmHQpKO8lJVJAVgXOKwRDSQB4gkYlJzGvQkIMC7w5u";
    const unsigned char exp84[16] = {0xa8,0x32,0x95,0x84,0x9b,0x13,0xb7,0x21,0x6b,0xd1,0x93,0x94,0x2a,0x86,0xba,0x98};
    unsigned char out84[16];
    MD4_CTX ctx84;
    MD4_Init(&ctx84);
    MD4_Update(&ctx84, in84, 137);
    MD4_Final(out84, &ctx84);
    if (memcmp(out84, exp84, 16) != 0) {
        printf("MD4 test 84 FAILED\n");
        fail = 1;
    }
    // test 85, len=140
    const unsigned char *in85 = (const unsigned char*)"u2xAWOB0UuMpKInyXJ7Vqx9CC9zaUcsMbHi4taton2ubX08S0r6JGJK7KjgcDwjiqx4LpoqZtfKzK6nUeUuYElF05SSK06gMPtcUZKyfXd6Xvw40BA73h3XoVP2M7aOXOydtHcuIKjuG";
    const unsigned char exp85[16] = {0x69,0x9e,0xdc,0x42,0xe3,0x86,0xcf,0x1c,0x9f,0xbc,0xd5,0x83,0x76,0xc8,0x82,0x99};
    unsigned char out85[16];
    MD4_CTX ctx85;
    MD4_Init(&ctx85);
    MD4_Update(&ctx85, in85, 140);
    MD4_Final(out85, &ctx85);
    if (memcmp(out85, exp85, 16) != 0) {
        printf("MD4 test 85 FAILED\n");
        fail = 1;
    }
    // test 86, len=178
    const unsigned char *in86 = (const unsigned char*)"ojdRUzCWMKGfoBsYzjivfEKVdJzqfzGBXSiWiEJmFzPKmJNVHpperXBuR7KfhQABxwmuwMPbXtkwN0ZCNjCc70omRxjWU2fhVdp8N7j310savSZhtCEbvnVInnIHWqJENUjSSQbyL5QHcqkdsmYSNrdDP8aeyQrQ26Qx3gbs34PyoyGTg5";
    const unsigned char exp86[16] = {0x1d,0xa9,0x26,0x55,0xee,0xa6,0x05,0x50,0xbb,0x36,0xa9,0xc0,0x62,0xc1,0x5d,0x92};
    unsigned char out86[16];
    MD4_CTX ctx86;
    MD4_Init(&ctx86);
    MD4_Update(&ctx86, in86, 178);
    MD4_Final(out86, &ctx86);
    if (memcmp(out86, exp86, 16) != 0) {
        printf("MD4 test 86 FAILED\n");
        fail = 1;
    }
    // test 87, len=80
    const unsigned char *in87 = (const unsigned char*)"F3MIflmG9DJ7Tbcp7HtvFzVkbwRwwOtpGrZdOq4y40b8J8rojv5zQifUyH9RN3ORoApKjBt6MvCIinPi";
    const unsigned char exp87[16] = {0x68,0xc7,0x5a,0x33,0x29,0x68,0xda,0x08,0x72,0x63,0xb4,0x8c,0xca,0x8a,0x85,0x9f};
    unsigned char out87[16];
    MD4_CTX ctx87;
    MD4_Init(&ctx87);
    MD4_Update(&ctx87, in87, 80);
    MD4_Final(out87, &ctx87);
    if (memcmp(out87, exp87, 16) != 0) {
        printf("MD4 test 87 FAILED\n");
        fail = 1;
    }
    // test 88, len=148
    const unsigned char *in88 = (const unsigned char*)"IRZm3itST5H6iB6XjP7K6kueJI8Uhlu14jUbWu4A9AtCV705O7VrjXmgilbWNNrMKNoMooRbwfSXEiG2METPxl2yFEikmocAWa7r8AoVQmWnel79C3NFSu3D4pBzXcMV0yUuzN8VKMIHP4TYcHgC";
    const unsigned char exp88[16] = {0x8e,0xab,0x6b,0xf3,0x90,0xb9,0x00,0x58,0x4a,0x84,0x58,0x7c,0xd6,0xa9,0xe5,0xd9};
    unsigned char out88[16];
    MD4_CTX ctx88;
    MD4_Init(&ctx88);
    MD4_Update(&ctx88, in88, 148);
    MD4_Final(out88, &ctx88);
    if (memcmp(out88, exp88, 16) != 0) {
        printf("MD4 test 88 FAILED\n");
        fail = 1;
    }
    // test 89, len=116
    const unsigned char *in89 = (const unsigned char*)"04c4pHIzVcJyHWO9dmsCz4tX0sDkBsN6dSH5jD1PCfUGhlXL85SIizAuCblDL5T5m4DfquSP6TYkTUhfhTCOxfHTyUYGN8kyJycXk6vK3Q3jk3jlXTdA";
    const unsigned char exp89[16] = {0xed,0xa7,0xe6,0x63,0x2d,0x76,0xd2,0xd6,0xa4,0x0b,0x83,0x71,0xca,0x83,0x30,0xe9};
    unsigned char out89[16];
    MD4_CTX ctx89;
    MD4_Init(&ctx89);
    MD4_Update(&ctx89, in89, 116);
    MD4_Final(out89, &ctx89);
    if (memcmp(out89, exp89, 16) != 0) {
        printf("MD4 test 89 FAILED\n");
        fail = 1;
    }
    // test 90, len=78
    const unsigned char *in90 = (const unsigned char*)"tUX9CsOlh5i9maNWqaDF2FIZaM4FpnLQEDACfMMap4JrNOJ00ndljdPwcj2cQK1Mtv6fdgAlkRsNQS";
    const unsigned char exp90[16] = {0x7a,0x45,0x43,0x9b,0x73,0x15,0x45,0x8a,0x00,0x70,0xa0,0x7e,0x2d,0x1e,0x02,0xe1};
    unsigned char out90[16];
    MD4_CTX ctx90;
    MD4_Init(&ctx90);
    MD4_Update(&ctx90, in90, 78);
    MD4_Final(out90, &ctx90);
    if (memcmp(out90, exp90, 16) != 0) {
        printf("MD4 test 90 FAILED\n");
        fail = 1;
    }
    // test 91, len=179
    const unsigned char *in91 = (const unsigned char*)"MKYJl9DVLx7cfXtux5y0eWB1JesEihS3rvHAHnSnNdgKUOHfEUSM7YTsBM2uqHKNw7iNKFHUOFFZl4NoTsmahbDOYhV2nZNAAcvwJZOnaOmSsqYettGJuXahRvvzUKN9b1lmv1v7RE6EZcPiEjOD53I5vDY0A7Vd1HtKURuJIbnKRvZ64Yw";
    const unsigned char exp91[16] = {0xa5,0x03,0x40,0xac,0x27,0xd5,0x7a,0x9f,0x83,0x29,0x13,0x47,0xda,0x6c,0x7e,0x84};
    unsigned char out91[16];
    MD4_CTX ctx91;
    MD4_Init(&ctx91);
    MD4_Update(&ctx91, in91, 179);
    MD4_Final(out91, &ctx91);
    if (memcmp(out91, exp91, 16) != 0) {
        printf("MD4 test 91 FAILED\n");
        fail = 1;
    }
    // test 92, len=16
    const unsigned char *in92 = (const unsigned char*)"jr1bvyOI1kKMylMh";
    const unsigned char exp92[16] = {0xb0,0x23,0x64,0xf7,0xd5,0x16,0x81,0x87,0x3a,0xd4,0xa7,0x49,0x99,0x88,0xb9,0xec};
    unsigned char out92[16];
    MD4_CTX ctx92;
    MD4_Init(&ctx92);
    MD4_Update(&ctx92, in92, 16);
    MD4_Final(out92, &ctx92);
    if (memcmp(out92, exp92, 16) != 0) {
        printf("MD4 test 92 FAILED\n");
        fail = 1;
    }
    // test 93, len=200
    const unsigned char *in93 = (const unsigned char*)"WtT2uTcrAfF4pxC18tnHtlhxYcXm6fCGbZE5Gjmv7EU3HtXujX3g08HRinUcDyT3Hhat7cR2M3fvD4cgHXQVtbKWtO5nummsrIuXCQhrjkrha9NJGgnIwJurj8TZsKpketN5vICdibE5RdgydfBzlTM5LO1SSCNwtv0mTWQZIf7WWDKif0Z6SDgDtRPTXDEo8oj35Nq6";
    const unsigned char exp93[16] = {0x4b,0x39,0xef,0xdf,0xb0,0x1f,0xee,0x58,0x9e,0x68,0xcd,0x20,0xd8,0x97,0xbc,0x59};
    unsigned char out93[16];
    MD4_CTX ctx93;
    MD4_Init(&ctx93);
    MD4_Update(&ctx93, in93, 200);
    MD4_Final(out93, &ctx93);
    if (memcmp(out93, exp93, 16) != 0) {
        printf("MD4 test 93 FAILED\n");
        fail = 1;
    }
    // test 94, len=93
    const unsigned char *in94 = (const unsigned char*)"zlS6QvY34uDFbeEhwED2ksXwMKiGgz0TYguJPeYtIDzLApNpJkEyevn0SLBYBKYvISplQQeV7TK1FhLMDuJg0Clt9zeMg";
    const unsigned char exp94[16] = {0x42,0x8d,0xb0,0x9f,0x3a,0xd6,0x00,0x03,0x7f,0x98,0xa5,0x26,0xbf,0x53,0x45,0x65};
    unsigned char out94[16];
    MD4_CTX ctx94;
    MD4_Init(&ctx94);
    MD4_Update(&ctx94, in94, 93);
    MD4_Final(out94, &ctx94);
    if (memcmp(out94, exp94, 16) != 0) {
        printf("MD4 test 94 FAILED\n");
        fail = 1;
    }
    // test 95, len=175
    const unsigned char *in95 = (const unsigned char*)"0MX0yuFPQdfn0i4L5WOZaWjQjCIsyNKCmnR4utKY6Rt687BT6wfLaNGz2i2sdx5J9daTJ0wh3s3bpBSLzOuTyzyBInQlEimJy17x1Ajs3QiiaePbjU4FQBifiPZA3D5YSM7BNlDGBJ0CywolBMaKF2UpTGrA7IKxccKETxhLE9SfjUU";
    const unsigned char exp95[16] = {0xd0,0x3d,0x90,0x16,0xae,0x91,0x2e,0x17,0x5d,0x98,0xc2,0x08,0x80,0x34,0x50,0x91};
    unsigned char out95[16];
    MD4_CTX ctx95;
    MD4_Init(&ctx95);
    MD4_Update(&ctx95, in95, 175);
    MD4_Final(out95, &ctx95);
    if (memcmp(out95, exp95, 16) != 0) {
        printf("MD4 test 95 FAILED\n");
        fail = 1;
    }
    // test 96, len=134
    const unsigned char *in96 = (const unsigned char*)"2WXrDHfH4NfpEOVQ9QeROIZLtNd5vIXaEDG5EKUvAw9ZsskcS7MVtUYKqdOELkKdQsZVNbsFfiGe2YrqiNrr2qaVhMl6LVjQCxZlqYSpFlZH3cvf9jM70j1FWAXypQCUOknKU1";
    const unsigned char exp96[16] = {0x86,0x68,0x63,0x0d,0x4b,0xec,0xed,0x38,0xd1,0x51,0x65,0x1b,0xae,0x24,0x0d,0x04};
    unsigned char out96[16];
    MD4_CTX ctx96;
    MD4_Init(&ctx96);
    MD4_Update(&ctx96, in96, 134);
    MD4_Final(out96, &ctx96);
    if (memcmp(out96, exp96, 16) != 0) {
        printf("MD4 test 96 FAILED\n");
        fail = 1;
    }
    // test 97, len=88
    const unsigned char *in97 = (const unsigned char*)"dPqW0hdkDzEtEV8W7IoyRTyEqjH3Bas7ZCyRu9HR9cg6IOw92BN6P2rvrrZgqPLzDXRVpURLXmHvRSluJaRa1eaA";
    const unsigned char exp97[16] = {0x06,0x0f,0xf3,0xb1,0x31,0xe8,0x3f,0x89,0xab,0x57,0xff,0x0c,0xf6,0x1f,0xe2,0x70};
    unsigned char out97[16];
    MD4_CTX ctx97;
    MD4_Init(&ctx97);
    MD4_Update(&ctx97, in97, 88);
    MD4_Final(out97, &ctx97);
    if (memcmp(out97, exp97, 16) != 0) {
        printf("MD4 test 97 FAILED\n");
        fail = 1;
    }
    // test 98, len=25
    const unsigned char *in98 = (const unsigned char*)"HgRCwoUsqmcbNfd8MQ51n8MOh";
    const unsigned char exp98[16] = {0xfe,0xc5,0x05,0x82,0xf4,0x3e,0xa8,0x34,0xd0,0x1f,0x03,0x7d,0x76,0x07,0xf4,0x93};
    unsigned char out98[16];
    MD4_CTX ctx98;
    MD4_Init(&ctx98);
    MD4_Update(&ctx98, in98, 25);
    MD4_Final(out98, &ctx98);
    if (memcmp(out98, exp98, 16) != 0) {
        printf("MD4 test 98 FAILED\n");
        fail = 1;
    }
    // test 99, len=181
    const unsigned char *in99 = (const unsigned char*)"9hf2MiyQW5PKZ9l5hSlqsDQ7eOD7rXBS5QXXuqkXerXdyyvdq90qlCeF7mNzlPFgjIXBnNPg6CTqgceeKUqXCb5FjPOa7cQyrjSv5zKaGT8XFEBz2UXZYeIoay9S0XEhKI7wvRtzdO9PfxI29vf1DWXsPmlJc9yQmtSy5gOSwFf4OCVmicmbU";
    const unsigned char exp99[16] = {0x25,0x7b,0x5b,0x57,0x71,0xc7,0xe1,0x42,0xb6,0xe3,0xda,0x83,0x0e,0x59,0x2f,0x86};
    unsigned char out99[16];
    MD4_CTX ctx99;
    MD4_Init(&ctx99);
    MD4_Update(&ctx99, in99, 181);
    MD4_Final(out99, &ctx99);
    if (memcmp(out99, exp99, 16) != 0) {
        printf("MD4 test 99 FAILED\n");
        fail = 1;
    }
    if (fail) { printf("Some MD4 tests failed\n"); return 1; }
    printf("All MD4 tests passed (%d)\n", 100);
    return 0;
}