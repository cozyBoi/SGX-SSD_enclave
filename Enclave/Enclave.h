/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include <stdlib.h>
#include <assert.h>

#if defined(__cplusplus)
extern "C" {
#endif

#define SECTOR_SIZE 512
#define SECTOR_BIT 9
#define KEY_SIZE 16
#define MAC_SIZE (KEY_SIZE*2)
#define VERSION_SIZE 4
#define FD_SIZE 4

#define __NR_enc_rdafwr 333

#define P_SIZE 4096
#define K_SIZE 1024
#define IO_SIZE 8192
#define RESPONSE_SIZE SECTOR_SIZE
#define PAGE_BIT 12
#define NAME_LEN 16
#define NODE_SIZE 4096
//DS_param, ds_cmd는 개발에 따라 정책이 수정될 수 있다.
//fs_open.c와 openssd jasmine펌웨어 sata_table.c, sata.h 와 반드시 맞춰줄것.
typedef struct DS_param{
    unsigned int fd;
    unsigned char cmd;
    unsigned long offset; //여기가 LBA영역에 들어감 6bytes
    unsigned int size; //이건 lba처럼 count영역에 들어가니, 섹터단위일듯.
    unsigned int ret_time;
}DS_PARAM;

enum ds_cmd{
    DS_WR_RANGE_MIN = 0x43,
    DS_CREATE_WR = 0x44,
    DS_OPEN_WR = 0x45,
    DS_CLOSE_WR = 0x46,
    DS_REMOVE_WR = 0x47,
    DS_RITE_WR = 0x48,
    DS_WR_RANGE_MAX = 0x49,
    DS_RD_RANGE_MIN = 0x4A,
    DS_READ_RD = 0x4B,
    DS_AUTH_RD = 0x4C ,
    DS_CREATE_RD = 0x4D,
    DS_OPEN_RD = 0x4E,
    DS_CLOSE_RD = 0x4F,
    DS_REMOVE_RD =0x50,
    DS_WRITE_RD = 0x51,
    DS_RD_RANGE_MAX= 0x52
};

enum spm_cmd{
    SPM_CREATE = 0x65,
    SPM_CHANGE,
    SPM_DELETE,
    SPM_RECOVERY
};

typedef struct SPM_PARAM{
    int ret_time;
    int backup_cycle;
    int version_num;
    int cmd;
}spm_param;

int spm_send_cmd(int fd, char* buffer, int node_size, char* response, int pid, spm_param*sp);

void printf(const char *fmt, ...);
void printf_helloworld();

#if defined(__cplusplus)
}
#endif

#endif /* !_ENCLAVE_H_ */
