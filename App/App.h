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


#ifndef _APP_H_
#define _APP_H_

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "sgx_error.h"       /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */

#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif

# define TOKEN_FILENAME   "enclave.token"
# define ENCLAVE_FILENAME "enclave.signed.so"

extern sgx_enclave_id_t global_eid;    /* global enclave id */

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

#if defined(__cplusplus)
extern "C" {
#endif

#if defined(__cplusplus)
}
#endif

#endif /* !_APP_H_ */
