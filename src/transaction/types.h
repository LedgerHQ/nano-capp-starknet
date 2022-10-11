#pragma once

#include <stddef.h>  // size_t
#include <stdint.h>  // uint*_t

#define MAX_TX_LEN   510
#define ADDRESS_LEN  32
#define MAX_MEMO_LEN 465  // 510 - ADDRESS_LEN - 2*SIZE(U64) - SIZE(MAX_VARINT)

typedef enum {
    PARSING_OK = 1,
    SENDER_ADDRESS_PARSING_ERROR = -1,
    MAX_FEE_PARSING_ERROR = -2,
    NONCE_PARSING_ERROR = -3,
    VERSION_PARSING_ERROR = -4,
    TO_PARSING_ERROR = -5,
    SELECTOR_LENGTH_PARSING_ERROR = -6,
    SELECTOR_PARSING_ERROR = -7,
    DATA_LENGTH_PARSING_ERROR = -8,
    CALLDATA_PARSING_ERROR = -9,
    WRONG_LENGTH_ERROR = -10
} parser_status_e;

typedef struct {
    uint8_t name_len;
    char* name;
    uint8_t* item;    
} callData_item_t;

typedef struct {
    uint8_t callarray_length;
    uint8_t* to;
    uint8_t entry_point_length;
    uint8_t* entry_point;
    uint8_t selector[32];
    uint8_t data_offset;
    uint8_t data_length;
    uint8_t calldata_length;
    callData_item_t calldata[5];
} callData_t;

typedef struct {
    uint8_t *sender_address;     /// FieldElement 32 bytes
    callData_t calldata;       /// List<FieldElement>
    uint8_t *max_fee;            /// FieldElement 32 bytes
    uint8_t *nonce;             /// FieldElement 32 bytes
    uint8_t *version;           /// FieldElement 32 bytes
    uint8_t *chain_id;   
} transaction_t;
