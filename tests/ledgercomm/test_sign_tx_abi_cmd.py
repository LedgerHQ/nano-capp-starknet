from boilerplate_client.transaction import Transaction

from starkware.starknet.public.abi import get_selector_from_name
from starkware.starknet.core.os.transaction_hash.transaction_hash import (
    TransactionHashPrefix,
    calculate_transaction_hash_common,
)
from starkware.crypto.signature.signature import verify

def test_sign_tx(cmd, button, model):
    bip32_path: str = "m/2645'/1195502025'/1148870696'/0'/0'/0"

    pub_key_x, pub_key_y = cmd.get_public_key(
            bip32_path=bip32_path,
            display=False)

    # Tx parameters
    signer_address = "0x7e00d496e324876bbc8531f2d9a82bf154d1a04a50218ee74cdd372f75a551a"
    contract_address = "0x0507446de5cfcb833d4e786f3a0510deb2429ae753741a836a7efa80c9c747cb"
    selector = 'mint'
    calldata=[("To", "0x7e00d496e324876bbc8531f2d9a82bf154d1a04a50218ee74cdd372f75a551a"), ("Quantity", "1000")]
    chain_id = "0x534e5f474f45524c49"
    max_fee = "1000000000000000"
    version = 1
    nonce = 1

    # Sign Tx with Nano
    tx = Transaction(
        aa=signer_address,
        chainid=chain_id,
        nonce=nonce,
        version=version,
        maxfee=max_fee,
        to=contract_address,
        selector=selector,
        calldata=calldata)

    r, s, v  = cmd.sign_tx(bip32_path=bip32_path,
                             transaction=tx,
                             button=button,
                             model=model)


    # Verify Signature

    data_offset = 0
    data_len = len(calldata)
    call_entry = [int(contract_address, 16), get_selector_from_name(selector), data_offset, data_len]
    call_array_len = 1
    call_data=[int(calldata[0][1], 16), int(calldata[1][1])]
    wrapped_method_calldata = [call_array_len, *call_entry, len(calldata), *call_data]
    
    hash_value = calculate_transaction_hash_common(
        tx_hash_prefix=TransactionHashPrefix.INVOKE,
        version=1,
        contract_address=int(signer_address, 16),
        entry_point_selector=0,
        calldata=wrapped_method_calldata,
        max_fee=int(max_fee),
        chain_id=int(chain_id, 16),
        additional_data=[nonce])
    
    assert(
        verify(
            msg_hash=hash_value, 
            r=int.from_bytes(r, byteorder='big'), 
            s=int.from_bytes(s, byteorder='big'), 
            public_key=int.from_bytes(pub_key_x, byteorder='big'))
        )
