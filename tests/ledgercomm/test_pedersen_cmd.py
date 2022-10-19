from starkware.crypto.signature.fast_pedersen_hash import pedersen_hash, pedersen_hash_func
from starkware.starknet.public.abi import starknet_keccak

import secrets

from datetime import datetime

# pedersen inputs
#a: str = "07e00d496e324876bbc8531f2d9a82bf154d1a04a50218ee74cdd372f75a551a"
#b: str = "0507446de5cfcb833d4e786f3a0510deb2429ae753741a836a7efa80c9c747cb"

N: int = 1

def test_pedersen(cmd, button, model):
    
    ra = secrets.token_bytes(32)
    a = starknet_keccak(data=ra)

    rb = secrets.token_bytes(32)
    b = starknet_keccak(data=rb)

    start = datetime.now()

    hash_nano = cmd.compute_pedersen(a=a.to_bytes(32, 'big'), b=b.to_bytes(32, 'big'), nb=N)

    end = datetime.now()

    total_time = (end-start).total_seconds()*1000

    print('\n')
    print(a.to_bytes(32, 'big').hex())
    print(b.to_bytes(32, 'big').hex())
    print(hash_nano.hex())
    print(total_time)
    print(total_time/N)
    
    for i in range(N):
        a = pedersen_hash(x=a, y=b)

    hash_ref = a

    print(hash_ref.to_bytes(32, 'big').hex())

    assert(int.from_bytes(hash_nano, byteorder='big') == hash_ref);

