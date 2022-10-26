from starkware.crypto.signature.fast_pedersen_hash import pedersen_hash, pedersen_hash_func
from starkware.starknet.public.abi import starknet_keccak

import secrets

from datetime import datetime

# pedersen inputs
#a: str = "00784f8bae775d53ce5afdff7b1754e3863a2bd0332960a48ea56f2c1939d07d"
#b: str = "03dec40fc1c0409adde42faeaa70f7e4af2784dca58a01f74e7f08c8d1dd75b4"

V: int = 1
N: int = 100 

def test_pedersen(cmd, button, model):
    
    ra = secrets.token_bytes(32)
    a = starknet_keccak(data=ra)

    rb = secrets.token_bytes(32)
    b = starknet_keccak(data=rb)

    #a = int.from_bytes(bytes.fromhex("00784f8bae775d53ce5afdff7b1754e3863a2bd0332960a48ea56f2c1939d07d"), "big") 
    #b = int.from_bytes(bytes.fromhex("03dec40fc1c0409adde42faeaa70f7e4af2784dca58a01f74e7f08c8d1dd75b4"), "big")
    
    start = datetime.now()

    hash_nano = cmd.compute_pedersen(a=a.to_bytes(32, 'big'), b=b.to_bytes(32, 'big'), nb=N, version=V)

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

