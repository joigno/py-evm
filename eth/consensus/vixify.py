from collections import OrderedDict
from typing import (
    Iterable,
    Tuple,
)

from eth_typing import (
    Address,
    Hash32,
)

from eth_utils import (
    big_endian_to_int,
    ValidationError,
    encode_hex,
)

from eth_hash.auto import keccak

from pyethash import (
    EPOCH_LENGTH,
    hashimoto_light,
    mkcache_bytes,
)


from eth.abc import (
    AtomicDatabaseAPI,
    BlockHeaderAPI,
    ConsensusAPI,
)
from eth.validation import (
    validate_length,
    validate_lte,
)



# Type annotation here is to ensure we don't accidentally use strings instead of bytes.
cache_by_epoch: 'OrderedDict[int, bytearray]' = OrderedDict()
CACHE_MAX_ITEMS = 10


def get_cache(block_number: int) -> bytes:
    epoch_index = block_number // EPOCH_LENGTH

    # doing explicit caching, because functools.lru_cache is 70% slower in the tests

    # Get the cache if already generated, marking it as recently used
    if epoch_index in cache_by_epoch:
        c = cache_by_epoch.pop(epoch_index)  # pop and append at end
        cache_by_epoch[epoch_index] = c
        return c

    # Generate the cache if it was not already in memory
    # Simulate requesting mkcache by block number: multiply index by epoch length
    c = mkcache_bytes(epoch_index * EPOCH_LENGTH)
    cache_by_epoch[epoch_index] = c

    # Limit memory usage for cache
    if len(cache_by_epoch) > CACHE_MAX_ITEMS:
        cache_by_epoch.popitem(last=False)  # remove last recently accessed

    return c


def check_pow(block_number: int,
              mining_hash: Hash32,
              mix_hash: Hash32,
              nonce: bytes,
              difficulty: int) -> None:
    validate_length(mix_hash, 32, title="Mix Hash")
    validate_length(mining_hash, 32, title="Mining Hash")
    validate_length(nonce, 8, title="POW Nonce")
    cache = get_cache(block_number)
    mining_output = hashimoto_light(
        block_number, cache, mining_hash, big_endian_to_int(nonce))
    if mining_output[b'mix digest'] != mix_hash:
        raise ValidationError(
            f"mix hash mismatch; expected: {encode_hex(mining_output[b'mix digest'])} "
            f"!= actual: {encode_hex(mix_hash)}. "
            f"Mix hash calculated from block #{block_number}, "
            f"mine hash {encode_hex(mining_hash)}, nonce {encode_hex(nonce)}"
            f", difficulty {difficulty}, cache hash {encode_hex(keccak(cache))}"
        )
    result = big_endian_to_int(mining_output[b'result'])
    validate_lte(result, 2**256 // difficulty, title="POW Difficulty")


MAX_TEST_MINE_ATTEMPTS = 1000

def mine_pow_nonce(block_number: int, mining_hash: Hash32, difficulty: int) -> Tuple[bytes, bytes]:
    cache = get_cache(block_number)
    # VDF input
    mining_input = hashimoto_light(block_number, cache, mining_hash)
    vdf_input_integer = big_endian_to_int(mining_input[b'result'])

    # Calculate VDF Steps needed.

    # Adding VRF (WIP)
    node_vrf_seed_b64 = self.vrf.get_seed_b64(vdf_input_integer)

    vdf_steps = hashimoto_light(DEFAULT_DEBUG_STAKE, TOTAL_COINS, node_vrf_seed_b64)
    vdf_difficulty = big_endian_to_int(vdf_steps[b'result'])
    print('VDF Difficulty = %d' % vdf_difficulty)
    
    print("DEBUG: Mining sequential VDF (Sloth) ...")
    # nonce = vdf_execute(vdf_input_integer,node_vdf_steps) # VRF version
    nonce = vdf_execute(vdf_input_integer, vdf_difficulty)
    print("DEBUG: Generated NONCE = %d" % nonce)

    return nonce, node_vrf_seed_b64, self.vrf.get_pem_public_key()      # , node_vrf_seed # with this


class PowConsensus(ConsensusAPI):
    """
    Modify a set of VMs to validate blocks via Proof of Work (POW)
    """

    def __init__(self, base_db: AtomicDatabaseAPI) -> None:
        pass

    def validate_seal(self, header: BlockHeaderAPI) -> None:
        """
        Validate the seal on the given header by checking the proof of work.
        """
        check_pow(
            header.block_number, header.mining_hash,
            header.mix_hash, header.nonce, header.difficulty)

    def validate_seal_extension(self,
                                header: BlockHeaderAPI,
                                parents: Iterable[BlockHeaderAPI]) -> None:
        pass

    @classmethod
    def get_fee_recipient(cls, header: BlockHeaderAPI) -> Address:
        """
        Return the ``coinbase`` of the passed ``header`` as the receipient for any
        rewards for the block.
        """
        return header.coinbase
