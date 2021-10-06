import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils

# GLOBAL VARIABLES
Users = []
mempool = []
transaction_id = []  # Look into renaming this into Transaction IDs turning into a dictionary with the key as timestamp.
sign = []  # Look into renaming this into Signatures turning into a dictionary with the key as timestamp.
chain = []
transaction_txid = None
new_sender_nonce = None
all_user_states = {}
updated_User_State = {}
user_states_after = {}
block_id_hash = None
block_id_hash_int = None
fee = 0
nonce_ = 0
total_difficulty = 0


# GLOBAL FUNCTIONS
def hash_sha1(x: bytes) -> hashes:
    """
    This is a function that creates a SHA-1 of the sender's and/or recipient's public key.

    Args:
        x: This is the sender's public key in bytes.

    Returns: SHA-1 hash of the public key

    """
    sender_hash_digest = hashes.Hash(hashes.SHA1())
    sender_hash_digest.update(x)
    return sender_hash_digest.finalize()


def unpack(x: tuple) -> 'appends tuple to lists':
    """
    This is a simple function to unpack the transaction class tuple into global variables of a list nature.
    These lists track all the transactions, transaction IDs and Signatures on an equal index footing.

    Args:
        x: tuple of the the Transaction Class

    Returns: Nothing. Just appends tuple variables to different lists of the global variables.

    """
    global mempool, transaction_id, sign
    mempool.append(x[0])
    transaction_id.append(x[1])
    sign.append(x[2])


def block_id(a: bytes, b: bytes, c: list, d: int, e: int, f: int) -> bytes:
    """

    Args:
        a: The block id of the block before this one in the block chain. This is zero for the first block.
        b: The public key hash of the user responsible for mining this block.
        c: Concatenation of all the txid's of the transactions.
        d: An unsigned, 8 byte, little endian representation of the difficulty.
        e: An unsigned, 16 byte, little endian representation of the difficulty.
        f: An unsigned, 8 byte, little endian representation of the nonce.

    Returns: A SHA-256 hash in bytes.

    """
    conc = ''
    for i in c:
        conc += str(i.txid)

    block_id_hash_digest = hashes.Hash(hashes.SHA256())
    block_id_hash_digest.update(a)
    block_id_hash_digest.update(b)
    block_id_hash_digest.update(bytes(conc, 'utf-8'))
    block_id_hash_digest.update(d.to_bytes(8, byteorder='little', signed=False))
    block_id_hash_digest.update(e.to_bytes(16, byteorder='little', signed=False))
    block_id_hash_digest.update(f.to_bytes(8, byteorder='little', signed=False))
    block_id_hash_digest.copy()
    return block_id_hash_digest.finalize()


def calculate_difficulty(x):
    total_difficulty_for_period = 0
    total_time_for_period = 0
    if x <= 10:
        pass
    else:
        for i in x[:11]:
            total_difficulty_for_period += i.difficulty
            total_difficulty_for_period += i.timestamp

    return (total_difficulty_for_period * 10 * 120) // total_time_for_period


def verify_and_apply_block(x):
    """
    This is the function that adds the block to the longest chain (object). It takes a single argument, a block. If this
    block is not a valid addition to the longest chain it should raise an exception. It checks:
    > The height of the block is the length of the block is the length of the longest chain
    > If the longest chain is empty then the previous fields of the block should be 32 bit 0
    > If the longest chain is not empty then the timestamp of the new block should be at least the timestamp of the
      recent block
    > The verify_and_get changes function succeeds (ie does not rain an exception) when provided the difficulty
      calculated by the calculate_difficulty method, and the current user_states dictionary.
    Args:
        x:

    Returns:

    """
    assert x.height == len(BlockchainState.longest_chain), \
        f"Zimman says the block height and the length of the longest chain do not matter"
    if len(BlockchainState.longestchain) == 0:
        assert x.previous == b'fhz\xad\xf8b\xbdwl\x8f\xc1\x8b\x8e\x9f\x8e \x08\x97\x14\x85n\xe23\xb3\x90*Y\x1d\r_)%', \
            f"Zimman krickey mate previous is a dumb fuckery"
    else:
        assert x.timestamp == chain[len(chain):].timestamp, \
            f"Zimman at this point is not responsible for your timestamps"

    assert len(BlockchainState.longest_chain) == 0, \
        f"Zimman says the longestchain is not empty"
    try:
        x.verify_and_get_changes()
    except AssertionError:
        print("verify_get_changes didnt pass and thus cannot go on the longest chain")
    BlockchainState.longest_chain.append(x)
    global total_difficulty
    total_difficulty + x.difficulty
    

# TRANSACTION CLASS:
class Transaction(object):

    def __init__(self, a: bytes, b: bytes, c, d: int, e: int, f: int, g: bytes, h: bytes):
        """
        This is purely a constructor class to specify the parameters of the class object.

        Args:
            a: The public key of the user sending the funds (sender's hash).
            b: The public key hash of the user receiving the funds (recipient's hash).
            c: The public key of the user sending the funds (sender's public key)
            d: The amount of funds being sent from the sender's address(amount).
            e: This is the amount of funds paid as a mining fee in this transaction(fee).
            f: This is a 64 bit number, this should increase by 1 for each transfer made by the sender
            g: A signature, created by the sender, confirming that they consent to this transaction
            h: The transaction id, this is a SHA-256 hash of the other fields of the transaction
        """

        self.sender_public_key_bytes = a
        self.sender_hash = hash_sha1(a)
        self.recipient_hash = b
        self.sender_public_key = c
        self.amount = d
        self.fee = e
        self.nonce = f
        self.signature = g
        self.txid = h

    def verify(self, a: int, b: int):
        """
        This is a function that verifies that transaction by looking whether or not:
            > The Sender's Public Key Hash and the Recipient's Public Key Has are both 20 bytes long
            > The Sender's Public Key Hash is a SHA-1 has of the Sender's Public Key
            > The amount is a whole number between 1 and 2**{64-1} inclusive
            > The fee is a whole number between 0 and amount inclusive
            > The nonce should be the sender's previous nonce + 1
            > The transaction ID is the hash of the other fields in the transaction
            > The signature is a valid signature using the Elliptic Curve

        Args:
            a: This is the sender's available balance for the transaction.
            b: This is the sender's 64-bit number that is used once and should have changed.

        Returns: This function does not return any object. It merely asserts which, if any, of the parameters being
        checked have failed.

        """

        def verify_signature(u: 'elliptic curve', v: bytes, w: bytes, x: int, y: int, z: int, ):
            """
            This function verifies the signature produced by the sender using the Elliptic curve and his public key
            to confirm.

            Args:
                u: The public key of the user sending the funds (sender's public key)
                v: The signature, created by the sender, confirming that they consent to this transaction
                w: The public key hash of the user receiving the funds (recipient's hash).
                x: he amount of funds being sent from the sender's address(amount).
                y: This is the amount of funds paid as a mining fee in this transaction(fee).
                z: This is a 64 bit number, this should increase by 1 for each transfer made by the sender

            Returns: This function does not return any object. It does raise an exception if the signature is not valid.

            """
            chosen_hash = hashes.SHA256()
            hasher = hashes.Hash(chosen_hash)
            hasher.update(w)
            hasher.update(x.to_bytes(8, byteorder='little', signed=False))
            hasher.update(y.to_bytes(8, byteorder='little', signed=False))
            hasher.update(z.to_bytes(8, byteorder='little', signed=False))
            verify_signature_digest = hasher.finalize()
            u.verify(v, verify_signature_digest, ec.ECDSA(utils.Prehashed(chosen_hash)))

        assert len(self.sender_hash) == 20, \
            f"Zimman says the length of sender_hash is not 20"
        assert len(self.recipient_hash) == 20, \
            f"Zimman says the length of sender_hash is not 20"
        assert len(self.sender_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )) == 88, \
            f"Zimman says the length of sender_public_key is not 88"
        assert self.sender_hash == hash_sha1(self.sender_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )), \
            f"Zimman says sender_hash is a bit dodgy"
        assert 1 <= self.amount <= 2 ** 64 - 1, \
            f"Zimman says ({self.amount}) is not a whole number between 1 and 2**64-1"
        assert 0 <= self.fee <= self.amount, \
            f"Zimman says {self.fee} is not a whole number between 0 and {self.amount} inclusive"
        global new_sender_nonce
        assert b + 1 == new_sender_nonce, \
            f"Zimman says this nonce {self.nonce} doesn't seem to change after this transaction"
        assert self.txid == transaction_txid, \
            f"Zimman says this transaction id txid doesn't match the hash of the inputs of this transaction"
        verify_signature(self.sender_public_key,
                         self.signature,
                         self.recipient_hash,
                         self.amount,
                         self.fee,
                         self.nonce,
                         )
        assert self.amount <= a, \
            f"Zimman says sender lacks funds"


# BLOCKCHAIN STATE CLASS
class BlockchainState(object):

    def __init__(self, a, b, c):
        """

        Args:
            a: A list of Blocks
            b: A dictionary mapping strings to UserStates, represents the state of eacg address at the end of the
            longest chain.
            c: An integer, this will be the sum of the difficulties of all the blocks in the longest chain.
        """
        self.longest_chain = a
        self.user_state = b
        self.total_difficulty = c




# USER STATE CLASS
class UserState(object):
    """
    This is a class used to help keep track of the state of users as blocks are accepted onto the blockchain.
    """

    def __init__(self, a, b):
        """
        This is a constructor of the UserState Class.

        Args:
            a: The (on-chain) balance of the user.
            b: The most recently used nonce of the user.
        """
        self.balance = a
        self.nonce = b


# NONCE TRACKER
class UserNonce(object):
    def __init__(self, a):
        self.previous_nonce = a
        self.new_nonce = a + 1

    # def copy(self):


# BLOCK
class Block(object):
    """
    A block, also known as records.
    """
    block_id_1 = 0
    hash_digest = hashes.Hash(hashes.SHA256())
    hash_digest.update(block_id_1.to_bytes(32, byteorder='little', signed=False))
    block_id_1_hash = hash_digest.finalize()

    def __init__(self, a: bytes, b: int, c: bytes, d: list, e: int, f: int, g: bytes, h: int):
        """

        Args:
            a: The block id of the block before this one in the block chain. This is zero for the first block.
            b: The number of blocks before this one in the block chain. The first block will have a height of 0.
            c: The public key hash of the user responsible for mining this block.
            d: A list containing the transactions contained within this block.
            e: An integer between 0 and 2**{64 - 1}, the number of seconds since 1st January 1970.
            f: An integer between 1 and 2**{128 - 1} indicating difficulty of the proof of work needed to mine this block.
            g: A 32 byte hash of the block.
            h: An integer between 0 and 2**64 - 1.
        """
        if a == 0:
            self.previous = Block.block_id_1_hash
        else:
            self.previous = a
        self.height = b
        self.miner = c
        self.transaction = d
        self.timestamp = e
        self.difficulty = f
        self.block_id = g
        self.nonce = h

    def verify_and_get_changes(self, a, b: dict):
        """
        The aim of this function is to verify the block.

        Args:
            a: The expected difficulty for this block
            b: A map from bytes to UserState. The state of all the users before bytes this block.

        Returns: If the block verifies successfully then this function should return a map from bytes to UserState,
        otherwise it will raise an exception.

        """
        d_copy = b.copy()
        transaction_len = len(self.transaction)
        for i in range(transaction_len):
            amount_ = self.transaction[i].amount
            sender_hash_ = self.transaction[i].sender_hash
            recipient_hash_ = self.transaction[i].recipient_hash
            for j in d_copy:
                if d_copy[j] == sender_hash_:
                    d_copy[j].balance -= amount_
                if d_copy[j] == recipient_hash_:
                    d_copy[j].balance += amount_

        assert self.difficulty == a, \
            f"Zimman says the difficulty for this block does not mathc the argument"
        global block_id_hash
        assert self.block_id == block_id_hash, \
            f"Zimman says this block ID does not match"
        assert len(self.transaction) <= 25, \
            f"Zimman says the number of transactions is 1 too many"
        assert len(self.miner) == 20, \
            f"Zimman says this miner's hash looks a bit dodgy there"
        nonce__ = 1
        found = 0
        while found == 0:
            block_id_hash_int_ = int.from_bytes(block_id_hash, byteorder='little', signed=False)
            if block_id_hash_int_ <= 2 ** 256 // nonce__:
                found += 1
            nonce__ += 1
        # proof of work verification is intermitent while using assert method do not know why. so chose to calculate
        return d_copy

    def get_changes_for_undo(self, a: dict):
        """

        Args:
            a: This is a user_states_after, a dictionary of strings to UserStates

        Returns:

        """
        d_copy = a.copy()
        transaction_len = len(self.transaction)
        for i in range(transaction_len):
            amount__ = self.transaction[i].amount
            sender_hash_ = self.transaction[i].sender_hash
            recipient_hash_ = self.transaction[i].recipient_hash
            for j in d_copy:
                if d_copy[j] == sender_hash_:
                    d_copy[j].balance += amount__
                if d_copy[j] == recipient_hash_:
                    d_copy[j].balance -= amount__

        return d_copy


# USERS
class User(object):
    """
    This a class that creates and tracks user states in the Zimman network.
    """

    def __init__(self, a: str, b: int, c: int):
        """
        This is a constructor  and takes the following parameters.

        Args:
            a: The name of the user being created on the network.
            b: The (on-chain) balance of the user being created.
            c: Previous nonce
        """
        self.private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
        self.public_key = self.private_key.public_key()
        self.public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.name = a
        self.address = hash_sha1(self.public_key_bytes)
        self.balance = b
        self.nonce = c

    def send_money(self, a, b: bytes, c: int, d: int, e: int):
        """
        This is a function in the User class that a user calls on to sender money to another user in the Zimman network.
        This functions publishes on the global zimman network the transaction, the transaction ID and the signature.
        This is to create an openness in the network. We don't like dodgy people.

        Args:
            a: This is the sender's private key.
            b: This is the address of the user where the money will be sent.
            c: This is the amount being sent
            d: This is the fee to be paid to the miners
            e: This is a 64 bit number, this should increase by 1 for each transfer made by the sender

        Returns: There isn't a return variable but rather it publishes on the gloabl network the transaction,
        transaction ID and the signature of the sender.

        """
        recipient = None
        global Users
        for i in Users:
            if i.address == b:
                recipient = i

        global fee
        fee += d

        def create_signed_transaction(v: 'Elliptic Curve', w: bytes, x: int, y: int, z: int) -> tuple:
            """
            This function takes the arguments of sender_private_key, recipient_hash, amount, fee and nonce and creates a
            transactions.

            The first step is that it takes the sender's private key generated by the Elliptic Curve and generates a public
            key. It also produces that public key into a bytes form that can be easily hashed.

            Using the Sender's Private Key this functions follows on by creating a signature of the transaction using SHA-256.

            Using the Sender's Public Key in bytes form the function creates a transaction ID using SHA-256.

            The function then uses the Transaction class to perform the transaction. It also put on the public domain two
            variables. The transaction ID which can be used for verification and/or updating the blockchain.

            Args:
                v: This the 'EllipticCurvePrivateKey' object representing the private key of the sender
                w: This the Recipient's Public Key
                x: The amount of funds being transferred (amount)
                y: This is the amount of funds paid as a mining fee in this transaction(fee)
                z: This is a 64 bit number, this should increase by 1 for each transfer made by the sender (nonce).

            Returns: A transaction to pay a specific recipient, transaction ID and the signature.
            It also updates the sender's nonce by 1.

            """

            sender_public_key = v.public_key()
            sender_public_key_bytes = sender_public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            chosen_hash = hashes.SHA256()
            hasher = hashes.Hash(chosen_hash)
            hasher.update(w)
            hasher.update(x.to_bytes(8, byteorder='little', signed=False))
            hasher.update(y.to_bytes(8, byteorder='little', signed=False))
            hasher.update(z.to_bytes(8, byteorder='little', signed=False))
            created_transaction_sign_digest = hasher.finalize()
            transaction_signature = v.sign(created_transaction_sign_digest, ec.ECDSA(utils.Prehashed(chosen_hash)))

            created_transaction_txid_digest = hashes.Hash(hashes.SHA256())
            created_transaction_txid_digest.update(hash_sha1(sender_public_key_bytes))
            created_transaction_txid_digest.update(w)
            created_transaction_txid_digest.update(sender_public_key_bytes)
            created_transaction_txid_digest.update(x.to_bytes(8, byteorder='little', signed=False))
            created_transaction_txid_digest.update(y.to_bytes(8, byteorder='little', signed=False))
            created_transaction_txid_digest.update(z.to_bytes(8, byteorder='little', signed=False))
            global transaction_txid
            transaction_txid = created_transaction_txid_digest.finalize()

            trans = Transaction(a=sender_public_key_bytes,
                                b=w,
                                c=sender_public_key,
                                d=x,
                                e=y,
                                f=z,
                                g=transaction_signature,
                                h=transaction_txid
                                )
            global new_sender_nonce
            new_sender_nonce = z + 1
            return trans, transaction_txid, transaction_signature

        try:
            transaction_transaction_id_sign_tuple = create_signed_transaction(a,
                                                                              b,
                                                                              c,
                                                                              d,
                                                                              e)
            unpack(transaction_transaction_id_sign_tuple)
            print('You have sent {},\nan amount of {},\nand ID is {}.'.format(b, c, transaction_id))
            transaction_transaction_id_sign_tuple[0].verify(self.balance, e)
            global all_user_states
            all_user_states[self.address] = UserState(self.balance, self.nonce)
            all_user_states[b] = UserState(recipient.balance, recipient.nonce)
            self.balance -= c
            recipient.balance += c
            self.nonce += 1
            recipient.nonce += 1
            global user_states_after
            user_states_after[self.address] = UserState(self.balance, self.nonce)
            user_states_after[b] = UserState(recipient.balance, recipient.nonce)

        except AssertionError as exc:
            print("Verification failed. Why? Well, ", exc)

    def check_balance(self):
        print(self.balance)

    def mine_block(self, a: bytes, b: int, c: bytes, d: list, e: int, f: int):
        """
         This function mines a block.

        Args:
            a: The block id of the previous block.
            b: The block height.
            c: The public key hash of the miner of the block.
            d: A list of the transactions that should be included
            e: The timestamp of the block
            f: The difficulty of the block

        Returns:

        """
        global nonce_
        nonce_ = 1
        found = 0
        while found == 0:
            global block_id_hash
            block_id_hash = block_id(a,
                                     c,
                                     d,
                                     e,
                                     f,
                                     nonce_,
                                     )
            global block_id_hash_int
            block_id_hash_int = int.from_bytes(block_id_hash, byteorder='little', signed=False)
            print(block_id_hash_int)
            if block_id_hash_int <= 2 ** 256 // nonce_:
                found += 1
            nonce_ += 1
            print(nonce_)
            block_1 = Block(a,
                            b,
                            c,
                            d,
                            e,
                            f,
                            block_id_hash,
                            nonce_)
            global updated_User_State
            updated_User_State = block_1.verify_and_get_changes(500, all_user_states)
            global fee
            self.balance += fee
            self.balance += 10000

            return block_1


# USERS
alice = User('Alice', 30000, 123456788)
bob = User('Bob', 900000, 123456789)
miner = User('Greedy_Bastard', 1000000, 0)
Users.append(alice)
Users.append(bob)
Users.append(miner)

# TRANSACTION
alice.send_money(alice.private_key, bob.address, 50, 2, alice.nonce)
bob.send_money(bob.private_key, alice.address, 45, 2, bob.nonce)
alice.check_balance()
bob.check_balance()

chain.append(
    miner.mine_block(Block.block_id_1_hash,
                     len(chain),
                     hash_sha1(miner.public_key_bytes),
                     mempool,
                     int(time.time()),
                     500,
                     )
)

miner.check_balance()

gay = miner.mine_block(Block.block_id_1_hash,
                       len(chain),
                       hash_sha1(miner.public_key_bytes),
                       mempool,
                       int(time.time()),
                       500,
                       )

block_id_1 = 0
hash_digest = hashes.Hash(hashes.SHA256())
hash_digest.update(block_id_1.to_bytes(32, byteorder='little', signed=False))
block_id_2_hash = hash_digest.finalize()
print(block_id_2_hash)
print(gay.previous)

print(len(chain))
