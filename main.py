import random
import hashlib

def write_blocks_to_file(blocks, filename):
    with open(filename, 'w') as file:
        for block in blocks:
            file.write(f"Block {block['block_count']}:\n")
            file.write(f"Data: {block['data']}\n")
            file.write(f"Previous Hash: {block['previous_hash']}\n")
            file.write(f"Nonce: {block['nonce']}\n")
            file.write(f"Hash: {block['hash']}\n")
            file.write(f"Difficulty: {block['difficulty']}\n\n")

def generate_random_data():
    return ''.join(random.choices('0123456789abcdef', k=32))
def check_hash(hash, hash_complexity):
    return hash.startswith('0'*hash_complexity)

def compute_hash(data, previous_hash, nonce):
    hash = data + str(previous_hash) + str(nonce)
    return hashlib.sha256(hash.encode('utf-8')).hexdigest()

def mining(block_count, previous_hash):
    founded_hash = {}
    data = generate_random_data()
    nonce = 0
    while not any(founded_hash):
        hash = compute_hash(data, previous_hash, nonce)
        print(f'{hash_complexity} - {hash}')
        if check_hash(hash, hash_complexity):
            founded_hash = {'block_count':block_count, 'data': data, 'previous_hash': previous_hash, 'nonce': nonce, 'hash': hash, 'difficulty': hash_complexity}
        nonce += 1
    return founded_hash


if __name__ == '__main__':
    num_of_blocks = 5
    previous_hash = ''
    blocks = []
    hash_complexity_values = [x for x in range(2,6)]
    hash_complexity_len = len(hash_complexity_values)-1

    for i in range(0, num_of_blocks):
        hash_complexity_index = random.randint(0,  hash_complexity_len)
        hash_complexity = hash_complexity_values[hash_complexity_index]
        block = mining(i, previous_hash)
        blocks.append(block)
        previous_hash = block['hash']

    write_blocks_to_file(blocks, 'blockchain.txt')