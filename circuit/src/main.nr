// All comments must be in English.

use dep::poseidon::poseidon;

global MERKLE_DEPTH: u32 = 3; // 3 for demo

struct Note {
    amount: Field,  // Purpose Bound Money amount
    pbm_token_id: Field,
    owner: Field,   // Hash(Pubkey) of Sender (for old) or Receiver (for new)
    donor: Field,   // Hash(Pubkey) of the Original Donor (Fixed)
    salt: Field,
}

fn note_hash(note: Note) -> Field {
    let inputs = [
        note.amount,
        note.pbm_token_id,
        note.owner,
        note.donor,
        note.salt,
    ];
    poseidon::bn254::hash_5(inputs)
}

fn compute_merkle_proof(
    leaf: Field,
    index: u32,
    path: [Field; MERKLE_DEPTH],
) -> Field {
    let mut current_hash = leaf;
    let mut current_index = index;

    for i in 0..MERKLE_DEPTH {
        let sibling_hash = path[i];
        let is_right = current_index as u32 % 2;
        if is_right == 0 {
            current_hash = poseidon::bn254::hash_2([current_hash, sibling_hash]);
        } else {
            current_hash = poseidon::bn254::hash_2([sibling_hash, current_hash]);
        }
        current_index = current_index / 2;
    }

    current_hash
}




fn main(x: u64, y: pub u64) {
    assert(x != y);
}

#[test]
fn test_main() {
    main(1, 2);

    // Uncomment to make test fail
    // main(1, 1);
}

#[test]
fn test_compute_merkle_proof() {
    let leaf = 0x1234;
    
    let node_a = 0x5678;
    let node_c = 0x9abc;
    let node_e = 0xdef0;

    let path = [node_a, node_c, node_e];
    let index = 2; // 010 in binary

    let level_1 = poseidon::bn254::hash_2([leaf, node_a]);
    
    let level_2 = poseidon::bn254::hash_2([node_c, level_1]);
    
    let expected_root = poseidon::bn254::hash_2([level_2, node_e]);

    let calculated_root = compute_merkle_proof(leaf, index, path);
    
    assert(calculated_root == expected_root);
}

#[test]
fn test_merkle_proof_different_index() {
    let leaf = 0x111;
    let sibling = 0x222;
    let path = [sibling, 0x333, 0x444];
    
    let root_0 = compute_merkle_proof(leaf, 0, path);
    
    let root_1 = compute_merkle_proof(leaf, 1, path);
    
    assert(root_0 != root_1);
}