// All comments must be in English.

use dep::poseidon::poseidon;

global MERKLE_DEPTH: u32 = 3; // 3 for demo

struct Note {
    amount: u64,  // Purpose Bound Money amount
    pbm_token_id: u32,
    owner: Field,   // Hash(Pubkey) of Sender (for old) or Receiver (for new)
    funder: Field,   // Hash(Pubkey) of the Original Funder (Fixed)
    salt: Field,
}

fn note_hash(note: Note) -> Field {
    let inputs = [
        note.amount as Field,
        note.pbm_token_id as Field,
        note.owner,
        note.funder,
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
        let is_right = current_index % 2;
        if is_right == 0 {
            current_hash = poseidon::bn254::hash_2([current_hash, sibling_hash]);
        } else {
            current_hash = poseidon::bn254::hash_2([sibling_hash, current_hash]);
        }
        current_index = current_index / 2;
    }

    current_hash
}

fn verify_old_note(
    old_note: Note,
    pbm_token_id: u32,
    funder_public_point: std::embedded_curve_ops::EmbeddedCurvePoint,
    owner_private_key: std::embedded_curve_ops::EmbeddedCurveScalar,
    nullifier: Field,
    merkle_root: Field,
    merkle_index: u32,
    merkle_path: [Field; MERKLE_DEPTH],
    is_dummy: bool,
) {
    assert_eq(old_note.pbm_token_id, pbm_token_id, "PBM Token ID does not match");
    {
        let derived_funder_hash = poseidon::bn254::hash_2([
            funder_public_point.x,
            funder_public_point.y,
        ]);
        assert_eq(old_note.funder, derived_funder_hash, "Funder public key mismatch for old note");
    }
    {
        let derived_owner_public_point = std::embedded_curve_ops::fixed_base_scalar_mul(owner_private_key);
        let derived_owner_hash = poseidon::bn254::hash_2([
            derived_owner_public_point.x,
            derived_owner_public_point.y,
        ]);
        assert_eq(derived_owner_hash, old_note.owner, "Owner private key mismatch for old note");
    }

    let old_note_hash = note_hash(old_note);
    let derived_nullifier = poseidon::bn254::hash_3([
        old_note_hash,
        owner_private_key.hi,
        owner_private_key.lo,
    ]);
    assert_eq(derived_nullifier, nullifier, "Nullifier does not match");

    let calculated_merkle_root = compute_merkle_proof(old_note_hash, merkle_index, merkle_path);
    if is_dummy {
        assert_eq(old_note.amount, 0, "Dummy note amount must be zero");
    } else {
        assert(old_note.amount > 0, "Old note amount must be greater than zero");
        assert_eq(calculated_merkle_root, merkle_root, "Merkle root does not match");
    }
}

fn verify_new_note(
    new_note: Note,
    new_note_hash: Field,
    pbm_token_id: u32,
    receiver_public_point: std::embedded_curve_ops::EmbeddedCurvePoint,
    funder_public_point: std::embedded_curve_ops::EmbeddedCurvePoint,
) {
    assert_eq(note_hash(new_note), new_note_hash, "New note hash does not match");

    assert_eq(new_note.pbm_token_id, pbm_token_id, "PBM Token ID does not match for new note");

    let derived_receiver_hash = poseidon::bn254::hash_2([
        receiver_public_point.x,
        receiver_public_point.y,
    ]);
    assert_eq(new_note.owner, derived_receiver_hash, "Receiver public key mismatch for new note");

    let derived_funder_hash = poseidon::bn254::hash_2([
        funder_public_point.x,
        funder_public_point.y,
    ]);
    assert_eq(new_note.funder, derived_funder_hash, "Funder public key mismatch for new note");
}

struct Scalar256bit {
    low: u128,
    high: u128,
}

struct Ciphertext {
    low: Field,
    high: Field,
}

fn encrypt_128bit_with_curve_point(
    secret: u128,
    shared_point: std::embedded_curve_ops::EmbeddedCurvePoint,
    salt: Field,
) -> Field {
    let keystream = poseidon::bn254::hash_2([shared_point.x, salt]);
    let encrypted_secret = (secret as Field) + keystream;
    encrypted_secret
}

fn verify_encryption(
    encryption_randomness: std::embedded_curve_ops::EmbeddedCurveScalar,
    public_point: std::embedded_curve_ops::EmbeddedCurvePoint,
    ephemeral_public_point: std::embedded_curve_ops::EmbeddedCurvePoint,
    shared_secret: Scalar256bit,
    encrypted_key: Ciphertext,
) {
    {
        let derived_ephemeral_point = std::embedded_curve_ops::fixed_base_scalar_mul(encryption_randomness);
        assert_eq(derived_ephemeral_point.x, ephemeral_public_point.x, "Ephemeral public point X mismatch");
        assert_eq(derived_ephemeral_point.y, ephemeral_public_point.y, "Ephemeral public point Y mismatch");
    }

    let shared_point: std::embedded_curve_ops::EmbeddedCurvePoint = std::embedded_curve_ops::multi_scalar_mul([public_point], [encryption_randomness]);

    let derived_encrypted_key_low = encrypt_128bit_with_curve_point(shared_secret.low, shared_point, 1);
    let derived_encrypted_key_high = encrypt_128bit_with_curve_point(shared_secret.high, shared_point, 2);

    assert_eq(derived_encrypted_key_low, encrypted_key.low, "Encrypted key low mismatch");
    assert_eq(derived_encrypted_key_high, encrypted_key.high, "Encrypted key high mismatch");
}



fn main(
    receiver_1_public_point: pub std::embedded_curve_ops::EmbeddedCurvePoint,
    receiver_2_public_point: pub std::embedded_curve_ops::EmbeddedCurvePoint,
    funder_public_point: pub std::embedded_curve_ops::EmbeddedCurvePoint,

    pbm_token_id: pub u32,
    merkle_root_1: pub Field,
    merkle_root_2: pub Field,

    nullifier_1: pub Field,
    nullifier_2: pub Field,
    new_note_1_hash: pub Field,
    new_note_2_hash: pub Field,

    encrypted_key_for_receiver_1: pub Ciphertext,
    encrypted_key_for_receiver_2: pub Ciphertext,
    encrypted_key_1_for_funder: pub Ciphertext,
    encrypted_key_2_for_funder: pub Ciphertext,

    ephemeral_public_point_for_receiver_1: pub std::embedded_curve_ops::EmbeddedCurvePoint,
    ephemeral_public_point_for_receiver_2: pub std::embedded_curve_ops::EmbeddedCurvePoint,
    ephemeral_public_point_1_for_funder: pub std::embedded_curve_ops::EmbeddedCurvePoint,
    ephemeral_public_point_2_for_funder: pub std::embedded_curve_ops::EmbeddedCurvePoint,

    // Private Inputs
    owner_private_key: std::embedded_curve_ops::EmbeddedCurveScalar,

    old_note_1: Note,
    old_note_2: Note,
    merkle_path_1: [Field; MERKLE_DEPTH],
    merkle_path_2: [Field; MERKLE_DEPTH],
    merkle_index_1: u32,
    merkle_index_2: u32,
    is_dummy_1: bool,
    is_dummy_2: bool,
    new_note_1: Note,
    new_note_2: Note,

    shared_key_1: Scalar256bit,
    shared_key_2: Scalar256bit,
    encryption_randomness_for_receiver_1: std::embedded_curve_ops::EmbeddedCurveScalar,
    encryption_randomness_for_receiver_2: std::embedded_curve_ops::EmbeddedCurveScalar,
    encryption_randomness_1_for_funder: std::embedded_curve_ops::EmbeddedCurveScalar,
    encryption_randomness_2_for_funder: std::embedded_curve_ops::EmbeddedCurveScalar,
) {
    verify_old_note(
        old_note_1,
        pbm_token_id,
        funder_public_point,
        owner_private_key,
        nullifier_1,
        merkle_root_1,
        merkle_index_1,
        merkle_path_1,
        is_dummy_1,
    );
    verify_old_note(
        old_note_2,
        pbm_token_id,
        funder_public_point,
        owner_private_key,
        nullifier_2,
        merkle_root_2,
        merkle_index_2,
        merkle_path_2,
        is_dummy_2,
    );

    verify_new_note(
        new_note_1,
        new_note_1_hash,
        pbm_token_id,
        receiver_1_public_point,
        funder_public_point,
    );
    verify_new_note(
        new_note_2,
        new_note_2_hash,
        pbm_token_id,
        receiver_2_public_point,
        funder_public_point,
    );

    {
        let input_sum = old_note_1.amount + old_note_2.amount;
        let output_sum = new_note_1.amount + new_note_2.amount;
        assert_eq(input_sum, output_sum, "Total amount imbalance (2-in, 2-out)");
    }


    verify_encryption(
        encryption_randomness_for_receiver_1,
        receiver_1_public_point,
        ephemeral_public_point_for_receiver_1,
        shared_key_1,
        encrypted_key_for_receiver_1,
    );
    verify_encryption(
        encryption_randomness_for_receiver_2,
        receiver_2_public_point,
        ephemeral_public_point_for_receiver_2,
        shared_key_2,
        encrypted_key_for_receiver_2,
    );
    verify_encryption(
        encryption_randomness_1_for_funder,
        funder_public_point,
        ephemeral_public_point_1_for_funder,
        shared_key_1,
        encrypted_key_1_for_funder,
    );
    verify_encryption(
        encryption_randomness_2_for_funder,
        funder_public_point,
        ephemeral_public_point_2_for_funder,
        shared_key_2,
        encrypted_key_2_for_funder,
    );
}



fn encrypt(
    randomness: std::embedded_curve_ops::EmbeddedCurveScalar,
    public_point: std::embedded_curve_ops::EmbeddedCurvePoint,
    shared_key: Scalar256bit,
) -> (
    std::embedded_curve_ops::EmbeddedCurvePoint,
    Ciphertext,
) {
    // Elliptic curve Diffie-Hellman
    let ephemeral_public_point= std::embedded_curve_ops::fixed_base_scalar_mul(randomness);
    let shared_point: std::embedded_curve_ops::EmbeddedCurvePoint = std::embedded_curve_ops::multi_scalar_mul::<1>(
        [public_point],
        [randomness]
    );

    // Encryption using shared point
    let keystream_low = poseidon::bn254::hash_2([shared_point.x, 1]);
    let keystream_high = poseidon::bn254::hash_2([shared_point.x, 2]);
    let encrypted_key = Ciphertext {
        low: (shared_key.low as Field) + keystream_low,
        high: (shared_key.high as Field) + keystream_high,
    };

    (ephemeral_public_point, encrypted_key)
}


fn print_helper<let N: u32, T>(field_name: str<N>, value: T) {
    std::print(field_name);
    std::print(" = \"");
    std::print(value);
    std::println("\"");
}

fn print_helper_note<let N: u32>(name: str<N>, note: Note) {
    std::print(name);
    std::print(" = { amount = \"");
    std::print(note.amount);
    std::print("\", pbm_token_id = \"");
    std::print(note.pbm_token_id);
    std::print("\", owner = \"");
    std::print(note.owner);
    std::print("\", funder = \"");
    std::print(note.funder);
    std::print("\", salt = \"");
    std::print(note.salt);
    std::println("\" }");
}

fn print_helper_scalar<let N: u32>(name: str<N>, scalar: std::embedded_curve_ops::EmbeddedCurveScalar) {
    std::print(name);
    std::print(" = { hi = \"");
    std::print(scalar.hi);
    std::print("\", lo = \"");
    std::print(scalar.lo);
    std::println("\" }");
}

fn print_helper_curve_point<let N: u32>(name: str<N>, point: std::embedded_curve_ops::EmbeddedCurvePoint) {
    std::print(name);
    std::print(" = { x = \"");
    std::print(point.x);
    std::print("\", y = \"");
    std::print(point.y);
    std::println("\", is_infinite = false }");
}

fn print_helper_low_and_high<let N: u32, T>(name: str<N>, low: T, high: T) {
    std::print(name);
    std::print(" = { low = \"");
    std::print(low);
    std::print("\", high = \"");
    std::print(high);
    std::println("\" }");
}


#[test]
fn test_main() {
    // =======================
    // Setup Keys (Sender, Receiver, Funder)
    // Note: In a real app, these are random. For tests, we use fixed numbers.
    // =======================

    // Funder
    let funder_private_field: Field = 11111;
    let funder_private_key = std::embedded_curve_ops::EmbeddedCurveScalar::from_field(funder_private_field);
    let funder_public_point = std::embedded_curve_ops::fixed_base_scalar_mul(funder_private_key);
    let funder_public_hash = poseidon::bn254::hash_2([funder_public_point.x, funder_public_point.y]);

    // Sender (Owner of old notes)
    let owner_private_field: Field = 22222;
    let owner_private_key = std::embedded_curve_ops::EmbeddedCurveScalar::from_field(owner_private_field);
    let owner_public_point = std::embedded_curve_ops::fixed_base_scalar_mul(owner_private_key);
    let owner_public_hash = poseidon::bn254::hash_2([owner_public_point.x, owner_public_point.y]);

    // Receiver 1
    let receiver_1_private_field: Field = 33333;
    let receiver_1_private_key = std::embedded_curve_ops::EmbeddedCurveScalar::from_field(receiver_1_private_field);
    let receiver_1_public_point = std::embedded_curve_ops::fixed_base_scalar_mul(receiver_1_private_key);
    let receiver_1_public_hash = poseidon::bn254::hash_2([receiver_1_public_point.x, receiver_1_public_point.y]);

    // Receiver 2
    let receiver_2_private_field: Field = 44444;
    let receiver_2_private_key = std::embedded_curve_ops::EmbeddedCurveScalar::from_field(receiver_2_private_field);
    let receiver_2_public_point = std::embedded_curve_ops::fixed_base_scalar_mul(receiver_2_private_key);
    let receiver_2_public_hash = poseidon::bn254::hash_2([receiver_2_public_point.x, receiver_2_public_point.y]);

    // Ephemeral Randomness (used for encryption)
    let rand_receiver_1_field: Field = 101;
    let rand_receiver_1 = std::embedded_curve_ops::EmbeddedCurveScalar::from_field(rand_receiver_1_field);
    let rand_receiver_2_field: Field = 102;
    let rand_receiver_2 = std::embedded_curve_ops::EmbeddedCurveScalar::from_field(rand_receiver_2_field);
    let rand_1_funder_field: Field = 103;
    let rand_1_funder = std::embedded_curve_ops::EmbeddedCurveScalar::from_field(rand_1_funder_field);
    let rand_2_funder_field: Field = 104;
    let rand_2_funder = std::embedded_curve_ops::EmbeddedCurveScalar::from_field(rand_2_funder_field);

    std::println("Step 1: Keys Generated Successfully");



    // =======================
    // Create Notes
    // =======================
    let pbm_token_id: u32 = 1;
    let salt: Field = 58179125;

    let old_note_1: Note = Note {
        amount: 70,
        pbm_token_id: pbm_token_id,
        owner: owner_public_hash,
        funder: funder_public_hash,
        salt: salt,
    };
    let old_note_2: Note = Note {
        amount: 30,
        pbm_token_id: pbm_token_id,
        owner: owner_public_hash,
        funder: funder_public_hash,
        salt: salt,
    };
    let new_note_1: Note = Note {
        amount: 40,
        pbm_token_id: pbm_token_id,
        owner: receiver_1_public_hash,
        funder: funder_public_hash,
        salt: salt,
    };
    let new_note_2: Note = Note {
        amount: 60,
        pbm_token_id: pbm_token_id,
        owner: receiver_2_public_hash,
        funder: funder_public_hash,
        salt: salt,
    };

    let old_note_1_hash = note_hash(old_note_1);
    let old_note_2_hash = note_hash(old_note_2);
    let new_note_1_hash = note_hash(new_note_1);
    let new_note_2_hash = note_hash(new_note_2);

    std::println("Step 2: Notes Created");



    // =======================
    // Merkle Tree Construction
    // =======================
    // Tree Structure:
    // Root:            Hash(D1_0, D1_1)
    // Depth 1:         [Hash(D2_0, D2_1), Hash(D2_2, D2_3)]
    // Depth 2:         [Hash(N1,N2), Hash(0,0), Hash(0,0), Hash(0,0)]
    // Depth 3(Leaves): [Note1, Note2, 0, 0, 0, 0, 0, 0]

    // Depth 3 (Leaves)
    // Note 1 is at Index 0, Note 2 is at Index 1
    let leaf_0 = old_note_1_hash;
    let leaf_1 = old_note_2_hash;
    let zero_leaf = 0; // Empty leaf

    // --- Depth 2 (Hashes of leaves) ---
    // Parent of 0 and 1
    let depth_2_node_0 = poseidon::bn254::hash_2([leaf_0, leaf_1]);
    // Parent of 2 and 3 (Empty)
    let depth_2_node_1 = poseidon::bn254::hash_2([zero_leaf, zero_leaf]);
    // Parent of 4 and 5 (Empty)
    let depth_2_node_2 = poseidon::bn254::hash_2([zero_leaf, zero_leaf]);
    // Parent of 6 and 7 (Empty)
    let depth_2_node_3 = poseidon::bn254::hash_2([zero_leaf, zero_leaf]);

    // --- Depth 1 ---
    let depth_1_node_0 = poseidon::bn254::hash_2([depth_2_node_0, depth_2_node_1]);
    let depth_1_node_1 = poseidon::bn254::hash_2([depth_2_node_2, depth_2_node_3]);

    // --- Root ---
    let merkle_root = poseidon::bn254::hash_2([depth_1_node_0, depth_1_node_1]);

    let merkle_path_1: [Field; MERKLE_DEPTH] = [
        leaf_1,         // Sibling at Depth 3
        depth_2_node_1, // Sibling at Depth 2
        depth_1_node_1, // Sibling at Depth 1
    ];
    let merkle_path_2: [Field; MERKLE_DEPTH] = [
        leaf_0,         // Sibling at Depth 3
        depth_2_node_1, // Sibling at Depth 2
        depth_1_node_1, // Sibling at Depth 1
    ];

    std::println("Step 3: Merkle Tree Built");

    // =======================
    // Prepare Encryption Inputs
    // =======================

    // First, calculate Nullifiers (needed for public inputs)
    // Circuit: derived_nullifier = hash(old_note_hash, owner_hash)
    let nullifier_1 = poseidon::bn254::hash_3([old_note_1_hash, owner_private_key.hi, owner_private_key.lo]);
    let nullifier_2 = poseidon::bn254::hash_3([old_note_2_hash, owner_private_key.hi, owner_private_key.lo]);


    // --- Define the Secrets (Shared Keys) ---
    // In a real app, this is the decryption key for the note. Here, just a number.
    let shared_key_1 = Scalar256bit {
        low: 12345,
        high: 0,
    };
    let shared_key_2 = Scalar256bit {
        low: 67890,
        high: 0,
    };


    let (
        ephemeral_public_point_for_receiver_1,
        encrypted_key_for_receiver_1,
    ) = encrypt(
        rand_receiver_1,
        receiver_1_public_point,
        shared_key_1,
    );

    let (
        ephemeral_public_point_for_receiver_2,
        encrypted_key_for_receiver_2,
    ) = encrypt(
        rand_receiver_2,
        receiver_2_public_point,
        shared_key_2,
    );

    let (
        ephemeral_public_point_1_for_funder,
        encrypted_key_1_for_funder,
    ) = encrypt(
        rand_1_funder,
        funder_public_point,
        shared_key_1,
    );

    let (
        ephemeral_public_point_2_for_funder,
        encrypted_key_2_for_funder,
    ) = encrypt(
        rand_2_funder,
        funder_public_point,
        shared_key_2,
    );

    std::println("Step 4: Encryption Prepared");



    // =======================
    // Call Main (The Moment of Truth)
    // =======================
    // - Merkle indices must match the paths created in Step 3 (0 and 1)

    main(
        // --- Public Inputs ---

        receiver_1_public_point,
        receiver_2_public_point,
        funder_public_point,

        pbm_token_id,
        merkle_root,
        merkle_root, // Both notes are in the same tree
        nullifier_1,
        nullifier_2,
        new_note_1_hash,
        new_note_2_hash,


        // Encrypted Keys (Outputs from test_encrypt)
        encrypted_key_for_receiver_1,
        encrypted_key_for_receiver_2,
        encrypted_key_1_for_funder,
        encrypted_key_2_for_funder,

        // Public Points (Receivers & Funder)
        ephemeral_public_point_for_receiver_1,
        ephemeral_public_point_for_receiver_2,
        ephemeral_public_point_1_for_funder,
        ephemeral_public_point_2_for_funder,


        // --- Private Inputs ---
        owner_private_key,

        old_note_1,
        old_note_2,
        merkle_path_1,
        merkle_path_2,
        0_u32, // Index of old_note_1
        1_u32, // Index of old_note_2
        false, // is_dummy_1
        false, // is_dummy_2
        new_note_1,
        new_note_2,

        shared_key_1,
        shared_key_2,
        rand_receiver_1,
        rand_receiver_2,
        rand_1_funder,
        rand_2_funder,
    );

    std::println("Step 5: PROOF VERIFIED SUCCESSFULLY!");



    // --- Print for Prover.toml ---
    std::println("\n--- COPY BELOW INTO Prover.toml ---");

    // Public Inputs
    print_helper_curve_point("receiver_1_public_point", receiver_1_public_point);
    print_helper_curve_point("receiver_2_public_point", receiver_2_public_point);
    print_helper_curve_point("funder_public_point", funder_public_point);
    print_helper("pbm_token_id", pbm_token_id);
    print_helper("merkle_root_1", merkle_root);
    print_helper("merkle_root_2", merkle_root);
    print_helper("nullifier_1", nullifier_1);
    print_helper("nullifier_2", nullifier_2);
    print_helper("new_note_1_hash", new_note_1_hash);
    print_helper("new_note_2_hash", new_note_2_hash);

    print_helper_low_and_high("encrypted_key_for_receiver_1", encrypted_key_for_receiver_1.low, encrypted_key_for_receiver_1.high);
    print_helper_low_and_high("encrypted_key_for_receiver_2", encrypted_key_for_receiver_2.low, encrypted_key_for_receiver_2.high);
    print_helper_low_and_high("encrypted_key_1_for_funder", encrypted_key_1_for_funder.low, encrypted_key_1_for_funder.high);
    print_helper_low_and_high("encrypted_key_2_for_funder", encrypted_key_2_for_funder.low, encrypted_key_2_for_funder.high);

    print_helper_curve_point("ephemeral_public_point_for_receiver_1", ephemeral_public_point_for_receiver_1);
    print_helper_curve_point("ephemeral_public_point_for_receiver_2", ephemeral_public_point_for_receiver_2);
    print_helper_curve_point("ephemeral_public_point_1_for_funder", ephemeral_public_point_1_for_funder);
    print_helper_curve_point("ephemeral_public_point_2_for_funder", ephemeral_public_point_2_for_funder);


    // Private Inputs
    print_helper_scalar("owner_private_key", owner_private_key);

    // --- Note ---
    print_helper_note("old_note_1", old_note_1);
    print_helper_note("old_note_2", old_note_2);

    // --- Arrays/Paths ---
    std::print("merkle_path_1 = [");
    for i in 0..MERKLE_DEPTH {
        std::print("\""); std::print(merkle_path_1[i]); std::print("\", ");
    }
    std::println("]");

    std::print("merkle_path_2 = [");
    for i in 0..MERKLE_DEPTH {
        std::print("\""); std::print(merkle_path_2[i]); std::print("\", ");
    }
    std::println("]");

    // --- Indices & Dummies ---
    std::println("merkle_index_1 = 0");
    std::println("merkle_index_2 = 1");
    std::println("is_dummy_1 = false");
    std::println("is_dummy_2 = false");

    // --- New Notes ---
    print_helper_note("new_note_1", new_note_1);
    print_helper_note("new_note_2", new_note_2);


    // --- Shared Keys ---
    print_helper_low_and_high("shared_key_1", shared_key_1.low, shared_key_1.high);
    print_helper_low_and_high("shared_key_2", shared_key_2.low, shared_key_2.high);

    // --- Randomness (EmbeddedCurveScalar) ---
    print_helper_scalar("encryption_randomness_for_receiver_1", rand_receiver_1);
    print_helper_scalar("encryption_randomness_for_receiver_2", rand_receiver_2);
    print_helper_scalar("encryption_randomness_1_for_funder", rand_1_funder);
    print_helper_scalar("encryption_randomness_2_for_funder", rand_2_funder);
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

#[test]
fn test_verify_encryption_success() {
    let recipient_priv_key = std::embedded_curve_ops::EmbeddedCurveScalar {
        lo: 0x11111,
        hi: 0x22222,
    };
    let recipient_pub_point = std::embedded_curve_ops::fixed_base_scalar_mul(recipient_priv_key);

    
    let payload = Scalar256bit {
        low: 100,
        high: 200,
    };

    let randomness = std::embedded_curve_ops::EmbeddedCurveScalar {
        lo: 0xabcdef,
        hi: 0x123456,
    };
    
    let ephemeral_pub_point = std::embedded_curve_ops::fixed_base_scalar_mul(randomness);

    let shared_point_sender = std::embedded_curve_ops::multi_scalar_mul([recipient_pub_point], [randomness]);
    
    let k_low = poseidon::bn254::hash_2([shared_point_sender.x, 1]);
    let k_high = poseidon::bn254::hash_2([shared_point_sender.x, 2]);

    let expected_ciphertext = Ciphertext {
        low: (payload.low as Field) + k_low,
        high: (payload.high as Field) + k_high,
    };

    verify_encryption(
        randomness,
        recipient_pub_point,
        ephemeral_pub_point,
        payload,
        expected_ciphertext
    );
}

#[test(should_fail)]
fn test_fail_wrong_randomness() {
    let recipient_priv_key = std::embedded_curve_ops::EmbeddedCurveScalar {
        lo: 0x11111,
        hi: 0x22222,
    };
    let recipient_pub = std::embedded_curve_ops::fixed_base_scalar_mul(recipient_priv_key);
    
    let randomness_a = std::embedded_curve_ops::EmbeddedCurveScalar {
        lo: 111,
        hi: 111,
    };
    let randomness_b = std::embedded_curve_ops::EmbeddedCurveScalar {
        lo: 222,
        hi: 222,
    };

    let ephemeral_real = std::embedded_curve_ops::fixed_base_scalar_mul(randomness_a);

    let payload = Scalar256bit { low: 1, high: 1 };
    let dummy_cipher = Ciphertext { low: 0, high: 0 };

    verify_encryption(
        randomness_b, 
        recipient_pub, 
        ephemeral_real, 
        payload, 
        dummy_cipher
    );
}

fn decrypt(
    encrypted_key: Ciphertext,
    shared_point: std::embedded_curve_ops::EmbeddedCurvePoint,
) -> Scalar256bit {
    let keystream_low = poseidon::bn254::hash_2([shared_point.x, 1]);
    let keystream_high = poseidon::bn254::hash_2([shared_point.x, 2]);

    let decrypted_low = (encrypted_key.low - keystream_low) as u128;
    let decrypted_high = (encrypted_key.high - keystream_high) as u128;

    Scalar256bit {
        low: decrypted_low,
        high: decrypted_high,
    }
}

#[test]
fn test_decrypt() {
    let recipient_priv_key = std::embedded_curve_ops::EmbeddedCurveScalar {
        lo: 0x11111,
        hi: 0x22222,
    };
    let recipient_pub_point = std::embedded_curve_ops::fixed_base_scalar_mul(recipient_priv_key);

    
    let original_payload = Scalar256bit {
        low: 123456789,
        high: 987654321,
    };

    let randomness = std::embedded_curve_ops::EmbeddedCurveScalar {
        lo: 0xabcdef,
        hi: 0x123456,
    };
    
    let ephemeral_pub_point = std::embedded_curve_ops::fixed_base_scalar_mul(randomness);

    let shared_point_sender = std::embedded_curve_ops::multi_scalar_mul([recipient_pub_point], [randomness]);
    
    let ciphertext = Ciphertext {
        low: encrypt_128bit_with_curve_point(original_payload.low, shared_point_sender, 1),
        high: encrypt_128bit_with_curve_point(original_payload.high, shared_point_sender, 2),
    };

    verify_encryption(
        randomness,
        recipient_pub_point,
        ephemeral_pub_point,
        original_payload,
        ciphertext,
    );

    
    let shared_point_recipient = std::embedded_curve_ops::multi_scalar_mul([ephemeral_pub_point], [recipient_priv_key]);

    let decrypted_payload = decrypt(ciphertext, shared_point_recipient);

    assert(decrypted_payload.low == original_payload.low);
    assert(decrypted_payload.high == original_payload.high);
}
