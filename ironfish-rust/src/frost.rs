use std::io::{Read, Write};

use ff::Field;
use group::GroupEncoding;
use ironfish_zkp::constants::SPENDING_KEY_GENERATOR;
use jubjub::ExtendedPoint;
use rand::{thread_rng, Rng};

use crate::errors::IronfishError;

/// https://github.com/ZcashFoundation/zips/pull/3/files
/// https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-11.html
/// Latest version can be found here: https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost/
///
/// https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-08.html#fig-frost
///         (group info)            (group info,     (group info,
///             |               signing key share)   signing key share)
///             |                         |                |
///             v                         v                v
///         Coordinator               Signer-1   ...   Signer-n
///     ------------------------------------------------------------
///     message
/// ------------>
///             |
///         == Round 1 (Commitment) ==
///             |    signer commitment   |                 |
///             |<-----------------------+                 |
///             |          ...                             |
///             |    signer commitment              (commit state) ==\
///             |<-----------------------------------------+         |
///                                                                  |
///         == Round 2 (Signature Share Generation) ==               |
///             |                                                    |
///             |     signer input       |                 |         |
///             +------------------------>                 |         |
///             |     signature share    |                 |         |
///             |<-----------------------+                 |         |
///             |          ...                             |         |
///             |     signer input                         |         |
///             +------------------------------------------>         /
///             |     signature share                      |<=======/
///             <------------------------------------------+
///             |
///         == Aggregation ==
///             |
///   signature |
/// <-----------+

/// Definitions
/// - Participant: an entity that is trusted to hold and use a signing key share
/// - MAX_SIGNERS: number of participants, and the number of shares that s is
///     split into. Must not exceed 2^16-1
/// - MIN_SIGNERS: threshold number of participants required to issue a
///     signature, where MIN_SIGNERS <= MAX_SIGNERS
/// - NUM_SIGNERS: number of signers that participate in an invocation of FROST
///     signing, where MIN_SIGNERS <= NUM_SIGNERSE <= MAX_SIGNERS
/// - identifier: an integer value associated with a participant, or signer, and
///     is a value in the range [1, MAX_SIGNERS]

/// Additional notation used in the protocol:
/// - encode_uint16(x): Convert two byte unsigned integer (uin16) x to a 2-byte
///     big-endian byte-string. Ex: encode_uint16(310) = [0x01, 0x36]
/// - random_bytes(n): Outputs n bytes, sampled uniformly using a CSPRNG
/// - len(l): Outputs the length of input list l, ex: len([1,2,3]) = 3
/// - reverse(l): Outputs the list l in reverse, ex: reverse([1,2,3]) = [3,2,1]
/// - range(a, b): Outputs a list of integers from a to b-1 in ascending order, ex: range(1,4) = [1,2,3]
/// pow(a, b): Output the integer result of a to the power of b, ex: pow(2,3) = 8
/// - ||: denotes concatenation, ex: x || y = xy
/// - nil: denotes an empty byte string

/// Prime-Order Group
/// - Scalar(x): conversion of integer input x to the corresponding Scalar value with the same numeric value
/// - Order(): outputs the order of G (i.e. p)
/// - Identity(): outputs the identity Element of the group (i.e. I)
/// - RandomScalar(): otuputs a random Scalar element in GF(p)
/// - ScalarMult(A, k): outputs scalar multiplication between Element A and the scalar k
/// - ScalarBaseMult(A): outputs scalar multiplication between Element A and the group generator B
/// - SerializeElement(A): Maps an Element A to a unique byte array buf of fixed length Ne
/// - DeserializeElement(buf): Attempts to map a byte array buf to an Element A. Can error, see doc for more.
/// - SerializeScalar(s): Maps a scalar s to a unique byte array buf of fixed length Ns
/// - DeserializeScalar(buf): Attempts to map a byte array buf to a Scalar s. can error, see doc.

/// Hashing
/// H1, H2, and H3 map arbitrary byte strings to Scalar elements of the prime-order group scalar field.
/// H4, H5 are aliases for H with distinct domain separators
/// Details vary by ciphersuite. See doc for more.
/// Guesstimating:
/// Hash function: blake2b
/// I BELIEVE contextString = "Zcash_RedJubjubH".
/// H1(m): H(contextString || "rho" || m) -> Scalar
/// H2(m): H(contextString || "chal" || m) -> Scalar
/// H3(m): H(contextString || "nonce" || m) -> Scalar
/// H4(m): H(contextString || "msg" || m) -> ?
/// H5(m): H(contextString || "com" || m) -> ?

/// Roles:
///     Signer participants: entities with signing key shares that participate in the threshold signing protocol
///     Coordinator: entity with the following responsibilities:
///         1. Determining which signers  will participate (at least MIN_SIGNERS in number)
///         2. Coordinating rounds (receiving and forwarding inputs among participants)
///         3. Aggregating signature shares output by each participant, and publishing the resulting signature
///         It is possible to utilize FROST without the Coordinator role, however since someone still has to
///             actually create the transaction, it is probably fine to keep.
/// Assumptions:
///     Because key generation is not specified, all signers are assumed to have the public group state
///         ("Group Info") and their corresponding signing key shares (sk_i)
/// Group Info:
///     PK: Group public key, an Element in G corresponding to the group secret key s which is a Scalar.
///         PK is an output from the group's key generation protocol, such as `trusted_dealer_keygen` or a DKG
///         PK = G.ScalarBaseMult(s)
///     PK_i: Public keys for each signer, which are similarly outputs from the group's key generation protocol,
///         Element values in G.
///         PK_i = G.ScalarMultBase(sk_i) for each participant i
/// sk_i:
///     Each participant i knows their signing key share sk_i which is the i-th secret share of s, a Scalar
/// Steps:
/// --- ??? Coodinator creates transaction or something
/// --- Initial Setup
/// --- Round 1
/// - Each signer generating nonces and corresponding public commitments
///     Nonce is a pair of scalar values: (hiding_nonce, binding_nonce)
///     Commitment is a pair of Element values: (hiding_nonce_commitment, binding_nonce_commitment)
/// - Nonces are stored locally by the signer and kept private for use in the second round.
/// - Commitments are sent to the Coordinator
/// --- Round 2
/// - Coordinator generates a random scalar `randomizer` using `randomizer_generate`
///     fn returns `randomizer_point = G.ScalarBaseMult(randomizer)`
/// - Coordinator sends to each signer along with message to be signed and the set of signing commitments
/// --- ??? Coordinator signs transaction, sends it off
///
/// ######
/// ######
/// ######
///
/// TODOS:
/// - Go over changelog for drafts 9-11, got most of the way through this using draft 8
///     Changelog probably references PRs here: https://github.com/cfrg/draft-irtf-cfrg-frost
/// - Finish implementing SSS, VSS for validation
///
/// ######
/// ######
/// ######

struct Hasher {
    state: blake2b_simd::State,
}

impl Hasher {
    /// Base hash function. Equivalent of hstar in redjubjub
    fn new() -> Self {
        let state = blake2b_simd::Params::new()
            .hash_length(64)
            .personal(b"Zcash_RedJubjubH")
            .to_state();

        Self { state }
    }

    /// H1(m): H(contextString || "rho" || m) -> Scalar
    fn h1() -> Self {
        Self::new().update(b"rho")
    }

    /// H2(m): H(contextString || "chal" || m) -> Scalar
    fn h2() -> Self {
        Self::new().update(b"chal")
    }

    /// H3(m): H(contextString || "nonce" || m) -> Scalar
    fn h3() -> Self {
        Self::new().update(b"nonce")
    }

    /// H4(m): H(contextString || "msg" || m) -> ?
    fn h4() -> Self {
        Self::new().update(b"msg")
    }

    /// H5(m): H(contextString || "com" || m) -> ?
    fn h5() -> Self {
        Self::new().update(b"com")
    }

    fn update(mut self, bytes: &[u8]) -> Self {
        self.state.update(bytes);

        self
    }

    fn to_scalar(self) -> jubjub::Fr {
        let hash = self.state.finalize();

        jubjub::Fr::from_bytes_wide(hash.as_array())
    }

    fn to_array(self) -> [u8; 64] {
        let hash = self.state.finalize();

        *hash.as_array()
    }
}

struct NoncePair {
    hiding_nonce: jubjub::Fr,
    binding_nonce: jubjub::Fr,
}

impl NoncePair {
    fn new(sk_i: &jubjub::Fr) -> Self {
        Self {
            hiding_nonce: generate_nonce(sk_i),
            binding_nonce: generate_nonce(sk_i),
        }
    }
}

struct CommitmentPair {
    hiding_nonce_commitment: ExtendedPoint,
    binding_nonce_commitment: ExtendedPoint,
}

impl CommitmentPair {
    fn new(nonce_pair: &NoncePair) -> Self {
        Self {
            hiding_nonce_commitment: base_point() * nonce_pair.hiding_nonce,
            binding_nonce_commitment: base_point() * nonce_pair.binding_nonce,
        }
    }
}

fn base_point() -> ExtendedPoint {
    ExtendedPoint::from(SPENDING_KEY_GENERATOR)
}

/// inputs:
/// - secret, a scalar
///
/// outputs:
/// - nonce, a scalar
///
/// nonce_generate(secret)
fn generate_nonce(secret: &jubjub::Fr) -> jubjub::Fr {
    // k_enc = random_bytes(32)
    let k_enc = {
        let mut buf = [0u8; 32];
        thread_rng().fill(&mut buf);

        buf
    };

    // secret_enc = G.SerializeScalar(secret)
    let secret_enc = secret.to_bytes();

    // return H3(k_enc || secret_enc)
    Hasher::h3().update(&k_enc).update(&secret_enc).to_scalar()
}

/// Inputs:
/// - x, input at which to evaluate the polynomial, a Scalar
/// - coeffs, the polynomial coefficients, a list of Scalars
///
/// Outputs: Scalar result of the polynomial evaluated at input x
///
/// def polynomial_evaluate(x, coeffs):
fn polynomial_evaluate(x: jubjub::Fr, coeffs: &[jubjub::Fr]) -> jubjub::Fr {
    //   value = 0
    let mut value = jubjub::Fr::zero();

    //   for coeff in reverse(coeffs):
    //     value *= x
    //     value += coeff
    for coeff in coeffs.iter().rev() {
        value *= x;
        value += coeff;
    }

    //   return value
    value
}

/// Inputs:
/// - x_i, an x-coordinate contained in L, a Scalar
/// - L, the set of x-coordinates, each a Scalar
///
/// Outputs: L_i, the i-th Lagrange coefficient
///
/// Errors:
/// - "invalid parameters", if any x-coordinate is equal to 0 or if x_i
///   is not in L
///
/// def derive_lagrange_coefficient(x_i, L):
fn derive_lagrange_coefficient(
    x_i: &jubjub::Fr,
    L: &[jubjub::Fr],
) -> Result<jubjub::Fr, IronfishError> {
    //   if x_i == 0:
    //     raise "invalid parameters"
    if *x_i == jubjub::Fr::zero() {
        return Err(IronfishError::InvalidData);
    }

    //   for x_j in L:
    //     if x_j == 0:
    //       raise "invalid parameters"
    for x_j in L {
        if *x_j == jubjub::Fr::zero() {
            return Err(IronfishError::InvalidData);
        }
    }

    //   if x_i not in L:
    //     raise "invalid parameters"
    if !L.contains(x_i) {
        return Err(IronfishError::InvalidData);
    }

    //   numerator = Scalar(1)
    //   denominator = Scalar(1)
    let mut numerator = jubjub::Fr::one();
    let mut denominator = jubjub::Fr::one();

    //   for x_j in L:
    //     if x_j == x_i: continue
    //     numerator *= x_j
    //     denominator *= x_j - x_i
    for x_j in L {
        if x_j == x_i {
            continue;
        }
        numerator *= x_j;
        denominator *= x_j - x_i;
    }

    //   L_i = numerator / denominator
    //   return L_i
    Ok(numerator * denominator.invert().unwrap())
}

/// Inputs:
/// - commitment_list = [(i, hiding_nonce_commitment_i, binding_nonce_commitment_i), ...],
///   a list of commitments issued by each signer, where each element in the list
///   indicates the signer identifier i and their two commitment Element values
///   (hiding_nonce_commitment_i, binding_nonce_commitment_i). This list MUST be sorted
///   in ascending order by signer identifier.
///
/// Outputs: A byte string containing the serialized representation of commitment_list
///
/// def encode_group_commitment_list(commitment_list):
fn encode_group_commitment_list(
    commitment_list: &Vec<(u16, NoncePair, CommitmentPair)>,
) -> Vec<u8> {
    //   encoded_group_commitment = nil
    let mut encoded_group_commitment = Vec::new();
    //   for (identifier, hiding_nonce_commitment, binding_nonce_commitment) in commitment_list:
    //     encoded_commitment = encode_uint16(identifier) ||
    //                          G.SerializeElement(hiding_nonce_commitment) ||
    //                          G.SerializeElement(binding_nonce_commitment)
    //     encoded_group_commitment = encoded_group_commitment || encoded_commitment
    for (identifier, _, commitments) in commitment_list {
        encoded_group_commitment.write(&identifier.to_be_bytes());
        encoded_group_commitment.write(&commitments.hiding_nonce_commitment.to_bytes());
        encoded_group_commitment.write(&commitments.binding_nonce_commitment.to_bytes());
    }

    //   return encoded_group_commitment
    encoded_group_commitment
}

/// Inputs:
/// - commitment_list = [(i, hiding_nonce_commitment_i, binding_nonce_commitment_i), ...],
///   a list of commitments issued by each signer, where each element in the list
///   indicates the signer identifier i and their two commitment Element values
///   (hiding_nonce_commitment_i, binding_nonce_commitment_i). This list MUST be sorted
///   in ascending order by signer identifier.
///
/// Outputs: A list of signer participant identifiers
///
/// def participants_from_commitment_list(commitment_list):
fn participants_from_commitment_list(
    commitment_list: &Vec<(u16, NoncePair, CommitmentPair)>,
) -> Vec<u16> {
    // identifiers = []
    let mut identifiers = Vec::new();

    // for (identifier, _, _) in commitment_list:
    //   identifiers.append(identifier)
    for (identifier, _, _) in commitment_list {
        identifiers.push(*identifier);
    }

    // return identifiers
    identifiers
}

/// Inputs:
/// - binding_factor_list = [(i, binding_factor), ...],
///   a list of binding factors for each signer, where each element in the list
///   indicates the signer identifier i and their binding factor. This list MUST be sorted
///   in ascending order by signer identifier.
/// - identifier, Identifier i of the signer.
///
/// Outputs: A Scalar value.
///
/// Errors: "invalid participant", when the designated participant is not known
///
/// def binding_factor_for_participant(binding_factor_list, identifier):
fn binding_factor_for_participant(
    binding_factor_list: &Vec<(u16, jubjub::Fr)>,
    identifier: u16,
) -> Result<jubjub::Fr, IronfishError> {
    // for (i, binding_factor) in commitment_list:
    //   if identifier == i:
    //     return binding_factor
    for (i, binding_factor) in binding_factor_list {
        if identifier == *i {
            return Ok(*binding_factor);
        }
    }

    // raise "invalid participant"
    Err(IronfishError::InvalidData)
}

/// Inputs:
/// - commitment_list = [(i, hiding_nonce_commitment_i, binding_nonce_commitment_i), ...],
///   a list of commitments issued by each signer, where each element in the list
///   indicates the signer identifier i and their two commitment Element values
///   (hiding_nonce_commitment_i, binding_nonce_commitment_i). This list MUST be sorted
///   in ascending order by signer identifier.
/// - msg, the message to be signed.
///
/// Outputs: A list of (identifier, Scalar) tuples representing the binding factors.
///
/// def compute_binding_factors(commitment_list, msg):
fn compute_binding_factors(
    commitment_list: &Vec<(u16, NoncePair, CommitmentPair)>,
    msg: &[u8],
) -> Vec<(u16, jubjub::Fr)> {
    //   msg_hash = H4(msg)
    let msg_hash = Hasher::h4().update(msg).to_array();

    //   encoded_commitment_hash = H5(encode_group_commitment_list(commitment_list))
    let encoded_commitment_hash = Hasher::h5()
        .update(&encode_group_commitment_list(commitment_list))
        .to_array();

    //   rho_input_prefix = msg_hash || encoded_commitment_hash
    let mut rho_input_prefix = Vec::new();
    rho_input_prefix.write(&msg_hash);
    rho_input_prefix.write(&encoded_commitment_hash);

    //   binding_factor_list = []
    let mut binding_factor_list = Vec::new();
    //   for (identifier, hiding_nonce_commitment, binding_nonce_commitment) in commitment_list:
    //     rho_input = rho_input_prefix || encode_uint16(identifier)
    //     binding_factor = H1(rho_input)
    //     binding_factor_list.append((identifier, binding_factor))
    for (identifier, _, _) in commitment_list {
        let binding_factor = Hasher::h1()
            .update(&rho_input_prefix)
            .update(&identifier.to_be_bytes())
            .to_scalar();
        binding_factor_list.push((*identifier, binding_factor))
    }

    //   return binding_factor_list
    binding_factor_list
}

/// Inputs:
/// - commitment_list =
///    [(i, hiding_nonce_commitment_i, binding_nonce_commitment_i), ...], a list
///   of commitments issued by each signer, where each element in the list
///   indicates the signer identifier i and their two commitment Element values
///   (hiding_nonce_commitment_i, binding_nonce_commitment_i). This list MUST be
///   sorted in ascending order by signer identifier.
/// - binding_factor_list = [(i, binding_factor), ...],
///   a list of (identifier, Scalar) tuples representing the binding factor Scalar
///   for the given identifier. This list MUST be sorted in ascending order by identifier.
///
/// Outputs: An Element in G representing the group commitment
///
/// def compute_group_commitment(commitment_list, binding_factor_list):
fn compute_group_commitment(
    commitment_list: &Vec<(u16, NoncePair, CommitmentPair)>,
    binding_factor_list: &Vec<(u16, jubjub::Fr)>,
) -> ExtendedPoint {
    //   group_commitment = G.Identity()
    let mut group_commitment = ExtendedPoint::identity();

    //   for (identifier, hiding_nonce_commitment, binding_nonce_commitment) in commitment_list:
    //     binding_factor = binding_factor_for_participant(binding_factors, identifier)
    //     group_commitment = group_commitment +
    //       hiding_nonce_commitment + G.ScalarMult(binding_nonce_commitment, binding_factor)
    for (identifier, _, commitments) in commitment_list {
        let binding_factor =
            binding_factor_for_participant(binding_factor_list, *identifier).unwrap();
        group_commitment = group_commitment
            + commitments.hiding_nonce_commitment
            + (commitments.binding_nonce_commitment * binding_factor);
    }

    //   return group_commitment
    group_commitment
}

/// Inputs:
/// - group_commitment, an Element in G representing the group commitment
/// - group_public_key, public key corresponding to the group signing key, an
///   Element in G.
/// - msg, the message to be signed.
///
/// Outputs: A Scalar representing the challenge
///
/// def compute_challenge(group_commitment, group_public_key, msg):
fn compute_challenge(
    group_commitment: &ExtendedPoint,
    group_public_key: &ExtendedPoint,
    msg: &[u8],
) -> jubjub::Fr {
    //   group_comm_enc = G.SerializeElement(group_commitment)
    let group_comm_enc = group_commitment.to_bytes();

    //   group_public_key_enc = G.SerializeElement(group_public_key)
    let group_public_key_enc = group_public_key.to_bytes();

    //   challenge_input = group_comm_enc || group_public_key_enc || msg
    //   challenge = H2(challenge_input)
    //   return challenge
    Hasher::h2()
        .update(&group_comm_enc)
        .update(&group_public_key_enc)
        .update(msg)
        .to_scalar()
}

/// inputs:
/// - sk_i, the secret key share, a scalar
///
/// outputs:
/// - (nonce, comm) a tuple of nonce and nonce commitment pairs, where each
///     value in the nonce pair is a scalar and each value in the nonce commitment
///     pair is an Element
///
/// commit(sk_i)
fn commit(sk_i: &jubjub::Fr) -> (NoncePair, CommitmentPair) {
    // hiding_nonce = nonce_generate(sk_i)
    // binding_nonce = nonce_generate(sk_i)
    // nonce = (hiding_nonce, binding_nonce)
    let nonce_pair = NoncePair::new(sk_i);

    // hiding_nonce_commitment = G.ScalarBaseMult(hiding_nonce)
    // binding_nonce_commitment = G.ScalarBaseMult(binding_nonce)
    // comm = (hiding_nonce_commitment, binding_nonce_commitment)
    let commitment_pair = CommitmentPair::new(&nonce_pair);

    // return (nonce, comm)
    (nonce_pair, commitment_pair)
}

/// Inputs:
/// - identifier, Identifier i of the signer. Note identifier will never equal 0.
/// - sk_i, Signer secret key share, a Scalar.
/// - group_public_key, public key corresponding to the group signing key,
///   an Element in G.
/// - nonce_i, pair of Scalar values (hiding_nonce, binding_nonce) generated in
///   round one.
/// - msg, the message to be signed (sent by the Coordinator).
/// - commitment_list =
///     [(j, hiding_nonce_commitment_j, binding_nonce_commitment_j), ...], a
///   list of commitments issued in Round 1 by each signer and sent by the Coordinator.
///   Each element in the list indicates the signer identifier j and their two commitment
///   Element values (hiding_nonce_commitment_j, binding_nonce_commitment_j).
///   This list MUST be sorted in ascending order by signer identifier.
/// - randomizer_point, an Element in G, sent by the Coordinator
///
/// Outputs: a Scalar value representing the signature share
///
/// def sign(identifier, sk_i, group_public_key, nonce_i, msg, commitment_list):
fn sign(
    identifier: u16,
    sk_i: jubjub::Fr,
    group_public_key: ExtendedPoint,
    nonce_i: &NoncePair,
    msg: &[u8],
    commitment_list: &Vec<(u16, NoncePair, CommitmentPair)>,
    randomizer_point: &ExtendedPoint,
) -> jubjub::Fr {
    //   # Compute the randomized group public key
    //   randomized_group_public_key = group_public_key + randomizer_point
    let randomized_group_public_key = group_public_key + randomizer_point;

    //   # Compute the binding factor(s)
    //   binding_factor_list = compute_binding_factors(commitment_list, msg)
    //   binding_factor = binding_factor_for_participant(binding_factor_list, identifier)
    let binding_factor_list = compute_binding_factors(commitment_list, msg);
    let binding_factor = binding_factor_for_participant(&binding_factor_list, identifier).unwrap();

    //   # Compute the group commitment
    //   group_commitment = compute_group_commitment(commitment_list, binding_factor_list)
    let group_commitment = compute_group_commitment(commitment_list, &binding_factor_list);

    //   # Compute Lagrange coefficient
    //   participant_list = participants_from_commitment_list(commitment_list)
    //   lambda_i = derive_lagrange_coefficient(Scalar(identifier), participant_list)
    let participant_list = participants_from_commitment_list(commitment_list);
    // TODO: This may not be necessary, derive_lagrange_coefficient fn is broken per spec
    let participant_scalars: Vec<jubjub::Fr> = participant_list
        .iter()
        .map(|i| jubjub::Fr::from(*i as u64))
        .collect();
    let lambda_i =
        derive_lagrange_coefficient(&jubjub::Fr::from(identifier as u64), &participant_scalars)
            .unwrap();

    //   # Compute the per-message challenge
    //   challenge = compute_challenge(group_commitment, randomized_group_public_key, msg)
    let challenge = compute_challenge(&group_commitment, &randomized_group_public_key, msg);

    //   # Compute the signature share
    //   (hiding_nonce, binding_nonce) = nonce_i
    //   sig_share = hiding_nonce + (binding_nonce * binding_factor) + (lambda_i * sk_i * challenge)
    //   return sig_share
    nonce_i.hiding_nonce + (nonce_i.binding_nonce * binding_factor) + (lambda_i * sk_i * challenge)
}

/// Inputs:
/// - identifier, Identifier i of the signer. Note: identifier MUST never equal 0.
/// - PK_i, the public key for the ith signer, where PK_i = G.ScalarBaseMult(sk_i),
///   an Element in G
/// - comm_i, pair of Element values in G (hiding_nonce_commitment, binding_nonce_commitment)
///   generated in round one from the ith signer.
/// - sig_share_i, a Scalar value indicating the signature share as produced in
///   round two from the ith signer.
/// - commitment_list =
///     [(j, hiding_nonce_commitment_j, binding_nonce_commitment_j), ...], a
///   list of commitments issued in Round 1 by each signer, where each element
///   in the list indicates the signer identifier j and their two commitment
///   Element values (hiding_nonce_commitment_j, binding_nonce_commitment_j).
///   This list MUST be sorted in ascending order by signer identifier.
/// - group_public_key, public key corresponding to the group signing key,
///   an Element in G.
/// - msg, the message to be signed.
/// - randomizer_point, an Element in G
///
/// Outputs: True if the signature share is valid, and False otherwise.
///
/// def verify_signature_share(identifier, PK_i, comm_i, sig_share_i, commitment_list,
//                            group_public_key, msg):
fn verify_signature_share(
    identifier: u16,
    pk_i: &ExtendedPoint,
    comm_i: &CommitmentPair,
    sig_share_i: &jubjub::Fr,
    commitment_list: &Vec<(u16, NoncePair, CommitmentPair)>,
    group_public_key: &ExtendedPoint,
    msg: &[u8],
    randomizer_point: &ExtendedPoint,
) -> bool {
    //   # Compute the randomized group public key
    //   randomized_group_public_key = group_public_key + randomizer_point;
    let randomized_group_public_key = group_public_key + randomizer_point;

    //   # Compute the binding factors
    //   binding_factor_list = compute_binding_factors(commitment_list, msg)
    //   binding_factor = binding_factor_for_participant(binding_factor_list, identifier)
    let binding_factor_list = compute_binding_factors(commitment_list, msg);
    let binding_factor = binding_factor_for_participant(&binding_factor_list, identifier).unwrap();

    //   # Compute the group commitment
    //   group_commitment = compute_group_commitment(commitment_list, binding_factor_list)
    let group_commitment = compute_group_commitment(commitment_list, &binding_factor_list);

    //   # Compute the commitment share
    //   (hiding_nonce_commitment, binding_nonce_commitment) = comm_i
    //   comm_share = hiding_nonce_commitment + G.ScalarMult(binding_nonce_commitment, binding_factor)
    let comm_share =
        comm_i.hiding_nonce_commitment + (comm_i.binding_nonce_commitment * binding_factor);

    //   # Compute the challenge
    //   challenge = compute_challenge(group_commitment, randomized_group_public_key, msg)
    let challenge = compute_challenge(&group_commitment, &randomized_group_public_key, msg);

    //   # Compute Lagrange coefficient
    //   participant_list = participants_from_commitment_list(commitment_list)
    //   lambda_i = derive_lagrange_coefficient(Scalar(identifier), participant_list)
    let participant_list = participants_from_commitment_list(commitment_list);
    // TODO: This may not be necessary, derive_lagrange_coefficient fn is broken per spec
    let participant_scalars: Vec<jubjub::Fr> = participant_list
        .iter()
        .map(|i| jubjub::Fr::from(*i as u64))
        .collect();
    let lambda_i =
        derive_lagrange_coefficient(&jubjub::Fr::from(identifier as u64), &participant_scalars)
            .unwrap();

    //   # Compute relation values
    //   l = G.ScalarBaseMult(sig_share_i)
    //   r = comm_share + G.ScalarMult(PK_i, challenge * lambda_i)
    let l = base_point() * sig_share_i;
    let r = comm_share + (pk_i * (challenge * lambda_i));

    //   return l == r
    l == r
}

/// Inputs:
/// - group_commitment, the group commitment returned by compute_group_commitment,
///   an Element in G.
/// - sig_shares, a set of signature shares z_i, Scalar values, for each signer,
///   of length NUM_SIGNERS, where MIN_SIGNERS <= NUM_SIGNERS <= MAX_SIGNERS.
/// - group_public_key, public key corresponding to the group signing key, an Element in G.
/// - challenge, the challenge returned by the compute challenge, a Scalar.
/// - randomizer, the randomizer Scalar.
///
/// Outputs:
/// - (R, z), a Schnorr signature consisting of an Element R and Scalar z.
/// - randomized_group_public_key, the randomized_group_public_key
///
/// def aggregate(group_commitment, sig_shares):
fn aggregate(
    group_commitment: &ExtendedPoint,
    sig_shares: &[jubjub::Fr],
    group_public_key: &ExtendedPoint,
    challenge: &jubjub::Fr,
    randomizer: &jubjub::Fr,
) -> (ExtendedPoint, jubjub::Fr) {
    // TODO: is G base_point?
    //   randomized_group_public_key = group_public_key + G * randomizer;
    //   z = 0
    let mut z = jubjub::Fr::zero();
    //   for z_i in sig_shares:
    //     z = z + z_i
    for z_i in sig_shares {
        z += z_i;
    }

    //   return (group_commitment, z)
    // TODO: this function just shouldnt take the group_commitment
    (group_commitment.clone(), (z + randomizer * challenge))
}

/// inputs:
/// - s, a group secret, Scalar, that MUST be derived from at least Ns bytes of entropy
/// - MAX_SIGNERS, the number of shares to generate, an integer
/// - MIN_SIGNERS, the threshold of the secret sharing scheme, an integer
///
/// outputs:
/// - signer_private_keys, MAX_SIGNERS shares of the secret key s, each a tuple
///     consisting of the participant identifier and the key share (a Scalar).
/// - vss_commitment, a vector commitment of Elements in G, to each of the
///     coefficients in the polynomial defined by secret_key_shares and whose first
///     element is G.ScalarBaseMult(s).
///
/// trusted_dealer_keygen(s, MAX_SIGNERS, MIN_SIGNERS)
fn trusted_dealer_keygen(
    secret: jubjub::Fr,
    max_signers: u16,
    min_signers: u16,
) -> (Vec<(u16, jubjub::Fr)>, Vec<ExtendedPoint>) {
    // signer_private_keys, coefficients = secret_share_shard(secret_key, MAX_SIGNERS, MIN_SIGNERS)
    let (signer_private_keys, coefficients) =
        secret_share_shard(secret, max_signers, min_signers).unwrap();

    // vss_commitment = vss_commit(coefficients):
    let vss_commitment = vss_commit(&coefficients);

    // return signer_private_keys, vss_commitment
    (signer_private_keys, vss_commitment)
}

/// Inputs:
/// - s, secret value to be shared, a Scalar
/// - MAX_SIGNERS, the number of shares to generate, an integer
/// - MIN_SIGNERS, the threshold of the secret sharing scheme, an integer
///
/// Outputs:
/// - secret_key_shares, A list of MAX_SIGNERS number of secret shares, each a tuple
///   consisting of the participant identifier and the key share (a Scalar)
/// - coefficients, a vector of the t coefficients which uniquely determine
///   a polynomial f.
///
/// Errors:
/// - "invalid parameters", if MIN_SIGNERS > MAX_SIGNERS or if MIN_SIGNERS is less than 2
///
/// def secret_share_shard(s, MAX_SIGNERS, MIN_SIGNERS):
fn secret_share_shard(
    secret: jubjub::Fr,
    max_signers: u16,
    min_signers: u16,
) -> Result<(Vec<(u16, jubjub::Fr)>, Vec<jubjub::Fr>), IronfishError> {
    //   if MIN_SIGNERS > MAX_SIGNERS:
    //     raise "invalid parameters"
    if min_signers > max_signers {
        return Err(IronfishError::IllegalValue);
    }

    //   if MIN_SIGNERS < 2:
    //     raise "invalid parameters"
    if min_signers < 2 {
        return Err(IronfishError::IllegalValue);
    }

    //   # Generate random coefficients for the polynomial, yielding
    //   # a polynomial of degree (MIN_SIGNERS - 1)
    //   coefficients = [s]
    //   for i in range(1, MIN_SIGNERS):
    //     coefficients.append(G.RandomScalar())
    let mut coefficients: Vec<jubjub::Fr> = vec![secret];
    for _ in 0..(min_signers - 1) {
        coefficients.push(jubjub::Fr::random(&mut thread_rng()));
    }

    //   # Evaluate the polynomial for each point x=1,...,n
    //   secret_key_shares = []
    //   for x_i in range(1, MAX_SIGNERS + 1):
    //     y_i = polynomial_evaluate(Scalar(x_i), coefficients)
    //     secret_key_share_i = (x_i, y_i)
    //     secret_key_share.append(secret_key_share_i)
    let mut secret_key_shares = vec![];
    for x_i in 1..=max_signers {
        let y_i = polynomial_evaluate(jubjub::Fr::from(x_i as u64), &coefficients);
        secret_key_shares.push((x_i, y_i));
    }

    //   return secret_key_shares, coefficients
    Ok((secret_key_shares, coefficients))
}

/// Inputs:
/// - coeffs, a vector of the MIN_SIGNERS coefficients which uniquely determine
/// a polynomial f.
///
/// Outputs: a commitment vss_commitment, which is a vector commitment to each of the
/// coefficients in coeffs, where each element of the vector commitment is an `Element` in `G`.
///
/// def vss_commit(coeffs):
fn vss_commit(coeffs: &[jubjub::Fr]) -> Vec<ExtendedPoint> {
    //   vss_commitment = []
    let mut vss_commitment = vec![];
    //   for coeff in coeffs:
    //     A_i = G.ScalarBaseMult(coeff)
    //     vss_commitment.append(A_i)
    for coeff in coeffs {
        vss_commitment.push(base_point() * coeff);
    }

    //   return vss_commitment
    vss_commitment
}

/// Inputs:
/// - None
///
/// Outputs:
/// - randomizer, a Scalar
/// def randomizer_generate():
fn generate_randomizer() -> jubjub::Fr {
    let mut buf = [0; 64];
    thread_rng().fill(&mut buf);

    Hasher::h3().update(&buf).to_scalar()
}

#[cfg(test)]
mod test {
    use std::io::Write;

    use ff::Field;
    use group::GroupEncoding;
    use ironfish_zkp::{
        constants::SPENDING_KEY_GENERATOR,
        redjubjub::{PublicKey, Signature},
    };
    use jubjub::ExtendedPoint;
    use rand::thread_rng;

    use crate::{
        errors::IronfishError,
        frost::{
            aggregate, commit, compute_binding_factors, compute_challenge,
            compute_group_commitment, generate_randomizer, sign, verify_signature_share,
            CommitmentPair, NoncePair,
        },
    };

    use super::{base_point, trusted_dealer_keygen};

    #[test]
    fn test_frost() {
        const MAX_SIGNERS: u16 = 5;
        const THRESHOLD: u16 = 3;

        let msg = b"This is the message we are signing.";

        // TODO: Index accesors are all wrong here.

        // Initial key generation and sharing of public information
        // TODO: Figure out how the spec creates secret
        let secret = jubjub::Fr::random(&mut thread_rng());
        // PK = G.ScalarBaseMult(secret_key)
        let pk = base_point() * secret;

        let (signer_private_keys, vss_commitment) =
            trusted_dealer_keygen(secret, MAX_SIGNERS, THRESHOLD);

        let mut signer_public_keys: Vec<(u16, ExtendedPoint)> =
            Vec::with_capacity(signer_private_keys.len());
        for (i, sk_i) in &signer_private_keys {
            signer_public_keys.push((*i, base_point() * sk_i));
        }

        // Round 1 - commitment
        // TODO: we should test picking specific signers
        let mut signer_commitments: Vec<(u16, NoncePair, CommitmentPair)> =
            Vec::with_capacity(THRESHOLD as usize);
        for i in 1..=THRESHOLD {
            let sk_i = signer_private_keys
                .iter()
                .find(|(ii, _)| i == *ii)
                .unwrap()
                .1;
            let commit = commit(&sk_i);
            signer_commitments.push((i, commit.0, commit.1));
        }

        // Round 2 - signature share generation

        let randomizer = generate_randomizer();
        let randomizer_point = base_point() * randomizer;
        let randomized_group_public_key = pk + randomizer_point;

        let mut sig_shares: Vec<jubjub::Fr> = Vec::new();
        for i in 1..=THRESHOLD {
            let sk_i = signer_private_keys
                .iter()
                .find(|(ii, _)| i == *ii)
                .unwrap()
                .1;
            let nonce_i = &signer_commitments
                .iter()
                .find(|(ii, _, _)| i == *ii)
                .unwrap()
                .1;

            let sig_share = sign(
                i,
                sk_i,
                pk,
                nonce_i,
                msg,
                &signer_commitments,
                &randomizer_point,
            );
            sig_shares.push(sig_share);
        }

        // Signature share verification and aggregation

        for i in 1..=THRESHOLD {
            let pk_i = &signer_public_keys
                .iter()
                .find(|(ii, _)| i == *ii)
                .unwrap()
                .1;
            let comm_i = &signer_commitments
                .iter()
                .find(|(ii, _, _)| i == *ii)
                .unwrap()
                .2;
            let sig_share_i = &sig_shares[(i - 1) as usize];

            let is_valid = verify_signature_share(
                i,
                pk_i,
                comm_i,
                sig_share_i,
                &signer_commitments,
                &pk,
                msg,
                &randomizer_point,
            );

            if !is_valid {
                panic!("Participant {i} share was invalid.");
            }
        }

        let binding_factor_list = &compute_binding_factors(&signer_commitments, msg);
        let group_commitment = &compute_group_commitment(&signer_commitments, binding_factor_list);
        let challenge = compute_challenge(group_commitment, &randomized_group_public_key, msg);
        let signature_contents =
            aggregate(group_commitment, &sig_shares, &pk, &challenge, &randomizer);

        let mut signature_bytes = [0u8; 64];
        signature_bytes[..32].copy_from_slice(&signature_contents.0.to_bytes());
        signature_bytes[32..].copy_from_slice(&signature_contents.1.to_bytes());

        let signature = Signature::read(&mut signature_bytes.as_ref()).unwrap();

        let pub_key = PublicKey(randomized_group_public_key);
        pub_key.verify(b"foobar", &signature, SPENDING_KEY_GENERATOR);

        // Docs say the format should be:
        // Still need to figure out what Ne and Ns should be
        // Guessing:
        // Ne should be the length of ExtendedPoint::to_bytes() which is 32
        // Ns should be the length of jubjub::Fr::to_bytes() which is 32
        // This matches what's needed for Signature
        // struct {
        //     opaque R_encoded[Ne];
        //     opaque z_encoded[Ns];
        //   } Signature;
    }
}
