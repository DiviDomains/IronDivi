// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The C1 joint key `J` (`docs/plans/swap-poc/xmr-c1-design.md` §4.1, §5, §9): a 2-of-2 ECDSA
//! key neither party holds, signed exactly once, on `Tx_cancel`'s sighash.
//!
//! Lindell 2017 ("Fast Secure Two-Party ECDSA Signing", malicious-secure with abort), built
//! here on the audited primitives `cggmp21` re-exports: `fast-paillier` for Paillier,
//! `paillier-zk` for the proofs about it, `generic-ec` for secp256k1. The maker is P1 (holds
//! the Paillier key and `x1`), the taker is P2 (`x2`). `J = x1·x2·G`.
//!
//! Where the 2017 paper's PDL proof would go (P1 proving the ciphertext `c_key` encrypts the
//! discrete log of `Q1`), we use CGGMP'21's Πlog\* against a ring-Pedersen modulus the
//! *taker* generated and proved well-formed (Πprm), plus Πmod and Πfac on the maker's Paillier
//! modulus `N0`. So neither side checks a proof against parameters its peer chose alone —
//! the gap §9 G2 found in ZenGo's implementation.
//!
//! Messages:
//!
//! ```text
//! T1 taker  Ñ, s, t, Πprm(s ∈ ⟨t⟩)                       (taker drops p̃, q̃, λ)
//! M1 maker  com(Q1, pok(x1))
//! T2 taker  Q2, pok(x2)
//! M2 maker  open(Q1, pok(x1)); N0, c_key = Enc(x1), Πmod(N0), Πfac(N0), Πlog*(c_key ↔ Q1)
//!           — both sides now hold J (KeyReady)
//! M3 maker  com(R1, pok(k1))                             (maker's sign)
//! T3 taker  R2, pok(k2)                                  (taker's sign, once M3 is in)
//! M4 maker  open(R1, pok(k1))
//! T4 taker  c3 = Enc(ρq + k2⁻¹m) ⊕ (k2⁻¹·r·x2) ⊙ c_key
//! M5 maker  σ = (r, k1⁻¹·Dec(c3)), low-S, checked under J — both sides Signed
//! ```
//!
//! A session signs once: every transition moves the secrets out of the old state, the one
//! signature ends it, and there is no API for a second. Nothing is serialized or persisted;
//! a restart before `σ_J` aborts the swap, which costs nothing (`Tx_lock` is broadcast only
//! after `σ_J` exists). Every Fiat–Shamir challenge and commitment is bound to the session
//! id and its own tag.
//!
//! Transport is sans-IO: [`JSession::round`] takes the peer's messages and returns ours. The
//! taker drives (`POST /xmr/swaps/:id/j`); the maker answers each round. A message out of
//! order, for the wrong phase, or failing any check aborts the session.

use cggmp21::generic_ec::coords::HasAffineX;
use cggmp21::generic_ec::{Point, Scalar};
use cggmp21::paillier_zk::fast_paillier::{utils::external_rand, DecryptionKey, EncryptionKey};
use cggmp21::paillier_zk::rug::{integer::Order, Integer};
use cggmp21::paillier_zk::{
    group_element_vs_paillier_encryption_in_range as pi_log, no_small_factor as pi_fac,
    paillier_blum_modulus as pi_mod,
};
use cggmp21::security_level::{SecurityLevel, SecurityLevel128, M as MOD_ROUNDS};
use cggmp21::supported_curves::Secp256k1;
use cggmp21::PregeneratedPrimes;
use divi_swap::{Result, SwapError};
use parking_lot::Mutex;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

macro_rules! anyhow { ($($t:tt)*) => { SwapError::Other(format!($($t)*)) } }
macro_rules! bail { ($($t:tt)*) => { return Err(anyhow!($($t)*)) } }

/// The taker's party index.
pub const TAKER: u16 = 0;
/// The maker's party index.
pub const MAKER: u16 = 1;

/// The wire scheme both sides must speak (`SetupRequest::j_scheme`).
pub const SCHEME: &str = "lindell17-v1";

/// Paillier / ring-Pedersen safe primes for one session (seconds to minutes to generate;
/// pool them). The maker's become `N0`, the taker's `Ñ`.
pub type Primes = PregeneratedPrimes<SecurityLevel128>;

/// Generate one session's primes (CPU-bound, 20–90 s on an old Xeon).
pub fn generate_primes() -> Primes {
    Primes::generate(&mut OsRng)
}

type E = Secp256k1;
type Sc = Scalar<E>;
type Pt = Point<E>;

/// Smallest modulus either side accepts: `8·SECURITY_BITS − 1` bits, as cggmp21 does.
const MIN_MODULUS_BITS: u32 = 8 * 384 - 1;
/// Largest, so a peer cannot make us exponentiate huge numbers.
const MAX_MODULUS_BITS: u32 = 4096;
/// Πprm rounds (soundness 2⁻¹²⁸).
const PRM_ROUNDS: usize = 128;
/// Bits of the statistical mask ρ in T4 (§9 G2: ℓ + ε + 256 + 80).
const RHO_BITS: u32 = 256 + 230 + 256 + 80;

/// Which part of the protocol a message belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// The taker's ring-Pedersen parameters and their proof.
    Aux,
    /// Key generation of `J`, with the maker's Paillier key and its proofs.
    Keygen,
    /// The one signing, on `Tx_cancel`'s sighash.
    Sign,
}

/// One protocol message on the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JMsg {
    /// Its part of the protocol.
    pub phase: Phase,
    /// Always `false` (two parties); kept for wire compatibility.
    pub broadcast: bool,
    /// The message, serde JSON.
    pub body: serde_json::Value,
}

/// Where a session is after a round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JStatus {
    /// Still exchanging messages.
    Running,
    /// `J` exists (compressed); waiting for [`JSession::sign`].
    KeyReady([u8; 33]),
    /// The one signature: DER + SIGHASH_ALL, low-S. The session is over.
    Signed(Vec<u8>),
}

/// Our messages for the peer, and our status.
#[derive(Debug, Clone)]
pub struct JRound {
    /// Send these to the peer.
    pub outgoing: Vec<JMsg>,
    /// Where we are.
    pub status: JStatus,
}

/// Schnorr proof of knowledge of a discrete log, on the wire.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pok {
    a: String,
    z: String,
}

// M2 is large and short-lived (one per session): boxing it buys nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize)]
#[serde(tag = "m", rename_all = "snake_case", deny_unknown_fields)]
enum Body {
    T1 {
        n: String,
        s: String,
        t: String,
        prm_a: Vec<String>,
        prm_z: Vec<String>,
    },
    M1 {
        com: String,
    },
    T2 {
        q2: String,
        pok: Pok,
    },
    M2 {
        q1: String,
        pok: Pok,
        nonce: String,
        n0: String,
        c_key: String,
        mod_comm: pi_mod::Commitment,
        mod_proof: pi_mod::Proof<MOD_ROUNDS>,
        fac: pi_fac::non_interactive::Proof,
        log_comm: pi_log::Commitment<E>,
        log_proof: pi_log::Proof,
    },
    M3 {
        com: String,
    },
    T3 {
        r2: String,
        pok: Pok,
    },
    M4 {
        r1: String,
        pok: Pok,
        nonce: String,
    },
    T4 {
        c3: String,
    },
    M5 {
        sig: String,
    },
}

impl Body {
    fn phase(&self) -> Phase {
        match self {
            Body::T1 { .. } => Phase::Aux,
            Body::M1 { .. } | Body::T2 { .. } | Body::M2 { .. } => Phase::Keygen,
            _ => Phase::Sign,
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Body::T1 { .. } => "T1",
            Body::M1 { .. } => "M1",
            Body::T2 { .. } => "T2",
            Body::M2 { .. } => "M2",
            Body::M3 { .. } => "M3",
            Body::T3 { .. } => "T3",
            Body::M4 { .. } => "M4",
            Body::T4 { .. } => "T4",
            Body::M5 { .. } => "M5",
        }
    }
}

/// The taker's ring-Pedersen parameters (public).
type Aux = pi_fac::non_interactive::Aux;

/// What the taker keeps once `J` exists.
struct TakerKey {
    x2: Sc,
    j: Pt,
    ek: EncryptionKey,
    c_key: Integer,
    com3: Option<[u8; 32]>,
    m: Option<[u8; 32]>,
}

enum State {
    TakerStart {
        p: Integer,
        q: Integer,
    },
    TakerAwaitM1 {
        aux: Aux,
    },
    TakerAwaitM2 {
        aux: Aux,
        com1: [u8; 32],
        x2: Sc,
    },
    TakerKey(TakerKey),
    TakerAwaitM4 {
        key: TakerKey,
        k2: Sc,
        com3: [u8; 32],
        m: [u8; 32],
    },
    TakerAwaitM5 {
        j: Pt,
        m: [u8; 32],
    },
    MakerStart {
        p: Integer,
        q: Integer,
    },
    MakerAwaitT2 {
        p: Integer,
        q: Integer,
        aux: Aux,
        x1: Sc,
        q1: Pt,
        pok1: Pok,
        nonce1: [u8; 32],
    },
    MakerKey {
        dk: DecryptionKey,
        j: Pt,
    },
    MakerAwaitT3 {
        dk: DecryptionKey,
        j: Pt,
        m: [u8; 32],
        k1: Sc,
        r1: Pt,
        pok: Pok,
        nonce3: [u8; 32],
    },
    MakerAwaitT4 {
        dk: DecryptionKey,
        j: Pt,
        m: [u8; 32],
        k1: Sc,
        r: Sc,
    },
    Done,
}

/// One side of one swap's `J`: see the module docs.
pub struct JSession {
    sid: Vec<u8>,
    st: Mutex<State>,
}

impl JSession {
    /// Start our side (`me` = [`TAKER`] or [`MAKER`]) of session `sid` (unique per swap; both
    /// sides use the same) with `primes` for our modulus.
    pub fn start(sid: &[u8], me: u16, primes: Primes) -> Self {
        let (p, q) = primes.split();
        let st = if me == MAKER {
            State::MakerStart { p, q }
        } else {
            State::TakerStart { p, q }
        };
        JSession {
            sid: sid.to_vec(),
            st: Mutex::new(st),
        }
    }

    /// Feed the peer's messages (none to open, for the taker); returns ours. Blocking (the
    /// proofs take seconds): run it through [`blocking`].
    pub fn round(&self, msgs: Vec<JMsg>) -> Result<JRound> {
        self.with(|sid, mut st| {
            let mut out = Vec::new();
            let mut signed = None;
            if let State::TakerStart { p, q } = st {
                if !msgs.is_empty() {
                    bail!("2P-ECDSA: the taker opens the session");
                }
                st = taker_t1(sid, p, q, &mut out)?;
            }
            for m in msgs {
                if matches!(st, State::Done) {
                    bail!("2P-ECDSA: message after the signature");
                }
                let body = parse(m)?;
                st = on_msg(sid, st, body, &mut out, &mut signed)?;
            }
            Ok((st, out, signed))
        })
    }

    /// Sign `sighash` — the one signature this session will ever make. Both sides call it
    /// once `J` exists, with the same hash. Blocking: run it through [`blocking`].
    pub fn sign(&self, sighash: [u8; 32]) -> Result<JRound> {
        self.with(|sid, st| {
            let mut out = Vec::new();
            let st = match st {
                State::TakerKey(mut key) => {
                    if key.m.is_some() {
                        bail!("2P-ECDSA: sign called twice");
                    }
                    key.m = Some(sighash);
                    taker_fire(sid, key, &mut out)?
                }
                State::MakerKey { dk, j } => {
                    let k1 = Sc::random(&mut OsRng);
                    let r1 = Point::generator() * k1;
                    let pok = pok_prove(sid, "pok-r1", &k1, &r1);
                    let nonce3 = rand32();
                    let com = commit(sid, "com-r1", &sighash, &r1, &pok, &nonce3);
                    out.push(msg(Body::M3 {
                        com: hex::encode(com),
                    })?);
                    State::MakerAwaitT3 {
                        dk,
                        j,
                        m: sighash,
                        k1,
                        r1,
                        pok,
                        nonce3,
                    }
                }
                _ => bail!("2P-ECDSA: sign before the joint key exists"),
            };
            Ok((st, out, None))
        })
    }

    fn with(
        &self,
        f: impl FnOnce(&[u8], State) -> Result<(State, Vec<JMsg>, Option<Vec<u8>>)>,
    ) -> Result<JRound> {
        let mut g = self.st.lock();
        // Take the state out: on any error the session stays Done (aborted), and secrets of
        // superseded states are dropped as each step moves on.
        let st = std::mem::replace(&mut *g, State::Done);
        if matches!(st, State::Done) {
            bail!("2P-ECDSA session is over");
        }
        let (st, outgoing, signed) = f(&self.sid, st)?;
        let status = match (&signed, &st) {
            (Some(sig), _) => JStatus::Signed(sig.clone()),
            (None, State::TakerKey(k)) => JStatus::KeyReady(pt_bytes(&k.j)),
            (None, State::MakerKey { j, .. }) => JStatus::KeyReady(pt_bytes(j)),
            _ => JStatus::Running,
        };
        *g = if signed.is_some() { State::Done } else { st };
        Ok(JRound { outgoing, status })
    }
}

fn on_msg(
    sid: &[u8],
    st: State,
    body: Body,
    out: &mut Vec<JMsg>,
    signed: &mut Option<Vec<u8>>,
) -> Result<State> {
    let name = body.name();
    Ok(match (st, body) {
        (
            State::MakerStart { p, q },
            Body::T1 {
                n,
                s,
                t,
                prm_a,
                prm_z,
            },
        ) => {
            let n = modulus(&n, "Ñ")?;
            let s = unit(&s, &n, "s")?;
            let t = unit(&t, &n, "t")?;
            if s == 1 || t == 1 {
                bail!("2P-ECDSA: degenerate ring-Pedersen parameters");
            }
            prm_verify(sid, &n, &s, &t, &prm_a, &prm_z)?;
            let aux = Aux {
                s,
                t,
                rsa_modulo: n,
                multiexp: None,
                crt: None,
            };
            let x1 = Sc::random(&mut OsRng);
            let q1 = Point::generator() * x1;
            let pok1 = pok_prove(sid, "pok-q1", &x1, &q1);
            let nonce1 = rand32();
            let com = commit(sid, "com-q1", &[], &q1, &pok1, &nonce1);
            out.push(msg(Body::M1 {
                com: hex::encode(com),
            })?);
            State::MakerAwaitT2 {
                p,
                q,
                aux,
                x1,
                q1,
                pok1,
                nonce1,
            }
        }
        (State::TakerAwaitM1 { aux }, Body::M1 { com }) => {
            let com1 = b32(&com, "com")?;
            let x2 = Sc::random(&mut OsRng);
            let q2 = Point::generator() * x2;
            let pok = pok_prove(sid, "pok-q2", &x2, &q2);
            out.push(msg(Body::T2 {
                q2: hex::encode(pt_bytes(&q2)),
                pok,
            })?);
            State::TakerAwaitM2 { aux, com1, x2 }
        }
        (
            State::MakerAwaitT2 {
                p,
                q,
                aux,
                x1,
                q1,
                pok1,
                nonce1,
            },
            Body::T2 { q2, pok },
        ) => {
            let q2 = point(&q2, "Q2")?;
            pok_verify(sid, "pok-q2", &q2, &pok)?;
            let j = q2 * x1;
            if j.is_zero() {
                bail!("2P-ECDSA: degenerate joint key");
            }
            let dk = DecryptionKey::from_primes(p.clone(), q.clone())
                .map_err(|e| anyhow!("2P-ECDSA Paillier key: {e:?}"))?;
            let ek = dk.encryption_key().clone();
            let n0 = ek.n().clone();
            let x1_int = sc_int(&x1);
            let (c_key, r) = ek
                .encrypt_with_random(&mut OsRng, &x1_int)
                .map_err(|e| anyhow!("2P-ECDSA encrypt: {e:?}"))?;
            let (mod_comm, mod_proof) = pi_mod::non_interactive::prove::<{ MOD_ROUNDS }, Sha256>(
                &shared(sid, "pi-mod"),
                &pi_mod::Data { n: n0.clone() },
                &pi_mod::PrivateData {
                    p: p.clone(),
                    q: q.clone(),
                },
                &mut OsRng,
            )
            .map_err(|e| anyhow!("2P-ECDSA Πmod: {e:?}"))?;
            let n_root = Integer::from(n0.sqrt_ref());
            let fac = pi_fac::non_interactive::prove::<Sha256>(
                &shared(sid, "pi-fac"),
                &aux,
                pi_fac::Data {
                    n: &n0,
                    n_root: &n_root,
                },
                pi_fac::PrivateData { p: &p, q: &q },
                &fac_params(),
                &mut OsRng,
            )
            .map_err(|e| anyhow!("2P-ECDSA Πfac: {e:?}"))?;
            let g = Point::generator().to_point();
            let (log_comm, log_proof) = pi_log::non_interactive::prove::<E, Sha256>(
                &shared(sid, "pi-log"),
                &aux,
                pi_log::Data {
                    key0: &ek,
                    c: &c_key,
                    b: &g,
                    x: &q1,
                },
                pi_log::PrivateData {
                    x: &x1_int,
                    nonce: &r,
                },
                &log_params(),
                &mut OsRng,
            )
            .map_err(|e| anyhow!("2P-ECDSA Πlog*: {e:?}"))?;
            drop((p, q, r, x1_int));
            out.push(msg(Body::M2 {
                q1: hex::encode(pt_bytes(&q1)),
                pok: pok1,
                nonce: hex::encode(nonce1),
                n0: int_hex(&n0),
                c_key: int_hex(&c_key),
                mod_comm,
                mod_proof,
                fac,
                log_comm,
                log_proof,
            })?);
            State::MakerKey { dk, j }
        }
        (
            State::TakerAwaitM2 { aux, com1, x2 },
            Body::M2 {
                q1,
                pok,
                nonce,
                n0,
                c_key,
                mod_comm,
                mod_proof,
                fac,
                log_comm,
                log_proof,
            },
        ) => {
            let q1 = point(&q1, "Q1")?;
            let nonce = b32(&nonce, "nonce")?;
            if commit(sid, "com-q1", &[], &q1, &pok, &nonce) != com1 {
                bail!("2P-ECDSA: Q1 does not open the maker's commitment");
            }
            pok_verify(sid, "pok-q1", &q1, &pok)?;
            let n0 = modulus(&n0, "N0")?;
            pi_mod::non_interactive::verify::<{ MOD_ROUNDS }, Sha256>(
                &shared(sid, "pi-mod"),
                &pi_mod::Data { n: n0.clone() },
                &mod_comm,
                &mod_proof,
            )
            .map_err(|e| anyhow!("2P-ECDSA Πmod rejected: {e:?}"))?;
            let n_root = Integer::from(n0.sqrt_ref());
            pi_fac::non_interactive::verify::<Sha256>(
                &shared(sid, "pi-fac"),
                &aux,
                pi_fac::Data {
                    n: &n0,
                    n_root: &n_root,
                },
                &fac_params(),
                &fac,
            )
            .map_err(|e| anyhow!("2P-ECDSA Πfac rejected: {e:?}"))?;
            let ek = EncryptionKey::from_n(n0);
            let c_key = int_below(&c_key, ek.nn(), "c_key")?;
            let g = Point::generator().to_point();
            pi_log::non_interactive::verify::<E, Sha256>(
                &shared(sid, "pi-log"),
                &aux,
                pi_log::Data {
                    key0: &ek,
                    c: &c_key,
                    b: &g,
                    x: &q1,
                },
                &log_comm,
                &log_params(),
                &log_proof,
            )
            .map_err(|e| anyhow!("2P-ECDSA Πlog* rejected: {e:?}"))?;
            let j = q1 * x2;
            if j.is_zero() {
                bail!("2P-ECDSA: degenerate joint key");
            }
            State::TakerKey(TakerKey {
                x2,
                j,
                ek,
                c_key,
                com3: None,
                m: None,
            })
        }
        (State::TakerKey(mut key), Body::M3 { com }) => {
            if key.com3.is_some() {
                bail!("2P-ECDSA: second nonce commitment — session aborted");
            }
            key.com3 = Some(b32(&com, "com")?);
            taker_fire(sid, key, out)?
        }
        (
            State::MakerAwaitT3 {
                dk,
                j,
                m,
                k1,
                r1,
                pok,
                nonce3,
            },
            Body::T3 { r2, pok: pok2 },
        ) => {
            let r2 = point(&r2, "R2")?;
            pok_verify(sid, "pok-r2", &r2, &pok2)?;
            let r = x_scalar(&(r2 * k1))?;
            out.push(msg(Body::M4 {
                r1: hex::encode(pt_bytes(&r1)),
                pok,
                nonce: hex::encode(nonce3),
            })?);
            State::MakerAwaitT4 { dk, j, m, k1, r }
        }
        (State::TakerAwaitM4 { key, k2, com3, m }, Body::M4 { r1, pok, nonce }) => {
            let r1 = point(&r1, "R1")?;
            let nonce = b32(&nonce, "nonce")?;
            if commit(sid, "com-r1", &m, &r1, &pok, &nonce) != com3 {
                bail!("2P-ECDSA: R1 does not open the maker's commitment");
            }
            pok_verify(sid, "pok-r1", &r1, &pok)?;
            let r = x_scalar(&(r1 * k2))?;
            let k2_inv = k2.invert().ok_or_else(|| anyhow!("2P-ECDSA: zero nonce"))?;
            let a = sc_int(&(k2_inv * Sc::from_be_bytes_mod_order(m)));
            let v = sc_int(&(k2_inv * r * key.x2));
            let mut osr = OsRng;
            let mut rs = external_rand(&mut osr);
            let rho = Integer::from(Integer::random_bits(RHO_BITS, &mut rs));
            let pt = rho * curve_order() + a;
            let (c1, _) = key
                .ek
                .encrypt_with_random(&mut OsRng, &pt)
                .map_err(|e| anyhow!("2P-ECDSA encrypt: {e:?}"))?;
            let c2 = key
                .ek
                .omul(&v, &key.c_key)
                .map_err(|e| anyhow!("2P-ECDSA omul: {e:?}"))?;
            let c3 = key
                .ek
                .oadd(&c1, &c2)
                .map_err(|e| anyhow!("2P-ECDSA oadd: {e:?}"))?;
            out.push(msg(Body::T4 { c3: int_hex(&c3) })?);
            State::TakerAwaitM5 { j: key.j, m }
        }
        (State::MakerAwaitT4 { dk, j, m, k1, r }, Body::T4 { c3 }) => {
            let c3 = int_below(&c3, dk.encryption_key().nn(), "c3")?;
            let s_prime = dk
                .decrypt(&c3)
                .map_err(|e| anyhow!("2P-ECDSA decrypt: {e:?}"))?;
            let k1_inv = k1.invert().ok_or_else(|| anyhow!("2P-ECDSA: zero nonce"))?;
            let s = k1_inv * int_sc(&s_prime);
            let sig = finish_sig(&j, &m, &r, &s)?;
            out.push(msg(Body::M5 {
                sig: hex::encode(&sig),
            })?);
            *signed = Some(sig);
            State::Done
        }
        (State::TakerAwaitM5 { j, m }, Body::M5 { sig }) => {
            let sig = hex::decode(&sig).map_err(|_| anyhow!("2P-ECDSA: bad signature hex"))?;
            if !sig_ok(&j, &m, &sig) {
                bail!("2P-ECDSA: the maker's signature does not verify under J");
            }
            *signed = Some(sig);
            State::Done
        }
        (_, _) => bail!("2P-ECDSA: unexpected message {name} — session aborted"),
    })
}

/// T1: the taker's ring-Pedersen modulus Ñ = p̃q̃, t = r², s = t^λ, and Πprm. Only the
/// public parts survive this function.
fn taker_t1(sid: &[u8], p: Integer, q: Integer, out: &mut Vec<JMsg>) -> Result<State> {
    let n = Integer::from(&p * &q);
    let phi = Integer::from(&p - 1u32) * Integer::from(&q - 1u32);
    drop((p, q));
    let mut osr = OsRng;
    let mut rs = external_rand(&mut osr);
    let r = loop {
        let r = Integer::from(n.random_below_ref(&mut rs));
        if r > 1 && Integer::from(r.gcd_ref(&n)) == 1 {
            break r;
        }
    };
    let lambda = Integer::from(phi.random_below_ref(&mut rs));
    let t = powm(&Integer::from(r.square_ref()), &Integer::from(1u32), &n)?;
    let s = powm(&t, &lambda, &n)?;
    let mut alphas = Vec::with_capacity(PRM_ROUNDS);
    let mut a = Vec::with_capacity(PRM_ROUNDS);
    for _ in 0..PRM_ROUNDS {
        let al = Integer::from(phi.random_below_ref(&mut rs));
        a.push(powm(&t, &al, &n)?);
        alphas.push(al);
    }
    let e = prm_challenge(sid, &n, &s, &t, &a);
    let z: Vec<Integer> = alphas
        .into_iter()
        .zip(e)
        .map(|(al, ei)| {
            if ei {
                Integer::from(&al + &lambda).modulo(&phi)
            } else {
                al
            }
        })
        .collect();
    drop((phi, lambda));
    out.push(msg(Body::T1 {
        n: int_hex(&n),
        s: int_hex(&s),
        t: int_hex(&t),
        prm_a: a.iter().map(int_hex).collect(),
        prm_z: z.iter().map(int_hex).collect(),
    })?);
    Ok(State::TakerAwaitM1 {
        aux: Aux {
            s,
            t,
            rsa_modulo: n,
            multiexp: None,
            crt: None,
        },
    })
}

/// The taker's T3, once both its own `sign` and the maker's M3 are in.
fn taker_fire(sid: &[u8], key: TakerKey, out: &mut Vec<JMsg>) -> Result<State> {
    let (Some(com3), Some(m)) = (key.com3, key.m) else {
        return Ok(State::TakerKey(key));
    };
    let k2 = Sc::random(&mut OsRng);
    let r2 = Point::generator() * k2;
    let pok = pok_prove(sid, "pok-r2", &k2, &r2);
    out.push(msg(Body::T3 {
        r2: hex::encode(pt_bytes(&r2)),
        pok,
    })?);
    Ok(State::TakerAwaitM4 { key, k2, com3, m })
}

/// Πprm verification: for each round, t^z = a·s^e (mod Ñ).
fn prm_verify(
    sid: &[u8],
    n: &Integer,
    s: &Integer,
    t: &Integer,
    a: &[String],
    z: &[String],
) -> Result<()> {
    if a.len() != PRM_ROUNDS || z.len() != PRM_ROUNDS {
        bail!("2P-ECDSA: Πprm has the wrong number of rounds");
    }
    let a: Vec<Integer> = a
        .iter()
        .map(|x| unit(x, n, "Πprm a"))
        .collect::<Result<_>>()?;
    let e = prm_challenge(sid, n, s, t, &a);
    for ((ai, zi), ei) in a.iter().zip(z).zip(e) {
        let zi = int_below(zi, n, "Πprm z")?;
        let lhs = powm(t, &zi, n)?;
        let rhs = if ei {
            Integer::from(ai * s).modulo(n)
        } else {
            ai.clone()
        };
        if lhs != rhs {
            bail!("2P-ECDSA: Πprm rejected");
        }
    }
    Ok(())
}

fn prm_challenge(sid: &[u8], n: &Integer, s: &Integer, t: &Integer, a: &[Integer]) -> Vec<bool> {
    let mut parts: Vec<Vec<u8>> = vec![int_bytes(n), int_bytes(s), int_bytes(t)];
    parts.extend(a.iter().map(int_bytes));
    let refs: Vec<&[u8]> = parts.iter().map(|v| v.as_slice()).collect();
    let d = h(sid, "pi-prm", &refs);
    (0..PRM_ROUNDS)
        .map(|i| d[i / 8] >> (i % 8) & 1 == 1)
        .collect()
}

/// Schnorr: A = kG, e = H(sid, tag, P, A), z = k + e·x.
fn pok_prove(sid: &[u8], tag: &str, x: &Sc, p: &Pt) -> Pok {
    let k = Sc::random(&mut OsRng);
    let a = Point::generator() * k;
    let e = pok_challenge(sid, tag, p, &a);
    let z = k + e * x;
    Pok {
        a: hex::encode(pt_bytes(&a)),
        z: hex::encode(z.to_be_bytes().as_ref()),
    }
}

fn pok_verify(sid: &[u8], tag: &str, p: &Pt, pok: &Pok) -> Result<()> {
    let a = point(&pok.a, "proof commitment")?;
    let z = hex::decode(&pok.z)
        .ok()
        .and_then(|b| Sc::from_be_bytes(b).ok())
        .ok_or_else(|| anyhow!("2P-ECDSA: bad proof response"))?;
    let e = pok_challenge(sid, tag, p, &a);
    if Point::generator() * z != a + *p * e {
        bail!("2P-ECDSA: proof of knowledge rejected ({tag})");
    }
    Ok(())
}

fn pok_challenge(sid: &[u8], tag: &str, p: &Pt, a: &Pt) -> Sc {
    Sc::from_be_bytes_mod_order(h(sid, tag, &[&pt_bytes(p), &pt_bytes(a)]))
}

fn commit(sid: &[u8], tag: &str, m: &[u8], p: &Pt, pok: &Pok, nonce: &[u8; 32]) -> [u8; 32] {
    h(
        sid,
        tag,
        &[m, &pt_bytes(p), pok.a.as_bytes(), pok.z.as_bytes(), nonce],
    )
}

/// SHA-256 over the domain, session, tag and length-prefixed parts.
fn h(sid: &[u8], tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut d = Sha256::new();
    for x in [b"irondivi/jsig-l17/v1".as_slice(), sid, tag.as_bytes()]
        .into_iter()
        .chain(parts.iter().copied())
    {
        d.update((x.len() as u64).to_be_bytes());
        d.update(x);
    }
    d.finalize().into()
}

/// The Fiat–Shamir shared state for one paillier-zk proof.
fn shared(sid: &[u8], tag: &str) -> String {
    format!("irondivi/jsig-l17/v1/{}/{tag}", hex::encode(sid))
}

fn log_params() -> pi_log::SecurityParams {
    pi_log::SecurityParams {
        l: SecurityLevel128::ELL,
        epsilon: SecurityLevel128::EPSILON,
        q: SecurityLevel128::q(),
    }
}

fn fac_params() -> pi_fac::SecurityParams {
    pi_fac::SecurityParams {
        l: SecurityLevel128::ELL,
        epsilon: SecurityLevel128::EPSILON,
        q: SecurityLevel128::q(),
    }
}

/// σ = (r, s), low-S, checked under `J`: DER + SIGHASH_ALL.
fn finish_sig(j: &Pt, m: &[u8; 32], r: &Sc, s: &Sc) -> Result<Vec<u8>> {
    if s.is_zero() {
        bail!("2P-ECDSA: zero signature");
    }
    let half = (curve_order() - 1u32) / 2u32;
    let s = if sc_int(s) > half { -*s } else { *s };
    let mut rs = [0u8; 64];
    rs[..32].copy_from_slice(r.to_be_bytes().as_ref());
    rs[32..].copy_from_slice(s.to_be_bytes().as_ref());
    let mut der = divi_crypto::signature::Signature::from_compact(&rs)
        .map_err(|e| anyhow!("2P-ECDSA signature encoding: {e}"))?
        .to_der();
    der.push(0x01);
    if !sig_ok(j, m, &der) {
        bail!("2P-ECDSA signature does not verify");
    }
    Ok(der)
}

fn sig_ok(j: &Pt, m: &[u8; 32], sig: &[u8]) -> bool {
    let Some((&0x01, der)) = sig.split_last() else {
        return false;
    };
    let (Ok(pk), Ok(sig)) = (
        divi_crypto::PublicKey::from_bytes(&pt_bytes(j)),
        divi_crypto::signature::Signature::from_der(der),
    ) else {
        return false;
    };
    divi_crypto::signature::verify_hash(&pk, &sig, m)
}

fn msg(body: Body) -> Result<JMsg> {
    Ok(JMsg {
        phase: body.phase(),
        broadcast: false,
        body: serde_json::to_value(&body).map_err(|e| anyhow!("2P-ECDSA encode: {e}"))?,
    })
}

fn parse(m: JMsg) -> Result<Body> {
    let body: Body =
        serde_json::from_value(m.body).map_err(|e| anyhow!("2P-ECDSA: bad message: {e}"))?;
    if body.phase() != m.phase || m.broadcast {
        bail!("2P-ECDSA: message {} in the wrong phase", body.name());
    }
    Ok(body)
}

fn rand32() -> [u8; 32] {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    b
}

fn b32(s: &str, what: &str) -> Result<[u8; 32]> {
    hex::decode(s)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow!("2P-ECDSA: bad {what}"))
}

fn pt_bytes(p: &Pt) -> [u8; 33] {
    let mut b = [0u8; 33];
    b.copy_from_slice(p.to_bytes(true).as_ref());
    b
}

/// A non-zero compressed point.
fn point(s: &str, what: &str) -> Result<Pt> {
    let p = hex::decode(s)
        .ok()
        .filter(|b| b.len() == 33)
        .and_then(|b| Pt::from_bytes(b).ok())
        .ok_or_else(|| anyhow!("2P-ECDSA: bad point {what}"))?;
    if p.is_zero() {
        bail!("2P-ECDSA: {what} is the identity");
    }
    Ok(p)
}

fn x_scalar(p: &Pt) -> Result<Sc> {
    let r = p
        .x()
        .ok_or_else(|| anyhow!("2P-ECDSA: R is the identity"))?
        .to_scalar();
    if r.is_zero() {
        bail!("2P-ECDSA: r = 0");
    }
    Ok(r)
}

fn curve_order() -> Integer {
    Integer::from_str_radix(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        16,
    )
    .expect("secp256k1 order")
}

fn sc_int(s: &Sc) -> Integer {
    Integer::from_digits(s.to_be_bytes().as_ref(), Order::Msf)
}

/// Any integer, reduced mod the curve order.
fn int_sc(i: &Integer) -> Sc {
    let r = i.clone().modulo(&curve_order());
    Sc::from_be_bytes_mod_order(r.to_digits::<u8>(Order::Msf))
}

fn int_hex(i: &Integer) -> String {
    i.to_string_radix(16)
}

fn int_bytes(i: &Integer) -> Vec<u8> {
    i.to_digits::<u8>(Order::Msf)
}

/// A non-negative hex integer below `bound`.
fn int_below(s: &str, bound: &Integer, what: &str) -> Result<Integer> {
    let max_digits = bound.significant_bits() as usize / 4 + 1;
    if s.is_empty() || s.len() > max_digits || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
        bail!("2P-ECDSA: bad {what}");
    }
    let i = Integer::from_str_radix(s, 16).map_err(|_| anyhow!("2P-ECDSA: bad {what}"))?;
    if &i >= bound {
        bail!("2P-ECDSA: {what} out of range");
    }
    Ok(i)
}

/// A unit of Z*_n.
fn unit(s: &str, n: &Integer, what: &str) -> Result<Integer> {
    let i = int_below(s, n, what)?;
    if i == 0 || Integer::from(i.gcd_ref(n)) != 1 {
        bail!("2P-ECDSA: {what} is not a unit");
    }
    Ok(i)
}

/// An odd modulus of acceptable size.
fn modulus(s: &str, what: &str) -> Result<Integer> {
    let max = Integer::from(1u32) << MAX_MODULUS_BITS;
    let n = int_below(s, &max, what)?;
    if n.significant_bits() < MIN_MODULUS_BITS || n.is_even() {
        bail!("2P-ECDSA: {what} has the wrong size");
    }
    Ok(n)
}

fn powm(b: &Integer, e: &Integer, n: &Integer) -> Result<Integer> {
    b.clone()
        .pow_mod(e, n)
        .map_err(|_| anyhow!("2P-ECDSA: modular exponentiation failed"))
}

/// Run blocking session work (`JSession::round`/`sign`, prime generation) off the async
/// runtime.
pub async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| anyhow!("2P-ECDSA task: {e}"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    fn primes() -> &'static (Primes, Primes) {
        static P: OnceLock<(Primes, Primes)> = OnceLock::new();
        P.get_or_init(|| {
            std::thread::scope(|s| {
                let a = s.spawn(generate_primes);
                let b = s.spawn(generate_primes);
                (a.join().unwrap(), b.join().unwrap())
            })
        })
    }

    fn pair(sid: &[u8]) -> (JSession, JSession) {
        let (pt, pm) = primes().clone();
        (
            JSession::start(sid, TAKER, pt),
            JSession::start(sid, MAKER, pm),
        )
    }

    fn edit(m: &mut JMsg, field: &str, f: impl FnOnce(&str) -> String) {
        let v = m.body[field].as_str().unwrap().to_string();
        m.body[field] = serde_json::Value::String(f(&v));
    }

    /// Flip the last hex digit.
    fn flip(s: &str) -> String {
        let (head, last) = s.split_at(s.len() - 1);
        let d = u8::from_str_radix(last, 16).unwrap() ^ 1;
        format!("{head}{d:x}")
    }

    /// Both sides in one process, the way the taker and maker drive it over HTTP: key
    /// generation, one signing; then the sessions refuse anything further.
    #[test]
    fn two_party_key_and_one_signature() {
        let (taker, maker) = pair(b"test-session");
        let mut to_maker = taker.round(vec![]).unwrap().outgoing;
        let joint = loop {
            let m = maker.round(to_maker).unwrap();
            let t = taker.round(m.outgoing).unwrap();
            to_maker = t.outgoing;
            if let (JStatus::KeyReady(a), JStatus::KeyReady(b)) = (&m.status, &t.status) {
                assert_eq!(a, b);
                break *a;
            }
        };
        assert!(to_maker.is_empty());
        let sighash = [7u8; 32];
        let mut to_taker = maker.sign(sighash).unwrap().outgoing;
        let t0 = taker.sign(sighash).unwrap();
        let mut to_maker = t0.outgoing;
        let (mut ts, mut ms) = (None, None);
        while ts.is_none() || ms.is_none() {
            if ms.is_none() {
                let m = maker.round(std::mem::take(&mut to_maker)).unwrap();
                to_taker.extend(m.outgoing);
                if let JStatus::Signed(s) = m.status {
                    ms = Some(s);
                }
            }
            if ts.is_none() {
                let t = taker.round(std::mem::take(&mut to_taker)).unwrap();
                to_maker.extend(t.outgoing);
                if let JStatus::Signed(s) = t.status {
                    ts = Some(s);
                }
            }
        }
        let (ts, ms) = (ts.unwrap(), ms.unwrap());
        assert_eq!(ts, ms);
        let (&ty, der) = ts.split_last().unwrap();
        assert_eq!(ty, 0x01);
        let pk = divi_crypto::PublicKey::from_bytes(&joint).unwrap();
        let sig = divi_crypto::signature::Signature::from_der(der).unwrap();
        assert!(divi_crypto::signature::verify_hash(&pk, &sig, &sighash));
        // Sign once: the sessions are over.
        assert!(taker.sign([8u8; 32]).is_err());
        assert!(maker.sign([8u8; 32]).is_err());
        assert!(maker.round(vec![]).is_err());
        assert!(taker.round(vec![]).is_err());
    }

    /// The order the HTTP flow uses: the maker's M3 rides with M2, before the taker signs.
    #[test]
    fn maker_commitment_before_taker_signs() {
        let (taker, maker) = pair(b"order");
        let t1 = taker.round(vec![]).unwrap().outgoing;
        let m1 = maker.round(t1).unwrap().outgoing;
        let t2 = taker.round(m1).unwrap().outgoing;
        let m = maker.round(t2).unwrap();
        assert!(matches!(m.status, JStatus::KeyReady(_)));
        let mut m2 = m.outgoing;
        m2.extend(maker.sign([3u8; 32]).unwrap().outgoing);
        let t = taker.round(m2).unwrap();
        assert!(matches!(t.status, JStatus::KeyReady(_)) && t.outgoing.is_empty());
        let t3 = taker.sign([3u8; 32]).unwrap().outgoing;
        assert_eq!(t3.len(), 1);
        let m4 = maker.round(t3).unwrap().outgoing;
        let t4 = taker.round(m4).unwrap().outgoing;
        let m5 = maker.round(t4).unwrap();
        assert!(matches!(m5.status, JStatus::Signed(_)));
        assert!(matches!(
            taker.round(m5.outgoing).unwrap().status,
            JStatus::Signed(_)
        ));
    }

    #[test]
    fn maker_rejects_bad_prm() {
        let (taker, maker) = pair(b"bad-prm");
        let mut t1 = taker.round(vec![]).unwrap().outgoing;
        let z0 = t1[0].body["prm_z"][0].as_str().unwrap().to_string();
        t1[0].body["prm_z"][0] = serde_json::Value::String(flip(&z0));
        assert!(maker.round(t1).is_err());
        // Aborted for good.
        assert!(maker.round(vec![]).is_err());
    }

    #[test]
    fn taker_rejects_tampered_c_key() {
        let (taker, maker) = pair(b"bad-c-key");
        let t1 = taker.round(vec![]).unwrap().outgoing;
        let m1 = maker.round(t1).unwrap().outgoing;
        let t2 = taker.round(m1).unwrap().outgoing;
        let mut m2 = maker.round(t2).unwrap().outgoing;
        edit(&mut m2[0], "c_key", flip);
        assert!(taker.round(m2).is_err());
    }

    #[test]
    fn taker_rejects_q1_not_matching_commitment() {
        let (taker, maker) = pair(b"bad-open");
        let t1 = taker.round(vec![]).unwrap().outgoing;
        let m1 = maker.round(t1).unwrap().outgoing;
        let t2 = taker.round(m1).unwrap().outgoing;
        let mut m2 = maker.round(t2).unwrap().outgoing;
        edit(&mut m2[0], "nonce", flip);
        assert!(taker.round(m2).is_err());
    }

    #[test]
    fn taker_rejects_bad_signature_and_maker_rejects_bad_c3() {
        let (taker, maker) = pair(b"bad-sig");
        let t1 = taker.round(vec![]).unwrap().outgoing;
        let m1 = maker.round(t1).unwrap().outgoing;
        let t2 = taker.round(m1).unwrap().outgoing;
        let mut m2 = maker.round(t2).unwrap().outgoing;
        m2.extend(maker.sign([5u8; 32]).unwrap().outgoing);
        taker.round(m2).unwrap();
        // The taker signs a different hash: the maker's σ check fails.
        let t3 = taker.sign([6u8; 32]).unwrap().outgoing;
        let m4 = maker.round(t3).unwrap().outgoing;
        // The taker rejects M4: the maker's commitment bound the hash it signs.
        assert!(taker.round(m4).is_err());

        let (taker, maker) = pair(b"bad-sig-2");
        let t1 = taker.round(vec![]).unwrap().outgoing;
        let m1 = maker.round(t1).unwrap().outgoing;
        let t2 = taker.round(m1).unwrap().outgoing;
        let mut m2 = maker.round(t2).unwrap().outgoing;
        m2.extend(maker.sign([5u8; 32]).unwrap().outgoing);
        taker.round(m2).unwrap();
        let t3 = taker.sign([5u8; 32]).unwrap().outgoing;
        let m4 = maker.round(t3).unwrap().outgoing;
        let mut t4 = taker.round(m4).unwrap().outgoing;
        edit(&mut t4[0], "c3", flip);
        assert!(maker.round(t4).is_err());

        let (taker, maker) = pair(b"bad-sig-3");
        let t1 = taker.round(vec![]).unwrap().outgoing;
        let m1 = maker.round(t1).unwrap().outgoing;
        let t2 = taker.round(m1).unwrap().outgoing;
        let mut m2 = maker.round(t2).unwrap().outgoing;
        m2.extend(maker.sign([5u8; 32]).unwrap().outgoing);
        taker.round(m2).unwrap();
        let t3 = taker.sign([5u8; 32]).unwrap().outgoing;
        let m4 = maker.round(t3).unwrap().outgoing;
        let t4 = taker.round(m4).unwrap().outgoing;
        let mut m5 = maker.round(t4).unwrap().outgoing;
        edit(&mut m5[0], "sig", |s| {
            // Flip a bit inside s (before the trailing sighash byte).
            let (head, tail) = s.split_at(s.len() - 4);
            format!("{}{}", flip(head), tail)
        });
        assert!(taker.round(m5).is_err());
    }

    #[test]
    fn out_of_order_message_aborts() {
        let (taker, maker) = pair(b"order-abort");
        let t1 = taker.round(vec![]).unwrap().outgoing;
        // Replaying T1 to a maker that already answered it aborts.
        maker.round(t1.clone()).unwrap();
        assert!(maker.round(t1).is_err());
        // The taker cannot sign before J exists.
        assert!(taker.sign([1u8; 32]).is_err());

        // A second nonce commitment before the taker signs aborts too.
        let (taker, maker) = pair(b"two-m3");
        let t1 = taker.round(vec![]).unwrap().outgoing;
        let m1 = maker.round(t1).unwrap().outgoing;
        let t2 = taker.round(m1).unwrap().outgoing;
        let mut m2 = maker.round(t2).unwrap().outgoing;
        let m3 = maker.sign([2u8; 32]).unwrap().outgoing;
        m2.extend(m3.clone());
        taker.round(m2).unwrap();
        assert!(taker.round(m3).is_err());
    }
}
