// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The C1 joint key `J` (`docs/plans/swap-poc/xmr-c1-design.md` §4.1, §5): a 2-of-2 ECDSA key
//! neither party holds, signed exactly once, on `Tx_cancel`'s sighash.
//!
//! Built on `cggmp21` (CGGMP'21, malicious-secure with abort, audited by Kudelski at an earlier
//! version than the one pinned): one [`JSession`] per swap per side runs aux-info generation
//! (Paillier keys and their proofs), key generation and a single signing in that order, on its
//! own thread. The session is the only place the key share ever exists — it is never
//! serialized or persisted — and the thread ends, dropping it, as soon as the one signature is
//! out. So no second signature under `J` can be made by either side: there is no API for it,
//! and no stored share to start one from. A restart before the signature aborts the swap,
//! which costs nothing (`Tx_lock` is broadcast only after `σ_J` exists).
//!
//! Transport is sans-IO: [`JSession::round`] takes the peer's messages and returns ours once
//! the protocol needs more from the peer. The taker drives (`POST /xmr/swaps/:id/j`); the
//! maker answers each round. Messages carry their [`Phase`]; anything for a phase already
//! finished is a protocol violation and aborts the session.

use std::collections::VecDeque;
use std::sync::mpsc;

use cggmp21::round_based::state_machine::{ProceedResult, StateMachine};
use cggmp21::round_based::{Incoming, MessageDestination, MessageType};
use cggmp21::security_level::SecurityLevel128;
use cggmp21::supported_curves::Secp256k1;
use cggmp21::{DataToSign, ExecutionId, KeyShare, PregeneratedPrimes};
use parking_lot::Mutex;
use rand::rngs::OsRng;
use divi_swap::{Result, SwapError};
use serde::{Deserialize, Serialize};

macro_rules! anyhow { ($($t:tt)*) => { SwapError::Other(format!($($t)*)) } }
macro_rules! bail { ($($t:tt)*) => { return Err(anyhow!($($t)*)) } }

/// The taker's party index.
pub const TAKER: u16 = 0;
/// The maker's party index.
pub const MAKER: u16 = 1;
const PARTIES: [u16; 2] = [TAKER, MAKER];

/// Paillier safe primes for one session (seconds to minutes to generate; pool them).
pub type Primes = PregeneratedPrimes<SecurityLevel128>;

/// Generate one session's primes (CPU-bound, 20–90 s on an old Xeon).
pub fn generate_primes() -> Primes {
    Primes::generate(&mut OsRng)
}

/// Which sub-protocol a message belongs to; sessions run them in this order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Paillier keys and their ZK proofs.
    Aux,
    /// Distributed key generation of `J`.
    Keygen,
    /// The one signing, on `Tx_cancel`'s sighash.
    Sign,
}

/// One protocol message on the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JMsg {
    /// Its sub-protocol.
    pub phase: Phase,
    /// Broadcast (`true`) or point-to-point; with two parties both go to the peer.
    pub broadcast: bool,
    /// The cggmp21 message, serde JSON.
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

enum Cmd {
    Msgs(Vec<JMsg>),
    Sign([u8; 32]),
}

type Reply = mpsc::Sender<Result<JRound>>;

/// One side of one swap's `J`: see the module docs.
pub struct JSession {
    tx: Mutex<Option<mpsc::Sender<(Cmd, Reply)>>>,
}

impl JSession {
    /// Start our side (`me` = [`TAKER`] or [`MAKER`]) of session `sid` (unique per swap; both
    /// sides use the same) with `primes` for our Paillier key.
    pub fn start(sid: &[u8], me: u16, primes: Primes) -> Self {
        let (tx, rx) = mpsc::channel::<(Cmd, Reply)>();
        let sid = sid.to_vec();
        std::thread::Builder::new()
            .name("jsig".into())
            .spawn(move || {
                let mut w = Worker { me, rx, pending: VecDeque::new(), out: Vec::new(), reply: None, next_id: 0 };
                let r = w.run(&sid, primes);
                if let Err(e) = r {
                    w.answer(Err(e));
                }
            })
            .expect("spawn jsig thread");
        JSession { tx: Mutex::new(Some(tx)) }
    }

    fn call(&self, cmd: Cmd) -> Result<JRound> {
        let (rtx, rrx) = mpsc::channel();
        let mut g = self.tx.lock();
        let Some(tx) = g.as_ref() else { bail!("2P-ECDSA session is over") };
        if tx.send((cmd, rtx)).is_err() {
            *g = None;
            bail!("2P-ECDSA session is over");
        }
        drop(g);
        let r = rrx.recv().map_err(|_| anyhow!("2P-ECDSA session ended"))?;
        match &r {
            Ok(JRound { status: JStatus::Signed(_), .. }) | Err(_) => *self.tx.lock() = None,
            _ => {}
        }
        r
    }

    /// Feed the peer's messages (none on our first call) and run until the protocol needs
    /// more from the peer. Blocking: CPU-heavy in the aux phase; call off the async runtime.
    pub fn round(&self, incoming: Vec<JMsg>) -> Result<JRound> {
        self.call(Cmd::Msgs(incoming))
    }

    /// Start the one signing, on `sighash`; only after [`JStatus::KeyReady`]. Blocking.
    pub fn sign(&self, sighash: [u8; 32]) -> Result<JRound> {
        self.call(Cmd::Sign(sighash))
    }
}

struct Worker {
    me: u16,
    rx: mpsc::Receiver<(Cmd, Reply)>,
    pending: VecDeque<JMsg>,
    out: Vec<JMsg>,
    reply: Option<Reply>,
    next_id: u64,
}

impl Worker {
    fn answer(&mut self, r: Result<JRound>) {
        if let Some(reply) = self.reply.take() {
            let _ = reply.send(r);
        }
    }

    fn flush(&mut self, status: JStatus) {
        let outgoing = std::mem::take(&mut self.out);
        self.answer(Ok(JRound { outgoing, status }));
    }

    /// Block for the next command.
    fn next(&mut self) -> Result<Cmd> {
        let (cmd, reply) = self.rx.recv().map_err(|_| anyhow!("2P-ECDSA session dropped"))?;
        self.reply = Some(reply);
        Ok(cmd)
    }

    fn take_msgs(&mut self, msgs: Vec<JMsg>, phase: Phase) -> Result<()> {
        for m in msgs {
            if m.phase < phase {
                bail!("2P-ECDSA message for finished phase {:?} (now {phase:?})", m.phase);
            }
            self.pending.push_back(m);
        }
        Ok(())
    }

    fn drive<S>(&mut self, phase: Phase, sm: &mut S) -> Result<S::Output>
    where
        S: StateMachine,
        S::Msg: Serialize + serde::de::DeserializeOwned,
    {
        loop {
            match sm.proceed() {
                ProceedResult::SendMsg(o) => self.out.push(JMsg {
                    phase,
                    broadcast: matches!(o.recipient, MessageDestination::AllParties),
                    body: serde_json::to_value(&o.msg).map_err(|e| anyhow!("2P-ECDSA encode: {e}"))?,
                }),
                ProceedResult::NeedsOneMoreMessage => {
                    while !self.pending.iter().any(|m| m.phase == phase) {
                        self.flush(JStatus::Running);
                        match self.next()? {
                            Cmd::Msgs(m) => self.take_msgs(m, phase)?,
                            Cmd::Sign(_) => bail!("2P-ECDSA sign before the key exists"),
                        }
                    }
                    let i = self.pending.iter().position(|m| m.phase == phase).unwrap();
                    let m = self.pending.remove(i).unwrap();
                    self.next_id += 1;
                    let msg = Incoming {
                        id: self.next_id,
                        sender: 1 - self.me,
                        msg_type: if m.broadcast { MessageType::Broadcast } else { MessageType::P2P },
                        msg: serde_json::from_value(m.body).map_err(|e| anyhow!("2P-ECDSA decode: {e}"))?,
                    };
                    sm.received_msg(msg).map_err(|_| anyhow!("2P-ECDSA {phase:?} message rejected"))?;
                }
                ProceedResult::Yielded => {}
                ProceedResult::Output(o) => return Ok(o),
                ProceedResult::Error(e) => bail!("2P-ECDSA {phase:?} aborted: {e}"),
                #[allow(unreachable_patterns)]
                _ => bail!("2P-ECDSA {phase:?}: unexpected state"),
            }
        }
    }

    fn run(&mut self, sid: &[u8], primes: Primes) -> Result<()> {
        // The first command is the caller's first round.
        match self.next()? {
            Cmd::Msgs(m) => self.take_msgs(m, Phase::Aux)?,
            Cmd::Sign(_) => bail!("2P-ECDSA sign before the key exists"),
        }
        let me = self.me;
        let mut rng = OsRng;
        let eid_aux = [sid, b"/aux"].concat();
        let aux = {
            let mut sm = cggmp21::aux_info_gen(ExecutionId::new(&eid_aux), me, 2, primes)
                .into_state_machine(&mut rng);
            self.drive(Phase::Aux, &mut sm)?
        }
        .map_err(|e| anyhow!("2P-ECDSA aux: {e}"))?;
        let eid_kg = [sid, b"/keygen"].concat();
        let incomplete = {
            let mut sm = cggmp21::keygen::<Secp256k1>(ExecutionId::new(&eid_kg), me, 2)
                .into_state_machine(&mut rng);
            self.drive(Phase::Keygen, &mut sm)?
        }
        .map_err(|e| anyhow!("2P-ECDSA keygen: {e}"))?;
        let share: KeyShare<Secp256k1> = KeyShare::from_parts((incomplete, aux))
            .map_err(|e| anyhow!("2P-ECDSA key share: {e}"))?;
        let pk = share.shared_public_key;
        let enc = pk.to_bytes(true);
        let joint: [u8; 33] = enc.as_ref().try_into().map_err(|_| anyhow!("J not 33 bytes"))?;

        self.flush(JStatus::KeyReady(joint));
        let sighash = loop {
            match self.next()? {
                Cmd::Sign(h) => break h,
                Cmd::Msgs(m) => {
                    self.take_msgs(m, Phase::Sign)?;
                    self.flush(JStatus::KeyReady(joint));
                }
            }
        };
        let scalar = cggmp21::generic_ec::Scalar::<Secp256k1>::from_be_bytes_mod_order(sighash);
        let msg = DataToSign::from_scalar(scalar);
        let eid_sign = [sid, b"/sign"].concat();
        let sig = {
            let mut sm = cggmp21::signing(ExecutionId::new(&eid_sign), me, &PARTIES, &share)
                .sign_sync(&mut rng, msg);
            self.drive(Phase::Sign, &mut sm)?
        }
        .map_err(|e| anyhow!("2P-ECDSA signing: {e}"))?;
        drop(share);
        sig.verify(&pk, &msg).map_err(|_| anyhow!("2P-ECDSA signature does not verify"))?;
        let mut rs = [0u8; 64];
        sig.normalize_s().write_to_slice(&mut rs);
        let mut der = divi_crypto::signature::Signature::from_compact(&rs)
            .map_err(|e| anyhow!("2P-ECDSA signature encoding: {e}"))?
            .to_der();
        der.push(0x01);
        self.flush(JStatus::Signed(der));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both sides in one process, the way the taker and maker drive it over HTTP: aux,
    /// keygen, one signing; then the session refuses anything further.
    #[test]
    fn two_party_key_and_one_signature() {
        let (pt, pm) = (generate_primes(), generate_primes());
        let sid = b"test-session";
        let taker = JSession::start(sid, TAKER, pt);
        let maker = JSession::start(sid, MAKER, pm);
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
        assert!(maker.round(vec![]).is_err());
    }
}
