//! `UsbForensics`: named, documented recipes for issuing USB traffic a compliant
//! host would never send — the deliberately-illegal operations that make this a
//! forensics tool.
//!
//! Every method is a thin, discoverable wrapper over [`UsbHost::control_raw`] /
//! [`UsbHost::raw_transaction`], so intent is explicit at the call site. After
//! calling one, drain [`UsbHost::poll_events`] to see exactly what the device did
//! (including errors a compliant host would hide). See `docs/FORENSICS.md` for the
//! full violation matrix.
//!
//! SPDX-License-Identifier: BSD-3-Clause

use crate::error::Result;
use crate::host::{
    request, ControlForensics, ControlResult, Pid, RawTransaction, Setup, TransactionResult,
    TxFlags, UsbHost,
};

/// Forensic / non-compliant operations, available on any [`UsbHost`] via a
/// blanket implementation.
pub trait UsbForensics: UsbHost {
    /// `GET_DESCRIPTOR` asking for far more bytes than the descriptor contains
    /// (`wLength` = `claim_len`). A compliant host requests the real length.
    fn get_descriptor_oversized(
        &mut self,
        address: u8,
        desc_type: u8,
        index: u8,
        claim_len: u16,
    ) -> Result<ControlResult> {
        self.control_transfer(
            address,
            Setup {
                request_type: 0x80,
                request: request::GET_DESCRIPTOR,
                value: (u16::from(desc_type) << 8) | u16::from(index),
                index: 0,
                length: claim_len,
            },
            &[],
        )
    }

    /// Send a SETUP whose `wLength` disagrees with the data actually moved: the 8
    /// SETUP bytes go on the wire verbatim, but the data stage runs for
    /// `actual_len` bytes instead of the declared `wLength`.
    fn setup_length_mismatch(
        &mut self,
        address: u8,
        setup: [u8; 8],
        data_out: &[u8],
        actual_len: usize,
    ) -> Result<ControlResult> {
        self.control_raw(
            address,
            setup,
            data_out,
            ControlForensics {
                data_len_override: Some(actual_len),
                ..Default::default()
            },
        )
    }

    /// Run the status stage in the wrong direction for the given SETUP.
    fn setup_wrong_direction(
        &mut self,
        address: u8,
        setup: [u8; 8],
        data_out: &[u8],
    ) -> Result<ControlResult> {
        self.control_raw(
            address,
            setup,
            data_out,
            ControlForensics {
                status_wrong_dir: true,
                ..Default::default()
            },
        )
    }

    /// Issue a control transfer with **no status stage** — never closing the
    /// transaction the way the spec requires.
    fn control_without_status(
        &mut self,
        address: u8,
        setup: [u8; 8],
        data_out: &[u8],
    ) -> Result<ControlResult> {
        self.control_raw(
            address,
            setup,
            data_out,
            ControlForensics {
                skip_status: true,
                ..Default::default()
            },
        )
    }

    /// Send any 8 SETUP bytes verbatim with otherwise-compliant stages — e.g. a
    /// reserved `bRequest`, an illegal `bmRequestType`, or a nonexistent recipient.
    fn raw_setup(&mut self, address: u8, setup: [u8; 8]) -> Result<ControlResult> {
        self.control_raw(address, setup, &[], ControlForensics::default())
    }

    /// Send an IN token to an address/endpoint that shouldn't answer and report
    /// whether anything responded (no retry — one shot, exact result).
    fn talk_to_unassigned(&mut self, address: u8, endpoint: u8) -> Result<TransactionResult> {
        self.raw_transaction(RawTransaction {
            pid: Pid::In,
            address,
            endpoint,
            data: Vec::new(),
            flags: TxFlags {
                no_retry: true,
                ..Default::default()
            },
        })
    }

    /// Send an OUT data packet with a forced (possibly wrong) data PID, to
    /// desynchronise or probe the endpoint's toggle handling.
    fn toggle_desync(
        &mut self,
        address: u8,
        endpoint: u8,
        data: &[u8],
        pid: Pid,
    ) -> Result<TransactionResult> {
        self.raw_transaction(RawTransaction {
            pid: Pid::Out,
            address,
            endpoint,
            data: data.to_vec(),
            flags: TxFlags {
                force_data_pid: Some(pid),
                no_retry: true,
                ..Default::default()
            },
        })
    }

    /// Send a packet longer than the endpoint's maximum (babble): `data` plus
    /// `extra` junk bytes.
    fn babble(
        &mut self,
        address: u8,
        endpoint: u8,
        data: &[u8],
        extra: usize,
    ) -> Result<TransactionResult> {
        self.raw_transaction(RawTransaction {
            pid: Pid::Out,
            address,
            endpoint,
            data: data.to_vec(),
            flags: TxFlags {
                extra_bytes: extra,
                no_retry: true,
                ..Default::default()
            },
        })
    }

    /// Send a token with a corrupted PID check nibble — an illegal packet the
    /// device's hardware should reject.
    fn bad_pid(&mut self, address: u8, endpoint: u8, pid: Pid) -> Result<TransactionResult> {
        self.raw_transaction(RawTransaction {
            pid,
            address,
            endpoint,
            data: Vec::new(),
            flags: TxFlags {
                bad_pid_check: true,
                no_retry: true,
                ..Default::default()
            },
        })
    }
}

impl<T: UsbHost + ?Sized> UsbForensics for T {}
