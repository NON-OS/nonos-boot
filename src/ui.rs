//! ui.rs — NØNOS Boot UI (safe console, sections, progress, spinner)
//! eK@nonos-tech.xyz
//!
//! - No globals: pass &SystemTable<Boot> once and hold a &mut TextOutput
//! - Structured helpers: banner, section, kv, info/warn/ok/fail, panic
//! - Progress bar + spinner (ASCII-safe for UEFI text mode)
//! - Color themes w/ automatic reset; errors propagated (no silent drops)

#![allow(dead_code)]

use uefi::prelude::*;
use uefi::proto::console::text::Color;
use uefi::CStr16;

/// Boot UI with a borrowed console handle (no unsafe global loads).
pub struct Ui<'a> {
    system_table: &'a mut SystemTable<uefi::table::Boot>,
    theme: Theme,
}

#[derive(Clone, Copy)]
pub struct Theme {
    pub bg: Color,
    pub info: Color,
    pub ok: Color,
    pub warn: Color,
    pub err: Color,
    pub title: Color,
    pub text: Color,
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            bg: Color::Black,
            info: Color::LightGray,
            ok: Color::LightGreen,
            warn: Color::Yellow,
            err: Color::LightRed,
            title: Color::LightCyan,
            text: Color::White,
        }
    }
}

impl<'a> Ui<'a> {
    /// Acquire UI from a system table safely.
    pub fn new(st: &'a mut SystemTable<uefi::table::Boot>) -> Self {
        Ui {
            system_table: st,
            theme: Theme::default(),
        }
    }

    /// Replace color theme.
    pub fn set_theme(&mut self, t: Theme) {
        self.theme = t;
    }

    /// Clear screen and draw a banner.
    pub fn banner(&mut self) -> Result<(), Status> {
        self.color(self.theme.title, self.theme.bg)?;
        match self.system_table.stdout().clear() {
            Ok(()) => {}
            Err(_) => return Err(Status::DEVICE_ERROR),
        }
        self.line("")?;
        self.raw("              ╔═════════════════════════════════════════════════════════════╗")?;
        self.raw("              ║                 NØNOS :: ZERO-STATE LAUNCHPAD              ║")?;
        self.raw("              ║         Privacy-Native / Identity-Free / Capsule-First     ║")?;
        self.raw("              ║        UEFI Boot  →  Verified Capsule  →  Kernel Jump      ║")?;
        self.raw("              ╚═════════════════════════════════════════════════════════════╝")?;
        self.line("")?;
        self.color(self.theme.text, self.theme.bg)
    }

    /// Start a titled section.
    pub fn section(&mut self, title: &str) -> Result<(), Status> {
        self.color(self.theme.title, self.theme.bg)?;
        self.raw("── ")?;
        self.raw(title)?;
        self.raw(" ")?;
        self.rule(60)?;
        self.color(self.theme.text, self.theme.bg)
    }

    /// Key/Value aligned line.
    pub fn kv(&mut self, key: &str, val: &str) -> Result<(), Status> {
        self.color(self.theme.info, self.theme.bg)?;
        self.raw("• ")?;
        self.raw(key)?;
        self.raw(": ")?;
        self.color(self.theme.text, self.theme.bg)?;
        self.line(val)
    }

    /// Info / OK / Warn / Fail log lines.
    pub fn info(&mut self, msg: &str) -> Result<(), Status> {
        self.level(self.theme.info, "[info] ", msg)
    }
    pub fn ok(&mut self, msg: &str) -> Result<(), Status> {
        self.level(self.theme.ok, "[ ok ] ", msg)
    }
    pub fn warn(&mut self, msg: &str) -> Result<(), Status> {
        self.level(self.theme.warn, "[warn] ", msg)
    }
    pub fn fail(&mut self, msg: &str) -> Result<(), Status> {
        self.level(self.theme.err, "[FAIL] ", msg)
    }

    /// Panic/fatal block in red.
    pub fn panic_block(&mut self, msg: &str) -> Result<(), Status> {
        self.color(self.theme.err, self.theme.bg)?;
        self.line("")?;
        self.raw("──────────────────── SYSTEM FAULT DETECTED ────────────────────")?;
        self.line("")?;
        self.raw("[!] ")?;
        self.line(msg)?;
        self.raw("───────────────────────────────────────────────────────────────")?;
        self.line("")?;
        self.color(self.theme.text, self.theme.bg)
    }

    /// Draw a simple progress bar: current/total (0..total).
    pub fn progress(&mut self, current: usize, total: usize, label: &str) -> Result<(), Status> {
        let total = total.max(1);
        let width = 32usize;
        let filled = ((current.min(total) * width) / total).min(width);
        let mut bar = [b' '; 32];
        for item in bar.iter_mut().take(filled) {
            *item = b'=';
        }
        self.color(self.theme.info, self.theme.bg)?;
        self.raw("[")?;
        self.raw(core::str::from_utf8(&bar).unwrap_or("                                "))?;
        self.raw("] ")?;
        self.color(self.theme.text, self.theme.bg)?;
        self.line(label)
    }

    /// A tiny spinner (ASCII) you can tick in loops.
    pub fn spinner(&mut self, i: usize, label: &str) -> Result<(), Status> {
        const FR: &[u8] = b"|/-\\";
        let ch = FR[i % FR.len()];
        self.color(self.theme.info, self.theme.bg)?;
        self.raw("[")?;
        self.raw_char(ch as char)?;
        self.raw("] ")?;
        self.color(self.theme.text, self.theme.bg)?;
        self.line(label)
    }

    /* ------------- low-level helpers (color, write, etc.) ------------- */

    #[inline]
    fn color(&mut self, fg: Color, bg: Color) -> Result<(), Status> {
        match self.system_table.stdout().set_color(fg, bg) {
            Ok(()) => Ok(()),
            Err(_) => Err(Status::DEVICE_ERROR),
        }
    }

    #[inline]
    fn raw(&mut self, s: &str) -> Result<(), Status> {
        // Convert str to UEFI CStr16 and output
        let mut buffer = [0u16; 256];
        match CStr16::from_str_with_buf(s, &mut buffer) {
            Ok(uefi_str) => match self.system_table.stdout().output_string(uefi_str) {
                Ok(()) => Ok(()),
                Err(_) => Err(Status::DEVICE_ERROR),
            },
            Err(_) => Err(Status::INVALID_PARAMETER),
        }
    }

    #[inline]
    fn raw_char(&mut self, c: char) -> Result<(), Status> {
        let mut buf = [0u8; 4];
        let s = c.encode_utf8(&mut buf);
        self.raw(s)
    }

    #[inline]
    fn line(&mut self, s: &str) -> Result<(), Status> {
        self.raw(s)?;
        self.raw("\r\n")
    }

    fn level(&mut self, fg: Color, tag: &str, msg: &str) -> Result<(), Status> {
        self.color(fg, self.theme.bg)?;
        self.raw(tag)?;
        self.color(self.theme.text, self.theme.bg)?;
        self.line(msg)
    }

    fn rule(&mut self, n: usize) -> Result<(), Status> {
        const DASH: &str = "─";
        for _ in 0..n {
            self.raw(DASH)?;
        }
        self.line("")
    }
}
