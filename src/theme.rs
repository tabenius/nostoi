//! The ragbaz token ladder, bound to ratatui.
//!
//! [`crate::design`] is the vendored, generated projection of the design system's
//! `tokens.toml` and `themes.toml`. It is never edited and it knows nothing about
//! ratatui. This module is the whole adapter: a *role* goes in, a ratatui
//! [`Style`] comes out.
//!
//! That separation is deliberate. [`crate::tui`] asks for roles (`status.ok`,
//! `ink.muted`) and never names a colour, so a theme change is a change to
//! `themes.toml` and nothing here. It is also what makes the assertions in
//! `tui.rs`'s test module possible: "no literal colour" is a property of one
//! file because the other one is the only place a colour can be built.
//!
//! Three things are resolved, and none of them is reimplemented:
//!
//! * **colour** — role → theme hex → `nearest256`/`nearest16`/truecolor, from the
//!   generated ladder, for the [`ColorMode`] detected by the generated module.
//!   A `ColorMode::None`, or a theme listed in `colorless_themes()`, resolves
//!   every role to "no colour at all": attributes only.
//! * **glyph** — key → the active [`Set`], narrowed along the token policy
//!   (nerd → unicode → ascii).
//! * **space** — [`SPACE_CELLS`], the cell scale, never a bare number.

use crate::design::{self, ColorMode, Set, SPACE_CELLS};
use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols::border;

/// The TUI's default theme.
///
/// Terminals are dark far more often than not, so the browser opens in
/// `ragbaz-night` rather than in the design system's `DEFAULT_THEME`
/// (`ragbaz`, the printed-object palette on warm paper). `RAGBAZ_THEME`
/// overrides both; see [`theme_name`].
pub const DEFAULT_TUI_THEME: &str = "ragbaz-night";

/// The first step of the space scale that resolves to a whole cell.
///
/// `docs/layout.md` asks for "one `space.1` cell of padding" and "one blank row
/// (`space.1`)". In the terminal projection `SPACE_CELLS[1]` is **0**, because
/// the scale keeps the web's sub-cell steps: `[0, 0, 1, 1, 1, 2, 3, 4, 5]`. A gap
/// that must be visible therefore has to name a step that survives the
/// projection. This is the smallest one, and it is named here once rather than
/// repeated as a magic number. See the adaptation report.
pub const CELL_GAP: usize = 3;

/// The space scale, in cells, for `step` (0 = `space.0` … 8 = `space.8`).
pub fn space(step: usize) -> u16 {
    SPACE_CELLS[step.min(SPACE_CELLS.len() - 1)] as u16
}

/// [`space`] as literal padding, for a gap inside a rendered line.
pub fn gap(step: usize) -> String {
    " ".repeat(space(step) as usize)
}

/// Resolve the theme name.
///
/// * `RAGBAZ_THEME` naming a known theme wins, so an operator can choose
///   `ragbaz`, `ragbaz-white`, `ragbaz-night` or `mono` without a new flag;
/// * an unset name means a terminal, and terminals are dark, so
///   [`DEFAULT_TUI_THEME`];
/// * a name that is *not* a theme in the token file falls back to the design
///   system's own [`design::DEFAULT_THEME`] rather than failing. A typo in an
///   environment variable must not stop somebody reading a chain.
///
/// An unknown name is not silently ignored: the title bar reports the theme that
/// was actually resolved, so the fallback is visible on screen.
pub fn theme_name(requested: Option<String>) -> String {
    match requested {
        Some(name) if design::themes().contains_key(name.as_str()) => name,
        Some(_) => design::DEFAULT_THEME.to_string(),
        None => DEFAULT_TUI_THEME.to_string(),
    }
}

/// The resolved, immutable look of one session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Look {
    /// A name from the token file's theme registry.
    pub theme: String,
    /// The colour mode. Already forced to [`ColorMode::None`] for a colourless
    /// theme, so nothing downstream has to know that `mono` exists.
    pub mode: ColorMode,
    /// The glyph set.
    pub set: Set,
}

impl Look {
    /// What this session should use, from the environment: `RAGBAZ_THEME`, the
    /// generated colour-mode detection (`NO_COLOR`/`FORCE_COLOR`/`TERM`), and the
    /// generated glyph-set detection (Nerd Font is opt-in, never detected).
    pub fn detect() -> Self {
        let theme = theme_name(std::env::var("RAGBAZ_THEME").ok());
        let set = Set::detect();
        let mode = if design::colorless_themes().contains(&theme.as_str()) {
            // `mono` is a first-class theme, not a degraded one: it disables
            // colour outright rather than relying on the terminal to ignore it.
            ColorMode::None
        } else {
            ColorMode::detect()
        };
        Self { theme, mode, set }
    }

    /// A look chosen by the caller rather than by the environment. Used by the
    /// tests, which must not depend on the terminal they run under.
    pub fn new(theme: &str, mode: ColorMode, set: Set) -> Self {
        let look = Self {
            theme: theme.to_string(),
            mode,
            set,
        };
        // Same rule as `detect`: asking for a colourless theme means no colour.
        Self {
            mode: if design::colorless_themes().contains(&look.theme.as_str()) {
                ColorMode::None
            } else {
                look.mode
            },
            ..look
        }
    }
}

/// Roles resolved for one theme and one colour mode.
///
/// This is the single place a ratatui [`Color`] is built in this crate. Every
/// other module asks for a role and gets a [`Style`].
#[derive(Clone, Debug)]
pub struct Palette {
    name: String,
    mode: ColorMode,
    set: Set,
    roles: Vec<(&'static str, Option<Color>)>,
}

impl Palette {
    /// Resolve every role in the token file for this look.
    pub fn new(look: &Look) -> Self {
        let table = design::themes().get(look.theme.as_str());
        let roles = design::ROLES
            .iter()
            .map(|(role, _)| {
                let colour = table
                    .and_then(|theme| theme.get(*role))
                    .and_then(|hex| resolve(hex, look.mode));
                (*role, colour)
            })
            .collect();
        Self {
            name: look.theme.clone(),
            mode: look.mode,
            set: look.set,
            roles,
        }
    }

    /// The theme name, as the title bar reports it.
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn mode(&self) -> ColorMode {
        self.mode
    }

    /// True when nothing at all is coloured: `mono`, `NO_COLOR`, `TERM=dumb`,
    /// or a colour mode of `None`. Every [`Style`] below is then attributes only.
    pub fn colourless(&self) -> bool {
        self.mode == ColorMode::None
    }

    /// The colour for a role, or `None` when colour is off or the role is not in
    /// the token file. A role that is not in the token file is a bug in the
    /// renderer, not a colour to invent, so it is loud in a debug build.
    pub fn colour(&self, role: &str) -> Option<Color> {
        debug_assert!(
            design::ROLES.iter().any(|(known, _)| *known == role),
            "{role:?} is not a role in the ragbaz token file"
        );
        self.roles
            .iter()
            .find(|(known, _)| *known == role)
            .and_then(|(_, colour)| *colour)
    }

    /// Text in one role.
    pub fn style(&self, role: &str) -> Style {
        self.paint(Style::default(), Some(role), None)
    }

    /// Text in one role, with emphasis from the type scale (see the design
    /// language: a terminal's font size belongs to the terminal, so the type
    /// scale maps to modifiers).
    pub fn styled(&self, role: &str, emphasis: Modifier) -> Style {
        self.paint(Style::default().add_modifier(emphasis), Some(role), None)
    }

    /// Text on a filled surface: the token-layer way to say "reverse video".
    ///
    /// In colour, "reverse video" *is* `ink.invert` on the surface role, so that
    /// is what is emitted — setting `REVERSED` as well would invert twice and
    /// land back on the page colour. With no colour there are no roles to ask
    /// for, so the modifier carries it on its own. `docs/layout.md` asks for
    /// both signals on a selection; this is the first of them.
    pub fn inverse(&self, ink: &str, surface: &str, emphasis: Modifier) -> Style {
        if self.colourless() {
            Style::default().add_modifier(emphasis | Modifier::REVERSED)
        } else {
            self.paint(
                Style::default().add_modifier(emphasis),
                Some(ink),
                Some(surface),
            )
        }
    }

    fn paint(&self, base: Style, fg: Option<&str>, bg: Option<&str>) -> Style {
        let mut style = base;
        if let Some(role) = fg {
            if let Some(colour) = self.colour(role) {
                style = style.fg(colour);
            }
        }
        if let Some(role) = bg {
            if let Some(colour) = self.colour(role) {
                style = style.bg(colour);
            }
        }
        style
    }

    /// A glyph, narrowed from the active set along the token policy
    /// (`["nerd", "unicode", "ascii"]`).
    ///
    /// Every `nerd` rendering in the generated table is the empty string, so a
    /// Nerd Font session would otherwise draw *nothing* where a status glyph
    /// belongs. Skipping empty entries is the narrowing the policy describes,
    /// not a change to a token value.
    pub fn glyph(&self, key: &str) -> &'static str {
        debug_assert!(
            design::GLYPH_KEYS.contains(&key),
            "{key:?} is not a glyph key in the ragbaz token file"
        );
        let chain: &[Set] = match self.set {
            Set::Nerd => &[Set::Nerd, Set::Unicode, Set::Ascii],
            Set::Unicode => &[Set::Unicode, Set::Ascii],
            Set::Ascii => &[Set::Ascii],
        };
        for set in chain {
            let glyph = design::glyph(key, *set);
            if !glyph.is_empty() {
                return glyph;
            }
        }
        "?"
    }

    /// The box-drawing set for ratatui's blocks, mapped from the glyph keys
    /// rather than from ratatui's own constants, so the ascii narrowing applies
    /// to the borders as well as to the text.
    pub fn border(&self) -> border::Set<'static> {
        border::Set {
            top_left: self.glyph("box_tl"),
            top_right: self.glyph("box_tr"),
            bottom_left: self.glyph("box_bl"),
            bottom_right: self.glyph("box_br"),
            vertical_left: self.glyph("box_vl"),
            vertical_right: self.glyph("box_vr"),
            horizontal_top: self.glyph("box_h"),
            horizontal_bottom: self.glyph("box_h"),
        }
    }
}

/// The ladder rung a mode names on screen. `Display` cannot be implemented for
/// [`ColorMode`] here — the type is generated and the trait is foreign — so the
/// one string a surface needs is spelled out in one place.
pub fn rung(mode: ColorMode) -> &'static str {
    match mode {
        ColorMode::TrueColor => "truecolor",
        ColorMode::Ansi256 => "ansi256",
        ColorMode::Ansi16 => "ansi16",
        ColorMode::None => "none",
    }
}

/// One rung of the ladder: a theme's hex, narrowed for the detected mode.
fn resolve(hex: &str, mode: ColorMode) -> Option<Color> {
    match mode {
        ColorMode::TrueColor => {
            let (r, g, b) = hex_rgb(hex);
            Some(Color::Rgb(r, g, b))
        }
        ColorMode::Ansi256 => Some(Color::Indexed(design::nearest256(hex))),
        ColorMode::Ansi16 => Some(Color::Indexed(design::nearest16(hex))),
        ColorMode::None => None,
    }
}

/// `#rrggbb` → three channels. `design` keeps its own copy private, and adding a
/// public helper to a generated file is not an option.
fn hex_rgb(hex: &str) -> (u8, u8, u8) {
    let digits = hex.trim_start_matches('#');
    let channel = |at: usize| -> u8 {
        u8::from_str_radix(digits.get(at..at + 2).unwrap_or("00"), 16).unwrap_or(0)
    };
    (channel(0), channel(2), channel(4))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::design;

    fn palette(theme: &str, mode: ColorMode) -> Palette {
        Palette::new(&Look::new(theme, mode, Set::Unicode))
    }

    #[test]
    fn a_terminal_gets_the_night_theme_and_a_named_theme_wins() {
        // The choice, asserted: terminals are dark.
        assert_eq!(theme_name(None), DEFAULT_TUI_THEME);
        assert_eq!(theme_name(Some("ragbaz-night".into())), "ragbaz-night");
        assert_eq!(theme_name(Some("ragbaz-white".into())), "ragbaz-white");
        // An unknown name is the design system's default, never a crash and
        // never a palette invented here.
        assert_eq!(theme_name(Some("nope".into())), design::DEFAULT_THEME);
    }

    #[test]
    fn every_role_resolves_in_every_theme_that_defines_one() {
        for theme in design::themes().keys() {
            if design::colorless_themes().contains(theme) {
                continue;
            }
            for (role, _) in design::ROLES {
                assert!(
                    palette(theme, ColorMode::TrueColor).colour(role).is_some(),
                    "{theme} has no {role}"
                );
            }
        }
    }

    #[test]
    fn the_ladder_widens_nothing_and_narrows_everywhere() {
        for theme in design::themes().keys() {
            if design::colorless_themes().contains(theme) {
                continue;
            }
            for (mode, expected) in [
                (ColorMode::None, false),
                (ColorMode::Ansi16, true),
                (ColorMode::Ansi256, true),
                (ColorMode::TrueColor, true),
            ] {
                let palette = palette(theme, mode);
                let colour = palette.colour("ink.body");
                assert_eq!(colour.is_some(), expected, "{theme} {mode:?}");
                if mode == ColorMode::Ansi16 || mode == ColorMode::Ansi256 {
                    let hex = design::themes()[theme]["ink.body"];
                    let index = match colour {
                        Some(Color::Indexed(i)) => i,
                        other => panic!("{theme} {mode:?} did not narrow: {other:?}"),
                    };
                    let want = if mode == ColorMode::Ansi16 {
                        design::nearest16(hex)
                    } else {
                        design::nearest256(hex)
                    };
                    assert_eq!(index, want);
                }
            }
        }
    }

    #[test]
    fn mono_disables_colour_whichever_mode_was_detected() {
        for mode in [
            ColorMode::TrueColor,
            ColorMode::Ansi256,
            ColorMode::Ansi16,
            ColorMode::None,
        ] {
            let palette = palette("mono", mode);
            assert_eq!(palette.mode(), ColorMode::None);
            for (role, _) in design::ROLES {
                assert!(palette.colour(role).is_none(), "mono coloured {role}");
            }
            // Attributes survive: that is what makes it a theme, not a blank.
            assert!(palette
                .styled("status.ok", Modifier::BOLD)
                .add_modifier
                .contains(Modifier::BOLD));
        }
    }

    #[test]
    fn inverse_is_the_modifier_without_colour_and_the_roles_with_it() {
        let mono = palette("mono", ColorMode::None);
        let reversed = mono.inverse("ink.invert", "surface.raise", Modifier::empty());
        assert!(reversed.add_modifier.contains(Modifier::REVERSED));

        let colour = palette("ragbaz-night", ColorMode::TrueColor);
        let filled = colour.inverse("ink.invert", "surface.raise", Modifier::BOLD);
        assert!(!filled.add_modifier.contains(Modifier::REVERSED));
        assert_eq!(filled.fg, colour.colour("ink.invert"));
        assert_eq!(filled.bg, colour.colour("surface.raise"));
        assert!(filled.add_modifier.contains(Modifier::BOLD));
    }

    #[test]
    fn glyphs_narrow_to_ascii_and_never_to_nothing() {
        let unicode = palette("ragbaz", ColorMode::None).glyph("check");
        assert_eq!(unicode, "\u{2713}");
        // Nerd is opt-in, and every nerd rendering in the token file is empty,
        // so asking for it must still draw the check.
        let nerd = Palette::new(&Look::new("ragbaz", ColorMode::None, Set::Nerd));
        assert_eq!(nerd.glyph("check"), "\u{2713}");
        let ascii = Palette::new(&Look::new("ragbaz", ColorMode::None, Set::Ascii));
        assert_eq!(ascii.glyph("check"), "+");
        assert_eq!(ascii.glyph("ellipsis"), "...");
        // And the borders narrow with them.
        assert_eq!(ascii.border().top_left, "+");
        assert_eq!(ascii.border().horizontal_top, "-");
    }

    #[test]
    fn a_detected_look_is_always_a_theme_the_token_file_defines() {
        // Whatever the environment says, `detect` cannot produce a theme name the
        // token file does not define, and `mono` cannot come back coloured.
        let look = Look::detect();
        assert!(design::themes().contains_key(look.theme.as_str()));
        let palette = Palette::new(&look);
        assert_eq!(
            palette.colourless(),
            design::colorless_themes().contains(&look.theme.as_str())
                || look.mode == ColorMode::None
        );
    }

    #[test]
    fn the_space_scale_is_used_for_gaps_rather_than_a_bare_number() {
        assert_eq!(space(CELL_GAP), 1);
        assert_eq!(gap(CELL_GAP), " ");
        // Out of range is clamped rather than panicking: the scale is 0..=8.
        assert_eq!(space(99), *SPACE_CELLS.last().unwrap() as u16);
    }
}
