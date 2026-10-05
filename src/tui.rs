//! `nostoi tui`: browse a chain, see where it breaks, follow it live.
//!
//! # What is borrowed and what is not
//!
//! Every colour here is a *role* — `status.ok`, `ink.muted`, `edge.focus` — and
//! every role is resolved through [`crate::theme`], which owns the token ladder.
//! There is no colour literal in this file, and a test says so. Every glyph is a
//! *key* resolved through the same module, and the legend strip is generated from
//! the one binding table in [`crate::bindings`], which the dispatcher also reads,
//! so the help cannot describe a key that does nothing.
//!
//! See `design-system/docs/layout.md` for the grammar this follows: chrome rows
//! are counts, not percentages; a selection is a marker glyph *and* reverse
//! video; status is a glyph and a word as well as a colour, so `mono` is a
//! first-class theme rather than a broken one.
//!
//! # What is deliberately not adopted
//!
//! The frame in `layout.md` is three *panes* across, chosen for a browser that
//! navigates a fleet of boxes. This browser is a vertical reader of one chain, so
//! the pane split is not adopted — that is a layout decision, not a token one —
//! but the chrome grammar is: title bar 1, status 1, legend 1, content flexing,
//! and every gap taken from the space scale.

use crate::bindings::{self, Op, View};
use crate::theme::{self, Palette};
use crate::{open, Entry, Format, Report};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, HighlightSpacing, Paragraph, Row, Table, TableState, Wrap,
};
use ratatui::Frame;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
#[path = "runtime_status.rs"]
mod runtime_status;

/// How much of a digest to show in the status line and the table.
///
/// The whole digest is in the detail pane, and `Digest` is 64 hex characters,
/// which does not fit a one-row status line at any sane width. Truncation is
/// display-only and the full value is always one keypress away.
const DIGEST_CELLS: usize = 16;

/// Rows the attestation summary is given.
///
/// It wraps: `attest::describe` appends the staleness verdict and the commands
/// that fix it, and truncating that would hide the very thing being reported. So
/// it is content with a fixed row count, not a one-row status line.
const ATTESTATION_ROWS: u16 = 3;

/// Rows a `page` key moves. `ui.list_page` in the design system's configuration
/// schema; the entry stays where it is put, rather than being derived from the
/// viewport, so a resize does not move the selection.
const PAGE_ROWS: isize = 20;

/// The gap between legend entries, and between the title bar's ends. `layout.md`
/// names `space.2` for both; in the terminal projection that is one cell.
const LEGEND_GAP: usize = 2;

/// Rows the records table is given at minimum, and rows the detail pane needs
/// before it is worth showing. Together they are the point at which the detail
/// pane stops fitting, which is the ladder's "detail is the last thing to go".
const MIN_TABLE_ROWS: u16 = 5;
const MIN_DETAIL_ROWS: u16 = 4;

/// The browser's state, kept apart from the terminal so it can be tested.
pub struct App {
    path: PathBuf,
    format: Option<Format>,
    entries: Vec<Entry>,
    report: Option<Report>,
    error: Option<String>,
    /// Indexes into `entries` that match the filter.
    visible: Vec<usize>,
    table: TableState,
    filter: String,
    editing_filter: bool,
    follow: bool,
    detail: bool,
    /// One line about the chain's attestation, shown under the status.
    attestation: String,
    /// The document, read on reload so drawing never reads a file.
    attestation_document: Option<crate::attest::ReadDocument>,
    /// Which detail view is showing.
    pane: Pane,
    quit: bool,
    runtime: String,
    runtime_scroll: u16,
    /// The resolved theme, colour mode and glyph set for this session.
    palette: Palette,
}

/// What the detail pane is showing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Pane {
    Record,
    Attestation,
    Runtime,
}

impl Pane {
    /// The name the title bar and the binding table agree on.
    fn view(self) -> View {
        match self {
            Pane::Record => View::Record,
            Pane::Attestation => View::Attestation,
            Pane::Runtime => View::Runtime,
        }
    }

    fn title(self) -> &'static str {
        match self {
            Pane::Record => "records",
            Pane::Attestation => "attestation",
            Pane::Runtime => "runtime",
        }
    }

    fn next(self) -> Pane {
        match self {
            Pane::Record => Pane::Attestation,
            Pane::Attestation => Pane::Runtime,
            Pane::Runtime => Pane::Record,
        }
    }

    fn previous(self) -> Pane {
        match self {
            Pane::Record => Pane::Runtime,
            Pane::Attestation => Pane::Record,
            Pane::Runtime => Pane::Attestation,
        }
    }

    fn toggle(self) -> Pane {
        if self == Pane::Attestation {
            Pane::Record
        } else {
            Pane::Attestation
        }
    }
}

impl App {
    pub fn new(path: &Path, format: Option<Format>) -> Self {
        Self::with_look(path, format, theme::Look::detect())
    }

    /// The same browser with a chosen look. [`App::new`] is the environment's
    /// answer; this is how a caller — or a test, which must not depend on the
    /// terminal it runs under — asks for a specific theme, colour mode or glyph
    /// set.
    pub fn with_look(path: &Path, format: Option<Format>, look: theme::Look) -> Self {
        let mut app = App {
            path: path.to_path_buf(),
            format,
            entries: Vec::new(),
            report: None,
            error: None,
            visible: Vec::new(),
            table: TableState::default(),
            filter: String::new(),
            editing_filter: false,
            follow: false,
            detail: true,
            attestation: String::new(),
            attestation_document: None,
            pane: Pane::Record,
            quit: false,
            runtime: String::new(),
            runtime_scroll: 0,
            palette: Palette::new(&look),
        };
        app.reload();
        app
    }

    /// Re-read and re-verify the chain; keep the selection where it was.
    pub fn reload(&mut self) {
        self.runtime = runtime_status::read();
        let selected = self.selected().map(|e| e.seq);
        match open(&self.path, self.format) {
            Ok(loaded) => {
                let report = loaded.verify();
                // Read the attestation once per reload rather than once per frame:
                // drawing happens many times a second, and this parses a file.
                self.read_attestation(report.head.as_ref().map_or(0, |head| head.seq));
                self.report = Some(report);
                self.entries = loaded.entries;
                self.error = None;
            }
            Err(error) => {
                self.read_attestation(0);
                self.error = Some(error.to_string());
            }
        }
        self.refilter();
        if self.follow {
            self.last();
        } else if let Some(seq) = selected {
            if let Some(pos) = self
                .visible
                .iter()
                .position(|&i| self.entries[i].seq == seq)
            {
                self.table.select(Some(pos));
            }
        }
    }

    fn refilter(&mut self) {
        let needle = self.filter.to_lowercase();
        self.visible = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| {
                needle.is_empty()
                    || [
                        Some(e.kind.as_str()),
                        e.actor.as_deref(),
                        e.subject.as_deref(),
                    ]
                    .into_iter()
                    .flatten()
                    .any(|field| field.to_lowercase().contains(&needle))
            })
            .map(|(i, _)| i)
            .collect();
        match self.table.selected() {
            _ if self.visible.is_empty() => self.table.select(None),
            Some(pos) if pos >= self.visible.len() => {
                self.table.select(Some(self.visible.len() - 1))
            }
            None => self.table.select(Some(0)),
            _ => {}
        }
    }

    pub fn selected(&self) -> Option<&Entry> {
        self.table
            .selected()
            .and_then(|pos| self.visible.get(pos))
            .map(|&i| &self.entries[i])
    }

    fn verified(&self, entry: &Entry) -> bool {
        self.report
            .as_ref()
            .is_some_and(|r| entry.seq <= r.verified)
    }

    fn step(&mut self, delta: isize) {
        if self.visible.is_empty() {
            return;
        }
        let pos = self.table.selected().unwrap_or(0) as isize + delta;
        self.table
            .select(Some(pos.clamp(0, self.visible.len() as isize - 1) as usize));
    }

    fn last(&mut self) {
        if !self.visible.is_empty() {
            self.table.select(Some(self.visible.len() - 1));
        }
    }

    /// Jump to the first record that does not verify.
    fn jump_to_break(&mut self) {
        let Some(problem) = self.report.as_ref().and_then(|r| r.problem.as_ref()) else {
            return;
        };
        let seq = problem.position();
        self.filter.clear();
        self.refilter();
        let pos = self
            .visible
            .iter()
            .position(|&i| self.entries[i].seq >= seq);
        self.table
            .select(pos.or(Some(self.visible.len().saturating_sub(1))));
    }

    /// Refresh the cached attestation state. Everything the browser shows about
    /// an attestation comes from here, so no draw path touches the filesystem.
    fn read_attestation(&mut self, head_seq: u64) {
        self.attestation_document = crate::attest::present(&self.path);
        self.attestation = match &self.attestation_document {
            Some(read) => crate::attest::describe(&read.attestation, head_seq, &self.path),
            None => crate::attest::summary(&self.path, head_seq),
        };
    }

    /// One key event in.
    ///
    /// The table decides what the key means; this function only carries it out.
    /// Nothing here matches on a key code, which is what keeps the legend and the
    /// behaviour from being two lists that drift apart.
    pub fn key(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }
        let Some(binding) = bindings::resolve(self.pane.view(), self.editing_filter, &key) else {
            return;
        };
        self.dispatch(binding.op, &key);
    }

    fn dispatch(&mut self, op: Op, key: &KeyEvent) {
        match op {
            Op::Quit => self.quit = true,
            Op::RuntimeDown => self.runtime_scroll = self.runtime_scroll.saturating_add(1),
            Op::RuntimeUp => self.runtime_scroll = self.runtime_scroll.saturating_sub(1),
            Op::PaneRuntime => {
                self.pane = if self.pane == Pane::Runtime {
                    Pane::Record
                } else {
                    Pane::Runtime
                };
                self.runtime = runtime_status::read();
                self.runtime_scroll = 0;
                self.detail = true;
            }
            Op::MoveDown => self.step(1),
            Op::MoveUp => self.step(-1),
            Op::PageDown => self.step(PAGE_ROWS),
            Op::PageUp => self.step(-PAGE_ROWS),
            Op::First => self.step(isize::MIN / 2),
            Op::Last => self.last(),
            Op::JumpBreak => self.jump_to_break(),
            Op::Filter => self.editing_filter = true,
            Op::Follow => {
                self.follow = !self.follow;
                if self.follow {
                    self.reload();
                }
            }
            Op::Reload => self.reload(),
            Op::ViewNext => {
                self.pane = self.pane.next();
                self.detail = true;
            }
            Op::ViewPrev => {
                self.pane = self.pane.previous();
                self.detail = true;
            }
            Op::PaneAttestation => {
                self.pane = self.pane.toggle();
                self.detail = true;
            }
            Op::ToggleDetail => self.detail = !self.detail,
            Op::FieldAccept | Op::FieldCancel => self.editing_filter = false,
            Op::FieldBackspace => {
                self.filter.pop();
                self.refilter();
            }
            Op::FieldInsert => {
                if let KeyCode::Char(c) = key.code {
                    if !c.is_control() {
                        self.filter.push(c);
                        self.refilter();
                    }
                }
            }
        }
    }

    pub fn draw(&mut self, frame: &mut Frame) {
        // `layout.md`: chrome heights are counts, never percentages, and only the
        // content region flexes. Stated as constraints — three `Length(1)` rows
        // around a `Min(0)` — rather than by computing the geometry by hand,
        // because that is what keeps the three chrome rows intact on a terminal
        // too small for the content, instead of letting the solver eat them.
        let [title, status, content, legend] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .areas(frame.area());
        self.draw_title(frame, title);
        self.draw_status(frame, status);
        self.draw_content(frame, content);
        self.draw_legend(frame, legend);
    }

    /// The content region: the attestation summary, the records table, one blank
    /// row, and the detail pane when there is room for it.
    ///
    /// This is the one rung of `layout.md`'s degradation ladder this surface needs:
    /// content is `height - 3`, and the detail pane is the first thing to go, which
    /// is the rung the ladder itself describes ("nav is never dropped before
    /// detail, because navigation disappearing is more confusing than a detail panel
    /// disappearing"). The rest of the ladder is about the three-pane frame this
    /// surface does not have.
    fn draw_content(&mut self, frame: &mut Frame, area: Rect) {
        let gap = theme::space(theme::CELL_GAP);
        let needed = ATTESTATION_ROWS + gap + MIN_TABLE_ROWS + MIN_DETAIL_ROWS;
        let detail = self.detail && area.height >= needed;
        let [attestation, table, _gap, detail_area] = Layout::vertical([
            Constraint::Length(ATTESTATION_ROWS),
            Constraint::Min(0),
            Constraint::Length(if detail { gap } else { 0 }),
            Constraint::Percentage(40),
        ])
        .areas(area);
        self.draw_attestation(frame, attestation);
        self.draw_table(frame, table);
        if detail {
            self.draw_detail(frame, detail_area);
        }
    }

    /// Row 0. `layout.md`: bold + reverse, `ink.invert` on `surface.chrome`, a
    /// `space` cell of padding at each end and never zero, and the view name on
    /// the left.
    fn draw_title(&self, frame: &mut Frame, area: Rect) {
        let p = &self.palette;
        let pad = theme::gap(theme::CELL_GAP);
        let sep = format!("{pad}{}{pad}", p.glyph("bullet"));
        let left = format!("{pad}{}{pad}", self.pane.title());
        // Right: what is being followed, if anything, then which theme is on and
        // which rung of the ladder it resolved to. Naming the theme on screen is
        // the only way the `RAGBAZ_THEME` fallback is visible rather than merely
        // documented.
        let mut right = String::new();
        if self.follow {
            right.push_str(&format!("{} following{pad}", p.glyph("rec")));
        }
        right.push_str(&format!(
            "{pad}{}{sep}{}{pad}",
            p.name(),
            theme::rung(p.mode())
        ));
        let style = p.inverse("ink.invert", "surface.chrome", Modifier::BOLD);
        // `box_h` in the same attributes, so the bar reads as one surface rather
        // than as text on a coloured row.
        let filler = p
            .glyph("box_h")
            .repeat((area.width as usize).saturating_sub(cells(&left) + cells(&right)));
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(left, style),
                Span::styled(filler, style),
                Span::styled(right, style),
            ])),
            area,
        );
    }

    /// One row: the verdict. Glyph, word and role together, because a status that
    /// is only a colour stops meaning anything the moment the output is a log.
    fn draw_status(&self, frame: &mut Frame, area: Rect) {
        let p = &self.palette;
        let sep = format!(" {} ", p.glyph("bullet"));
        // The hint names a key, so it reads the binding table — and it is only
        // there when that key still works. While the filter has focus `b` types
        // a b, and the hint has nothing truthful to say.
        let jump = bindings::keys_for(
            &bindings::live(self.pane.view(), self.editing_filter),
            Op::JumpBreak,
        );
        let hint = if jump.is_empty() {
            String::new()
        } else {
            format!(" ({jump} jump there)")
        };
        // The verdict is the fact and the hint is a nicety, so on a narrow row the
        // hint is what goes: `layout.md` says the status line summarises, and a
        // summary that displaces the fact it is summarising is worse than a short
        // one.
        let fits = |text: &str| cells(text) + cells(&hint) + 4 <= area.width as usize;
        let (mark, role, text) = match (&self.error, &self.report) {
            (Some(error), _) => (p.glyph("cross"), "status.error", error.clone()),
            (None, Some(report)) => match &report.problem {
                None => (
                    p.glyph("check"),
                    "status.ok",
                    format!(
                        "{} records intact{sep}head{sep}{}",
                        report.records,
                        report.head.as_ref().map_or_else(
                            || "(empty)".into(),
                            |h| format!("{} {}", h.seq, short(&h.digest))
                        )
                    ),
                ),
                Some(problem) => {
                    let verdict =
                        format!("{problem}{sep}{}", crate::chain::intact(report.verified));
                    let text = if fits(&verdict) {
                        format!("{verdict}{hint}")
                    } else {
                        verdict
                    };
                    (p.glyph("cross"), "status.error", text)
                }
            },
            (None, None) => (p.glyph("ellipsis"), "status.pending", "reading".into()),
        };
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(format!(" {mark} "), p.styled(role, Modifier::BOLD)),
                Span::styled(format!("{text} "), p.style(role)),
            ])),
            area,
        );
    }

    /// The attestation state. Content, not chrome, and dimmed as a caption: it
    /// summarises what the detail pane is for.
    fn draw_attestation(&self, frame: &mut Frame, area: Rect) {
        frame.render_widget(
            Paragraph::new(format!(" {}", self.attestation))
                .wrap(Wrap { trim: false })
                .style(self.palette.style("ink.muted")),
            area,
        );
    }

    fn draw_table(&mut self, frame: &mut Frame, area: Rect) {
        let p = &self.palette;
        let marker = p.glyph("dot");
        let rows: Vec<Row> = self
            .visible
            .iter()
            .map(|&i| {
                let e = &self.entries[i];
                let ok = self.verified(e);
                let status = if ok {
                    p.glyph("check")
                } else {
                    p.glyph("cross")
                };
                let row = Row::new(vec![
                    Cell::from(Span::styled(
                        status,
                        p.style(if ok { "status.ok" } else { "status.error" }),
                    )),
                    Cell::from(e.seq.to_string()),
                    Cell::from(Span::styled(
                        e.at.clone().unwrap_or_default(),
                        p.style("ink.muted"),
                    )),
                    Cell::from(e.actor.clone().unwrap_or_default()),
                    Cell::from(e.kind.clone()),
                    Cell::from(e.subject.clone().unwrap_or_default()),
                    Cell::from(Span::styled(short(&e.digest), p.style("ink.code"))),
                ]);
                if ok {
                    row.style(p.style("ink.body"))
                } else {
                    // A record that does not verify is a status, so the row takes
                    // the status role. Cells that carry their own role (the
                    // timestamp, the digest) are the exception the row style
                    // cannot reach, which is why the check glyph and the `b` hint
                    // both also say so in words.
                    row.style(p.style("status.error"))
                }
            })
            .collect();
        let caret = p.glyph("bar_half");
        let filter = if self.filter.is_empty() && !self.editing_filter {
            String::new()
        } else {
            format!(
                " filter: {}{} ",
                self.filter,
                if self.editing_filter { caret } else { "" }
            )
        };
        let format = self
            .report
            .as_ref()
            .map_or("?", |r| r.format.as_str())
            .to_string();
        let border_role = if self.editing_filter {
            "edge.focus"
        } else {
            "edge.rule"
        };
        let table = Table::new(
            rows,
            [
                Constraint::Length(theme::space(theme::CELL_GAP)),
                Constraint::Length(7),
                Constraint::Length(24),
                Constraint::Length(18),
                Constraint::Min(16),
                Constraint::Length(20),
                Constraint::Length(DIGEST_CELLS as u16),
            ],
        )
        .header(
            Row::new(["", "seq", "at", "actor", "kind", "subject", "digest"])
                .style(p.styled("ink.emphasis", Modifier::BOLD)),
        )
        // Focus is three signals: the border role, the caret in the title, and the
        // legend's own "editing" notice. `layout.md`: never a border colour alone.
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_set(p.border())
                .border_style(p.style(border_role))
                .title_style(p.styled("ink.emphasis", Modifier::BOLD))
                .title(format!(
                    " records {}/{}{} {format}{filter} ",
                    self.visible.len(),
                    self.entries.len(),
                    p.glyph("bullet"),
                )),
        )
        // Selection is two signals. The marker is the first, and it is drawn in
        // `ink.emphasis` in a one-cell gutter column; the row style is the second.
        // `Always` rather than ratatui's `WhenSelected`, because a gutter column
        // that appears and disappears moves every column in the row.
        .highlight_spacing(HighlightSpacing::Always)
        .highlight_symbol(Span::styled(
            format!("{marker}{}", theme::gap(theme::CELL_GAP)),
            p.style("ink.emphasis"),
        ))
        .row_highlight_style(p.inverse("ink.invert", "surface.raise", Modifier::empty()));
        frame.render_stateful_widget(table, area, &mut self.table);
    }

    fn draw_detail(&self, frame: &mut Frame, area: Rect) {
        let p = &self.palette;
        let sep = format!(" {} ", p.glyph("bullet"));
        let block = |title: String| {
            Block::default()
                .borders(Borders::ALL)
                .border_set(p.border())
                .border_style(p.style("edge.rule"))
                .title_style(p.styled("ink.emphasis", Modifier::BOLD))
                .title(title)
        };
        if self.pane == Pane::Runtime {
            frame.render_widget(
                Paragraph::new(self.runtime.as_str())
                    .style(p.style("ink.body"))
                    .wrap(Wrap { trim: false })
                    .scroll((self.runtime_scroll, 0))
                    .block(block(" Runtime / URLs / human workflows ".into())),
                area,
            );
            return;
        }
        if self.pane == Pane::Attestation {
            let (title, body) = match &self.attestation_document {
                Some(read) => (
                    format!(
                        " attestation seq={}{sep}signature NOT checked here ",
                        read.attestation.seq
                    ),
                    // Rendered from the parsed document. Nothing a human sees here
                    // is ever read back or compared.
                    serde_json::to_string_pretty(&read.attestation).unwrap_or_default(),
                ),
                None => (
                    " attestation ".into(),
                    format!(
                        "{}\n\nsign one with:\n  nostoi attest {} --principal you@host\n\n\
                         check an existing one with:\n  nostoi verify-attestation {} \
                         --allowed-signers FILE --principal you@host --fingerprint SHA256:{}",
                        self.attestation,
                        self.path.display(),
                        self.path.display(),
                        p.glyph("ellipsis")
                    ),
                ),
            };
            frame.render_widget(
                Paragraph::new(body)
                    .wrap(Wrap { trim: false })
                    .block(block(title)),
                area,
            );
            return;
        }
        let (title, body) = match self.selected() {
            Some(entry) => {
                let verdict = if self.verified(entry) {
                    "verified"
                } else {
                    "NOT verified"
                };
                (
                    format!(" record {}{sep}{verdict} ", entry.seq),
                    serde_json::to_string_pretty(&entry.record).unwrap_or_default(),
                )
            }
            None => (" record ".into(), String::new()),
        };
        frame.render_widget(
            Paragraph::new(body)
                .wrap(Wrap { trim: false })
                .block(block(title)),
            area,
        );
    }

    /// The last row. Generated from the live bindings, so it can only ever
    /// describe keys that resolve to something in this view, in this mode.
    fn draw_legend(&self, frame: &mut Frame, area: Rect) {
        frame.render_widget(Paragraph::new(self.legend(area.width)), area);
    }

    /// The legend strip for `width`: `<keys> <action>` pairs, separated by the
    /// `box_v` glyph with a `space.2` gap, as many as fit.
    fn legend(&self, width: u16) -> Line<'static> {
        let p = &self.palette;
        let separator = format!(
            "{}{}{}",
            theme::gap(LEGEND_GAP),
            p.glyph("box_v"),
            theme::gap(LEGEND_GAP)
        );
        let muted = p.style("ink.muted");
        let mut spans: Vec<Span> = Vec::new();
        let mut used = 0usize;
        // While a field has focus the strip says so in a glyph and a word, not
        // only in the border role of the table block.
        if self.editing_filter {
            let notice = format!("{} field editing", p.glyph("warn"));
            spans.push(Span::styled(notice.clone(), p.style("status.warn")));
            used += cells(&notice);
        }
        for row in bindings::live(self.pane.view(), self.editing_filter) {
            // `char` stands for the printable range rather than naming a key, so
            // printing it would advertise a key nobody can press.
            let entry = if row.keys == [bindings::ANY_CHAR] {
                row.binding.help.to_string()
            } else {
                format!("{} {}", row.keys.join(","), row.binding.help)
            };
            let cost = cells(&entry) + if used == 0 { 0 } else { cells(&separator) };
            if used + cost > width as usize {
                break;
            }
            if used > 0 {
                spans.push(Span::styled(separator.clone(), muted));
            }
            spans.push(Span::styled(entry, muted));
            used += cost;
        }
        Line::from(spans)
    }
}

/// The first `DIGEST_CELLS` characters of a hex digest, for the narrow columns.
/// Character-boundary safe: it splits on chars, never mid-escape or mid-glyph.
fn short(digest: &str) -> String {
    digest.chars().take(DIGEST_CELLS).collect()
}

/// Width of a rendered string in cells.
///
/// Character count, not byte count: every glyph the token table can produce at
/// the default set is one cell wide, so this is exact for what is drawn here.
/// ratatui clips whatever still overflows, per cell, which is what keeps a
/// narrow terminal from being handed half a character.
fn cells(text: &str) -> usize {
    text.chars().count()
}

/// Run the browser until the user quits.
pub fn run(path: &Path, format: Option<Format>) -> std::io::Result<()> {
    let mut app = App::new(path, format);
    let mut terminal = ratatui::init();
    let result = (|| -> std::io::Result<()> {
        let mut last_reload = Instant::now();
        while !app.quit {
            terminal.draw(|frame| app.draw(frame))?;
            if event::poll(Duration::from_millis(250))? {
                if let Event::Key(key) = event::read()? {
                    app.key(key);
                }
            }
            if app.follow && last_reload.elapsed() >= Duration::from_secs(1) {
                app.reload();
                last_reload = Instant::now();
            }
        }
        Ok(())
    })();
    ratatui::restore();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::{Attestation, Sidecars};
    use crate::design::{self, ColorMode, Set};
    use crate::{append, Draft, Head};
    use crossterm::event::KeyEventState;
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;
    use ratatui::style::Color;
    use ratatui::Terminal;
    use serde_json::json;

    fn press(app: &mut App, code: KeyCode) {
        app.key(KeyEvent {
            code,
            modifiers: crossterm::event::KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        });
    }

    fn chain_path(dir: &Path) -> PathBuf {
        dir.join("audit.jsonl")
    }

    fn chain(dir: &Path) -> PathBuf {
        let path = chain_path(dir);
        for (kind, actor) in [
            ("task.claim", "agent:a"),
            ("tool.call", "agent:b"),
            ("task.finish", "agent:a"),
        ] {
            append(
                &path,
                Draft {
                    actor: Some(actor),
                    kind,
                    subject: Some("cs-1"),
                    body: json!({}),
                    at: None,
                },
            )
            .unwrap();
        }
        path
    }

    fn app(dir: &Path) -> App {
        App::new(&chain(dir), None)
    }

    fn look(theme: &str, mode: ColorMode, set: Set) -> theme::Look {
        theme::Look::new(theme, mode, set)
    }

    fn screen(app: &mut App) -> String {
        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();
        terminal.draw(|frame| app.draw(frame)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        buffer
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>()
    }

    fn buffer(app: &mut App) -> Buffer {
        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();
        terminal.draw(|frame| app.draw(frame)).unwrap();
        terminal.backend().buffer().clone()
    }

    /// Everything a key press can change, as one comparable value. Used to hold
    /// the dispatcher to the table: pressing a key must do exactly what running
    /// the action the table names would do.
    fn state(app: &App) -> String {
        format!(
            "pane={:?} quit={} follow={} detail={} editing={} filter={:?} selected={:?} visible={} runtime_scroll={}",
            app.pane,
            app.quit,
            app.follow,
            app.detail,
            app.editing_filter,
            app.filter,
            app.selected().map(|e| e.seq),
            app.visible.len(),
            app.runtime_scroll,
        )
    }

    fn event(key: &str) -> KeyEvent {
        let (code, modifiers) = match key {
            "enter" => (KeyCode::Enter, crossterm::event::KeyModifiers::NONE),
            "esc" => (KeyCode::Esc, crossterm::event::KeyModifiers::NONE),
            "backspace" => (KeyCode::Backspace, crossterm::event::KeyModifiers::NONE),
            "tab" => (KeyCode::Tab, crossterm::event::KeyModifiers::NONE),
            "backtab" => (KeyCode::BackTab, crossterm::event::KeyModifiers::NONE),
            "down" => (KeyCode::Down, crossterm::event::KeyModifiers::NONE),
            "up" => (KeyCode::Up, crossterm::event::KeyModifiers::NONE),
            "home" => (KeyCode::Home, crossterm::event::KeyModifiers::NONE),
            "end" => (KeyCode::End, crossterm::event::KeyModifiers::NONE),
            "pagedown" => (KeyCode::PageDown, crossterm::event::KeyModifiers::NONE),
            "pageup" => (KeyCode::PageUp, crossterm::event::KeyModifiers::NONE),
            other => match other.strip_prefix("C-") {
                Some(rest) => (
                    KeyCode::Char(rest.chars().next().unwrap()),
                    crossterm::event::KeyModifiers::CONTROL,
                ),
                None => (
                    KeyCode::Char(other.chars().next().unwrap()),
                    crossterm::event::KeyModifiers::NONE,
                ),
            },
        };
        KeyEvent {
            code,
            modifiers,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    /// A browser in a given view and mode, over a chain written once, ready for one
    /// key press.
    fn ready(dir: &Path, view: View, editing: bool) -> App {
        let mut app = App::new(&chain_path(dir), None);
        if view == View::Attestation {
            app.pane = Pane::Attestation;
        } else if view == View::Runtime {
            app.pane = Pane::Runtime;
        }
        if editing {
            app.editing_filter = true;
        }
        app
    }

    // ---------------------------------------------------------------------
    // the tokens are bound, not restated
    // ---------------------------------------------------------------------

    #[test]
    fn no_literal_colour_is_constructed_anywhere_in_this_file() {
        // Only the code that draws, not the tests below: the tests assert on
        // colours, and an assertion about a ban must not trip over itself.
        let source = include_str!("tui.rs").split("#[cfg(test)]").next().unwrap();
        let constructor = format!("{}::", "Color");
        for (n, line) in source.lines().enumerate() {
            assert!(
                !line.contains(&constructor),
                "src/tui.rs:{} builds a colour rather than asking for a role: {line}",
                n + 1
            );
            assert!(
                !is_hex_colour(line),
                "src/tui.rs:{} spells a hex colour: {line}",
                n + 1
            );
        }
        assert!(!source.contains("use ratatui::style::Color"));
    }

    /// `#` followed by six hex digits: a colour literal in any of its spellings.
    fn is_hex_colour(line: &str) -> bool {
        line.as_bytes()
            .windows(7)
            .any(|window| window[0] == b'#' && window[1..].iter().all(u8::is_ascii_hexdigit))
    }

    /// The drawing code, for the source-level scans below.
    fn drawn_source() -> &'static str {
        include_str!("tui.rs").split("#[cfg(test)]").next().unwrap()
    }

    #[test]
    fn every_role_this_file_names_is_a_role_in_the_token_file() {
        // Source-level, because a role *is* a sanctioned literal: the check is
        // that none of them is misspelled, which is what makes a typo fail here
        // rather than silently rendering uncoloured.
        let prefixes: Vec<&str> = design::ROLES
            .iter()
            .map(|(role, _)| role.split('.').next().unwrap())
            .collect();
        let mut checked = 0;
        for quote in drawn_source().split('"').skip(1).step_by(2) {
            let named = prefixes
                .iter()
                .any(|prefix| quote.len() > prefix.len() + 1 && quote.starts_with(prefix));
            if !named {
                continue;
            }
            checked += 1;
            assert!(
                design::ROLES.iter().any(|(role, _)| *role == quote),
                "{quote:?} is not a role in the ragbaz token file"
            );
        }
        assert!(
            checked >= 8,
            "only {checked} roles found; the scan is broken"
        );
    }

    #[test]
    fn every_glyph_this_file_names_is_a_glyph_key_in_the_token_file() {
        let mut checked = 0;
        for line in drawn_source().lines() {
            let Some(at) = line.find(".glyph(\"") else {
                continue;
            };
            let key = line[at + ".glyph(\"".len()..].split('"').next().unwrap();
            checked += 1;
            assert!(
                design::GLYPH_KEYS.contains(&key),
                "{key:?} is not a glyph key in the ragbaz token file"
            );
        }
        assert!(
            checked >= 8,
            "only {checked} glyphs found; the scan is broken"
        );
    }

    #[test]
    fn the_colourless_theme_emits_no_colour_attributes_at_all() {
        let dir = tempfile::tempdir().unwrap();
        let path = chain(dir.path());
        for set in [Set::Unicode, Set::Ascii] {
            let mut app = App::with_look(&path, None, look("mono", ColorMode::TrueColor, set));
            let buffer = buffer(&mut app);
            for cell in buffer.content() {
                assert_eq!(cell.fg, Color::Reset, "fg on {:?}", cell.symbol());
                assert_eq!(cell.bg, Color::Reset, "bg on {:?}", cell.symbol());
            }
            // `mono` asked for in colour is still colourless: it is a theme, not a
            // request the terminal may decline.
            assert!(app.palette.colourless());
            assert!(app.palette.colour("status.ok").is_none());
            // But it is not blank: the glyphs and the emphasis are all there.
            assert!(screen(&mut app).contains("3 records intact"));
        }
    }

    #[test]
    fn the_default_theme_is_the_night_one_and_ragbaz_theme_overrides_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = chain(dir.path());
        // The choice the design system asks for, asserted where it is made.
        let mut app = App::with_look(
            &path,
            None,
            theme::Look::new("ragbaz-night", ColorMode::TrueColor, Set::Unicode),
        );
        assert!(screen(&mut app).contains("ragbaz-night"));
        // `RAGBAZ_THEME` is the only override, and it never reaches the CLI.
        let mut app = App::with_look(
            &path,
            None,
            theme::Look::new("ragbaz-white", ColorMode::TrueColor, Set::Unicode),
        );
        let rendered = screen(&mut app);
        assert!(rendered.contains("ragbaz-white"), "{rendered}");
        assert!(!rendered.contains("ragbaz-night"), "{rendered}");
    }

    #[test]
    fn the_selection_is_two_signals_not_one() {
        let dir = tempfile::tempdir().unwrap();
        chain(dir.path());
        // Ask for colour explicitly rather than taking `App::new`'s answer from
        // the environment: on a runner with no terminal, detection settles on
        // `ColorMode::None`, the palette has no colours, and the assertion
        // below would panic instead of testing anything. That is the whole
        // reason `with_look` exists.
        let mut selected = App::with_look(
            &chain_path(dir.path()),
            None,
            look("ragbaz", ColorMode::Ansi256, Set::Ascii),
        );
        let colour = buffer(&mut selected);
        // Signal one: a marker glyph in the one-cell gutter column the table
        // reserves for it, immediately inside the block's border.
        let marker = selected.palette.glyph("dot");
        assert!(
            (0..colour.area.height).any(|y| (0..=1).any(|x| colour[(x, y)].symbol() == marker)),
            "no marker glyph in the gutter column"
        );
        // Signal two: the row itself, as `ink.invert` on `surface.raise` in colour
        // and as the reverse attribute when there is no colour.
        let raised = selected.palette.colour("surface.raise").unwrap();
        assert!(
            colour.content().iter().any(|cell| cell.bg == raised),
            "the selected row is not raised"
        );
        // Without colour it is still both signals: the glyph, and reverse video.
        let mut plain = App::with_look(
            &chain_path(dir.path()),
            None,
            look("mono", ColorMode::None, Set::Ascii),
        );
        let ascii = buffer(&mut plain);
        let marker = plain.palette.glyph("dot");
        assert!(
            (0..ascii.area.height).any(|y| (0..=1).any(|x| ascii[(x, y)].symbol() == marker)),
            "the marker did not survive mono"
        );
        assert!(
            ascii
                .content()
                .iter()
                .any(|cell| cell.modifier.contains(Modifier::REVERSED)),
            "mono lost the reverse signal"
        );
    }

    // ---------------------------------------------------------------------
    // one binding table
    // ---------------------------------------------------------------------

    #[test]
    fn every_key_in_the_table_does_what_the_dispatcher_would_do() {
        let dir = tempfile::tempdir().unwrap();
        for view in [View::Record, View::Attestation, View::Runtime] {
            for editing in [false, true] {
                for row in bindings::live(view, editing) {
                    for key in &row.keys {
                        // Pressing it...
                        let mut pressed = ready(dir.path(), view, editing);
                        pressed.key(event(key));
                        // ...is the same as running the action the table names.
                        let mut dispatched = ready(dir.path(), view, editing);
                        dispatched.dispatch(row.binding.op, &event(key));
                        assert_eq!(
                            state(&pressed),
                            state(&dispatched),
                            "{key} ({}) in {view:?} editing={editing}",
                            row.binding.action
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn runtime_bindings_scroll_the_snapshot_and_yield_to_field_editing() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app(dir.path());
        let selected = app.selected().map(|entry| entry.seq);
        press(&mut app, KeyCode::Char('s'));
        assert_eq!(app.pane, Pane::Runtime);
        app.runtime = "Runtime snapshot: current\nminotaur: running".into();
        assert!(screen(&mut app).contains("minotaur: running"));
        assert!(app
            .legend(10_000)
            .to_string()
            .contains("scroll runtime down"));
        press(&mut app, KeyCode::Char('j'));
        assert_eq!(app.runtime_scroll, 1);
        assert_eq!(app.selected().map(|entry| entry.seq), selected);
        press(&mut app, KeyCode::Char('k'));
        press(&mut app, KeyCode::Char('k'));
        assert_eq!(app.runtime_scroll, 0);
        press(&mut app, KeyCode::Char('/'));
        press(&mut app, KeyCode::Char('s'));
        press(&mut app, KeyCode::Char('j'));
        assert_eq!(app.filter, "sj");
        assert_eq!(app.pane, Pane::Runtime);
        assert_eq!(app.runtime_scroll, 0);
        press(&mut app, KeyCode::Enter);
        press(&mut app, KeyCode::Tab);
        assert_eq!(app.pane, Pane::Record);
        press(&mut app, KeyCode::BackTab);
        assert_eq!(app.pane, Pane::Runtime);
        press(&mut app, KeyCode::Char('a'));
        assert_eq!(app.pane, Pane::Attestation);
        press(&mut app, KeyCode::Char('a'));
        assert_eq!(app.pane, Pane::Record);
    }

    #[test]
    fn the_legend_is_generated_from_the_table_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app(dir.path());
        // Every live binding's wording is on screen, given a wide enough strip.
        let strip = app.legend(10_000).to_string();
        for row in bindings::live(app.pane.view(), false) {
            assert!(
                strip.contains(row.binding.help),
                "the legend omits {}: {strip}",
                row.binding.action
            );
            if row.keys != [bindings::ANY_CHAR] {
                assert!(strip.contains(&row.keys.join(",")));
            }
        }
        // No legend may print a key nobody can press, and `char` is not one: the
        // field's own entry is its help text and nothing in front of it.
        app.editing_filter = true;
        assert!(
            app.legend(10_000).to_string().contains(&format!(
                "{} type into the filter",
                app.palette.glyph("box_v")
            )),
            "the printable-range placeholder was printed as a key"
        );
        app.editing_filter = false;
        // One row, so it is page one of the table: truncated, never invented.
        let narrow = app.legend(24).to_string();
        assert!(cells(&narrow) <= 24, "{narrow}");
        // The separator is the `box_v` glyph, not a typed character.
        assert!(strip.contains(app.palette.glyph("box_v")));
        // And while a field has focus the strip says so in a glyph and a word.
        app.editing_filter = true;
        let editing = app.legend(200).to_string();
        assert!(editing.contains(app.palette.glyph("warn")), "{editing}");
        assert!(editing.contains("field editing"), "{editing}");
    }

    #[test]
    fn a_field_binding_outranks_a_global_one_on_the_same_key() {
        let dir = tempfile::tempdir().unwrap();
        {
            // `esc` quits when no field has focus...
            let mut quitting = app(dir.path());
            assert!(!quitting.quit);
            press(&mut quitting, KeyCode::Esc);
            assert!(quitting.quit);
        }
        {
            // ...and cancels the filter when one has, rather than quitting.
            let mut editing = app(dir.path());
            press(&mut editing, KeyCode::Char('/'));
            for c in "agent:b".chars() {
                press(&mut editing, KeyCode::Char(c));
            }
            assert!(editing.editing_filter);
            assert_eq!(editing.filter, "agent:b");
            press(&mut editing, KeyCode::Esc);
            assert!(!editing.quit, "the global quit ate the field's cancel");
            assert!(!editing.editing_filter);
        }
        {
            // Printable keys go to the field, so `q` types a q and does not quit.
            let mut typing = app(dir.path());
            press(&mut typing, KeyCode::Char('/'));
            for c in "qaG".chars() {
                press(&mut typing, KeyCode::Char(c));
            }
            assert!(!typing.quit);
            assert_eq!(typing.filter, "qaG");
            // `d` is a view key, so it is text here too rather than a pane toggle.
            assert!(typing.detail);
            // `enter` accepts the filter rather than toggling the detail pane.
            press(&mut typing, KeyCode::Enter);
            assert!(!typing.editing_filter);
            assert_eq!(typing.filter, "qaG");
            assert!(typing.detail, "the view binding ate the field's accept");
        }
        {
            // And with no field focused, the same keys are commands again.
            let mut idle = app(dir.path());
            press(&mut idle, KeyCode::Char('d'));
            assert!(!idle.detail);
            press(&mut idle, KeyCode::Enter);
            assert!(idle.detail);
        }
    }

    #[test]
    fn nav_is_suppressed_while_the_filter_has_focus() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app(dir.path());
        let before = app.selected().map(|e| e.seq);
        press(&mut app, KeyCode::Char('/'));
        press(&mut app, KeyCode::Down);
        press(&mut app, KeyCode::Char('G'));
        assert_eq!(app.selected().map(|e| e.seq), before);
        // Once the filter is accepted, navigation is live again.
        press(&mut app, KeyCode::Enter);
        press(&mut app, KeyCode::Char('G'));
        assert_eq!(app.selected().map(|e| e.seq), Some(3));
    }

    #[test]
    fn tab_and_backtab_cycle_the_views_and_nav_follows_the_view() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app(dir.path());
        press(&mut app, KeyCode::Tab);
        assert_eq!(app.pane, Pane::Attestation);
        // Record navigation is scoped to the records view: in the attestation
        // view it must not silently move a selection nothing shows.
        let selected = app.selected().map(|e| e.seq);
        press(&mut app, KeyCode::Down);
        assert_eq!(app.selected().map(|e| e.seq), selected);
        press(&mut app, KeyCode::BackTab);
        assert_eq!(app.pane, Pane::Record);
        press(&mut app, KeyCode::Down);
        assert_ne!(app.selected().map(|e| e.seq), selected);
        // And `a` still toggles, as before.
        press(&mut app, KeyCode::Char('a'));
        assert_eq!(app.pane, Pane::Attestation);
        press(&mut app, KeyCode::Char('a'));
        assert_eq!(app.pane, Pane::Record);
    }

    #[test]
    fn the_ascii_set_narrows_every_glyph_on_screen() {
        let dir = tempfile::tempdir().unwrap();
        let path = chain(dir.path());
        let mut app = App::with_look(&path, None, look("mono", ColorMode::None, Set::Ascii));
        let rendered = screen(&mut app);
        // 3 records intact, and the check glyph is ascii.
        assert!(rendered.contains("3 records intact"), "{rendered}");
        assert!(rendered.contains("+"), "{rendered}");
        for glyph in ["✓", "✗", "●", "│", "─"] {
            assert!(!rendered.contains(glyph), "{glyph} survived narrowing");
        }
    }

    // ---------------------------------------------------------------------
    // the behaviour that was already here
    // ---------------------------------------------------------------------

    #[test]
    fn resizing_never_panics_and_the_legend_stays_on_the_last_row() {
        let dir = tempfile::tempdir().unwrap();
        chain(dir.path());
        // Across the widths and heights a terminal actually gets, including the
        // degenerate ones. `layout.md`'s degradation ladder is a redesign of this
        // surface's geometry rather than a restyle of it, so the claim here is the
        // weaker one that matters for a restyle: no panic, no panic on the way
        // down, and the chrome keeps its fixed row count at every size.
        for (width, height) in [
            (200, 60),
            (120, 30),
            (100, 30),
            (80, 24),
            (76, 24),
            (75, 24),
            (60, 20),
            (40, 12),
            (20, 6),
            (8, 4),
            (4, 1),
        ] {
            let mut app = App::new(&chain_path(dir.path()), None);
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            terminal.draw(|frame| app.draw(frame)).unwrap();
            let buffer = terminal.backend().buffer().clone();
            let legend: String = (0..width)
                .map(|x| buffer[(x, height - 1)].symbol())
                .collect();
            // The last row is the legend strip: dim ink, never a box border, and
            // never the record table.
            assert!(
                !legend.contains('┌') && !legend.contains('└'),
                "{width}x{height}: the chrome lost its row count: {legend}"
            );
        }
    }

    #[test]
    fn browses_filters_and_shows_the_verdict() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = app(dir.path());
        assert!(screen(&mut app).contains("3 records intact"));
        press(&mut app, KeyCode::Char('/'));
        for c in "agent:b".chars() {
            press(&mut app, KeyCode::Char(c));
        }
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.selected().unwrap().kind, "tool.call");
        assert!(screen(&mut app).contains("records 1/3"));
    }

    #[test]
    fn the_attestation_is_summarised_and_can_be_opened() {
        let dir = tempfile::tempdir().unwrap();
        let path = chain(dir.path());
        let mut app = App::new(&path, None);

        // With no attestation, the browser says so and how to make one.
        let rendered = screen(&mut app);
        assert!(rendered.contains("no attestation"), "{rendered}");
        assert!(rendered.contains("nostoi attest"), "{rendered}");

        // `a` shows the instructions when there is nothing to show.
        press(&mut app, KeyCode::Char('a'));
        let rendered = screen(&mut app);
        assert!(rendered.contains("attestation"), "{rendered}");
        assert!(rendered.contains("verify-attestation"), "{rendered}");
        press(&mut app, KeyCode::Char('a'));

        // A document beside the chain is reported in the status line.
        let head = app.report.as_ref().unwrap().head.clone().unwrap();
        let attestation = Attestation::new(
            "kernel",
            "nostoi-v1",
            &head,
            "2026-02-01T12:00:00Z",
            "alice@laptop",
            "SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
            None,
        )
        .unwrap();
        let sidecars = Sidecars::for_chain(&path);
        std::fs::write(&sidecars.document, attestation.canonical_bytes().unwrap()).unwrap();
        std::fs::write(&sidecars.signature, b"placeholder").unwrap();
        app.reload();
        let rendered = screen(&mut app);
        assert!(rendered.contains("attested by alice@laptop"), "{rendered}");
        assert!(rendered.contains("covers the current head"), "{rendered}");
        // Never claims the signature was checked.
        assert!(rendered.contains("signature not checked"), "{rendered}");

        press(&mut app, KeyCode::Char('a'));
        let rendered = screen(&mut app);
        assert!(
            rendered.contains("signature NOT checked here"),
            "{rendered}"
        );
        assert!(rendered.contains("alice@laptop"), "{rendered}");
    }

    #[test]
    fn an_attestation_behind_the_head_is_reported_as_stale() {
        let dir = tempfile::tempdir().unwrap();
        let path = chain(dir.path());
        let head = App::new(&path, None)
            .report
            .as_ref()
            .unwrap()
            .head
            .clone()
            .unwrap();
        let early = Head {
            seq: 1,
            digest: head.digest.clone(),
        };
        let attestation = Attestation::new(
            "kernel",
            "nostoi-v1",
            &early,
            "2026-02-01T12:00:00Z",
            "alice@laptop",
            "SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
            None,
        )
        .unwrap();
        let sidecars = Sidecars::for_chain(&path);
        std::fs::write(&sidecars.document, attestation.canonical_bytes().unwrap()).unwrap();
        std::fs::write(&sidecars.signature, b"placeholder").unwrap();

        let rendered = screen(&mut App::new(&path, None));
        assert!(rendered.contains("stale"), "{rendered}");
        assert!(rendered.contains("the chain is at 3"), "{rendered}");
    }

    #[test]
    fn a_broken_chain_is_reported_and_b_jumps_to_the_break() {
        let dir = tempfile::tempdir().unwrap();
        let path = chain(dir.path());
        let text = std::fs::read_to_string(&path)
            .unwrap()
            .replacen("tool.call", "tool.KALL", 1);
        std::fs::write(&path, text).unwrap();
        let mut app = App::new(&path, None);
        // Named rather than coloured: the glyph and the word, so the verdict
        // survives `mono`, a log, and a screen reader.
        let rendered = screen(&mut app);
        assert!(rendered.contains("record 2 was altered"), "{rendered}");
        assert!(rendered.contains(app.palette.glyph("cross")));
        // And the cross is a real role in a colour theme, not only a glyph.
        let mut coloured = App::with_look(
            &path,
            None,
            look("ragbaz-night", ColorMode::TrueColor, Set::Unicode),
        );
        let buffer = buffer(&mut coloured);
        assert!(
            buffer
                .content()
                .iter()
                .any(|cell| cell.fg == coloured.palette.colour("status.error").unwrap()),
            "a broken chain is not coloured from the status role"
        );
        press(&mut app, KeyCode::Char('G'));
        press(&mut app, KeyCode::Char('b'));
        assert_eq!(app.selected().unwrap().seq, 2);
        press(&mut app, KeyCode::Char('q'));
        assert!(app.quit);
    }
}
