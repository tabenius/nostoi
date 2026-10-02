//! `nostoi tui`: browse a chain, see where it breaks, follow it live.

use crate::{open, Entry, Format, Report};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Wrap};
use ratatui::Frame;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

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
    /// Whether the detail pane is showing a record or the attestation.
    pane: Pane,
    quit: bool,
}

/// What the detail pane is showing.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pane {
    Record,
    Attestation,
}

impl App {
    pub fn new(path: &Path, format: Option<Format>) -> Self {
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
            pane: Pane::Record,
            quit: false,
        };
        app.reload();
        app
    }

    /// Re-read and re-verify the chain; keep the selection where it was.
    pub fn reload(&mut self) {
        let selected = self.selected().map(|e| e.seq);
        match open(&self.path, self.format) {
            Ok(loaded) => {
                let report = loaded.verify();
                self.attestation = crate::attest::summary(
                    &self.path,
                    report.head.as_ref().map_or(0, |head| head.seq),
                );
                self.report = Some(report);
                self.entries = loaded.entries;
                self.error = None;
            }
            Err(error) => {
                self.attestation = crate::attest::summary(&self.path, 0);
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

    pub fn key(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }
        if self.editing_filter {
            match key.code {
                KeyCode::Enter | KeyCode::Esc => self.editing_filter = false,
                KeyCode::Backspace => {
                    self.filter.pop();
                    self.refilter();
                }
                KeyCode::Char(c) => {
                    self.filter.push(c);
                    self.refilter();
                }
                _ => {}
            }
            return;
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => self.quit = true,
            KeyCode::Down | KeyCode::Char('j') => self.step(1),
            KeyCode::Up | KeyCode::Char('k') => self.step(-1),
            KeyCode::PageDown => self.step(20),
            KeyCode::PageUp => self.step(-20),
            KeyCode::Home | KeyCode::Char('g') => self.step(isize::MIN / 2),
            KeyCode::End | KeyCode::Char('G') => self.last(),
            KeyCode::Char('b') => self.jump_to_break(),
            KeyCode::Char('/') => self.editing_filter = true,
            KeyCode::Char('f') => {
                self.follow = !self.follow;
                if self.follow {
                    self.reload();
                }
            }
            KeyCode::Char('r') => self.reload(),
            KeyCode::Char('a') => {
                self.pane = if self.pane == Pane::Record {
                    Pane::Attestation
                } else {
                    Pane::Record
                };
                self.detail = true;
            }
            KeyCode::Enter | KeyCode::Char('d') => self.detail = !self.detail,
            _ => {}
        }
    }

    pub fn draw(&mut self, frame: &mut Frame) {
        let detail_height = if self.detail {
            Constraint::Percentage(40)
        } else {
            Constraint::Length(0)
        };
        let [status, table, detail, help] = Layout::vertical([
            // Verdict, plus an attestation line that may need two wrapped rows.
            // Truncating it would hide the very thing being reported.
            Constraint::Length(5),
            Constraint::Min(5),
            detail_height,
            Constraint::Length(1),
        ])
        .areas(frame.area());
        self.draw_status(frame, status);
        self.draw_table(frame, table);
        if self.detail {
            self.draw_detail(frame, detail);
        }
        self.draw_help(frame, help);
    }

    fn draw_status(&self, frame: &mut Frame, area: Rect) {
        let (mark, color, text) = match (&self.error, &self.report) {
            (Some(error), _) => ("✗", Color::Red, error.clone()),
            (None, Some(report)) => match &report.problem {
                None => (
                    "✓",
                    Color::Green,
                    format!(
                        "{} records intact · head {}",
                        report.records,
                        report.head.as_ref().map_or("(empty)".into(), |h| format!(
                            "{} {}",
                            h.seq,
                            h.digest.get(..16).unwrap_or(&h.digest)
                        ))
                    ),
                ),
                Some(problem) => (
                    "✗",
                    Color::Red,
                    format!(
                        "{problem} · {} (b: jump there)",
                        crate::chain::intact(report.verified)
                    ),
                ),
            },
            (None, None) => ("…", Color::Gray, "reading".into()),
        };
        let format = self
            .report
            .as_ref()
            .map_or("?", |r| r.format.as_str())
            .to_string();
        let mut title = vec![
            Span::raw(" Nostoi ").bold(),
            Span::raw(format!("· {} · {format} ", self.path.display())),
        ];
        if self.follow {
            title.push(Span::raw("· following ").fg(Color::Yellow));
        }
        // Two lines: the verdict, then the attestation state.
        let lines = vec![
            Line::from(vec![
                Span::styled(
                    format!(" {mark} "),
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(text, Style::default().fg(color)),
            ]),
            Line::from(Span::styled(
                format!(" {}", self.attestation),
                Style::default().fg(Color::DarkGray),
            )),
        ];
        frame.render_widget(
            Paragraph::new(lines).wrap(Wrap { trim: false }).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(Line::from(title)),
            ),
            area,
        );
    }

    fn draw_table(&mut self, frame: &mut Frame, area: Rect) {
        let rows: Vec<Row> = self
            .visible
            .iter()
            .map(|&i| {
                let e = &self.entries[i];
                let ok = self.verified(e);
                let mark = if ok {
                    Span::raw("✓").fg(Color::Green)
                } else {
                    Span::raw("✗").fg(Color::Red)
                };
                let row = Row::new(vec![
                    Cell::from(mark),
                    Cell::from(e.seq.to_string()),
                    Cell::from(e.at.clone().unwrap_or_default()),
                    Cell::from(e.actor.clone().unwrap_or_default()),
                    Cell::from(e.kind.clone()),
                    Cell::from(e.subject.clone().unwrap_or_default()),
                    Cell::from(e.digest.get(..12).unwrap_or(&e.digest).to_string()),
                ]);
                if ok {
                    row
                } else {
                    row.style(Style::default().fg(Color::Red))
                }
            })
            .collect();
        let filter = if self.filter.is_empty() && !self.editing_filter {
            String::new()
        } else {
            format!(
                " filter: {}{} ",
                self.filter,
                if self.editing_filter { "▏" } else { "" }
            )
        };
        let table = Table::new(
            rows,
            [
                Constraint::Length(1),
                Constraint::Length(7),
                Constraint::Length(24),
                Constraint::Length(18),
                Constraint::Min(16),
                Constraint::Length(20),
                Constraint::Length(12),
            ],
        )
        .header(
            Row::new(["", "seq", "at", "actor", "kind", "subject", "digest"])
                .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .block(Block::default().borders(Borders::ALL).title(format!(
            " records {}/{} {filter}",
            self.visible.len(),
            self.entries.len()
        )))
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));
        frame.render_stateful_widget(table, area, &mut self.table);
    }

    fn draw_detail(&self, frame: &mut Frame, area: Rect) {
        if self.pane == Pane::Attestation {
            let (title, body) = match crate::attest::present(&self.path) {
                Some((attestation, _)) => (
                    format!(
                        " attestation seq={} · signature NOT checked here ",
                        attestation.seq
                    ),
                    serde_json::to_string_pretty(&attestation).unwrap_or_default(),
                ),
                None => (
                    " attestation ".into(),
                    format!(
                        "{}\n\nsign one with:\n  nostoi attest {} --principal you@host\n\n\
                         check an existing one with:\n  nostoi verify-attestation {} \
                         --allowed-signers FILE --principal you@host --fingerprint SHA256:…",
                        crate::attest::summary(&self.path, 0),
                        self.path.display(),
                        self.path.display()
                    ),
                ),
            };
            frame.render_widget(
                Paragraph::new(body)
                    .wrap(Wrap { trim: false })
                    .block(Block::default().borders(Borders::ALL).title(title)),
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
                    format!(" record {} · {verdict} ", entry.seq),
                    serde_json::to_string_pretty(&entry.record).unwrap_or_default(),
                )
            }
            None => (" record ".into(), String::new()),
        };
        frame.render_widget(
            Paragraph::new(body)
                .wrap(Wrap { trim: false })
                .block(Block::default().borders(Borders::ALL).title(title)),
            area,
        );
    }

    fn draw_help(&self, frame: &mut Frame, area: Rect) {
        let help = " ↑↓/jk move · g/G ends · b break · / filter · f follow · r reload · \
                    a attestation · ⏎ detail · q quit";
        frame.render_widget(Paragraph::new(help).fg(Color::DarkGray), area);
    }
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
    use crate::{append, Draft, Head};
    use crossterm::event::KeyEventState;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use serde_json::json;

    fn press(app: &mut App, code: KeyCode) {
        app.key(KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        });
    }

    fn chain(dir: &Path) -> PathBuf {
        let path = dir.join("audit.jsonl");
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

    #[test]
    fn browses_filters_and_shows_the_verdict() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = App::new(&chain(dir.path()), None);
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
    fn a_broken_chain_is_red_and_b_jumps_to_the_break() {
        let dir = tempfile::tempdir().unwrap();
        let path = chain(dir.path());
        let text = std::fs::read_to_string(&path)
            .unwrap()
            .replacen("tool.call", "tool.KALL", 1);
        std::fs::write(&path, text).unwrap();
        let mut app = App::new(&path, None);
        assert!(screen(&mut app).contains("record 2 was altered"));
        press(&mut app, KeyCode::Char('G'));
        press(&mut app, KeyCode::Char('b'));
        assert_eq!(app.selected().unwrap().seq, 2);
        press(&mut app, KeyCode::Char('q'));
        assert!(app.quit);
    }
}
