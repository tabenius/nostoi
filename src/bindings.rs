//! One binding table for the browser.
//!
//! The point of this module is what it does *not* contain: there is no second
//! copy of the key list. [`BINDINGS`] is the only table in the crate that names
//! a key, [`live`] is what the legend strip renders, and [`resolve`] is what the
//! dispatcher goes through. A rebind cannot leave the help advertising a
//! binding the dispatcher lacks, because both read the same row.
//!
//! The shape follows `design-system/examples/legend.py`, which is the fleet's
//! reference: a binding carries a `view` and a `scope`, and scope decides
//! precedence.
//!
//! * [`Scope::Field`] is live only while a text field has focus (here: the `/`
//!   filter), and outranks [`Scope::Global`] on the same key.
//! * [`Scope::Nav`] is suppressed while a field has focus, which is the whole of
//!   "arrows and hjkl, unless you are typing".
//! * [`Scope::View`] is bound in every view; [`View::Record`]-scoped navigation is
//!   suppressed in the attestation view, which shows no record selection.
//!
//! The capital-`W` case from the design system — where a global `W` would eat
//! readline's kill-to-end — is the same predicate. Here the colliding keys are
//! `esc` (global quit vs field cancel), `enter` (view detail vs field accept) and
//! every printable character (a global letter key vs the field's own text).
//! [`resolve`] is where that rule lives; there is no per-view special case.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// The detail view a binding belongs to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum View {
    /// Live in every view.
    All,
    /// The records table is what is being selected in this view.
    Record,
    /// The attestation is the subject of this view.
    Attestation,
}

/// Where a binding is live. See the module docs for the precedence rule.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Scope {
    /// Live in both modes, and the *lowest* priority of the live scopes.
    Global,
    /// Bound in the binding's view, and not while a field has focus.
    View,
    /// Movement within the binding's view; suppressed while a field has focus.
    Nav,
    /// Live only while a text field has focus, and the highest priority.
    Field,
}

/// What a binding does. The dispatcher matches on this, never on a key: a key is
/// a name in the table and nothing else.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Op {
    Quit,
    Reload,
    Follow,
    Filter,
    ViewNext,
    ViewPrev,
    PaneAttestation,
    ToggleDetail,
    MoveDown,
    MoveUp,
    PageDown,
    PageUp,
    First,
    Last,
    JumpBreak,
    FieldInsert,
    FieldBackspace,
    FieldAccept,
    FieldCancel,
}

/// One row: what it is called, what it does, which keys, and where it is live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Binding {
    /// A stable, machine-readable name for the action. The legend strip shows
    /// `keys` and `help`, because those are what a person reads in one row; this
    /// is the name a consumer — a test, a future `--json` legend — looks an
    /// action up by, so it is kept even though the strip does not print it.
    #[allow(dead_code)]
    pub action: &'static str,
    /// Key tokens, as [`token`] spells them.
    pub keys: &'static [&'static str],
    /// The wording of the legend entry.
    pub help: &'static str,
    pub view: View,
    pub scope: Scope,
    pub op: Op,
}

/// The key that stands for "a printable character", i.e. the printable range the
/// field owns implicitly because it cannot be written out one key at a time.
pub const ANY_CHAR: &str = "char";

/// The one table.
///
/// In help order, which is also the order the legend strip shows, and the order
/// a key is claimed in: navigation first because the strip is a single row and
/// therefore only ever shows the head of the table, then the view keys, then the
/// globals, then the field's own keys. While a field has focus the field rows
/// sort to the front regardless of where they sit here — see [`live`].
pub const BINDINGS: &[Binding] = &[
    // --- records: selection -------------------------------------------------
    Binding {
        action: "move.next",
        keys: &["down", "j"],
        help: "next record",
        view: View::Record,
        scope: Scope::Nav,
        op: Op::MoveDown,
    },
    Binding {
        action: "move.prev",
        keys: &["up", "k"],
        help: "previous record",
        view: View::Record,
        scope: Scope::Nav,
        op: Op::MoveUp,
    },
    Binding {
        action: "move.page_next",
        keys: &["pagedown"],
        help: "page down",
        view: View::Record,
        scope: Scope::Nav,
        op: Op::PageDown,
    },
    Binding {
        action: "move.page_prev",
        keys: &["pageup"],
        help: "page up",
        view: View::Record,
        scope: Scope::Nav,
        op: Op::PageUp,
    },
    Binding {
        action: "move.first",
        keys: &["home", "g"],
        help: "first record",
        view: View::Record,
        scope: Scope::Nav,
        op: Op::First,
    },
    Binding {
        action: "move.last",
        keys: &["end", "G"],
        help: "last record",
        view: View::Record,
        scope: Scope::Nav,
        op: Op::Last,
    },
    Binding {
        action: "jump.break",
        keys: &["b"],
        help: "jump to the break",
        view: View::Record,
        scope: Scope::Nav,
        op: Op::JumpBreak,
    },
    // --- every view ---------------------------------------------------------
    Binding {
        action: "view.next",
        keys: &["tab"],
        help: "next view",
        view: View::All,
        scope: Scope::Global,
        op: Op::ViewNext,
    },
    Binding {
        action: "view.prev",
        keys: &["backtab"],
        help: "previous view",
        view: View::All,
        scope: Scope::Global,
        op: Op::ViewPrev,
    },
    Binding {
        action: "pane.attestation",
        keys: &["a"],
        help: "attestation view",
        view: View::All,
        scope: Scope::View,
        op: Op::PaneAttestation,
    },
    Binding {
        action: "pane.detail",
        keys: &["d", "enter"],
        help: "detail pane",
        view: View::All,
        scope: Scope::View,
        op: Op::ToggleDetail,
    },
    // --- globals ------------------------------------------------------------
    Binding {
        action: "filter",
        keys: &["/"],
        help: "filter records",
        view: View::All,
        scope: Scope::Global,
        op: Op::Filter,
    },
    Binding {
        action: "follow",
        keys: &["f"],
        help: "follow the tail",
        view: View::All,
        scope: Scope::Global,
        op: Op::Follow,
    },
    Binding {
        action: "reload",
        keys: &["r"],
        help: "reload and re-verify",
        view: View::All,
        scope: Scope::Global,
        op: Op::Reload,
    },
    Binding {
        action: "quit",
        keys: &["q", "esc", "C-c"],
        help: "quit",
        view: View::All,
        scope: Scope::Global,
        op: Op::Quit,
    },
    // --- the filter field: live only while it has focus ---------------------
    Binding {
        action: "field.insert",
        keys: &[ANY_CHAR],
        help: "type into the filter",
        view: View::All,
        scope: Scope::Field,
        op: Op::FieldInsert,
    },
    Binding {
        action: "field.delete",
        keys: &["backspace"],
        help: "delete a character",
        view: View::All,
        scope: Scope::Field,
        op: Op::FieldBackspace,
    },
    Binding {
        action: "field.accept",
        keys: &["enter"],
        help: "accept the filter",
        view: View::All,
        scope: Scope::Field,
        op: Op::FieldAccept,
    },
    Binding {
        action: "field.cancel",
        keys: &["esc"],
        help: "cancel the filter",
        view: View::All,
        scope: Scope::Field,
        op: Op::FieldCancel,
    },
];

/// A binding as it is live right now: the row, plus the keys of it that still
/// fire. A row can lose a key without losing the binding — `q` types a q while the
/// filter has focus, but `C-c` on the same row still quits — and the legend has to
/// print the keys that work, not the keys the row was written with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Live {
    pub binding: &'static Binding,
    pub keys: Vec<&'static str>,
}

/// The bindings live in `view` right now, in the order the legend shows them.
///
/// A key is claimed once: the first binding that owns it wins, which is why the
/// order of [`BINDINGS`] is load-bearing rather than cosmetic.
pub fn live(view: View, editing: bool) -> Vec<Live> {
    let mut rows: Vec<&'static Binding> = BINDINGS
        .iter()
        .filter(|binding| binding.view == View::All || binding.view == view)
        .filter(|binding| is_live(binding, editing))
        .collect();
    if editing {
        // A field owns the keys it is given, so its rows are consulted first.
        // Stable, so the table's own order still decides within a scope.
        rows.sort_by_key(|binding| match binding.scope {
            Scope::Field => 0,
            _ => 1,
        });
    }
    let mut claimed: Vec<&str> = Vec::new();
    let mut live: Vec<Live> = Vec::new();
    for row in rows {
        let keys: Vec<&'static str> = row
            .keys
            .iter()
            .copied()
            .filter(|key| !claimed.contains(key))
            .filter(|key| !(editing && is_printable_token(key)))
            .collect();
        if keys.is_empty() {
            // Nothing left to claim, so nothing to list: the legend must not
            // advertise a binding whose every key has stopped working.
            continue;
        }
        claimed.extend_from_slice(&keys);
        live.push(Live { binding: row, keys });
    }
    live
}

/// Whether one binding is live at all. This is the scope half of the rule; [`live`]
/// adds the per-key half. Both the legend and the dispatcher go through `live`, so
/// they cannot disagree about what a key does.
fn is_live(binding: &Binding, editing: bool) -> bool {
    match binding.scope {
        Scope::Field => editing,
        // Nav and view keys go quiet while a field has focus: they are commands,
        // and the field is where the printable ones belong.
        Scope::Nav | Scope::View => !editing,
        // A global is live either way. Whether each of its *keys* still fires is
        // decided per key in `live`, because a global may bind both a printable
        // letter and a control key, and only one of them stops working.
        Scope::Global => true,
    }
}

/// Whether a key token names a printable character, i.e. one the field owns.
fn is_printable_token(token: &str) -> bool {
    token.chars().count() == 1
}

/// The binding a key event means right now, or `None` when nothing claims it.
///
/// `editing` is the one predicate for "a text field has focus". It decides three
/// things at once: nav and view keys go quiet, field rows come alive, and a
/// printable character belongs to the field unless a *field* row names it
/// explicitly. [`live`] is what the legend asks, so the two agree by
/// construction.
pub fn resolve(view: View, editing: bool, key: &KeyEvent) -> Option<&'static Binding> {
    let live = live(view, editing);
    let token = token(key);
    if editing && is_typed_text(key) {
        // Only a field row may claim a printable key. Nothing else can, so `q`
        // types a q rather than quitting and `/` types a slash rather than
        // reopening the filter.
        return field_row(&live, &token)
            .or_else(|| field_row(&live, ANY_CHAR))
            .map(|row| row.binding);
    }
    live.iter()
        .find(|row| row.keys.contains(&token.as_str()))
        .map(|row| row.binding)
}

/// The field row owning `key`, if the field has focus and names it.
fn field_row<'a>(live: &'a [Live], key: &str) -> Option<&'a Live> {
    live.iter()
        .find(|row| row.binding.scope == Scope::Field && row.keys.contains(&key))
}

/// Whether this event is text going into the field rather than a command.
///
/// `Shift` is not excluded: it is how an uppercase character arrives, and `G`
/// belongs in a filter. `Control` and `Alt` are excluded, because a modified
/// character is a command — `C-c` must still quit with the filter open.
fn is_typed_text(key: &KeyEvent) -> bool {
    matches!(key.code, KeyCode::Char(c) if !c.is_control())
        && !key.modifiers.contains(KeyModifiers::CONTROL)
        && !key.modifiers.contains(KeyModifiers::ALT)
}

/// The keys that fire `op` right now, for the one place outside the legend that
/// mentions a binding in running text (the status line's "jump there" hint).
///
/// It reads the live table rather than repeating a key, which is the whole point:
/// the hint disappears when the key stops working, instead of advertising `b` as
/// "jump there" at the moment pressing `b` types a b.
pub fn keys_for(live: &[Live], op: Op) -> String {
    live.iter()
        .find(|row| row.binding.op == op)
        .map(|row| row.keys.join(", "))
        .unwrap_or_default()
}

/// A key event as the table spells it.
pub fn token(key: &KeyEvent) -> String {
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        if let KeyCode::Char(c) = key.code {
            return format!("C-{}", c.to_ascii_lowercase());
        }
    }
    match key.code {
        KeyCode::Char(' ') => "space".into(),
        KeyCode::Char(c) => c.to_string(),
        KeyCode::Enter => "enter".into(),
        KeyCode::Esc => "esc".into(),
        KeyCode::Backspace => "backspace".into(),
        KeyCode::Tab => "tab".into(),
        KeyCode::BackTab => "backtab".into(),
        KeyCode::Down => "down".into(),
        KeyCode::Up => "up".into(),
        KeyCode::Left => "left".into(),
        KeyCode::Right => "right".into(),
        KeyCode::Home => "home".into(),
        KeyCode::End => "end".into(),
        KeyCode::PageDown => "pagedown".into(),
        KeyCode::PageUp => "pageup".into(),
        KeyCode::Delete => "delete".into(),
        KeyCode::Insert => "insert".into(),
        other => format!("{other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyEventState;

    fn event(token: &str) -> KeyEvent {
        let (code, modifiers) = match token {
            "enter" => (KeyCode::Enter, KeyModifiers::NONE),
            "esc" => (KeyCode::Esc, KeyModifiers::NONE),
            "backspace" => (KeyCode::Backspace, KeyModifiers::NONE),
            "tab" => (KeyCode::Tab, KeyModifiers::NONE),
            "backtab" => (KeyCode::BackTab, KeyModifiers::NONE),
            "down" => (KeyCode::Down, KeyModifiers::NONE),
            "up" => (KeyCode::Up, KeyModifiers::NONE),
            "home" => (KeyCode::Home, KeyModifiers::NONE),
            "end" => (KeyCode::End, KeyModifiers::NONE),
            "pagedown" => (KeyCode::PageDown, KeyModifiers::NONE),
            "pageup" => (KeyCode::PageUp, KeyModifiers::NONE),
            other => match other.strip_prefix("C-") {
                Some(rest) => (
                    KeyCode::Char(rest.chars().next().unwrap()),
                    KeyModifiers::CONTROL,
                ),
                None => (
                    KeyCode::Char(other.chars().next().unwrap()),
                    KeyModifiers::NONE,
                ),
            },
        };
        KeyEvent {
            code,
            modifiers,
            kind: crossterm::event::KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    #[test]
    fn every_key_of_every_live_binding_resolves_to_that_binding() {
        for view in [View::Record, View::Attestation] {
            for editing in [false, true] {
                for row in live(view, editing) {
                    for key in &row.keys {
                        assert_eq!(
                            resolve(view, editing, &event(key)),
                            Some(row.binding),
                            "{key} in {view:?} editing={editing}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn a_field_binding_outranks_a_global_one_on_the_same_key() {
        // `esc` is a global quit and a field cancel.
        let quit = resolve(View::Record, false, &event("esc")).unwrap();
        assert_eq!(quit.op, Op::Quit);
        assert_eq!(quit.scope, Scope::Global);
        let cancel = resolve(View::Record, true, &event("esc")).unwrap();
        assert_eq!(cancel.op, Op::FieldCancel);
        assert_eq!(cancel.scope, Scope::Field);

        // And the printable range, where a global letter key would otherwise eat
        // the text being typed.
        for (typed, global) in [
            ("q", Op::Quit),
            ("/", Op::Filter),
            ("a", Op::PaneAttestation),
        ] {
            assert_eq!(
                resolve(View::Record, false, &event(typed)).unwrap().op,
                global
            );
            let inserted = resolve(View::Record, true, &event(typed)).unwrap();
            assert_eq!(inserted.op, Op::FieldInsert, "typing {typed}");
        }
    }

    #[test]
    fn a_view_binding_outranks_a_global_one_only_while_not_editing() {
        let toggle = resolve(View::Record, false, &event("enter")).unwrap();
        assert_eq!(toggle.op, Op::ToggleDetail);
        let accept = resolve(View::Record, true, &event("enter")).unwrap();
        assert_eq!(accept.op, Op::FieldAccept);
    }

    #[test]
    fn nav_is_suppressed_while_a_field_has_focus() {
        // Non-printable navigation simply goes quiet.
        for key in ["down", "up", "home", "end", "pagedown", "pageup"] {
            assert!(resolve(View::Record, false, &event(key)).is_some(), "{key}");
            assert_eq!(
                resolve(View::Record, true, &event(key)),
                None,
                "nav binding {key} survived a focused field"
            );
        }
        // And printable navigation becomes text, which is the other half of the
        // same rule: `j` must not move the selection while a filter is open.
        for key in ["j", "k", "g", "G", "b"] {
            assert!(resolve(View::Record, false, &event(key)).is_some(), "{key}");
            assert_eq!(
                resolve(View::Record, true, &event(key)).map(|b| b.op),
                Some(Op::FieldInsert),
                "{key} did not become text"
            );
        }
    }

    #[test]
    fn the_legend_never_lists_a_key_that_has_stopped_working() {
        // While a field has focus the printable globals are gone — pressing `q`
        // types a q — so the legend must not still call it "quit". This is the
        // drift the single table exists to prevent, in the direction people
        // usually forget: adding a key to the legend's *description* of a
        // binding whose keys have gone inert.
        let editing: Vec<&str> = live(View::Record, true)
            .iter()
            .flat_map(|row| row.keys.iter().copied())
            .collect();
        for gone in ["q", "/", "f", "r", "a", "d", "j", "k", "g", "G", "b"] {
            assert!(!editing.contains(&gone), "{gone} is listed but inert");
        }
        // What is left is what still works: the field, and the globals whose keys
        // are not printable characters.
        for stays in ["char", "backspace", "enter", "esc", "tab", "backtab", "C-c"] {
            assert!(editing.contains(&stays), "{stays} was dropped");
        }
        assert!(!live(View::Record, false)
            .iter()
            .any(|row| row.binding.op == Op::FieldInsert));
    }

    #[test]
    fn a_key_is_claimed_once_and_the_first_owner_wins() {
        for view in [View::Record, View::Attestation] {
            for editing in [false, true] {
                let mut seen: Vec<&str> = Vec::new();
                for row in live(view, editing) {
                    for key in &row.keys {
                        assert!(!seen.contains(key), "{key} listed twice: {view:?}");
                        seen.push(key);
                    }
                }
            }
        }
    }

    #[test]
    fn the_legend_cannot_advertise_a_binding_the_dispatcher_lacks() {
        // Every `Op` the dispatcher can be asked for has a row, and every row
        // names an op the dispatcher knows. Add an `Op` variant without a binding
        // and the dispatcher has a branch nothing can reach; add a binding for an
        // op and the legend would advertise something unhandled.
        const ALL_OPS: &[Op] = &[
            Op::Quit,
            Op::Reload,
            Op::Follow,
            Op::Filter,
            Op::ViewNext,
            Op::ViewPrev,
            Op::PaneAttestation,
            Op::ToggleDetail,
            Op::MoveDown,
            Op::MoveUp,
            Op::PageDown,
            Op::PageUp,
            Op::First,
            Op::Last,
            Op::JumpBreak,
            Op::FieldInsert,
            Op::FieldBackspace,
            Op::FieldAccept,
            Op::FieldCancel,
        ];
        for op in ALL_OPS {
            assert!(
                BINDINGS.iter().any(|binding| binding.op == *op),
                "{op:?} is dispatchable but nothing in the table can reach it"
            );
        }
        for binding in BINDINGS {
            assert!(
                ALL_OPS.contains(&binding.op),
                "{:?} is not dispatchable",
                binding.op
            );
            assert!(!binding.keys.is_empty(), "{} has no key", binding.action);
            assert!(!binding.help.is_empty(), "{} has no help", binding.action);
        }
    }

    #[test]
    fn tokens_round_trip_so_the_table_and_the_dispatcher_speak_the_same_words() {
        for binding in BINDINGS {
            for key in binding.keys {
                // `char` is the printable range standing in for itself, not a key
                // an event can produce.
                if *key == ANY_CHAR {
                    continue;
                }
                assert_eq!(&token(&event(key)), key, "{key} is not spellable");
            }
        }
    }

    #[test]
    fn the_status_line_hint_reads_the_table_and_the_keys_that_still_work() {
        let idle = live(View::Record, false);
        assert_eq!(keys_for(&idle, Op::JumpBreak), "b");
        assert_eq!(keys_for(&idle, Op::Quit), "q, esc, C-c");
        assert_eq!(keys_for(&idle, Op::FieldAccept), "");
        // While a field has focus `b` types a b, so the hint has nothing to say;
        // and `q` is gone from quit, while `C-c` on the same row still works.
        let typing = live(View::Record, true);
        assert_eq!(keys_for(&typing, Op::JumpBreak), "");
        assert_eq!(keys_for(&typing, Op::Quit), "C-c");
    }
}
