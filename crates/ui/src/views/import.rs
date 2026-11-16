//! Importing from OpenSnitch, with a preview: its rules (into a folder `OpenSnitch`) and its system firewall
//! (`system-fw.json`), each converted where it can be exactly, and what can't listed with the reason. Nothing is
//! changed until Import.

use std::path::Path;
use std::sync::mpsc;

use gpui::{
    AnyElement, App, AppContext as _, Context, InteractiveElement as _, IntoElement,
    ParentElement as _, Render, StatefulInteractiveElement as _, Styled as _, Window, div, px,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::{ActiveTheme as _, Sizable as _, WindowExt as _, h_flex, v_flex};
use snitchhiker_core::{opensnitch, system};

use crate::backend::Request;

const RULES_DIR: &str = "/etc/opensnitchd/rules";
const SYSTEM_FW: &str = "/etc/opensnitchd/system-fw.json";
const FOLDER: &str = "OpenSnitch";

/// What reading OpenSnitch's files gave.
pub struct Preview {
    /// The converted rules as a rule file, and their names; or why there are none.
    rules: Result<(String, Vec<String>), String>,
    rules_skipped: Vec<(String, String)>,
    firewall: Option<system::Firewall>,
    firewall_skipped: Vec<(String, String)>,
    firewall_notes: Vec<String>,
    firewall_error: Option<String>,
    import_rules: bool,
    replace_firewall: bool,
}

/// OpenSnitch's rule files in `dir`: (file name, JSON), sorted.
fn rule_files(dir: &Path) -> Result<Vec<(String, String)>, String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut files = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "json") {
            let text =
                std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            files.push((path.display().to_string(), text));
        }
    }
    files.sort();
    Ok(files)
}

impl Preview {
    /// Reads and converts OpenSnitch's files from `rules_dir` and `system_fw`.
    #[must_use]
    pub fn read(rules_dir: &Path, system_fw: &Path) -> Self {
        // Paths the user chose: read as the user alone.
        crate::userfs::as_user(|| Self::read_as_user(rules_dir, system_fw))
    }

    fn read_as_user(rules_dir: &Path, system_fw: &Path) -> Self {
        let mut rules_skipped = Vec::new();
        let rules = rule_files(rules_dir).and_then(|files| {
            let imported = opensnitch::import(&files, FOLDER);
            rules_skipped = imported.skipped;
            let names: Vec<String> = imported.file.rule.iter().map(|r| r.name.clone()).collect();
            toml::to_string(&imported.file)
                .map(|text| (text, names))
                .map_err(|e| e.to_string())
        });
        let (firewall, firewall_skipped, firewall_notes, firewall_error) =
            match std::fs::read_to_string(system_fw) {
                Ok(json) => {
                    let imported = system::import_opensnitch(&json);
                    (imported.firewall, imported.skipped, imported.notes, None)
                }
                Err(e) => (
                    None,
                    Vec::new(),
                    Vec::new(),
                    Some(format!("{}: {e}", system_fw.display())),
                ),
            };
        let import_rules = rules.as_ref().is_ok_and(|(_, names)| !names.is_empty());
        Self {
            rules,
            rules_skipped,
            firewall,
            firewall_skipped,
            firewall_notes,
            firewall_error,
            import_rules,
            replace_firewall: false,
        }
    }

    /// The requests Import sends.
    #[must_use]
    pub fn requests(&self) -> Vec<Request> {
        let mut requests = Vec::new();
        if self.import_rules
            && let Ok((toml, _)) = &self.rules
        {
            requests.push(Request::ImportRules {
                toml: toml.clone(),
                folder: FOLDER.to_owned(),
            });
        }
        if self.replace_firewall
            && let Some(firewall) = &self.firewall
        {
            requests.push(Request::SetSystemFirewall(
                snitchhiker_proto::v1::SetSystemFirewall {
                    firewall: Some(crate::views::system::wire(firewall)),
                    revert_after_secs: 0,
                },
            ));
            requests.push(Request::SystemFirewall);
        }
        requests
    }
}

/// "1 rule converts", "3 rules convert".
fn rules_convert(count: usize) -> String {
    if count == 1 {
        "1 rule converts".to_owned()
    } else {
        format!("{count} rules convert")
    }
}

fn skipped_list(skipped: &[(String, String)], muted: gpui::Hsla) -> AnyElement {
    let mut list = v_flex().gap_1();
    for (name, reason) in skipped {
        list = list.child(
            div()
                .text_sm()
                .child(format!("{name}: "))
                .child(div().text_color(muted).child(reason.clone())),
        );
    }
    list.into_any_element()
}

fn toggle(
    id: &'static str,
    label: &'static str,
    on: bool,
    cx: &mut Context<Preview>,
    set: fn(&mut Preview),
) -> Button {
    let button =
        Button::new(id)
            .small()
            .label(label)
            .on_click(cx.listener(move |preview, _, _, cx| {
                set(preview);
                cx.notify();
            }));
    if on { button.primary() } else { button.ghost() }
}

impl Render for Preview {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let muted = cx.theme().muted_foreground;
        let mut page = v_flex().gap_3();
        // Rules.
        page = page.child(div().text_lg().child("Rules"));
        match &self.rules {
            Err(e) => page = page.child(div().text_color(muted).child(format!("Not read: {e}"))),
            Ok((_, names)) => {
                page = page
                    .child(format!(
                        "{} of {} rules convert, into the folder {FOLDER}. They apply to the host only.",
                        names.len(),
                        names.len() + self.rules_skipped.len()
                    ))
                    .child(
                        div()
                            .text_sm()
                            .text_color(muted)
                            .child(names.iter().take(30).cloned().collect::<Vec<_>>().join(", ")),
                    );
                if !self.rules_skipped.is_empty() {
                    page = page
                        .child(div().child("Not converted:"))
                        .child(skipped_list(&self.rules_skipped, muted));
                }
                if !names.is_empty() {
                    let on = self.import_rules;
                    page = page.child(
                        h_flex()
                            .gap_1()
                            .child(toggle("import-rules-yes", "Import them", on, cx, |p| {
                                p.import_rules = true;
                            }))
                            .child(toggle("import-rules-no", "Leave them", !on, cx, |p| {
                                p.import_rules = false;
                            })),
                    );
                }
            }
        }
        // The system firewall.
        page = page.child(div().pt_2().text_lg().child("System firewall"));
        if let Some(e) = &self.firewall_error {
            page = page.child(div().text_color(muted).child(format!("Not read: {e}")));
        }
        if let Some(firewall) = &self.firewall {
            page = page.child(format!(
                "{}; OpenSnitch had it {}.",
                rules_convert(firewall.rules.len()),
                if firewall.enabled { "on" } else { "off" }
            ));
            for note in &self.firewall_notes {
                page = page.child(div().text_sm().text_color(muted).child(note.clone()));
            }
        }
        if !self.firewall_skipped.is_empty() {
            page = page
                .child(div().child("Not converted:"))
                .child(skipped_list(&self.firewall_skipped, muted));
        }
        if self.firewall.is_some() {
            let on = self.replace_firewall;
            page = page.child(
                h_flex()
                    .gap_1()
                    .child(toggle(
                        "import-fw-yes",
                        "Replace this node's system firewall",
                        on,
                        cx,
                        |p| {
                            p.replace_firewall = true;
                        },
                    ))
                    .child(toggle("import-fw-no", "Keep this node's", !on, cx, |p| {
                        p.replace_firewall = false;
                    })),
            );
        }
        div()
            .id("import-preview")
            .max_h(px(520.))
            .overflow_y_scroll()
            .child(page)
    }
}

/// Reads OpenSnitch's files and shows what importing them would do.
pub fn open(requests: mpsc::Sender<Request>, window: &mut Window, cx: &mut App) {
    let preview = cx.new(|_| Preview::read(Path::new(RULES_DIR), Path::new(SYSTEM_FW)));
    window.open_dialog(cx, move |dialog, _, _| {
        let (importing, requests) = (preview.clone(), requests.clone());
        dialog
            .title("Import from OpenSnitch")
            .w(px(760.))
            .child(preview.clone())
            .footer(
                h_flex()
                    .w_full()
                    .gap_2()
                    .justify_end()
                    .child(
                        Button::new("import-cancel")
                            .label("Cancel")
                            .on_click(|_, window, cx| window.close_dialog(cx)),
                    )
                    .child(Button::new("import-go").primary().label("Import").on_click(
                        move |_, window, cx| {
                            for request in importing.read(cx).requests() {
                                let _ = requests.send(request);
                            }
                            window.close_dialog(cx);
                        },
                    )),
            )
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_preview_reads_both_files_and_imports_only_whats_chosen() {
        let dir = std::env::temp_dir().join(format!("snitchhiker-import-{}", std::process::id()));
        let rules = dir.join("rules");
        std::fs::create_dir_all(&rules).unwrap();
        std::fs::write(
            rules.join("curl.json"),
            r#"{"name": "curl", "enabled": true, "action": "allow", "duration": "always",
                "operator": {"type": "simple", "operand": "process.path", "data": "/usr/bin/curl"}}"#,
        )
        .unwrap();
        let mut preview = Preview::read(&rules, &dir.join("missing.json"));
        assert!(preview.firewall_error.is_some());
        assert_eq!(preview.rules.as_ref().unwrap().1, vec!["curl"]);
        assert!(matches!(
            preview.requests().as_slice(),
            [Request::ImportRules { .. }]
        ));
        preview.import_rules = false;
        assert!(preview.requests().is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
