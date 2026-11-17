//! Importing from OpenSnitch, with a preview: its rules (into a folder `OpenSnitch`) and its system firewall
//! (`system-fw.json`), each converted where it can be exactly, and what can't listed with the reason. Nothing is
//! changed until Import. OpenSnitch's files are root's: the node reads them (`ReadOpenSnitch`), from OpenSnitch's own
//! locations only.

use std::sync::mpsc;

use gpui::{
    AnyElement, App, AppContext as _, Context, Entity, InteractiveElement as _, IntoElement,
    ParentElement as _, Render, StatefulInteractiveElement as _, Styled as _, Window, div, px,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::{ActiveTheme as _, Sizable as _, WindowExt as _, h_flex, v_flex};
use snitchhiker_core::{opensnitch, system};
use snitchhiker_proto::v1;

use crate::backend::Request;
use crate::model::Model;

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
    /// Waiting for the node to send the files.
    loading: bool,
}

impl Preview {
    /// Before the node has sent the files.
    fn loading() -> Self {
        Self {
            rules: Err(String::new()),
            rules_skipped: Vec::new(),
            firewall: None,
            firewall_skipped: Vec::new(),
            firewall_notes: Vec::new(),
            firewall_error: None,
            import_rules: false,
            replace_firewall: false,
            loading: true,
        }
    }

    /// Converts OpenSnitch's files, as the node sent them.
    #[must_use]
    pub fn from_files(files: &v1::OpenSnitchFiles) -> Self {
        let mut rules_skipped = Vec::new();
        let rules = if files.rules_error.is_empty() {
            let files: Vec<(String, String)> = files
                .rules
                .iter()
                .map(|f| (f.name.clone(), f.json.clone()))
                .collect();
            let imported = opensnitch::import(&files, FOLDER);
            rules_skipped = imported.skipped;
            let names: Vec<String> = imported.file.rule.iter().map(|r| r.name.clone()).collect();
            toml::to_string(&imported.file)
                .map(|text| (text, names))
                .map_err(|e| e.to_string())
        } else {
            Err(files.rules_error.clone())
        };
        let (firewall, firewall_skipped, firewall_notes, firewall_error) = match &files.system_fw {
            Some(json) => {
                let imported = system::import_opensnitch(json);
                (imported.firewall, imported.skipped, imported.notes, None)
            }
            None => (
                None,
                Vec::new(),
                Vec::new(),
                Some(files.system_fw_error.clone()),
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
            loading: false,
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
        if self.loading {
            return div()
                .id("import-preview")
                .text_color(muted)
                .child("Reading OpenSnitch's files on the node…");
        }
        let mut page = v_flex().gap_3();
        // Rules.
        page = page.child(
            div()
                .text_lg()
                .font_weight(gpui::FontWeight::SEMIBOLD)
                .child("Rules"),
        );
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
        page = page.child(
            div()
                .pt_2()
                .text_lg()
                .font_weight(gpui::FontWeight::SEMIBOLD)
                .child("System firewall"),
        );
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

/// Asks the node for OpenSnitch's files and shows what importing them would do.
pub fn open(
    model: &Entity<Model>,
    requests: mpsc::Sender<Request>,
    window: &mut Window,
    cx: &mut App,
) {
    model.update(cx, |model, _| model.opensnitch = None);
    let _ = requests.send(Request::ReadOpenSnitch);
    let preview = cx.new(|cx| {
        cx.observe(model, |preview: &mut Preview, model, cx| {
            if preview.loading
                && let Some(files) = &model.read(cx).opensnitch
            {
                *preview = Preview::from_files(files);
                cx.notify();
            }
        })
        .detach();
        Preview::loading()
    });
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
    fn a_preview_converts_the_files_and_imports_only_whats_chosen() {
        let files = v1::OpenSnitchFiles {
            rules: vec![v1::OpenSnitchFile {
                name: "/etc/opensnitchd/rules/curl.json".to_owned(),
                json: r#"{"name": "curl", "enabled": true, "action": "allow", "duration": "always",
                    "operator": {"type": "simple", "operand": "process.path", "data": "/usr/bin/curl"}}"#
                    .to_owned(),
            }],
            system_fw_error: "/etc/opensnitchd/system-fw.json: not found".to_owned(),
            ..v1::OpenSnitchFiles::default()
        };
        let mut preview = Preview::from_files(&files);
        assert!(preview.firewall_error.is_some());
        assert_eq!(preview.rules.as_ref().unwrap().1, vec!["curl"]);
        assert!(matches!(
            preview.requests().as_slice(),
            [Request::ImportRules { .. }]
        ));
        preview.import_rules = false;
        assert!(preview.requests().is_empty());
    }
}
