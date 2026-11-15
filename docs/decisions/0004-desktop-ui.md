# 0004. Desktop UI: GPUI through gpui-pre, with gpui-component

Status: accepted (M0)

## Context

The plan asked for a Rust-native UI framework "like GPUI Community Edition". The desktop app needs large virtualized
tables, a tree, text inputs, dialogs, notifications and charts, and it must run setgid on Wayland and X11.

## What was tried

The same spike in both, in the test VM: a window with a virtualized table of a million synthetic connection events,
installed `root:snitchhiker-ui 2755`, run by an ordinary user under a headless sway, with software Vulkan
(lavapipe), screenshotted with grim.

| | gpui-ce 0.3.0 | gpui-pre 0.3.12 + gpui-component 0.9.1 |
| --- | --- | --- |
| Runs setgid (egid = client group) on Wayland | yes | yes |
| A million-row virtualized table | `uniform_list`, columns hand-made | `DataTable`: header, resizable and sortable columns, stripes, context menus, `load_more` / `visible_rows_changed` for on-demand data |
| Other components | none | inputs, select, tree-capable list, tabs, dock, dialogs, sheets, notifications, forms and settings, charts and plots |
| Crates in the tree | ~620 | ~940 |
| Release build of the spike | 2 min 29 s | 1 min 49 s |
| Releases | a few a year | weekly, gpui-pre pinned exactly by gpui-component |

## Decision

GPUI through `gpui-pre` (snapshots of Zed's GPUI), with `gpui-component` (longbridge). It is the same programming
model as GPUI-CE, and the component library saves building every widget the app needs; gpui-component does not
support forks such as gpui-ce.

Notes for the implementation:

- `gpui-pre-platform` depends on `gpui-pre-linux` without default features, i.e. without a window system: the app
  then runs headless and shows nothing. Depend on `gpui-pre-linux` with `wayland` and `x11` explicitly.
- gpui-component pins `gpui-pre` to an exact version; they are upgraded together.
- Vulkan is loaded at run time; without a GPU (the test VMs) lavapipe works. EGL warnings at start are harmless.

## Open

Portals (file chooser), clipboard, IME and the tray under setgid are checked in M3, when the app exists.
