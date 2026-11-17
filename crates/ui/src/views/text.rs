//! Values that may not fit where they are shown: paths, hosts, rule conditions.

use gpui::{ElementId, InteractiveText, SharedString, StyledText};
use gpui_component::tooltip::Tooltip;

/// `text` on one line, cut with an ellipsis by its container (`overflow_hidden().text_ellipsis()`) when it doesn't
/// fit, and then readable in full in a tooltip on hover. Text that fits gets no tooltip: whether it was cut is read
/// off the laid-out line itself.
pub fn clipped(id: impl Into<ElementId>, text: impl Into<SharedString>) -> InteractiveText {
    let text: SharedString = text.into();
    let styled = StyledText::new(text.clone());
    let layout = styled.layout().clone();
    InteractiveText::new(id, styled).tooltip(move |_, window, cx| {
        (layout.text() != text.as_ref()).then(|| Tooltip::new(text.clone()).build(window, cx))
    })
}
