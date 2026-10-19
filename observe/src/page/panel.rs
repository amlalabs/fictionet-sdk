use serde::{Deserialize, Serialize};

/// A table cell presentation.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    /// Plain text, never markup.
    #[default]
    Text,
    /// Decimal number.
    Number,
    /// Byte count.
    Bytes,
    /// Run time in seconds.
    Time,
    /// Text status.
    Status,
}

/// A column selecting a field with a JSON pointer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Column {
    /// Visible label.
    pub label: String,
    /// JSON pointer evaluated on a row.
    pub pointer: String,
    /// Cell presentation.
    pub format: Format,
}

impl Column {
    /// Creates a plain text column.
    pub fn new(label: impl Into<String>, json_pointer: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            pointer: json_pointer.into(),
            format: Format::Text,
        }
    }
    /// Selects the cell presentation.
    pub fn format(mut self, format: Format) -> Self {
        self.format = format;
        self
    }
}

/// One panel in the page description. IDs are slugged titles.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PanelDescription {
    /// Stable route identifier.
    pub id: String,
    /// Visible title.
    pub title: String,
    /// Placement in the page.
    pub area: Area,
    /// Panel contents and service URLs.
    #[serde(flatten)]
    pub content: PanelContent,
}

/// Panel-specific declarations, tagged by `kind` on the wire.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PanelContent {
    /// Captured packets from the dashboard.
    Packets,
    /// Dashboard events.
    Events,
    /// Dashboard topology.
    Map,
    /// A host screen.
    Screen {
        /// Host name.
        host: String,
    },
    /// A host terminal.
    Terminal {
        /// Host name.
        host: String,
    },
    /// A filtered event projection.
    EventTable {
        /// GET endpoint.
        events: String,
        /// Column declarations.
        columns: Vec<Column>,
    },
    /// An embedded ES module with authoritative state.
    Custom {
        /// Same-origin module URL.
        module: String,
        /// State snapshot URL.
        state: String,
    },
    /// An authoritative state table.
    Table {
        /// Snapshot URL. Append `/stream` to subscribe.
        state: String,
        /// Column declarations.
        columns: Vec<Column>,
    },
    /// A typed world command mailbox.
    Control {
        /// POST endpoint.
        command: String,
        /// Declared commands rendered as buttons.
        actions: Vec<super::Action>,
        /// Optional authoritative topic. Copy its revision into the command's
        /// `expected_revision` field before posting; the world validates it.
        state: Option<String>,
    },
}

pub(super) fn slug(title: &str) -> String {
    title
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|s| !s.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>()
        .join("-")
}

pub(super) fn valid_pointer(pointer: &str) -> bool {
    if !pointer.is_empty() && !pointer.starts_with('/') {
        return false;
    }
    let mut bytes = pointer.bytes();
    while let Some(b) = bytes.next() {
        if b == b'~' && !matches!(bytes.next(), Some(b'0' | b'1')) {
            return false;
        }
    }
    true
}

/// Panel placement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Area {
    /// Main page workspace.
    Workspace,
    /// Tabbed inspector.
    Inspector,
}

impl PanelContent {
    pub(super) fn call(&self) -> &'static str {
        match self {
            Self::Table { .. } => "table",
            Self::Control { .. } => "control",
            Self::EventTable { .. } => "event_table",
            Self::Custom { .. } => "custom",
            _ => "standard_panels",
        }
    }
}
