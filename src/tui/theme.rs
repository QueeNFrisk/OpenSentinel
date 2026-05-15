use ratatui::style::{Color, Modifier, Style};

pub struct Theme;

impl Theme {
	pub const BG: Color = Color::Rgb(13, 17, 23);
	pub const BG_PANEL: Color = Color::Rgb(22, 27, 34);
	pub const BG_SELECTED: Color = Color::Rgb(33, 41, 54);
	pub const BORDER: Color = Color::Rgb(48, 54, 61);
	pub const BORDER_ACTIVE: Color = Color::Rgb(88, 166, 255);

	pub const TEXT_PRIMARY: Color = Color::Rgb(201, 209, 217);
	pub const TEXT_SECONDARY: Color = Color::Rgb(139, 148, 158);
	pub const TEXT_DIM: Color = Color::Rgb(88, 96, 105);

	pub const SEVERITY_CRITICAL: Color = Color::Rgb(255, 85, 85);
	pub const SEVERITY_HIGH: Color = Color::Rgb(255, 166, 77);
	pub const SEVERITY_MEDIUM: Color = Color::Rgb(255, 215, 0);
	pub const SEVERITY_LOW: Color = Color::Rgb(88, 166, 255);
	pub const SEVERITY_SAFE: Color = Color::Rgb(63, 185, 80);

	pub const ACCENT: Color = Color::Rgb(88, 166, 255);
	pub fn base() -> Style {
		Style::default().fg(Self::TEXT_PRIMARY).bg(Self::BG)
	}

	pub fn panel() -> Style {
		Style::default().fg(Self::TEXT_PRIMARY).bg(Self::BG_PANEL)
	}

	pub fn selected() -> Style {
		Style::default()
			.fg(Color::White)
			.bg(Self::BG_SELECTED)
			.add_modifier(Modifier::BOLD)
	}

	pub fn border_inactive() -> Style {
		Style::default().fg(Self::BORDER)
	}

	pub fn border_active() -> Style {
		Style::default().fg(Self::BORDER_ACTIVE)
	}

	pub fn severity_style(label: &str) -> Style {
		let color = match label {
			"CRITICAL" => Self::SEVERITY_CRITICAL,
			"HIGH" => Self::SEVERITY_HIGH,
			"MEDIUM" => Self::SEVERITY_MEDIUM,
			"LOW" => Self::SEVERITY_LOW,
			_ => Self::SEVERITY_SAFE,
		};
		Style::default().fg(color).add_modifier(Modifier::BOLD)
	}

	pub fn header() -> Style {
		Style::default()
			.fg(Self::ACCENT)
			.add_modifier(Modifier::BOLD)
	}

	pub fn secondary() -> Style {
		Style::default().fg(Self::TEXT_SECONDARY)
	}

	pub fn dim() -> Style {
		Style::default().fg(Self::TEXT_DIM)
	}

	pub fn accent() -> Style {
		Style::default().fg(Self::ACCENT)
	}
}
