use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use rand::Rng;
use ratatui::{
    backend::CrosstermBackend,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame, Terminal,
};
use std::{
    fs,
    io::{self, stdout},
    path::PathBuf,
    process::Command,
    time::{Duration, Instant},
};

// ---------------------------------------------------------------------------
// Character sets – we stick to code-points that every font shipped with
// Windows conhost can render.  Half-width Katakana (U+FF66..U+FF9D) is the
// classic Matrix look and is present in the "MS Gothic" fallback that conhost
// uses for CJK / East-Asian code-pages.  We mix in ASCII digits, Latin
// letters and a handful of common symbols for variety.
// ---------------------------------------------------------------------------

const KATAKANA: &[char] = &[
    'ｦ', 'ｧ', 'ｨ', 'ｩ', 'ｪ', 'ｫ', 'ｬ', 'ｭ', 'ｮ', 'ｯ',
    'ｰ', 'ｱ', 'ｲ', 'ｳ', 'ｴ', 'ｵ', 'ｶ', 'ｷ', 'ｸ', 'ｹ',
    'ｺ', 'ｻ', 'ｼ', 'ｽ', 'ｾ', 'ｿ', 'ﾀ', 'ﾁ', 'ﾂ', 'ﾃ',
    'ﾄ', 'ﾅ', 'ﾆ', 'ﾇ', 'ﾈ', 'ﾉ', 'ﾊ', 'ﾋ', 'ﾌ', 'ﾍ',
    'ﾎ', 'ﾏ', 'ﾐ', 'ﾑ', 'ﾒ', 'ﾓ', 'ﾔ', 'ﾕ', 'ﾖ', 'ﾗ',
    'ﾘ', 'ﾙ', 'ﾚ', 'ﾛ', 'ﾜ', 'ﾝ',
];

const SYMBOLS: &[char] = &[
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'Z', 'X',
    '+', '-', '*', '=', '<', '>', ':', ';', '|', '~',
    '!', '@', '#', '$', '%', '^', '&',
];

fn random_char(rng: &mut impl Rng) -> char {
    if rng.gen_bool(0.6) {
        KATAKANA[rng.gen_range(0..KATAKANA.len())]
    } else {
        SYMBOLS[rng.gen_range(0..SYMBOLS.len())]
    }
}

// ---------------------------------------------------------------------------
// A single falling "stream" (column of characters)
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Drop {
    col: u16,
    head: i32,
    trail: Vec<char>,
    max_len: usize,
    speed: u8,
    tick: u8,
    glitch: bool,
}

impl Drop {
    fn new(col: u16, rows: u16, rng: &mut impl Rng) -> Self {
        let max_len = rng.gen_range(8..=rows as usize);
        let speed = rng.gen_range(1..=4);
        let head = -(rng.gen_range(0..rows as i32 + 10));
        Self {
            col,
            head,
            trail: Vec::with_capacity(max_len),
            max_len,
            speed,
            tick: 0,
            glitch: rng.gen_bool(0.35),
        }
    }

    fn reset(&mut self, rows: u16, rng: &mut impl Rng) {
        self.head = -(rng.gen_range(0..rows as i32 / 2 + 5));
        self.max_len = rng.gen_range(8..=rows as usize);
        self.speed = rng.gen_range(1..=4);
        self.trail.clear();
        self.glitch = rng.gen_bool(0.35);
    }

    fn update(&mut self, rows: u16, rng: &mut impl Rng) {
        self.tick += 1;
        if self.tick < self.speed {
            return;
        }
        self.tick = 0;

        self.head += 1;

        self.trail.insert(0, random_char(rng));
        if self.trail.len() > self.max_len {
            self.trail.pop();
        }

        if self.glitch && self.trail.len() > 2 {
            let idx = rng.gen_range(1..self.trail.len());
            if rng.gen_bool(0.3) {
                self.trail[idx] = random_char(rng);
            }
        }

        let tail_row = self.head - self.trail.len() as i32;
        if tail_row > rows as i32 {
            self.reset(rows, rng);
        }
    }
}

// ---------------------------------------------------------------------------
// Payload menu – discovers .ps1 scripts from payload/ next to the exe
// ---------------------------------------------------------------------------

struct PayloadEntry {
    name: String,
    path: PathBuf,
}

struct PayloadCategory {
    name: String,
    entries: Vec<PayloadEntry>,
    expanded: bool,
}

#[derive(Clone)]
enum MenuIndex {
    Category(usize),
    Entry(usize, usize),
}

struct Menu {
    categories: Vec<PayloadCategory>,
    cursor: MenuIndex,
    scroll_offset: usize,
}

impl Menu {
    fn load() -> Self {
        let payload_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("payload")))
            .unwrap_or_else(|| PathBuf::from("payload"));

        let mut categories = Vec::new();

        if let Ok(entries) = fs::read_dir(&payload_dir) {
            let mut dirs: Vec<PathBuf> = entries
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.is_dir())
                .collect();
            dirs.sort();

            for dir in dirs {
                let dir_name = dir
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();

                let mut ps1_entries = Vec::new();
                if let Ok(files) = fs::read_dir(&dir) {
                    let mut file_paths: Vec<PathBuf> = files
                        .filter_map(|e| e.ok())
                        .map(|e| e.path())
                        .filter(|p| {
                            p.is_file()
                                && p.extension()
                                    .map(|ext| ext.eq_ignore_ascii_case("ps1"))
                                    .unwrap_or(false)
                        })
                        .collect();
                    file_paths.sort();

                    for fp in file_paths {
                        let name = fp
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_string();
                        ps1_entries.push(PayloadEntry {
                            name,
                            path: fp,
                        });
                    }
                }

                categories.push(PayloadCategory {
                    name: dir_name,
                    entries: ps1_entries,
                    expanded: true,
                });
            }
        }

        Menu {
            categories,
            cursor: MenuIndex::Category(0),
            scroll_offset: 0,
        }
    }

    /// Build a flat list of visible items: (is_category, cat_idx, entry_idx)
    fn visible_items(&self) -> Vec<(bool, usize, usize)> {
        let mut items = Vec::new();
        for (ci, cat) in self.categories.iter().enumerate() {
            items.push((true, ci, 0));
            if cat.expanded {
                for ei in 0..cat.entries.len() {
                    items.push((false, ci, ei));
                }
            }
        }
        items
    }

    fn cursor_flat_index(&self) -> usize {
        let items = self.visible_items();
        for (i, &(is_cat, ci, ei)) in items.iter().enumerate() {
            match &self.cursor {
                MenuIndex::Category(c) if is_cat && *c == ci => return i,
                MenuIndex::Entry(c, e) if !is_cat && *c == ci && *e == ei => return i,
                _ => {}
            }
        }
        0
    }

    fn move_up(&mut self) {
        let items = self.visible_items();
        if items.is_empty() {
            return;
        }
        let idx = self.cursor_flat_index();
        if idx > 0 {
            let (is_cat, ci, ei) = items[idx - 1];
            self.cursor = if is_cat {
                MenuIndex::Category(ci)
            } else {
                MenuIndex::Entry(ci, ei)
            };
        }
    }

    fn move_down(&mut self) {
        let items = self.visible_items();
        if items.is_empty() {
            return;
        }
        let idx = self.cursor_flat_index();
        if idx + 1 < items.len() {
            let (is_cat, ci, ei) = items[idx + 1];
            self.cursor = if is_cat {
                MenuIndex::Category(ci)
            } else {
                MenuIndex::Entry(ci, ei)
            };
        }
    }

}

fn launch_ps1(path: &PathBuf) {
    let _ = Command::new("powershell.exe")
        .args(["-ExecutionPolicy", "Bypass", "-File"])
        .arg(path)
        .spawn();
}

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

struct App {
    drops: Vec<Drop>,
    frame_count: u64,
    menu_open: bool,
    menu: Menu,
    launch_message: Option<(String, Instant)>,
}

impl App {
    fn new(cols: u16, rows: u16) -> Self {
        let mut rng = rand::thread_rng();
        let base = cols as usize;
        let extra = (cols as usize) / 3;
        let mut drops = Vec::with_capacity(base + extra);
        for c in 0..cols {
            drops.push(Drop::new(c, rows, &mut rng));
        }
        for _ in 0..extra {
            let c = rng.gen_range(0..cols);
            drops.push(Drop::new(c, rows, &mut rng));
        }
        Self {
            drops,
            frame_count: 0,
            menu_open: false,
            menu: Menu::load(),
            launch_message: None,
        }
    }

    fn update(&mut self, rows: u16) {
        let mut rng = rand::thread_rng();
        for drop in &mut self.drops {
            drop.update(rows, &mut rng);
        }
        self.frame_count += 1;
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn render(frame: &mut Frame, app: &App) {
    let area = frame.area();
    let rows = area.height;
    let cols = area.width;

    // Build a 2D buffer of (char, style) – latest write wins so overlapping
    // streams blend nicely.
    let mut grid: Vec<Vec<(char, Style)>> = vec![
        vec![(' ', Style::default().fg(Color::Black)); cols as usize];
        rows as usize
    ];

    let pulse = ((app.frame_count as f64 * 0.05).sin() * 30.0) as u8;

    for drop in &app.drops {
        for (i, &ch) in drop.trail.iter().enumerate() {
            let row = drop.head - i as i32;
            if row < 0 || row >= rows as i32 {
                continue;
            }
            let r = row as usize;
            let c = drop.col as usize;
            if c >= cols as usize {
                continue;
            }

            let style = if i == 0 {
                Style::default()
                    .fg(Color::Rgb(
                        200u8.saturating_add(pulse / 2),
                        255,
                        200u8.saturating_add(pulse / 2),
                    ))
                    .add_modifier(Modifier::BOLD)
            } else if i <= 2 {
                Style::default().fg(Color::Rgb(
                    30,
                    220u8.saturating_sub(i as u8 * 20),
                    30,
                ))
            } else {
                let frac = i as f64 / drop.max_len as f64;
                let g = (180.0 * (1.0 - frac * 0.85)) as u8;
                let r_c = (15.0 * (1.0 - frac)) as u8;
                Style::default().fg(Color::Rgb(r_c, g, r_c))
            };

            grid[r][c] = (ch, style);
        }
    }

    let lines: Vec<Line> = grid
        .into_iter()
        .map(|row| {
            let spans: Vec<Span> = row
                .into_iter()
                .map(|(ch, style)| Span::styled(ch.to_string(), style))
                .collect();
            Line::from(spans)
        })
        .collect();

    let paragraph = Paragraph::new(lines).block(Block::default().borders(Borders::NONE));
    frame.render_widget(paragraph, area);

    // Status bar
    let status = if app.menu_open {
        format!(" BADDERBLOOD // frame {} ", app.frame_count)
    } else {
        format!(
            " BADDERBLOOD // frame {} // Tab for menu // q to quit ",
            app.frame_count
        )
    };
    let sw = status.len() as u16;
    if cols > sw + 2 && rows > 1 {
        let status_area = Rect::new(cols - sw - 1, rows - 1, sw, 1);
        let status_widget = Paragraph::new(Line::from(Span::styled(
            status,
            Style::default()
                .fg(Color::Rgb(0, 60, 0))
                .bg(Color::Black),
        )));
        frame.render_widget(status_widget, status_area);
    }

    // Transient launch message
    if let Some((ref msg, when)) = app.launch_message {
        if when.elapsed() < Duration::from_secs(3) {
            let mw = msg.len() as u16 + 2;
            if cols > mw + 2 && rows > 2 {
                let msg_area = Rect::new(cols - mw - 1, rows - 2, mw, 1);
                let msg_widget = Paragraph::new(Line::from(Span::styled(
                    format!(" {} ", msg),
                    Style::default()
                        .fg(Color::Rgb(0, 200, 0))
                        .bg(Color::Black)
                        .add_modifier(Modifier::BOLD),
                )));
                frame.render_widget(msg_widget, msg_area);
            }
        }
    }

    // Menu overlay
    if app.menu_open {
        render_menu(frame, &app.menu, area);
    }
}

fn render_menu(frame: &mut Frame, menu: &Menu, area: Rect) {
    let menu_width = 64u16.min(area.width.saturating_sub(4));
    let menu_height = 24u16.min(area.height.saturating_sub(4));
    let x = (area.width.saturating_sub(menu_width)) / 2;
    let y = (area.height.saturating_sub(menu_height)) / 2;
    let menu_area = Rect::new(x, y, menu_width, menu_height);

    // Clear the area behind the menu
    frame.render_widget(Clear, menu_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(0, 180, 0)))
        .title(" BadderBlood // Payload Launcher ")
        .title_style(
            Style::default()
                .fg(Color::Rgb(200, 255, 200))
                .add_modifier(Modifier::BOLD),
        );

    let inner = block.inner(menu_area);
    let mut lines: Vec<Line> = Vec::new();

    // Instructions
    lines.push(Line::from(Span::styled(
        " [\u{2191}\u{2193}] Navigate  [Enter] Select  [\u{2190}\u{2192}] Collapse/Expand  [Esc] Close",
        Style::default().fg(Color::Rgb(0, 100, 0)),
    )));
    lines.push(Line::from(""));

    if menu.categories.is_empty() {
        lines.push(Line::from(Span::styled(
            " No payloads found in payload/ directory",
            Style::default().fg(Color::Rgb(180, 0, 0)),
        )));
    } else {
        for (ci, cat) in menu.categories.iter().enumerate() {
            let is_cat_selected = matches!(&menu.cursor, MenuIndex::Category(c) if *c == ci);
            let prefix = if cat.expanded { "\u{25BC} " } else { "\u{25B6} " };
            let cat_style = if is_cat_selected {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Rgb(0, 180, 0))
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
                    .fg(Color::Rgb(0, 220, 0))
                    .add_modifier(Modifier::BOLD)
            };
            lines.push(Line::from(Span::styled(
                format!(" {}{}", prefix, cat.name),
                cat_style,
            )));

            if cat.expanded {
                for (ei, entry) in cat.entries.iter().enumerate() {
                    let is_entry_selected =
                        matches!(&menu.cursor, MenuIndex::Entry(c, e) if *c == ci && *e == ei);
                    let entry_style = if is_entry_selected {
                        Style::default()
                            .fg(Color::Black)
                            .bg(Color::Rgb(0, 140, 0))
                    } else {
                        Style::default().fg(Color::Rgb(0, 160, 0))
                    };
                    lines.push(Line::from(Span::styled(
                        format!("     {} ", entry.name),
                        entry_style,
                    )));
                }
            }
        }
    }

    // Scroll if content exceeds visible area
    let visible_height = inner.height as usize;
    if lines.len() > visible_height {
        let cursor_line = {
            let mut line = 2; // skip instruction + blank
            for (ci, cat) in menu.categories.iter().enumerate() {
                match &menu.cursor {
                    MenuIndex::Category(c) if *c == ci => break,
                    MenuIndex::Entry(c, e) if *c == ci => {
                        line += 1 + *e;
                        break;
                    }
                    _ => {}
                }
                line += 1; // category header
                if cat.expanded {
                    line += cat.entries.len();
                }
            }
            line
        };
        // Keep cursor in view with 2 lines of padding
        let scroll = menu.scroll_offset;
        let scroll = if cursor_line < scroll + 2 {
            cursor_line.saturating_sub(2)
        } else if cursor_line >= scroll + visible_height - 2 {
            cursor_line.saturating_sub(visible_height - 3)
        } else {
            scroll
        };
        let end = (scroll + visible_height).min(lines.len());
        lines = lines[scroll..end].to_vec();
    }

    let paragraph = Paragraph::new(lines)
        .block(block)
        .style(Style::default().bg(Color::Black));
    frame.render_widget(paragraph, menu_area);
}

// ---------------------------------------------------------------------------
// Main loop
// ---------------------------------------------------------------------------

fn main() -> io::Result<()> {
    enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(out);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let size = terminal.size()?;
    let mut app = App::new(size.width, size.height);

    let target_fps = 30;
    let frame_dur = Duration::from_millis(1000 / target_fps);

    loop {
        let start = Instant::now();

        // Handle input (non-blocking)
        if event::poll(Duration::from_millis(0))? {
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    if app.menu_open {
                        match key.code {
                            KeyCode::Esc => app.menu_open = false,
                            KeyCode::Up => app.menu.move_up(),
                            KeyCode::Down => app.menu.move_down(),
                            KeyCode::Left => {
                                match &app.menu.cursor {
                                    MenuIndex::Entry(ci, _) => {
                                        let ci = *ci;
                                        app.menu.categories[ci].expanded = false;
                                        app.menu.cursor = MenuIndex::Category(ci);
                                    }
                                    MenuIndex::Category(ci) => {
                                        app.menu.categories[*ci].expanded = false;
                                    }
                                }
                            }
                            KeyCode::Right => {
                                if let MenuIndex::Category(ci) = &app.menu.cursor {
                                    app.menu.categories[*ci].expanded = true;
                                }
                            }
                            KeyCode::Enter => match &app.menu.cursor {
                                MenuIndex::Category(ci) => {
                                    let ci = *ci;
                                    app.menu.categories[ci].expanded =
                                        !app.menu.categories[ci].expanded;
                                }
                                MenuIndex::Entry(ci, ei) => {
                                    let path = app.menu.categories[*ci].entries[*ei]
                                        .path
                                        .clone();
                                    let display = app.menu.categories[*ci].entries[*ei]
                                        .name
                                        .clone();
                                    launch_ps1(&path);
                                    app.launch_message = Some((
                                        format!("Launched: {}", display),
                                        Instant::now(),
                                    ));
                                    app.menu_open = false;
                                }
                            },
                            _ => {}
                        }
                    } else {
                        match key.code {
                            KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => break,
                            KeyCode::Tab | KeyCode::Enter => app.menu_open = true,
                            _ => {}
                        }
                    }
                }
                Event::Resize(w, h) => {
                    let menu = std::mem::replace(&mut app.menu, Menu::load());
                    let msg = app.launch_message.take();
                    let was_open = app.menu_open;
                    app = App::new(w, h);
                    app.menu = menu;
                    app.launch_message = msg;
                    app.menu_open = was_open;
                }
                _ => {}
            }
        }

        app.update(size.height);

        terminal.draw(|f| render(f, &app))?;

        let elapsed = start.elapsed();
        if elapsed < frame_dur {
            std::thread::sleep(frame_dur - elapsed);
        }
    }

    // Cleanup
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}
