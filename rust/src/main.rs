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
    widgets::{Block, Borders, Paragraph},
    Frame, Terminal,
};
use std::{
    io::{self, stdout},
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
    /// Column on screen
    col: u16,
    /// Current head row (can be negative = not visible yet)
    head: i32,
    /// Characters in the trail (index 0 = head)
    trail: Vec<char>,
    /// Maximum trail length
    max_len: usize,
    /// How many ticks between each downward step
    speed: u8,
    /// Internal tick counter
    tick: u8,
    /// Whether characters randomly mutate
    glitch: bool,
}

impl Drop {
    fn new(col: u16, rows: u16, rng: &mut impl Rng) -> Self {
        let max_len = rng.gen_range(8..=rows as usize);
        let speed = rng.gen_range(1..=4);
        let head = -(rng.gen_range(0..rows as i32 + 10)); // stagger start
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

        // Advance head
        self.head += 1;

        // Push a new random character at the front of the trail
        self.trail.insert(0, random_char(rng));
        if self.trail.len() > self.max_len {
            self.trail.pop();
        }

        // Randomly mutate middle characters for that digital "glitch" feel
        if self.glitch && self.trail.len() > 2 {
            let idx = rng.gen_range(1..self.trail.len());
            if rng.gen_bool(0.3) {
                self.trail[idx] = random_char(rng);
            }
        }

        // If the entire trail has scrolled off the bottom, recycle
        let tail_row = self.head - self.trail.len() as i32;
        if tail_row > rows as i32 {
            self.reset(rows, rng);
        }
    }
}

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

struct App {
    drops: Vec<Drop>,
    frame_count: u64,
}

impl App {
    fn new(cols: u16, rows: u16) -> Self {
        let mut rng = rand::thread_rng();
        // One stream per column, plus some extra overlapping ones for density
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

    // Pulsing brightness accent based on frame count
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
                // ── HEAD: brilliant white / bright green flash ──
                Style::default()
                    .fg(Color::Rgb(
                        200u8.saturating_add(pulse / 2),
                        255,
                        200u8.saturating_add(pulse / 2),
                    ))
                    .add_modifier(Modifier::BOLD)
            } else if i <= 2 {
                // ── NEAR-HEAD: vivid green ──
                Style::default().fg(Color::Rgb(
                    30,
                    220u8.saturating_sub(i as u8 * 20),
                    30,
                ))
            } else {
                // ── BODY → TAIL: fade from green to dark green ──
                let frac = i as f64 / drop.max_len as f64; // 0.0 → 1.0
                let g = (180.0 * (1.0 - frac * 0.85)) as u8;
                let r_c = (15.0 * (1.0 - frac)) as u8;
                Style::default().fg(Color::Rgb(r_c, g, r_c))
            };

            grid[r][c] = (ch, style);
        }
    }

    // Flatten the 2D grid into Lines of Spans (one Line per row).
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

    // Overlay a small status bar in the bottom-right corner
    let status = format!(" MATRIX // frame {} // q to quit ", app.frame_count);
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
}

// ---------------------------------------------------------------------------
// Main loop
// ---------------------------------------------------------------------------

fn main() -> io::Result<()> {
    // Terminal setup
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
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => break,
                        _ => {}
                    }
                }
            }
            if let Event::Resize(w, h) = event::read().unwrap_or(Event::FocusLost) {
                app = App::new(w, h);
            }
        }

        app.update(size.height);

        terminal.draw(|f| render(f, &app))?;

        // Sleep to hit target FPS
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
