#![cfg(windows)]

use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
    process::Command,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::HANDLE,
    System::Console::{
        GetConsoleMode, GetConsoleScreenBufferInfo, GetNumberOfConsoleInputEvents, GetStdHandle,
        ReadConsoleInputW, SetConsoleMode, CONSOLE_SCREEN_BUFFER_INFO,
        ENABLE_EXTENDED_FLAGS, ENABLE_VIRTUAL_TERMINAL_PROCESSING, ENABLE_WINDOW_INPUT,
        INPUT_RECORD, KEY_EVENT, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, WINDOW_BUFFER_SIZE_EVENT,
    },
};

#[link(name = "winmm")]
extern "system" {
    fn timeBeginPeriod(uPeriod: u32) -> u32;
    fn timeEndPeriod(uPeriod: u32) -> u32;
}

extern "system" {
    fn WriteFile(
        hFile: HANDLE,
        lpBuffer: *const u8,
        nNumberOfBytesToWrite: u32,
        lpNumberOfBytesWritten: *mut u32,
        lpOverlapped: *mut std::ffi::c_void,
    ) -> i32;
}

// ---------------------------------------------------------------------------
// Fast xoshiro256++ PRNG – vastly faster than rand::thread_rng()
// ---------------------------------------------------------------------------

struct Rng {
    s: [u64; 4],
}

impl Rng {
    fn new() -> Self {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let mut s = [
            t ^ 0x9E3779B97F4A7C15,
            t.wrapping_mul(0x6C62272E07BB0142) ^ 0xBF58476D1CE4E5B9,
            t.wrapping_mul(0x94D049BB133111EB) ^ 0x853C49E6748FEA9B,
            t.rotate_left(17) ^ 0x2545F4914F6CDD1D,
        ];
        for _ in 0..8 {
            let t = s[1] << 17;
            s[2] ^= s[0];
            s[3] ^= s[1];
            s[1] ^= s[2];
            s[0] ^= s[3];
            s[2] ^= t;
            s[3] = s[3].rotate_left(45);
        }
        Self { s }
    }

    #[inline(always)]
    fn next_u64(&mut self) -> u64 {
        let result = (self.s[0].wrapping_add(self.s[3]))
            .rotate_left(23)
            .wrapping_add(self.s[0]);
        let t = self.s[1] << 17;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(45);
        result
    }

    #[inline(always)]
    fn gen_u32(&mut self, n: u32) -> u32 {
        let r = self.next_u64() as u32;
        ((r as u64).wrapping_mul(n as u64) >> 32) as u32
    }

    #[inline(always)]
    fn gen_range(&mut self, lo: i32, hi_exclusive: i32) -> i32 {
        let span = (hi_exclusive - lo) as u32;
        lo + self.gen_u32(span) as i32
    }

    #[inline(always)]
    fn gen_range_u16(&mut self, lo: u16, hi_inclusive: u16) -> u16 {
        let span = (hi_inclusive - lo + 1) as u32;
        lo + self.gen_u32(span) as u16
    }

    #[inline(always)]
    fn gen_bool(&mut self, p_numer: u32, p_denom: u32) -> bool {
        self.gen_u32(p_denom) < p_numer
    }
}

// ---------------------------------------------------------------------------
// Character sets as pre-encoded UTF-16 values
// ---------------------------------------------------------------------------

const KATAKANA_U16: &[u16] = &[
    0xFF66, 0xFF67, 0xFF68, 0xFF69, 0xFF6A, 0xFF6B, 0xFF6C, 0xFF6D, 0xFF6E, 0xFF6F,
    0xFF70, 0xFF71, 0xFF72, 0xFF73, 0xFF74, 0xFF75, 0xFF76, 0xFF77, 0xFF78, 0xFF79,
    0xFF7A, 0xFF7B, 0xFF7C, 0xFF7D, 0xFF7E, 0xFF7F, 0xFF80, 0xFF81, 0xFF82, 0xFF83,
    0xFF84, 0xFF85, 0xFF86, 0xFF87, 0xFF88, 0xFF89, 0xFF8A, 0xFF8B, 0xFF8C, 0xFF8D,
    0xFF8E, 0xFF8F, 0xFF90, 0xFF91, 0xFF92, 0xFF93, 0xFF94, 0xFF95, 0xFF96, 0xFF97,
    0xFF98, 0xFF99, 0xFF9A, 0xFF9B, 0xFF9C, 0xFF9D,
];

const SYMBOLS_U16: &[u16] = &[
    b'0' as u16, b'1' as u16, b'2' as u16, b'3' as u16, b'4' as u16,
    b'5' as u16, b'6' as u16, b'7' as u16, b'8' as u16, b'9' as u16,
    b'A' as u16, b'B' as u16, b'C' as u16, b'D' as u16, b'E' as u16,
    b'F' as u16, b'G' as u16, b'H' as u16, b'Z' as u16, b'X' as u16,
    b'+' as u16, b'-' as u16, b'*' as u16, b'=' as u16, b'<' as u16,
    b'>' as u16, b':' as u16, b';' as u16, b'|' as u16, b'~' as u16,
    b'!' as u16, b'@' as u16, b'#' as u16, b'$' as u16, b'%' as u16,
    b'^' as u16, b'&' as u16,
];

#[inline(always)]
fn random_char_u16(rng: &mut Rng) -> u16 {
    if rng.gen_bool(3, 5) {
        KATAKANA_U16[rng.gen_u32(KATAKANA_U16.len() as u32) as usize]
    } else {
        SYMBOLS_U16[rng.gen_u32(SYMBOLS_U16.len() as u32) as usize]
    }
}

// ---------------------------------------------------------------------------
// Console colour attributes (Win32 4-bit) -> ANSI SGR mapping
// ---------------------------------------------------------------------------

const ATTR_BLACK: u16 = 0x0000;
const ATTR_HEAD: u16 = 0x0F;    // bright white
const ATTR_NEAR1: u16 = 0x0A;   // bright green
const ATTR_NEAR2: u16 = 0x0A;
const ATTR_TRAIL_BRIGHT: u16 = 0x0A;
const ATTR_TRAIL_DIM: u16 = 0x02;  // dark green
const ATTR_STATUS: u16 = 0x02;
const ATTR_MSG: u16 = 0x0A;

const TRAIL_PALETTE_SIZE: usize = 16;

struct AttrPalette {
    head: u16,
    near_head: [u16; 2],
    trail: [u16; TRAIL_PALETTE_SIZE],
}

fn build_attr_palette() -> AttrPalette {
    let mut trail = [0u16; TRAIL_PALETTE_SIZE];
    let bright_end = TRAIL_PALETTE_SIZE * 6 / 10;
    for i in 0..TRAIL_PALETTE_SIZE {
        trail[i] = if i < bright_end {
            ATTR_TRAIL_BRIGHT
        } else {
            ATTR_TRAIL_DIM
        };
    }
    AttrPalette {
        head: ATTR_HEAD,
        near_head: [ATTR_NEAR1, ATTR_NEAR2],
        trail,
    }
}

/// Map a Win32 4-bit console attribute to an ANSI SGR sequence.
/// We only use a few distinct values so this is a simple match.
fn attr_to_sgr(attr: u16) -> &'static [u8] {
    match attr {
        0x0F => b"\x1b[97m",         // bright white foreground
        0x0A => b"\x1b[92m",         // bright green foreground
        0x02 => b"\x1b[32m",         // dark green foreground
        0x20 => b"\x1b[30;42m",      // black on green (menu selection)
        0x04 => b"\x1b[31m",         // red (error text)
        _ => b"\x1b[0m",             // reset (black/default)
    }
}

// ---------------------------------------------------------------------------
// Cell type for our logical framebuffer
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
struct Cell {
    ch: u16,    // UTF-16 code unit
    attr: u16,  // Win32 attribute value
}

impl Cell {
    const BLANK: Cell = Cell { ch: b' ' as u16, attr: ATTR_BLACK };
}

// ---------------------------------------------------------------------------
// A single falling "stream" – compact ring buffer
// ---------------------------------------------------------------------------

const MAX_TRAIL: usize = 128;

struct Drop {
    col: u16,
    head: i32,
    chars: [u16; MAX_TRAIL],
    len: u16,
    write_pos: u16,
    max_len: u16,
    speed: u8,
    tick: u8,
    glitch: bool,
}

impl Drop {
    fn new(col: u16, rows: u16, rng: &mut Rng) -> Self {
        let max_len = rng.gen_range_u16(8, rows.min(MAX_TRAIL as u16));
        let speed = rng.gen_range(1, 5) as u8;
        let head = -(rng.gen_range(0, rows as i32 + 10));
        Self {
            col,
            head,
            chars: [b' ' as u16; MAX_TRAIL],
            len: 0,
            write_pos: 0,
            max_len,
            speed,
            tick: 0,
            glitch: rng.gen_bool(35, 100),
        }
    }

    fn reset(&mut self, rows: u16, rng: &mut Rng) {
        self.head = -(rng.gen_range(0, rows as i32 / 2 + 5));
        self.max_len = rng.gen_range_u16(8, rows.min(MAX_TRAIL as u16));
        self.speed = rng.gen_range(1, 5) as u8;
        self.len = 0;
        self.write_pos = 0;
        self.glitch = rng.gen_bool(35, 100);
    }

    #[inline]
    fn update(&mut self, rows: u16, rng: &mut Rng) {
        self.tick += 1;
        if self.tick < self.speed {
            return;
        }
        self.tick = 0;
        self.head += 1;

        let ml = self.max_len;
        self.chars[self.write_pos as usize] = random_char_u16(rng);
        self.write_pos = (self.write_pos + 1) % ml;
        if self.len < ml {
            self.len += 1;
        }

        if self.glitch && self.len > 2 && rng.gen_bool(3, 10) {
            let idx = rng.gen_u32(self.len as u32 - 1) + 1;
            let ring_idx = (self.write_pos + ml - 1 - idx as u16) % ml;
            self.chars[ring_idx as usize] = random_char_u16(rng);
        }

        let tail_row = self.head - self.len as i32;
        if tail_row > rows as i32 {
            self.reset(rows, rng);
        }
    }

    #[inline(always)]
    fn trail_char_u16(&self, i: u16) -> u16 {
        let ring_idx = (self.write_pos + self.max_len - 1 - i) % self.max_len;
        self.chars[ring_idx as usize]
    }
}

// ---------------------------------------------------------------------------
// Payload menu
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
// Win32 console helpers
// ---------------------------------------------------------------------------

fn get_console_size(handle: HANDLE) -> (u16, u16) {
    unsafe {
        let mut info: CONSOLE_SCREEN_BUFFER_INFO = std::mem::zeroed();
        GetConsoleScreenBufferInfo(handle, &mut info);
        let w = (info.srWindow.Right - info.srWindow.Left + 1) as u16;
        let h = (info.srWindow.Bottom - info.srWindow.Top + 1) as u16;
        (w, h)
    }
}

// ---------------------------------------------------------------------------
// Win32 keyboard input
// ---------------------------------------------------------------------------

const VK_RETURN: u16 = 0x0D;
const VK_ESCAPE: u16 = 0x1B;
const VK_TAB: u16 = 0x09;
const VK_LEFT: u16 = 0x25;
const VK_UP: u16 = 0x26;
const VK_RIGHT: u16 = 0x27;
const VK_DOWN: u16 = 0x28;

enum InputAction {
    None,
    Quit,
    Tab,
    Enter,
    Escape,
    Up,
    Down,
    Left,
    Right,
    Resize(u16, u16),
}

fn poll_input(stdin_handle: HANDLE, stdout_handle: HANDLE) -> InputAction {
    let mut action = InputAction::None;

    loop {
        let mut count: u32 = 0;
        unsafe {
            GetNumberOfConsoleInputEvents(stdin_handle, &mut count);
        }
        if count == 0 {
            break;
        }

        let mut record: INPUT_RECORD = unsafe { std::mem::zeroed() };
        let mut read: u32 = 0;
        unsafe {
            ReadConsoleInputW(stdin_handle, &mut record, 1, &mut read);
        }
        if read == 0 {
            break;
        }

        match record.EventType as u32 {
            KEY_EVENT => {
                let key = unsafe { record.Event.KeyEvent };
                if key.bKeyDown == 0 {
                    continue;
                }
                let vk = key.wVirtualKeyCode;
                let ch = unsafe { key.uChar.UnicodeChar };

                match vk {
                    VK_ESCAPE => action = InputAction::Escape,
                    VK_RETURN => action = InputAction::Enter,
                    VK_TAB => action = InputAction::Tab,
                    VK_UP => action = InputAction::Up,
                    VK_DOWN => action = InputAction::Down,
                    VK_LEFT => action = InputAction::Left,
                    VK_RIGHT => action = InputAction::Right,
                    _ => {
                        if ch == b'q' as u16 || ch == b'Q' as u16 {
                            action = InputAction::Quit;
                        }
                    }
                }
            }
            WINDOW_BUFFER_SIZE_EVENT => {
                let (w, h) = get_console_size(stdout_handle);
                action = InputAction::Resize(w, h);
            }
            _ => {}
        }
    }

    action
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
    palette: AttrPalette,
    cols: u16,
    rows: u16,
    rng: Rng,
}

impl App {
    fn new(cols: u16, rows: u16) -> Self {
        let mut rng = Rng::new();
        let base = cols as usize;
        let extra = base / 3;
        let mut drops = Vec::with_capacity(base + extra);
        for c in 0..cols {
            drops.push(Drop::new(c, rows, &mut rng));
        }
        for _ in 0..extra {
            let c = rng.gen_u32(cols as u32) as u16;
            drops.push(Drop::new(c, rows, &mut rng));
        }
        Self {
            drops,
            frame_count: 0,
            menu_open: false,
            menu: Menu::load(),
            launch_message: None,
            palette: build_attr_palette(),
            cols,
            rows,
            rng,
        }
    }

    fn resize(&mut self, new_cols: u16, new_rows: u16) {
        let old_cols = self.cols;
        self.cols = new_cols;
        self.rows = new_rows;

        for drop in &mut self.drops {
            if drop.col >= new_cols {
                drop.col = self.rng.gen_u32(new_cols as u32) as u16;
                drop.reset(new_rows, &mut self.rng);
            }
        }

        if new_cols > old_cols {
            let base = new_cols as usize;
            let extra = base / 3;
            let target = base + extra;
            while self.drops.len() < target {
                let c = self.rng.gen_u32(new_cols as u32) as u16;
                self.drops.push(Drop::new(c, new_rows, &mut self.rng));
            }
        }

        let base = new_cols as usize;
        let extra = base / 3;
        let target = base + extra;
        if self.drops.len() > target {
            self.drops.truncate(target);
        }
    }

    fn update(&mut self) {
        let rows = self.rows;
        let rng = &mut self.rng;
        for drop in &mut self.drops {
            drop.update(rows, rng);
        }
        self.frame_count += 1;
    }
}

// ---------------------------------------------------------------------------
// Rendering into Cell buffer
// ---------------------------------------------------------------------------

fn render_to_buffer(buf: &mut [Cell], app: &App) {
    let cols = app.cols as usize;
    let rows = app.rows as usize;
    let total = cols * rows;

    for cell in buf[..total].iter_mut() {
        *cell = Cell::BLANK;
    }

    let palette = &app.palette;

    for drop in &app.drops {
        let c = drop.col as usize;
        if c >= cols || drop.len == 0 {
            continue;
        }

        let head_row = drop.head;
        let len = drop.len as i32;
        let tail_row = head_row - len + 1;

        let vis_top = tail_row.max(0);
        let vis_bot = head_row.min(rows as i32 - 1);
        if vis_top > vis_bot {
            continue;
        }

        let i_start = (head_row - vis_bot) as u16;
        let i_end = (head_row - vis_top) as u16;

        for i in i_start..=i_end {
            let r = (head_row - i as i32) as usize;
            let ch = drop.trail_char_u16(i);

            let attr = if i == 0 {
                palette.head
            } else if i <= 2 {
                palette.near_head[(i - 1) as usize]
            } else {
                let max_trail = drop.max_len.saturating_sub(3).max(1) as usize;
                let frac_idx = ((i as usize - 3) * TRAIL_PALETTE_SIZE) / max_trail;
                let idx = frac_idx.min(TRAIL_PALETTE_SIZE - 1);
                palette.trail[idx]
            };

            let cell = &mut buf[r * cols + c];
            cell.ch = ch;
            cell.attr = attr;
        }
    }

    // Status bar
    let status = if app.menu_open {
        format!(" BADDERBLOOD // frame {} ", app.frame_count)
    } else {
        format!(
            " BADDERBLOOD // frame {} // Tab for menu // q to quit ",
            app.frame_count
        )
    };
    let sw = status.len();
    if cols > sw + 2 && rows > 1 {
        let sx = cols - sw - 1;
        let sy = rows - 1;
        for (i, &b) in status.as_bytes().iter().enumerate() {
            let cell = &mut buf[sy * cols + sx + i];
            cell.ch = b as u16;
            cell.attr = ATTR_STATUS;
        }
    }

    // Launch message
    if let Some((ref msg, when)) = app.launch_message {
        if when.elapsed() < Duration::from_secs(3) {
            let display = format!(" {} ", msg);
            let mw = display.len();
            if cols > mw + 2 && rows > 2 {
                let mx = cols - mw - 1;
                let my = rows - 2;
                for (i, &b) in display.as_bytes().iter().enumerate() {
                    let cell = &mut buf[my * cols + mx + i];
                    cell.ch = b as u16;
                    cell.attr = ATTR_MSG;
                }
            }
        }
    }

    // Menu overlay
    if app.menu_open {
        render_menu_to_buffer(buf, &app.menu, cols, rows);
    }
}

fn render_menu_to_buffer(buf: &mut [Cell], menu: &Menu, cols: usize, rows: usize) {
    let menu_width = 64usize.min(cols.saturating_sub(4));
    let menu_height = 24usize.min(rows.saturating_sub(4));
    let mx = (cols.saturating_sub(menu_width)) / 2;
    let my = (rows.saturating_sub(menu_height)) / 2;

    let border_attr: u16 = 0x0A;
    let title_attr: u16 = 0x0A;
    let instr_attr: u16 = 0x02;
    let cat_attr: u16 = 0x0A;
    let cat_sel_attr: u16 = 0x20;
    let entry_attr: u16 = 0x02;
    let entry_sel_attr: u16 = 0x20;
    let bg_attr: u16 = 0x00;

    // Clear menu area
    for r in my..my + menu_height {
        for c in mx..mx + menu_width {
            if r < rows && c < cols {
                let cell = &mut buf[r * cols + c];
                cell.ch = b' ' as u16;
                cell.attr = bg_attr;
            }
        }
    }

    let draw_char = |buf: &mut [Cell], r: usize, c: usize, ch: u16, attr: u16| {
        if r < rows && c < cols {
            let cell = &mut buf[r * cols + c];
            cell.ch = ch;
            cell.attr = attr;
        }
    };

    // Top/bottom borders
    for c in mx..mx + menu_width {
        draw_char(buf, my, c, b'-' as u16, border_attr);
        draw_char(buf, my + menu_height - 1, c, b'-' as u16, border_attr);
    }
    for r in my..my + menu_height {
        draw_char(buf, r, mx, b'|' as u16, border_attr);
        draw_char(buf, r, mx + menu_width - 1, b'|' as u16, border_attr);
    }
    draw_char(buf, my, mx, b'+' as u16, border_attr);
    draw_char(buf, my, mx + menu_width - 1, b'+' as u16, border_attr);
    draw_char(buf, my + menu_height - 1, mx, b'+' as u16, border_attr);
    draw_char(buf, my + menu_height - 1, mx + menu_width - 1, b'+' as u16, border_attr);

    // Title
    let title = " BadderBlood // Payload Launcher ";
    let title_start = mx + 2;
    for (i, &b) in title.as_bytes().iter().enumerate() {
        if title_start + i < mx + menu_width - 1 {
            draw_char(buf, my, title_start + i, b as u16, title_attr);
        }
    }

    let inner_x = mx + 1;
    let inner_y = my + 1;
    let inner_w = menu_width - 2;
    let inner_h = menu_height - 2;

    let mut lines: Vec<(String, u16)> = Vec::new();

    let instructions = " [Up/Dn] Navigate  [Enter] Select  [L/R] Collapse/Expand  [Esc] Close";
    lines.push((instructions.to_string(), instr_attr));
    lines.push((String::new(), bg_attr));

    if menu.categories.is_empty() {
        lines.push((" No payloads found in payload/ directory".to_string(), 0x04));
    } else {
        for (ci, cat) in menu.categories.iter().enumerate() {
            let is_cat_selected = matches!(&menu.cursor, MenuIndex::Category(c) if *c == ci);
            let prefix = if cat.expanded { "v " } else { "> " };
            let attr = if is_cat_selected { cat_sel_attr } else { cat_attr };
            lines.push((format!(" {}{}", prefix, cat.name), attr));

            if cat.expanded {
                for (ei, entry) in cat.entries.iter().enumerate() {
                    let is_sel = matches!(&menu.cursor, MenuIndex::Entry(c, e) if *c == ci && *e == ei);
                    let attr = if is_sel { entry_sel_attr } else { entry_attr };
                    lines.push((format!("     {} ", entry.name), attr));
                }
            }
        }
    }

    let visible_height = inner_h;
    let mut scroll = menu.scroll_offset;
    if lines.len() > visible_height {
        let cursor_line = {
            let mut line = 2usize;
            for (ci, cat) in menu.categories.iter().enumerate() {
                match &menu.cursor {
                    MenuIndex::Category(c) if *c == ci => break,
                    MenuIndex::Entry(c, e) if *c == ci => {
                        line += 1 + *e;
                        break;
                    }
                    _ => {}
                }
                line += 1;
                if cat.expanded {
                    line += cat.entries.len();
                }
            }
            line
        };
        if cursor_line < scroll + 2 {
            scroll = cursor_line.saturating_sub(2);
        } else if cursor_line >= scroll + visible_height - 2 {
            scroll = cursor_line.saturating_sub(visible_height - 3);
        }
    } else {
        scroll = 0;
    }

    for (li, (text, attr)) in lines.iter().enumerate().skip(scroll).take(visible_height) {
        let row = inner_y + (li - scroll);
        if row >= rows {
            break;
        }
        for (ci, &b) in text.as_bytes().iter().enumerate() {
            let col = inner_x + ci;
            if col >= inner_x + inner_w {
                break;
            }
            if col < cols {
                draw_char(buf, row, col, b as u16, *attr);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// VT-based diff renderer: only emit escape sequences for changed cells
// ---------------------------------------------------------------------------

/// UTF-8 scratch buffer for building VT output.
/// Pre-allocated to avoid per-frame allocation.
struct VtRenderer {
    out: Vec<u8>,
    /// Small buffer for encoding a single UTF-16 code unit to UTF-8
    utf8_buf: [u8; 4],
}

impl VtRenderer {
    fn new(capacity: usize) -> Self {
        Self {
            out: Vec::with_capacity(capacity),
            utf8_buf: [0u8; 4],
        }
    }

    /// Compare `cur` against `prev`, emit VT sequences for differences,
    /// then copy cur -> prev. Writes the output to `handle` via WriteFile.
    fn render_diff(
        &mut self,
        cur: &[Cell],
        prev: &mut [Cell],
        cols: usize,
        rows: usize,
        handle: HANDLE,
    ) {
        self.out.clear();

        let total = cols * rows;
        let mut last_attr: u16 = 0xFFFF; // sentinel: no SGR set yet
        let mut cursor_row: usize = usize::MAX;
        let mut cursor_col: usize = usize::MAX;

        for idx in 0..total {
            let c = cur[idx];
            let p = prev[idx];
            if c == p {
                continue;
            }
            prev[idx] = c;

            let r = idx / cols;
            let col = idx % cols;

            // Emit cursor-move if not already at the right position
            if r != cursor_row || col != cursor_col {
                // VT uses 1-based coordinates
                write_cursor_pos(&mut self.out, r + 1, col + 1);
            }

            // Emit SGR if attribute changed
            if c.attr != last_attr {
                self.out.extend_from_slice(attr_to_sgr(c.attr));
                last_attr = c.attr;
            }

            // Emit the character as UTF-8
            let ch = c.ch;
            if ch < 0x80 {
                self.out.push(ch as u8);
            } else {
                let c = char::from_u32(ch as u32).unwrap_or(' ');
                let s = c.encode_utf8(&mut self.utf8_buf);
                self.out.extend_from_slice(s.as_bytes());
            }

            cursor_row = r;
            cursor_col = col + 1; // cursor advances by 1 after writing a char
        }

        if !self.out.is_empty() {
            // Reset attributes at end
            self.out.extend_from_slice(b"\x1b[0m");

            let mut written: u32 = 0;
            unsafe {
                WriteFile(
                    handle,
                    self.out.as_ptr(),
                    self.out.len() as u32,
                    &mut written,
                    std::ptr::null_mut(),
                );
            }
        }
    }

    /// Full repaint: mark entire prev buffer as dirty then render_diff.
    fn render_full(
        &mut self,
        cur: &[Cell],
        prev: &mut [Cell],
        cols: usize,
        rows: usize,
        handle: HANDLE,
    ) {
        // Invalidate prev so every cell is "changed"
        let sentinel = Cell { ch: 0xFFFF, attr: 0xFFFF };
        for p in prev.iter_mut() {
            *p = sentinel;
        }
        self.render_diff(cur, prev, cols, rows, handle);
    }
}

/// Write a VT cursor-position sequence into the buffer.
/// Format: \x1b[{row};{col}H  (1-based)
#[inline]
fn write_cursor_pos(buf: &mut Vec<u8>, row: usize, col: usize) {
    buf.extend_from_slice(b"\x1b[");
    write_usize(buf, row);
    buf.push(b';');
    write_usize(buf, col);
    buf.push(b'H');
}

/// Fast integer-to-ASCII for small numbers (avoids format!()).
#[inline]
fn write_usize(buf: &mut Vec<u8>, n: usize) {
    if n < 10 {
        buf.push(b'0' + n as u8);
    } else if n < 100 {
        buf.push(b'0' + (n / 10) as u8);
        buf.push(b'0' + (n % 10) as u8);
    } else if n < 1000 {
        buf.push(b'0' + (n / 100) as u8);
        buf.push(b'0' + ((n / 10) % 10) as u8);
        buf.push(b'0' + (n % 10) as u8);
    } else {
        // Fallback for very large terminals
        let s = n.to_string();
        buf.extend_from_slice(s.as_bytes());
    }
}

// ---------------------------------------------------------------------------
// FPS tracking
// ---------------------------------------------------------------------------

struct FpsTracker {
    window_frames: u64,
    total_frames: u64,
    window_start: Instant,
    fps_file_path: PathBuf,
}

impl FpsTracker {
    fn new() -> Self {
        let fps_file_path = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("fps.txt")))
            .unwrap_or_else(|| PathBuf::from("fps.txt"));

        Self {
            window_frames: 0,
            total_frames: 0,
            window_start: Instant::now(),
            fps_file_path,
        }
    }

    fn tick(&mut self) {
        self.window_frames += 1;
        self.total_frames += 1;

        let elapsed = self.window_start.elapsed();
        if elapsed >= Duration::from_secs(10) {
            let fps = self.window_frames as f64 / elapsed.as_secs_f64();
            self.log_fps(fps);
            self.window_frames = 0;
            self.window_start = Instant::now();
        }
    }

    fn log_fps(&self, fps: f64) {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let line = format!(
            "timestamp={} fps={:.1} total_frames={}\n",
            timestamp, fps, self.total_frames
        );
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.fps_file_path)
        {
            let _ = f.write_all(line.as_bytes());
        }
    }
}

// ---------------------------------------------------------------------------
// Main loop
// ---------------------------------------------------------------------------

fn main() -> io::Result<()> {
    unsafe { timeBeginPeriod(1) };

    let stdin_handle: HANDLE = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    let stdout_handle: HANDLE = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };

    // Save original console modes
    let mut original_stdin_mode: u32 = 0;
    let mut original_stdout_mode: u32 = 0;
    unsafe {
        GetConsoleMode(stdin_handle, &mut original_stdin_mode);
        GetConsoleMode(stdout_handle, &mut original_stdout_mode);

        // Enable VT processing on stdout so we can use ANSI escape sequences
        SetConsoleMode(
            stdout_handle,
            original_stdout_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING,
        );

        // Enable window resize events on stdin
        SetConsoleMode(stdin_handle, ENABLE_EXTENDED_FLAGS | ENABLE_WINDOW_INPUT);
    }

    // Hide cursor and clear screen using VT sequences
    {
        let init = b"\x1b[?25l\x1b[2J\x1b[H";
        let mut written: u32 = 0;
        unsafe {
            WriteFile(
                stdout_handle,
                init.as_ptr(),
                init.len() as u32,
                &mut written,
                std::ptr::null_mut(),
            );
        }
    }

    let (cols, rows) = get_console_size(stdout_handle);
    let mut app = App::new(cols, rows);

    let total_cells = cols as usize * rows as usize;
    let mut cur_buf: Vec<Cell> = vec![Cell::BLANK; total_cells];
    let mut prev_buf: Vec<Cell> = vec![Cell { ch: 0xFFFF, attr: 0xFFFF }; total_cells];

    // Pre-allocate VT output buffer (generous: ~10 bytes per changed cell)
    let mut vt = VtRenderer::new(total_cells * 10);

    let mut fps_tracker = FpsTracker::new();

    let target_fps: u64 = 30;
    let frame_dur = Duration::from_micros(1_000_000 / target_fps);

    let mut force_full_repaint = true;

    loop {
        let start = Instant::now();

        match poll_input(stdin_handle, stdout_handle) {
            InputAction::Quit => {
                if !app.menu_open {
                    break;
                }
            }
            InputAction::Escape => {
                if app.menu_open {
                    app.menu_open = false;
                } else {
                    break;
                }
            }
            InputAction::Tab | InputAction::Enter if !app.menu_open => {
                app.menu_open = true;
            }
            InputAction::Enter if app.menu_open => {
                match &app.menu.cursor {
                    MenuIndex::Category(ci) => {
                        let ci = *ci;
                        app.menu.categories[ci].expanded = !app.menu.categories[ci].expanded;
                    }
                    MenuIndex::Entry(ci, ei) => {
                        let path = app.menu.categories[*ci].entries[*ei].path.clone();
                        let display = app.menu.categories[*ci].entries[*ei].name.clone();
                        launch_ps1(&path);
                        app.launch_message =
                            Some((format!("Launched: {}", display), Instant::now()));
                        app.menu_open = false;
                    }
                }
            }
            InputAction::Up if app.menu_open => app.menu.move_up(),
            InputAction::Down if app.menu_open => app.menu.move_down(),
            InputAction::Left if app.menu_open => {
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
            InputAction::Right if app.menu_open => {
                if let MenuIndex::Category(ci) = &app.menu.cursor {
                    app.menu.categories[*ci].expanded = true;
                }
            }
            InputAction::Resize(w, h) => {
                app.resize(w, h);

                let new_total = w as usize * h as usize;
                cur_buf.resize(new_total, Cell::BLANK);
                prev_buf.resize(new_total, Cell { ch: 0xFFFF, attr: 0xFFFF });

                // Clear screen on resize
                let clear = b"\x1b[2J\x1b[H";
                let mut written: u32 = 0;
                unsafe {
                    WriteFile(
                        stdout_handle,
                        clear.as_ptr(),
                        clear.len() as u32,
                        &mut written,
                        std::ptr::null_mut(),
                    );
                }
                force_full_repaint = true;
            }
            _ => {}
        }

        app.update();

        render_to_buffer(&mut cur_buf, &app);

        if force_full_repaint {
            vt.render_full(
                &cur_buf,
                &mut prev_buf,
                app.cols as usize,
                app.rows as usize,
                stdout_handle,
            );
            force_full_repaint = false;
        } else {
            vt.render_diff(
                &cur_buf,
                &mut prev_buf,
                app.cols as usize,
                app.rows as usize,
                stdout_handle,
            );
        }

        fps_tracker.tick();

        let elapsed = start.elapsed();
        if elapsed < frame_dur {
            std::thread::sleep(frame_dur - elapsed);
        }
    }

    // Cleanup: show cursor, reset colors, restore console modes
    {
        let cleanup = b"\x1b[0m\x1b[?25h\x1b[2J\x1b[H";
        let mut written: u32 = 0;
        unsafe {
            WriteFile(
                stdout_handle,
                cleanup.as_ptr(),
                cleanup.len() as u32,
                &mut written,
                std::ptr::null_mut(),
            );
            SetConsoleMode(stdin_handle, original_stdin_mode);
            SetConsoleMode(stdout_handle, original_stdout_mode);
            timeEndPeriod(1);
        }
    }

    Ok(())
}
