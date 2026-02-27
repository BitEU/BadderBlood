# Matrix Rain – Ratatui Terminal Effect

A stunning Matrix-style digital rain effect built with **Rust**, **ratatui**, and **crossterm**.

## Features

- **Half-width Katakana + ASCII** character mix (classic Matrix look)
- **UTF-8 safe** – all characters are valid Unicode, using half-width Katakana (U+FF66–U+FF9D) which renders correctly in Windows conhost, Windows Terminal, and all modern Linux/macOS terminals
- **Smooth 30 FPS** animation with variable-speed falling streams
- **Dynamic trail fading** – bright white/green heads fade through vivid green to dark green tails
- **Glitch mutations** – characters randomly change mid-stream for that digital chaos feel
- **Overlapping streams** – extra density columns for a rich, layered look
- **Pulsing brightness** – subtle sinusoidal glow on stream heads
- **Responsive** – adapts to terminal resize

## Build & Run

```bash
# Debug build (fast compile)
cargo run

# Release build (smooth performance)
cargo run --release
```

## Controls

| Key       | Action |
|-----------|--------|
| `q` / `Q` | Quit   |
| `Esc`     | Quit   |

## Windows conhost Compatibility

The character set is specifically chosen for conhost compatibility:

- **Half-width Katakana** (U+FF66–U+FF9D) are single-cell-width characters present in the Japanese font fallback that Windows ships by default
- If characters show as boxes, change the conhost font to **MS Gothic**, **NSimSun**, or **Consolas** (Properties → Font)
- Works perfectly out of the box in **Windows Terminal**

## Requirements

- Rust 1.70+  
- A terminal that supports 24-bit (truecolor) RGB — virtually all modern terminals do
- For best results on Windows conhost: set the code page to UTF-8 with `chcp 65001` before running

## Dependencies

| Crate      | Purpose                        |
|------------|--------------------------------|
| `ratatui`  | Terminal UI framework          |
| `crossterm`| Cross-platform terminal I/O    |
| `rand`     | Random character generation    |
