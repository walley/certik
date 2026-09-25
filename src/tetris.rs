//! Tetris (Help > Tetris): classic falling-block game rendered into the certik
//! TUI with turbo-vision drawing primitives.
//!
//! 10x20 well, SRS tetrominoes, hard drop on Space, next-piece preview and a
//! dialog-colored score sidebar. Own file so the game logic stays out of the
//! application shell (src/app.rs).

use rand::rngs::ThreadRng;

use turbo_vision::core::draw::DrawBuffer;
use turbo_vision::core::event::Event;
use turbo_vision::core::geometry::Rect;
use turbo_vision::core::palette::{Attr, TvColor, colors, Palette};
use turbo_vision::core::state::GrowFlags;
use turbo_vision::terminal::Terminal;
use turbo_vision::views::view::{write_line_to_terminal, View, ViewCore};

// ---------------------------------------------------------------------------
// TetrisView - simple Tetris game using native drawing
// ---------------------------------------------------------------------------

const TETRIS_WIDTH: usize = 10;
const TETRIS_HEIGHT: usize = 20;
const TETRIS_CELL_W: usize = 2;
const TETRIS_CELL_H: usize = 1;

#[derive(Clone, Copy, PartialEq)]
enum TetrominoType {
    I, J, L, O, S, T, Z,
}

impl TetrominoType {
    /// Foreground color for a piece on the blue board.
    fn fg(self) -> TvColor {
        match self {
            TetrominoType::I => TvColor::LightCyan,
            TetrominoType::J => TvColor::LightBlue,
            TetrominoType::L => TvColor::Yellow,
            TetrominoType::O => TvColor::LightGreen,
            TetrominoType::S => TvColor::LightRed,
            TetrominoType::T => TvColor::LightMagenta,
            TetrominoType::Z => TvColor::White,
        }
    }
}

#[derive(Clone, Copy)]
struct Tetromino {
    ttype: TetrominoType,
    x: i8,
    y: i8,
    rotation: u8,
}

impl Tetromino {
    fn new(ttype: TetrominoType) -> Self {
        Self { ttype, x: 3, y: 0, rotation: 0 }
    }

    fn blocks(&self) -> [(i8, i8); 4] {
        // Standard tetromino blocks at rotation 0, centered around rotation center
        // Each shape's blocks are relative to its rotation center
        let (center_x, center_y, blocks) = match self.ttype {
            TetrominoType::I => (0, 0, [
                [(-2, 0), (-1, 0), (0, 0), (1, 0)],   // horizontal
                [(0, -1), (0, 0), (0, 1), (0, 2)],     // vertical
                [(-2, 0), (-1, 0), (0, 0), (1, 0)],    // horizontal
                [(0, -1), (0, 0), (0, 1), (0, 2)],     // vertical
            ]),
            TetrominoType::J => (0, 0, [
                [(-1, 0), (-1, -1), (0, 0), (1, 0)],   // ┘ shape
                [(0, -1), (0, 0), (0, 1), (-1, 1)],    // ╥ shape
                [(-1, 0), (0, 0), (1, 0), (1, 1)],     // └ shape
                [(1, -1), (0, -1), (0, 0), (0, 1)],    // ╙ shape
            ]),
            TetrominoType::L => (0, 0, [
                [(1, 0), (1, -1), (0, 0), (-1, 0)],   // mirror of J spawn
                [(0, -1), (0, 0), (0, 1), (1, 1)],
                [(-1, 0), (0, 0), (1, 0), (-1, 1)],
                [(-1, -1), (0, -1), (0, 0), (0, 1)],
            ]),
            TetrominoType::O => (0, 0, [
                [(0, 0), (1, 0), (0, 1), (1, 1)],      // square
                [(0, 0), (1, 0), (0, 1), (1, 1)],      // square
                [(0, 0), (1, 0), (0, 1), (1, 1)],      // square
                [(0, 0), (1, 0), (0, 1), (1, 1)],      // square
            ]),
            TetrominoType::S => (0, 0, [
                [(0, 0), (1, 0), (-1, -1), (0, -1)],   // horizontal S
                [(0, 0), (0, -1), (1, -1), (1, -2)],   // vertical S
                [(0, 0), (1, 0), (-1, -1), (0, -1)],   // horizontal S
                [(0, 0), (0, -1), (1, -1), (1, -2)],   // vertical S
            ]),
            TetrominoType::T => (0, 0, [
                [(-1, 0), (0, 0), (1, 0), (0, -1)],    // T up
                [(0, -1), (0, 0), (0, 1), (1, 0)],     // T right
                [(-1, 0), (0, 0), (1, 0), (0, 1)],     // T down
                [(0, -1), (0, 0), (0, 1), (-1, 0)],    // T left
            ]),
            TetrominoType::Z => (0, 0, [
                [(-1, 0), (0, 0), (0, -1), (1, -1)],   // horizontal Z
                [(0, 0), (0, -1), (-1, -1), (-1, -2)], // vertical Z
                [(-1, 0), (0, 0), (0, -1), (1, -1)],   // horizontal Z
                [(0, 0), (0, -1), (-1, -1), (-1, -2)], // vertical Z
            ]),
        };

        let rot = self.rotation as usize % 4;
        let (cx, cy) = (center_x + self.x, center_y + self.y);
        let base = blocks[rot];
        [
            (base[0].0 + cx, base[0].1 + cy),
            (base[1].0 + cx, base[1].1 + cy),
            (base[2].0 + cx, base[2].1 + cy),
            (base[3].0 + cx, base[3].1 + cy),
        ]
    }

    fn rotated(&self) -> Self {
        let mut t = *self;
        t.rotation = (t.rotation + 1) % 4;
        t
    }

    fn moved(&self, dx: i8, dy: i8) -> Self {
        let mut t = *self;
        // No clamp here: can_place() validates that every block of the new
        // position stays inside the well, which lets pieces with narrow
        // rotations (e.g. a vertical I) reach the rightmost column.
        t.x += dx;
        t.y += dy;
        t
    }
}

pub struct TetrisView {
    bounds: Rect,
    core: ViewCore,
    board: [[Option<TetrominoType>; TETRIS_WIDTH]; TETRIS_HEIGHT],
    current: Option<Tetromino>,
    next: TetrominoType,
    score: u32,
    lines: u32,
    level: u32,
    game_over: bool,
    tick_timer: u32,
    grow_mode: GrowFlags,
    rng: ThreadRng,
}

impl TetrisView {
    pub fn new(bounds: Rect) -> Self {
        let mut rng = rand::thread_rng();
        let next = Self::random_type(&mut rng);
        let mut view = Self {
            bounds,
            core: ViewCore::new(bounds),
            board: [[None; TETRIS_WIDTH]; TETRIS_HEIGHT],
            current: None,
            next,
            score: 0,
            lines: 0,
            level: 1,
            game_over: false,
            tick_timer: 0,
            grow_mode: GrowFlags::empty(),
            rng,
        };
        view.spawn_piece();
        view
    }

    fn random_type(rng: &mut impl rand::Rng) -> TetrominoType {
        match rng.gen_range(0..7) {
            0 => TetrominoType::I,
            1 => TetrominoType::J,
            2 => TetrominoType::L,
            3 => TetrominoType::O,
            4 => TetrominoType::S,
            5 => TetrominoType::T,
            _ => TetrominoType::Z,
        }
    }

    fn spawn_piece(&mut self) {
        self.current = Some(Tetromino::new(self.next));
        self.next = Self::random_type(&mut self.rng);
        // Check game over
        if let Some(cur) = self.current {
            for (x, y) in cur.blocks() {
                if y >= 0 && y < TETRIS_HEIGHT as i8 && x >= 0 && x < TETRIS_WIDTH as i8 {
                    if self.board[y as usize][x as usize].is_some() {
                        self.game_over = true;
                        break;
                    }
                }
            }
        }
    }

    fn can_place(&self, t: &Tetromino) -> bool {
        for (x, y) in t.blocks() {
            if x < 0 || x >= TETRIS_WIDTH as i8 || y >= TETRIS_HEIGHT as i8 {
                return false;
            }
            if y >= 0 && self.board[y as usize][x as usize].is_some() {
                return false;
            }
        }
        true
    }

    fn lock_piece(&mut self) {
        if let Some(cur) = self.current.take() {
            for (x, y) in cur.blocks() {
                if y >= 0 && y < TETRIS_HEIGHT as i8 && x >= 0 && x < TETRIS_WIDTH as i8 {
                    self.board[y as usize][x as usize] = Some(cur.ttype);
                }
            }
            self.clear_lines();
            self.spawn_piece();
        }
    }

    /// Hard drop: move the current piece straight down until it lands,
    /// award 2 points per cell dropped, then lock it.
    fn hard_drop(&mut self) {
        if let Some(cur) = self.current {
            let mut dropped = cur;
            let mut cells = 0u32;
            loop {
                let next = dropped.moved(0, 1);
                if self.can_place(&next) {
                    dropped = next;
                    cells += 1;
                } else {
                    break;
                }
            }
            self.current = Some(dropped);
            self.score += cells * 2;
            self.lock_piece();
        }
    }

    fn clear_lines(&mut self) {
        let mut cleared = 0;
        let mut y = TETRIS_HEIGHT - 1;
        while y > 0 {
            if self.board[y].iter().all(|c| c.is_some()) {
                cleared += 1;
                for row in (1..=y).rev() {
                    self.board[row] = self.board[row - 1];
                }
                self.board[0] = [None; TETRIS_WIDTH];
            } else {
                if y == 0 { break; }
                y -= 1;
            }
        }
        if cleared > 0 {
            self.lines += cleared;
            self.score += match cleared {
                1 => 40 * (self.level + 1),
                2 => 100 * (self.level + 1),
                3 => 300 * (self.level + 1),
                4 => 1200 * (self.level + 1),
                _ => 0,
            };
            self.level = self.lines / 10 + 1;
        }
    }

    fn tick(&mut self) {
        if self.game_over {
            return;
        }
        self.tick_timer += 1;
        let speed = match self.level {
            1 => 48, 2 => 43, 3 => 38, 4 => 33, 5 => 28,
            6 => 23, 7 => 18, 8 => 13, 9 => 8, _ => 5,
        };
        if self.tick_timer >= speed {
            self.tick_timer = 0;
            if let Some(cur) = self.current {
                let moved = cur.moved(0, 1);
                if self.can_place(&moved) {
                    self.current = Some(moved);
                } else {
                    self.lock_piece();
                }
            }
        }
    }

    fn handle_key(&mut self, key: u16) {
        use turbo_vision::core::event::{KB_LEFT, KB_RIGHT, KB_DOWN, KB_UP, KB_ESC};
        if self.game_over {
            if key == KB_ESC {
                self.reset();
            }
            return;
        }
        if let Some(cur) = self.current {
            match key {
                KB_LEFT => {
                    let moved = cur.moved(-1, 0);
                    if self.can_place(&moved) {
                        self.current = Some(moved);
                    }
                }
                KB_RIGHT => {
                    let moved = cur.moved(1, 0);
                    if self.can_place(&moved) {
                        self.current = Some(moved);
                    }
                }
                KB_DOWN => {
                    let moved = cur.moved(0, 1);
                    if self.can_place(&moved) {
                        self.current = Some(moved);
                        self.score += 1;
                    } else {
                        self.lock_piece();
                    }
                }
                KB_UP => {
                    let rotated = cur.rotated();
                    if self.can_place(&rotated) {
                        self.current = Some(rotated);
                    } else {
                        // Wall kicks
                        for dx in [-1, 1, -2, 2] {
                            let kicked = Tetromino { x: rotated.x + dx, ..rotated };
                            if self.can_place(&kicked) {
                                self.current = Some(kicked);
                                break;
                            }
                        }
                    }
                }
                0x20 => { // Space: hard drop to the ground
                    self.hard_drop();
                }
                KB_ESC => {
                    // Could pause or quit
                }
                _ => {}
            }
        }
    }

    fn reset(&mut self) {
        self.board = [[None; TETRIS_WIDTH]; TETRIS_HEIGHT];
        self.current = None;
        self.score = 0;
        self.lines = 0;
        self.level = 1;
        self.game_over = false;
        self.tick_timer = 0;
        self.spawn_piece();
    }
}

impl View for TetrisView {
    fn core(&self) -> &ViewCore {
        &self.core
    }
    fn core_mut(&mut self) -> &mut ViewCore {
        &mut self.core
    }
    fn bounds(&self) -> Rect {
        self.bounds
    }
    fn set_bounds(&mut self, bounds: Rect) {
        self.bounds = bounds;
    }
fn draw(&mut self, terminal: &mut Terminal) {
        self.tick();
        let width = self.bounds.width_clamped() as usize;
        let height = self.bounds.height_clamped() as usize;
        let board_w = TETRIS_WIDTH * TETRIS_CELL_W;
        let board_h = TETRIS_HEIGHT * TETRIS_CELL_H;
        let start_x = (width.saturating_sub(board_w + 14)) / 2; // Reserve space for sidebar
        let start_y = (height.saturating_sub(board_h)) / 2;
        let info_x = start_x + board_w + 2;

        // One buffer per window row. Everything is stamped into the buffers
        // first and flushed once at the end, so no single line write can wipe
        // out the border, board, or previously drawn cells mid-frame.
        let mut rows: Vec<DrawBuffer> = (0..height).map(|_| DrawBuffer::new(width)).collect();

        // --- Window background: standard app blue ---------------------------
        for y in 0..height {
            rows[y].move_str(0, &" ".repeat(width), colors::NORMAL);
        }

        // --- Board background: standard blue ---------------------------------
        for row in 0..TETRIS_HEIGHT {
            let y = start_y + row;
            if y < height {
                rows[y].move_str(start_x, &"  ".repeat(TETRIS_WIDTH), colors::NORMAL);
            }
        }

        // --- Sidebar background: dialog color (black on light gray) ----------
        let dialog_bg = colors::DIALOG_NORMAL;
        if info_x + 12 < width {
            for row in 0..TETRIS_HEIGHT {
                let y = start_y + row;
                if y < height {
                    rows[y].move_str(info_x, &" ".repeat(12), dialog_bg);
                }
            }
        }

        // --- Board border: clean box, drawn into the buffers -----------------
        // Corners sit at (start_x-1, start_y-1) .. (start_x+board_w, start_y+board_h).
        let border_attr = Attr::new(TvColor::LightCyan, TvColor::Blue);
        if start_y > 0 && start_y - 1 < height {
            let top = start_y - 1;
            if start_x > 0 {
                rows[top].move_char(start_x - 1, '┌', border_attr, 1);
            }
            if start_x + board_w < width {
                rows[top].move_char(start_x + board_w, '┐', border_attr, 1);
            }
            if start_x < width {
                rows[top].move_char(start_x, '─', border_attr, board_w);
            }
        }
        let bottom = start_y + board_h;
        if bottom < height {
            if start_x > 0 {
                rows[bottom].move_char(start_x - 1, '└', border_attr, 1);
            }
            if start_x + board_w < width {
                rows[bottom].move_char(start_x + board_w, '┘', border_attr, 1);
            }
            if start_x < width {
                rows[bottom].move_char(start_x, '─', border_attr, board_w);
            }
        }
        for y in start_y..start_y + board_h {
            if y < height {
                if start_x > 0 {
                    rows[y].move_char(start_x - 1, '│', border_attr, 1);
                }
                if start_x + board_w < width {
                    rows[y].move_char(start_x + board_w, '│', border_attr, 1);
                }
            }
        }

        // --- Locked pieces ---------------------------------------------------
        for (row, line) in self.board.iter().enumerate() {
            for (col, cell) in line.iter().enumerate() {
                if let Some(ttype) = cell {
                    let x = start_x + col * TETRIS_CELL_W;
                    let y = start_y + row * TETRIS_CELL_H;
                    if x + 1 < width && y < height {
                        rows[y].move_str(x, "██", Attr::new(ttype.fg(), TvColor::Blue));
                    }
                }
            }
        }

        // --- Current falling piece -------------------------------------------
        if let Some(cur) = self.current {
            let attr = Attr::new(cur.ttype.fg(), TvColor::Blue);
            for (x, y) in cur.blocks() {
                if y >= 0 && y < TETRIS_HEIGHT as i8 && x >= 0 && x < TETRIS_WIDTH as i8 {
                    let dx = start_x + (x as usize) * TETRIS_CELL_W;
                    let dy = start_y + (y as usize) * TETRIS_CELL_H;
                    if dx + 1 < width && dy < height {
                        rows[dy].move_str(dx, "██", attr);
                    }
                }
            }
        }

        // --- Sidebar info: score / level / next piece ------------------------
        if info_x + 12 < width {
            let lines = [
                format!("Score:{:>5}", self.score),
                format!("Lines:{:>5}", self.lines),
                format!("Level:{:>5}", self.level),
                String::new(),
                "Next:".to_string(),
            ];
            for (i, line) in lines.iter().enumerate() {
                let y = start_y + i;
                if y < height {
                    rows[y].move_str(info_x, line, dialog_bg);
                }
            }
            // Next-piece preview on the dialog-colored sidebar.
            // Derived from blocks() (rotation 0, centered at origin) so the
            // preview always matches the actual piece shapes.
            let next_piece = Tetromino { ttype: self.next, x: 0, y: 0, rotation: 0 };
            let next_attr = Attr::new(self.next.fg(), TvColor::LightGray);
            for (bx, by) in next_piece.blocks() {
                let x = info_x + ((bx as isize + 2) as usize) * TETRIS_CELL_W;
                let y = start_y + 6 + ((-(by as isize) + 2) as usize) * TETRIS_CELL_H;
                if x + 1 < width && y < height {
                    rows[y].move_str(x, "██", next_attr);
                }
            }
        }

        // --- Game over overlay ------------------------------------------------
        if self.game_over {
            let msg = "GAME OVER";
            let msg2 = "Press ESC to restart";
            let x = (width.saturating_sub(msg.len())) / 2;
            let x2 = (width.saturating_sub(msg2.len())) / 2;
            let y = start_y + TETRIS_HEIGHT / 2;
            if y < height {
                rows[y].move_char(x, ' ', dialog_bg, msg.len());
                rows[y].move_str(x, msg, Attr::new(TvColor::LightRed, TvColor::LightGray));
            }
            if y + 1 < height {
                rows[y + 1].move_char(x2, ' ', dialog_bg, msg2.len());
                rows[y + 1].move_str(x2, msg2, dialog_bg);
            }
        }

        // --- Flush all rows once ----------------------------------------------
        for y in 0..height {
            write_line_to_terminal(terminal, self.bounds.a.x, self.bounds.a.y + y as i16, &rows[y]);
        }
    }

    fn handle_event(&mut self, event: &mut Event) {
        use turbo_vision::core::event::EventType;
        match event.what {
            EventType::Keyboard => {
                self.handle_key(event.key_code);
                event.clear();
            }
            _ => {}
        }
    }
    fn can_focus(&self) -> bool {
        true
    }
    fn get_palette(&self) -> Option<Palette> {
        None
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
    fn grow_mode(&self) -> GrowFlags {
        self.grow_mode
    }
    fn set_grow_mode(&mut self, grow_mode: GrowFlags) {
        self.grow_mode = grow_mode;
    }
}
