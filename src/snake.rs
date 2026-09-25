//! Snake (Help > Snake): a Nokia-style game rendered into the certik TUI.
//!
//! The snake crawls over a black LCD panel framed by a green border; food
//! spawns randomly and each piece scores 10 points while the snake speeds
//! up. Arrows steer (one turn per tick, no reversing into yourself),
//! ESC restarts after game over. Score sits in a dialog-colored sidebar.

use std::collections::VecDeque;

use rand::rngs::ThreadRng;
use rand::Rng;

use turbo_vision::core::draw::DrawBuffer;
use turbo_vision::core::event::Event;
use turbo_vision::core::geometry::Rect;
use turbo_vision::core::palette::{Attr, TvColor, colors, Palette};
use turbo_vision::core::state::GrowFlags;
use turbo_vision::terminal::Terminal;
use turbo_vision::views::view::{write_line_to_terminal, View, ViewCore};

/// Play field size in cells (not counting the border).
const SNAKE_WIDTH: i16 = 22;
const SNAKE_HEIGHT: i16 = 20;

/// Base tick interval before the first food; speeds up as the score grows.
const BASE_INTERVAL: u32 = 12;
const MIN_INTERVAL: u32 = 3;

/// Spacing between the LCD board frame and the score sidebar, and the width
/// of the dialog-colored score panel.
const GAP: usize = 2;
const SIDEBAR_WIDTH: usize = 12;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Dir {
    Up,
    Down,
    Left,
    Right,
}

impl Dir {
    fn is_opposite(self, other: Dir) -> bool {
        matches!(
            (self, other),
            (Dir::Up, Dir::Down) | (Dir::Down, Dir::Up) | (Dir::Left, Dir::Right) | (Dir::Right, Dir::Left)
        )
    }
}

pub struct SnakeView {
    bounds: Rect,
    core: ViewCore,
    /// Snake cells, head at the front.
    snake: VecDeque<(i16, i16)>,
    dir: Dir,
    /// One queued turn, applied at the next tick.
    pending: Option<Dir>,
    food: (i16, i16),
    score: u32,
    game_over: bool,
    tick_timer: u32,
    interval: u32,
    grow_mode: GrowFlags,
    rng: ThreadRng,
}

impl SnakeView {
    pub fn new(bounds: Rect) -> Self {
        let mut view = Self {
            bounds,
            core: ViewCore::new(bounds),
            snake: VecDeque::new(),
            dir: Dir::Right,
            pending: None,
            food: (0, 0),
            score: 0,
            game_over: false,
            tick_timer: 0,
            interval: BASE_INTERVAL,
            grow_mode: GrowFlags::empty(),
            rng: rand::thread_rng(),
        };
        view.reset();
        view
    }

    fn reset(&mut self) {
        self.snake.clear();
        let cy = SNAKE_HEIGHT / 2;
        // Head at the front (leads the travel direction); body trails left.
        self.snake.push_back((2, cy));
        self.snake.push_back((1, cy));
        self.snake.push_back((0, cy));
        self.dir = Dir::Right;
        self.pending = None;
        self.score = 0;
        self.game_over = false;
        self.tick_timer = 0;
        self.interval = BASE_INTERVAL;
        self.spawn_food();
    }

    fn spawn_food(&mut self) {
        loop {
            let x = self.rng.gen_range(0..SNAKE_WIDTH);
            let y = self.rng.gen_range(0..SNAKE_HEIGHT);
            if !self.snake.contains(&(x, y)) {
                self.food = (x, y);
                return;
            }
        }
    }

    fn next_head(&self) -> (i16, i16) {
        let (hx, hy) = *self.snake.front().unwrap_or(&(0, 0));
        match self.dir {
            Dir::Up => (hx, hy - 1),
            Dir::Down => (hx, hy + 1),
            Dir::Left => (hx - 1, hy),
            Dir::Right => (hx + 1, hy),
        }
    }

    fn tick(&mut self) {
        if self.game_over {
            return;
        }
        self.tick_timer += 1;
        if self.tick_timer < self.interval {
            return;
        }
        self.tick_timer = 0;

        // Apply the queued turn (at most one per tick; never reverse).
        if let Some(d) = self.pending {
            if !d.is_opposite(self.dir) {
                self.dir = d;
            }
            self.pending = None;
        }

        let head = self.next_head();
        if head.0 < 0 || head.0 >= SNAKE_WIDTH || head.1 < 0 || head.1 >= SNAKE_HEIGHT {
            self.game_over = true;
            return;
        }
        // The tail cell vacates this tick (unless this move grows us), so
        // steering into the exact tail cell is legal.
        let tail = *self.snake.back().unwrap_or(&(SNAKE_WIDTH, SNAKE_HEIGHT));
        if self.snake.contains(&head) && head != tail {
            self.game_over = true;
            return;
        }

        self.snake.push_front(head);
        if head == self.food {
            self.score += 10;
            // Speed up as the snake grows.
            self.interval = (BASE_INTERVAL - self.score / 50).max(MIN_INTERVAL);
            self.spawn_food();
        } else {
            self.snake.pop_back();
        }
    }

    fn handle_key(&mut self, key: u16) {
        use turbo_vision::core::event::{KB_DOWN, KB_ESC, KB_LEFT, KB_RIGHT, KB_UP};
        if self.game_over {
            if key == KB_ESC {
                self.reset();
            }
            return;
        }
        let d = match key {
            KB_UP => Some(Dir::Up),
            KB_DOWN => Some(Dir::Down),
            KB_LEFT => Some(Dir::Left),
            KB_RIGHT => Some(Dir::Right),
            _ => None,
        };
        if let Some(d) = d {
            self.pending = Some(d);
        }
    }
}

impl View for SnakeView {
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
        let board_w = SNAKE_WIDTH as usize + 2;
        let board_h = SNAKE_HEIGHT as usize + 2;
        // Center the board + gap + side panel block, leaving a visible margin
        // of app blue on both sides of the window.
        let start_x = (width.saturating_sub(board_w + GAP + SIDEBAR_WIDTH)) / 2;
        let start_y = (height.saturating_sub(board_h)) / 2;
        let info_x = start_x + board_w + GAP;

        // One buffer per row; stamp everything, flush once.
        let mut rows: Vec<DrawBuffer> = (0..height).map(|_| DrawBuffer::new(width)).collect();

        // --- Window background: standard app blue --------------------------
        for y in 0..height {
            rows[y].move_str(0, &" ".repeat(width), colors::NORMAL);
        }

        // --- Nokia LCD screen: black field ---------------------------------
        let lcd = Attr::new(TvColor::Black, TvColor::Black);
        for fy in 0..SNAKE_HEIGHT {
            let y = start_y + 1 + fy as usize;
            if y < height {
                rows[y].move_str(start_x + 1, &" ".repeat(SNAKE_WIDTH as usize), lcd);
            }
        }

        // --- Sidebar background: dialog color (black on light gray) --------
        let dialog_bg = colors::DIALOG_NORMAL;
        if info_x + SIDEBAR_WIDTH <= width {
            for fy in 0..SNAKE_HEIGHT {
                let y = start_y + 1 + fy as usize;
                if y < height {
                    rows[y].move_str(info_x, &" ".repeat(SIDEBAR_WIDTH), dialog_bg);
                }
            }
        }

        // --- Green LCD frame around the field -------------------------------
        let frame_attr = Attr::new(TvColor::LightGreen, TvColor::Black);
        if start_y < height {
            if start_x < width {
                rows[start_y].move_char(start_x, '┌', frame_attr, 1);
            }
            if start_x + 1 < width {
                rows[start_y].move_char(start_x + 1, '─', frame_attr, board_w - 2);
            }
            if start_x + board_w - 1 < width {
                rows[start_y].move_char(start_x + board_w - 1, '┐', frame_attr, 1);
            }
        }
        let bottom = start_y + board_h - 1;
        if bottom < height {
            if start_x < width {
                rows[bottom].move_char(start_x, '└', frame_attr, 1);
            }
            if start_x + 1 < width {
                rows[bottom].move_char(start_x + 1, '─', frame_attr, board_w - 2);
            }
            if start_x + board_w - 1 < width {
                rows[bottom].move_char(start_x + board_w - 1, '┘', frame_attr, 1);
            }
        }
        for y in (start_y + 1)..(start_y + board_h - 1) {
            if y < height {
                if start_x < width {
                    rows[y].move_char(start_x, '│', frame_attr, 1);
                }
                if start_x + board_w - 1 < width {
                    rows[y].move_char(start_x + board_w - 1, '│', frame_attr, 1);
                }
            }
        }

        // --- Snake + food on the LCD screen ---------------------------------
        let snake_attr = Attr::new(TvColor::LightGreen, TvColor::Black);
        for (sx, sy) in self.snake.iter() {
            let x = start_x + 1 + *sx as usize;
            let y = start_y + 1 + *sy as usize;
            if x < width && y < height {
                rows[y].move_char(x, '█', snake_attr, 1);
            }
        }
        let food_attr = Attr::new(TvColor::LightRed, TvColor::Black);
        let fx = start_x + 1 + self.food.0 as usize;
        let fy = start_y + 1 + self.food.1 as usize;
        if fx < width && fy < height {
            rows[fy].move_char(fx, '●', food_attr, 1);
        }

        // --- Sidebar info ----------------------------------------------------
        if info_x + SIDEBAR_WIDTH <= width {
            let lines = [
                format!("Score:{:>5}", self.score),
                format!("Length:{:>4}", self.snake.len()),
                String::new(),
                "Arrows: move".to_string(),
                "ESC: restart".to_string(),
            ];
            for (i, line) in lines.iter().enumerate() {
                let y = start_y + 1 + i;
                if y < height {
                    rows[y].move_str(info_x, line, dialog_bg);
                }
            }
        }

        // --- Game over overlay ------------------------------------------------
        if self.game_over {
            let msg = "GAME OVER";
            let msg2 = "Press ESC to restart";
            let x = (width.saturating_sub(msg.len())) / 2;
            let x2 = (width.saturating_sub(msg2.len())) / 2;
            let y = start_y + SNAKE_HEIGHT as usize / 2 + 2;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawns_and_moves_forward_without_dying() {
        let mut view = SnakeView::new(Rect::new(0, 0, 38, 24));
        view.interval = 1;
        for _ in 0..5 {
            view.tick();
        }
        assert!(!view.game_over, "snake died while just moving forward");
        assert_eq!(view.snake.len(), 3);
        assert_eq!(*view.snake.front().unwrap(), (2 + 5, SNAKE_HEIGHT / 2));
    }

    #[test]
    fn eating_grows_and_scores() {
        let mut view = SnakeView::new(Rect::new(0, 0, 38, 24));
        view.interval = 1;
        // Place food directly in front of the head.
        let head = *view.snake.front().unwrap();
        view.food = (head.0 + 1, head.1);
        view.tick();
        assert!(!view.game_over);
        assert_eq!(view.score, 10);
        assert_eq!(view.snake.len(), 4);
        assert_eq!(*view.snake.front().unwrap(), (head.0 + 1, head.1));
    }

    #[test]
    fn cannot_reverse_into_self_on_next_tick() {
        let mut view = SnakeView::new(Rect::new(0, 0, 38, 24));
        view.interval = 1;
        // A left turn is opposite to the current direction (Right) and must
        // be ignored rather than killing the snake.
        view.pending = Some(Dir::Left);
        view.tick();
        assert!(!view.game_over);
        assert_eq!(view.dir, Dir::Right);
        assert!(view.pending.is_none());
        assert_eq!(*view.snake.front().unwrap(), (3, SNAKE_HEIGHT / 2));
    }

    #[test]
    fn hitting_the_wall_is_game_over() {
        let mut view = SnakeView::new(Rect::new(0, 0, 38, 24));
        view.interval = 1;
        view.dir = Dir::Up;
        for _ in 0..12 {
            view.tick();
        }
        assert!(view.game_over);
    }
}