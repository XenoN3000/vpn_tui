/// Terminal CAPTCHA rendering utility using half-block Unicode characters.
pub struct CaptchaRenderer;

impl CaptchaRenderer {
    /// Renders a 2D boolean grid (true = dark pixel, false = light pixel)
    /// into terminal half-block characters ('▀', '▄', '█', ' ').
    #[allow(clippy::needless_range_loop)]
    pub fn render_grid(pixels: &[Vec<bool>]) -> Vec<String> {
        let height = pixels.len();
        if height == 0 {
            return Vec::new();
        }
        let width = pixels[0].len();
        let mut lines = Vec::new();

        for y in (0..height).step_by(2) {
            let mut line = String::with_capacity(width);
            for x in 0..width {
                let top = pixels[y][x];
                let bottom = if y + 1 < height {
                    pixels[y + 1][x]
                } else {
                    false
                };
                let ch = match (top, bottom) {
                    (true, true) => '█',
                    (true, false) => '▀',
                    (false, true) => '▄',
                    (false, false) => ' ',
                };
                line.push(ch);
            }
            lines.push(line);
        }

        lines
    }

    /// Converts a raw grayscale byte slice (w x h) with a threshold into a 2D boolean grid
    pub fn bytes_to_grid(
        bytes: &[u8],
        width: usize,
        height: usize,
        threshold: u8,
    ) -> Vec<Vec<bool>> {
        let mut grid = Vec::with_capacity(height);
        for y in 0..height {
            let mut row = Vec::with_capacity(width);
            for x in 0..width {
                let idx = y * width + x;
                let val = if idx < bytes.len() { bytes[idx] } else { 255 };
                row.push(val < threshold);
            }
            grid.push(row);
        }
        grid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_grid_half_blocks() {
        let grid = vec![
            vec![true, false, true, false],
            vec![true, true, false, false],
        ];
        let lines = CaptchaRenderer::render_grid(&grid);
        assert_eq!(lines.len(), 1);
        // (true, true) -> '█', (false, true) -> '▄', (true, false) -> '▀', (false, false) -> ' '
        assert_eq!(lines[0], "█▄▀ ");
    }

    #[test]
    fn test_bytes_to_grid_and_render() {
        // 2x2 image with threshold 128
        let bytes = vec![
            50, 200, // row 0: dark, light
            50, 50, // row 1: dark, dark
        ];
        let grid = CaptchaRenderer::bytes_to_grid(&bytes, 2, 2, 128);
        assert_eq!(grid[0], vec![true, false]);
        assert_eq!(grid[1], vec![true, true]);

        let lines = CaptchaRenderer::render_grid(&grid);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0], "█▄");
    }
}
