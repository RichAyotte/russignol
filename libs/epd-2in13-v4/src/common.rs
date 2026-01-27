pub const WIDTH: u32 = 122;
pub const HEIGHT: u32 = 250;
pub const BUFFER_SIZE: usize = (WIDTH as usize).div_ceil(8) * HEIGHT as usize;

#[derive(Clone, Copy, Debug)]
pub enum Rotation {
    Deg0,
    Deg90,
}
