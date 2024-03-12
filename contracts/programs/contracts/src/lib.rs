use anchor_lang::prelude::*;

declare_id!("C79KJka4Het3Y1gPh51KtCtCZcmhRgqoNZs9r4t7tfQD");

#[program]
pub mod contracts {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize {}
