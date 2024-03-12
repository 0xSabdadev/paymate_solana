use anchor_lang::prelude::*;
use anchor_spl::token::{self, TokenAccount, Transfer};

declare_id!("7dBGVKd322kdBdUWhiqcY3UxHuGZnjxtZTqa57svFRcx");

#[program]
pub mod my_payment_processor {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, master_wallet: Pubkey) -> Result<()> {
        let payment_processor = &mut ctx.accounts.payment_processor;
        payment_processor.master_wallet = master_wallet;
        Ok(())
    }

    pub fn create_temporary_wallet(ctx: Context<CreateTemporaryWallet>, amount: u64) -> Result<()> {
        let temporary_wallet = &mut ctx.accounts.temporary_wallet;
        temporary_wallet.amount = amount;
        temporary_wallet.authority = ctx.accounts.user.key();
        temporary_wallet.created_at = Clock::get()?.unix_timestamp;
    
        // PDA untuk digunakan sebagai owner akun token
        let (pda, _bump_seed) = Pubkey::find_program_address(
            &[b"temporary_wallet", ctx.accounts.user.key().as_ref()],
            ctx.program_id,
        );
    
        // PDA ini bisa digunakan sebagai owner dari akun token yang dibuat di luar rantai atau melalui instruksi terpisah
        temporary_wallet.token_account = pda;
    
        Ok(())
    }

    pub fn verify_payment(ctx: Context<VerifyPayment>, amount: u64) -> Result<()> {
        let temporary_wallet = &ctx.accounts.temporary_wallet;
        let master_wallet = &ctx.accounts.master_wallet;

        if temporary_wallet.amount != amount {
            return Err(ErrorCode::InvalidPaymentAmount.into());
        }

        // Transfer tokens from temporary wallet to master wallet
        let cpi_accounts = Transfer {
            from: ctx.accounts.from_token_account.to_account_info(),
            to: ctx.accounts.to_token_account.to_account_info(),
            authority: ctx.accounts.temporary_wallet.to_account_info(),
        };
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
        token::transfer(cpi_ctx, amount)?;
        Ok(())
    }

    pub fn transfer_to_master_wallet(ctx: Context<TransferToMasterWallet>, amount: u64) -> Result<()> {
        let temporary_wallet = &ctx.accounts.temporary_wallet;
        let master_wallet = &ctx.accounts.master_wallet;

        // Transfer tokens from temporary wallet to master wallet
        let cpi_accounts = Transfer {
            from: ctx.accounts.from_token_account.to_account_info(),
            to: ctx.accounts.to_token_account.to_account_info(),
            authority: ctx.accounts.temporary_wallet.to_account_info(),
        };
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
        token::transfer(cpi_ctx, amount)?;

        Ok(())
    }

    // handle
    pub fn handle_underpayment(ctx: Context<HandleUnderpayment>, amount: u64) -> Result<()> {
        let temporary_wallet = &ctx.accounts.temporary_wallet;
        let master_wallet = &ctx.accounts.payer;

        // implement notify the payer to complete the payment.
        msg!("Underpayment detected. Notifying payer to complete the payment.");
        Ok(())
    }

    pub fn handle_overpayment(ctx: Context<HandleOverpayment>, amount_expected: u64) -> Result<()> {
        let temporary_wallet = &ctx.accounts.temporary_wallet;
        let payer_token_account = &ctx.accounts.payer_token_account;
    
        if temporary_wallet.amount > amount_expected {
            let excess_amount = temporary_wallet.amount - amount_expected;
    
            // pemanggilan CPI 
            let cpi_accounts = Transfer {
                from: ctx.accounts.temporary_wallet_token_account.to_account_info(),
                to: payer_token_account.to_account_info(),
                authority: ctx.accounts.authority.to_account_info(),
            };
            let cpi_program = ctx.accounts.token_program.to_account_info();
            let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
            token::transfer(cpi_ctx, excess_amount)?;
        }
    
        Ok(())
    }

    pub fn handle_non_payment(ctx: Context<HandleNonPayment>, amount: u64) -> Result<()> {
        let temporary_wallet = &mut ctx.accounts.temporary_wallet;
        // recycle the temporary wallet
        msg!("Non-payment detected. Recycling the temporary wallet.");
        temporary_wallet.is_active = false;
        Ok(())
    } 

    pub fn close_session(ctx: Context<CloseSession>, amount: u64) -> Result<()> {
        let temporary_wallet = &ctx.accounts.temporary_wallet;
        let master_wallet = &ctx.accounts.payer;

        // finalize the transaction, notify the user
        msg!("Closing session. Finalizing the transaction and notifying the user.");
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = user, space = 8 + 40)]
    pub payment_processor: Account<'info, PaymentProcessorState>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CreateTemporaryWallet<'info> {
    #[account(init, payer = user, space = 8 + 8 + 32 + 32 + 8)]
    pub temporary_wallet: Account<'info, TemporaryWallet>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
    pub token_program: AccountInfo<'info>,
    // pub token_program: Program<'info, Token>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct VerifyPayment<'info> {
    #[account(mut)]
    pub temporary_wallet: Account<'info, TemporaryWallet>,
    #[account(mut)]
    pub master_wallet: Account<'info, MasterWallet>,
    pub from_token_account: Account<'info, TokenAccount>, 
    pub to_token_account: Account<'info, TokenAccount>, 
    /// CHECK: only used for CPI to Token Program
    pub token_program: AccountInfo<'info>,
    // pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct TransferToMasterWallet<'info> {
    #[account(mut)]
    pub temporary_wallet: Account<'info, TemporaryWallet>,
    #[account(mut)]
    pub master_wallet: Account<'info, MasterWallet>,
    pub from_token_account: Account<'info, TokenAccount>, 
    pub to_token_account: Account<'info, TokenAccount>, 
    /// CHECK: only used for CPI to Token Program
    pub token_program: AccountInfo<'info>,
    // pub token_program: Program<'info, Token>,
}

// handle
#[derive(Accounts)]
pub struct HandleUnderpayment<'info> {
    #[account(mut)]
    pub temporary_wallet: Account<'info, TemporaryWallet>,
    #[account(mut)]
    pub payer: Signer<'info>,
}

#[derive(Accounts)]
pub struct HandleOverpayment<'info> {
    #[account(mut)]
    pub temporary_wallet: Account<'info, TemporaryWallet>,
    pub temporary_wallet_token_account: Account<'info, TokenAccount>, // Akun token untuk temporary_wallet
    pub payer_token_account: Account<'info, TokenAccount>, // Akun token pengirim untuk pengembalian dana
    pub authority: Signer<'info>, // Authority yang bisa menandatangani transfer dari temporary_wallet
    // pub token_program: Program<'info, Token>
    pub token_program: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct HandleNonPayment<'info> {
    #[account(mut)]
    pub temporary_wallet: Account<'info, TemporaryWallet>,
}

#[derive(Accounts)]
pub struct CloseSession<'info> {
    #[account(mut)]
    pub temporary_wallet: Account<'info, TemporaryWallet>,
    #[account(mut)]
    pub payer: Signer<'info>,
}
// handle end

#[account]
pub struct TemporaryWallet {
    pub authority: Pubkey,
    pub amount: u64,
    pub token_account: Pubkey, // Changed to Pubkey to avoid storing the entire TokenAccount
    pub created_at: i64,
    pub is_active: bool,
}

#[account]
pub struct MasterWallet {
    pub authority: Pubkey,
    pub token_account: Pubkey, 
}

#[account]
pub struct PaymentProcessorState {
    pub master_wallet: Pubkey,
}

// Define custom error codes
#[error_code]
pub enum ErrorCode {
    #[msg("Invalid payment amount")]
    InvalidPaymentAmount,
    #[msg("Insufficient funds")]
    InsufficientFunds,
}
