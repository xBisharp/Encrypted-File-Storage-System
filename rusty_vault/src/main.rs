use clap::{Parser, Subcommand};
use std::path::PathBuf;
use anyhow::{Result, Context};
use rpassword::read_password;
use std::io::{self, Write};

// This struct represents the entire command line
#[derive(Parser)]
#[command(name = "RustyVault")]
#[command(version = "1.0")]
#[command(about = "A secure, chunked file encryption tool", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

// Enum variants become "encrypt" and "decrypt" commands
#[derive(Subcommand)]
enum Commands {
    /// Encrypt a file
    Encrypt {
        /// Input file path
        #[arg(short, long)]
        file: PathBuf,

        /// Output file path (optional, defaults to file.enc)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Decrypt a file
    Decrypt {
        /// Input file path
        #[arg(short, long)]
        file: PathBuf,

        /// Output file path (optional, defaults to file.dec)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Encrypt { file, output } => {
            println!("🔒 Encrypting {:?}", file);
            
            // Determine output path (default to filename + .enc)
            let output_path = output.clone().unwrap_or_else(|| {
                let mut p = file.clone();
                if let Some(ext) = p.extension() {
                    let mut new_ext = ext.to_os_string();
                    new_ext.push(".enc");
                    p.set_extension(new_ext);
                } else {
                    p.set_extension("enc");
                }
                p
            });

            // Securely prompt for password
            let password = get_password("Enter password: ")?;
            let confirm = get_password("Confirm password: ")?;
            
            if password != confirm {
                anyhow::bail!("Passwords do not match!");
            }

            // TO:DO ENCRYPTION LOGIC
            // crypto::encrypt_file(file.to_str().unwrap(), output_path.to_str().unwrap(), &password)?;
            
            println!("✅ Success! Encrypted file saved to {:?}", output_path);
        }

        Commands::Decrypt { file, output } => {
            println!("Decrypting {:?}", file);

            let output_path = output.clone().unwrap_or_else(|| {
                let mut p = file.clone();
                p.set_extension("dec");
                p
            });

            let password = get_password("Enter password: ")?;

            // TO:DO DECRYPTION LOGIC
            // crypto::decrypt_file(file.to_str().unwrap(), output_path.to_str().unwrap(),
            
            println!("Success! Decrypted file saved to {:?}", output_path);
        }
    }

    Ok(())
}

fn get_password(prompt: &str) -> Result<String> {
    print!("{}", prompt);
    io::stdout().flush().context("Failed to flush stdout")?;
    let password = read_password().context("Failed to read password")?;
    Ok(password)
}