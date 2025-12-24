use abna::Session;
use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = Options::parse();
    let mut sess = Session::new(opts.account.clone()).await?;
    sess.login(opts.pass, &opts.pin).await?;
    let mutations = sess.mutations(&opts.account, None).await?;
    println!("{:#?}", mutations);
    Ok(())
}

#[derive(Parser)]
struct Options {
    /// Account number (IBAN)
    #[arg(short, long)]
    account: String,

    /// Pass number
    #[arg(short, long)]
    pass: u16,

    /// PIN code
    #[arg(long)]
    pin: String,
}
