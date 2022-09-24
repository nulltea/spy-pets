use gumdrop::Options;

#[derive(Debug, Options, Clone)]
pub struct CLIArgs {
    help: bool,
    #[options(command)]
    pub command: Option<Command>,
}

#[derive(Debug, Options, Clone)]
pub enum Command {
    #[options(help = "Setup wallet")]
    Setup(SetupArgs),
    #[options(help = "Deploy seller daemon")]
    Provide(ProvideArgs),
    #[options(help = "Run buyer client")]
    Swap(SwapArgs),
}

#[derive(Debug, Options, Clone)]
pub struct SetupArgs {
    help: bool,

    #[options(help = "path to keystore location", default = "./keys")]
    pub keystore_dir: String,
}

#[derive(Debug, Options, Clone)]
pub struct ProvideArgs {
    help: bool,

    #[options(help = "chain RPC address", default = "http://localhost:8545")]
    pub rpc_address: String,

    #[options(help = "chain id", default = "http://localhost:8545")]
    pub chain_id: String,

    #[options(help = "target address (to)")]
    pub target_address: String
}

#[derive(Debug, Options, Clone)]
pub struct SwapArgs {
    help: bool,

    #[options(help = "maker server address")]
    pub maker_address: String,

    #[options(help = "chain RPC address", default = "http://localhost:8545")]
    pub rpc_address: String,

    #[options(help = "chain id", default = "31337")]
    pub chain_id: String,

    #[options(help = "target address (to)")]
    pub target_address: String,

    #[options(help = "transfer amount (ETH)")]
    pub amount: f64
}
