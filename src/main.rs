// Copyright 2024 Photon Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use clap::Parser;
use log::{error, info};
use std::sync::Arc;

mod config;
mod gateway;
mod health;
mod load_balancer;
mod metrics;
mod middleware;
mod routes;

use config::Config;
use gateway::ApiGateway;

/// ⚡ Photon - Ultra-high-performance API Gateway built with Cloudflare Pingora
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short, long, default_value = "config.yaml")]
    config: String,

    /// Log level
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// Enable daemon mode
    #[arg(short, long)]
    daemon: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(&args.log_level))
        .init();

    info!("⚡ Starting Photon API Gateway...");

    // Load configuration
    let config = match Config::from_file(&args.config) {
        Ok(config) => {
            info!("Configuration loaded successfully from {}", args.config);
            Arc::new(config)
        }
        Err(e) => {
            error!("Failed to load configuration: {}", e);
            return Err(e);
        }
    };

    // Create and start Photon runtime
    let rt = tokio::runtime::Runtime::new()?;
    let gateway = rt.block_on(async { ApiGateway::new(config).await })?;

    info!("⚡ Photon initialized successfully - light-speed performance ready!");

    // Start the gateway server
    gateway.run()?;

    Ok(())
}
