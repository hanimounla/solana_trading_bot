use base64::{self, Engine};
use reqwest::blocking::Client;
use reqwest::header::CONTENT_TYPE;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::VersionedTransaction,
};
use spl_associated_token_account::get_associated_token_address;
use std::thread;
use std::time::{Duration, Instant};

// Function to decode base58 secret key and extract public/private keys
fn decode_solana_secret_key(base58_secret: &str) -> anyhow::Result<(Keypair, String, String)> {
    // Decode base58 string to bytes
    let secret_key_bytes = bs58::decode(base58_secret)
        .into_vec()
        .map_err(|e| anyhow::anyhow!("Failed to decode base58 secret key: {}", e))?;

    // Create keypair from the decoded bytes
    let keypair = Keypair::try_from(secret_key_bytes.as_slice())
        .map_err(|e| anyhow::anyhow!("Failed to create keypair from secret key: {}", e))?;

    // Get public key as base58 string
    let public_key_base58 = keypair.pubkey().to_string();

    // Get private key as base58 string (the original input)
    let private_key_base58 = base58_secret.to_string();

    Ok((keypair, public_key_base58, private_key_base58))
}

// Function to check token balance
fn check_token_balance(
    rpc_client: &RpcClient,
    wallet_pubkey: &Pubkey,
    token_mint: &str,
) -> anyhow::Result<f64> {
    let mint_pubkey = token_mint.parse::<Pubkey>()?;
    let ata = get_associated_token_address(wallet_pubkey, &mint_pubkey);

    match rpc_client.get_token_account_balance(&ata) {
        Ok(balance) => Ok(balance.ui_amount.unwrap_or(0.0)),
        Err(_) => Ok(0.0), // Return 0 if account doesn't exist or other error
    }
}

fn main() -> anyhow::Result<()> {
    // === Configuration ===
    // RPC endpoint for Solana network (devnet).
    // Note: If you encounter address lookup table errors, consider switching to mainnet RPC
    // as Jupiter's address lookup tables are typically on mainnet

    dotenvy::from_filename(".env").expect("missing .env file, make sure to create it");

    let solana_network = std::env::var("SOLANA_NETWORK").expect("SOLANA_NETWORK is missing");

    let rpc_url = std::env::var("SOLANA_RPC_URL").expect("SOLANA_RPC_URL is missing");
    // Your Solana wallet secret key (base58 encoded)
    let base58_secret_key =
        std::env::var("SOLANA_WALLET_SECRET").expect("SOLANA_WALLET_SECRET is missing");

    // Decode the secret key and get public/private keys
    let (keypair, public_key_base58, private_key_base58) =
        decode_solana_secret_key(&base58_secret_key)?;

    // Print the extracted keys
    println!("=== Solana Keypair Information ===");
    println!("Public Key: {}", public_key_base58);
    println!("Private Key: {}", private_key_base58);
    println!("===================================");

    let public_key = keypair.pubkey();
    println!("Trading bot initialized for wallet: {}", public_key);
    println!("Network: {solana_network}");

    // Token mint addresses (Solana mainnet)
    let usdc_mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"; // USDC mint address

    let sol_mint = "So11111111111111111111111111111111111111112"; // wSOL mint (used by Jupiter for SOL)
                                                                  // Trade parameters
    let trade_amount_usdc: u64 = 1_000_000; // amount in smallest units of USDC (here 1 USDC, since USDC has 6 decimals)

    let target_gain_percent: f64 = 0.5; // target gain in percent (e.g., 1.0 means 1%)
    let slippage_bps: u64 = 50; // slippage tolerance in basis points (50 = 0.5%)
    let check_interval = Duration::from_secs(2); // how often to check price (60 seconds)
    let trade_cooldown = Duration::from_secs(10000); // 1 hour cooldown between trades

    // Bot state: start holding USDC (true = holding USDC, false = holding SOL)
    let mut holding_usdc = true;
    // Get initial price to set baseline (quote 1 USDC to SOL to find USDC/SOL price)
    let client = Client::new();
    let initial_quote_url = format!(
        "https://quote-api.jup.ag/v6/quote?cluster={solana_network}&inputMint={usdc_mint}&outputMint={sol_mint}&amount={trade_amount_usdc}\
            &slippageBps={slippage_bps}"
    );
    let quote_resp: serde_json::Value = client.get(&initial_quote_url).send()?.json()?;
    // The quote response contains data about the best route. We extract the output amount (amount of SOL).
    let out_amount_str = quote_resp["outAmount"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid quote response: {}", quote_resp))?;
    let out_amount: u64 = out_amount_str.parse().unwrap_or(0);
    // Calculate initial price: how many USDC per 1 SOL (in terms of smallest units).
    // out_amount is in lamports of SOL (1 SOL = 1e9 lamports). trade_amount_usdc is in USDC smallest units (1e6 per USDC).
    // Price (USDC per SOL) = trade_amount_usdc / (out_amount SOL) * (scale adjustments)
    // Actually, easier: Jupiter quote API gives "outAmount" in smallest unit of output. For SOL, 1 SOL = 1e9.
    // So if out_amount is e.g. 0.11 SOL, it would be ~110,000,000 lamports.
    // We can compute price as (trade_amount_usdc / 10^6) / (out_amount / 10^9).
    let initial_price_per_sol = if out_amount > 0 {
        (trade_amount_usdc as f64 / 1e6) / (out_amount as f64 / 1e9)
    } else {
        0.0
    };
    if initial_price_per_sol == 0.0 {
        return Err(anyhow::anyhow!(
            "Failed to get initial price from Jupiter quote."
        ));
    }
    println!("Initial SOL price ~ {:.6} USDC", initial_price_per_sol);

    let mut last_trade_price = initial_price_per_sol;
    let mut last_trade_time = Instant::now() - trade_cooldown; // allow immediate trade if condition meets (set last trade far in past)

    println!(
        "Starting main loop. Threshold set to {}% for trades.",
        target_gain_percent
    );
    // Main monitoring and trading loop
    loop {
        // Determine which direction to quote based on what we're holding
        let (input_mint, output_mint, amount) = if holding_usdc {
            // We have USDC, plan to buy SOL with 'trade_amount_usdc'
            (usdc_mint, sol_mint, trade_amount_usdc)
        } else {
            // We have SOL, plan to sell some SOL for USDC. We use out_amount from last trade as the amount of SOL we hold (or a fixed trade amount).
            // For simplicity, assume we trade the same nominal value each time. So compute how much SOL corresponds to that value.
            // Alternatively, track the actual amount of SOL held. Here, we'll approximate by using last trade price: USDC value ~ trade_amount_usdc.
            // Compute SOL amount to trade = trade_amount_usdc / last_trade_price (in actual SOL units, scaled).
            let sol_amount = ((trade_amount_usdc as f64 / 1e6) / last_trade_price) * 1e9; // in lamports
            let sol_amount_int = sol_amount.round() as u64;
            (sol_mint, usdc_mint, sol_amount_int)
        };

        // Fetch a fresh quote for the intended swap
        let quote_url = format!(
            "https://quote-api.jup.ag/v6/quote?cluster={solana_network}&inputMint={input_mint}&outputMint={output_mint}&amount={amount}\
                &slippageBps={slippage_bps}"
        );
        let quote_data: serde_json::Value = match client.get(&quote_url).send() {
            Ok(resp) => resp.json().unwrap_or(serde_json::json!({})),
            Err(e) => {
                eprintln!("Error fetching quote: {}", e);
                // Wait and continue if error
                thread::sleep(check_interval);
                continue;
            }
        };
        // Adjusted for new quote_data structure (no "data", fields at top level)
        if quote_data.get("inAmount").is_none() || quote_data.get("outAmount").is_none() {
            eprintln!("Invalid quote response, will retry. Resp: {:?}", quote_data);

            // Check for specific Jupiter API errors
            if let Some(error) = quote_data.get("error") {
                eprintln!("Jupiter quote API error: {}", error);
            }

            thread::sleep(check_interval);
            continue;
        }
        // Extract inAmount and outAmount from top-level fields
        let in_amt = quote_data["inAmount"].as_str().unwrap_or("0");
        let out_amt = quote_data["outAmount"].as_str().unwrap_or("0");
        let in_amount: f64 = in_amt.parse::<u64>().unwrap_or(0) as f64;
        let out_amount_val: f64 = out_amt.parse::<u64>().unwrap_or(0) as f64;

        // Assign route to routePlan from quote_data
        // let route = match quote_data.get("routePlan") {
        //     Some(rp) => rp.clone(),
        //     None => {
        //         eprintln!(
        //             "No routePlan found in quote response, will retry. Resp: {:?}",
        //             quote_data
        //         );
        //         thread::sleep(check_interval);
        //         continue;
        //     }
        // };
        // Calculate current price depending on direction:
        let current_price = if holding_usdc {
            // input USDC, output SOL: price = (USDC input)/(SOL output) in real units
            let usdc_val = in_amount / 1e6; // convert to USDC
            let sol_val = out_amount_val / 1e9; // convert lamports to SOL
            if sol_val > 0.0 {
                usdc_val / sol_val
            } else {
                0.0
            }
        } else {
            // input SOL, output USDC: price = (USDC output)/(SOL input)
            let sol_val = in_amount / 1e9;
            let usdc_val = out_amount_val / 1e6;
            if sol_val > 0.0 {
                usdc_val / sol_val
            } else {
                0.0
            }
        };
        if current_price == 0.0 {
            eprintln!("Warning: current_price is 0. Something might be wrong with quote data.");
            thread::sleep(check_interval);
            continue;
        }
        // Determine how far from threshold:
        let price_change = if holding_usdc {
            // We want price to drop below (1 - pct) * last_trade_price to buy
            let target_price = last_trade_price * (1.0 - target_gain_percent / 100.0);
            (current_price - target_price) / target_price * 100.0 // how far above target (in %)
        } else {
            // We want price to rise above (1 + pct) * last_trade_price to sell
            let target_price = last_trade_price * (1.0 + target_gain_percent / 100.0);
            (current_price - target_price) / target_price * 100.0 // how far above (will be negative until above target)
        };
        // Log current status
        if holding_usdc {
            println!(
                "Price {:.6} USDC/SOL, need {:.2}% drop to reach buy target.",
                current_price,
                if price_change > 0.0 {
                    price_change
                } else {
                    -price_change
                }
            );
        } else {
            println!(
                "Price {:.6} USDC/SOL, need {:.2}% rise to reach sell target.",
                current_price,
                if price_change < 0.0 {
                    -price_change
                } else {
                    price_change
                }
            );
        }

        // Check if threshold condition met
        let condition_met = if holding_usdc {
            // condition: current_price <= last_trade_price * (1 - gain%)
            current_price <= last_trade_price * (1.0 - target_gain_percent / 100.0)
        } else {
            // condition: current_price >= last_trade_price * (1 + gain%)
            current_price >= last_trade_price * (1.0 + target_gain_percent / 100.0)
        };
        let cooldown_over = last_trade_time.elapsed() >= trade_cooldown;

        if condition_met && cooldown_over {
            println!("Threshold met and cooldown passed! Executing trade...");

            // Check wallet balance before attempting swap
            let rpc_client = RpcClient::new(&rpc_url);
            match rpc_client.get_balance(&public_key) {
                Ok(balance) => {
                    let sol_balance = balance as f64 / 1e9;
                    println!("Current SOL balance: {:.6} SOL", sol_balance);

                    // Ensure we have enough SOL for transaction fees (at least 0.01 SOL)
                    if sol_balance < 0.01 {
                        eprintln!("Insufficient SOL balance ({:.6} SOL) for transaction fees. Need at least 0.01 SOL.", sol_balance);
                        thread::sleep(check_interval);
                        continue;
                    }
                }
                Err(e) => {
                    eprintln!("Failed to check balance: {}. Proceeding with caution.", e);
                }
            }

            // Check token balances
            if holding_usdc {
                match check_token_balance(&rpc_client, &public_key, usdc_mint) {
                    Ok(usdc_balance) => {
                        println!("Current USDC balance: {:.6} USDC", usdc_balance);
                        if usdc_balance < (trade_amount_usdc as f64 / 1_000_000.0) {
                            eprintln!("Insufficient USDC balance ({:.6} USDC) for trade amount {:.6} USDC", 
                                usdc_balance, trade_amount_usdc);
                            thread::sleep(check_interval);
                            continue;
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "Failed to check USDC balance: {}. Proceeding with caution.",
                            e
                        );
                    }
                }
            } else {
                match check_token_balance(&rpc_client, &public_key, sol_mint) {
                    Ok(sol_balance) => {
                        let sol_amount = sol_balance / 1e9;
                        println!("Current SOL balance: {:.6} SOL", sol_amount);
                        let required_sol = (trade_amount_usdc as f64 / 1e6) / last_trade_price;
                        if sol_amount < required_sol {
                            eprintln!(
                                "Insufficient SOL balance ({:.6} SOL) for trade amount {:.6} SOL",
                                sol_amount, required_sol
                            );
                            thread::sleep(check_interval);
                            continue;
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "Failed to check SOL balance: {}. Proceeding with caution.",
                            e
                        );
                    }
                }
            }

            // Prepare swap API call body
            let swap_request = serde_json::json!({
                "quoteResponse": quote_data,         // pass the chosen quote route from Jupiter
                "userPublicKey": public_key.to_string(),
                // "wrapAndUnwrapSol": true,
                // "computeUnitPriceMicroLamports": 50000,  // Add compute unit price
                // "asLegacyTransaction": false,  // Ensure we use versioned transactions
                // "dynamicComputeUnitLimit": true,
                "cluster": solana_network,
                // "feeAccount": null,  // Let Jupiter handle fee account creation
                // "prioritizationFeeLamports": 50000  // Additional priority fee
            });

            println!("Swap request prepared:");
            println!("  Input mint: {}", input_mint);
            println!("  Output mint: {}", output_mint);
            println!("  Amount: {}", amount);
            println!("  Network: {}", solana_network);
            let swap_resp = client
                .post("https://quote-api.jup.ag/v6/swap")
                .header(CONTENT_TYPE, "application/json")
                .body(swap_request.to_string())
                .send();
            if swap_resp.is_err() {
                eprintln!("Swap API request failed: {:?}", swap_resp.err());
                thread::sleep(check_interval);
                continue;
            }
            let swap_resp = swap_resp.unwrap();

            // Check HTTP status code
            if !swap_resp.status().is_success() {
                eprintln!("Swap API returned error status: {}", swap_resp.status());
                let error_text = swap_resp.text().unwrap_or_default();
                eprintln!("Error response: {}", error_text);
                thread::sleep(check_interval);
                continue;
            }

            let swap_json: serde_json::Value = match swap_resp.json() {
                Ok(val) => val,
                Err(e) => {
                    eprintln!("Failed to parse swap response JSON: {}", e);
                    serde_json::json!({})
                }
            };

            // Check for Jupiter API errors
            if let Some(error) = swap_json.get("error") {
                eprintln!("Jupiter API error: {}", error);
                thread::sleep(check_interval);
                continue;
            }

            if swap_json.get("swapTransaction").is_none() {
                eprintln!("Unexpected swap response: {}", swap_json);
                thread::sleep(check_interval);
                continue;
            }
            let swap_tx_base64 = swap_json["swapTransaction"].as_str().unwrap();
            // Decode base64 to bytes and deserialize into a VersionedTransaction
            let swap_tx_bytes = base64::engine::general_purpose::STANDARD
                .decode(swap_tx_base64)
                .map_err(|e| anyhow::anyhow!("Base64 decode error: {}", e))?;
            let mut transaction: VersionedTransaction = bincode::deserialize(&swap_tx_bytes)
                .map_err(|e| anyhow::anyhow!("Transaction deserialize error: {}", e))?;

            // Sign the transaction with our keypair
            // For VersionedTransaction, we need to sign the message and update signatures
            let message_bytes = transaction.message.serialize();
            let signature = keypair.sign_message(&message_bytes);
            transaction.signatures = vec![signature];

            println!("Transaction prepared and signed. Attempting to send...");
            println!(
                "Transaction has {} instructions",
                transaction.message.instructions().len()
            );

            // Simulate transaction first to catch errors early
            match rpc_client.simulate_transaction(&transaction) {
                Ok(sim_result) => {
                    if let Some(err) = sim_result.value.err {
                        eprintln!("Transaction simulation failed: {:?}", err);
                        eprintln!("Simulation logs: {:?}", sim_result.value.logs);
                        thread::sleep(check_interval);
                        continue;
                    }
                    println!("Transaction simulation successful. Proceeding to send...");
                }
                Err(e) => {
                    eprintln!(
                        "Failed to simulate transaction: {}. Proceeding with caution.",
                        e
                    );
                }
            }

            // Send the transaction to Solana
            let rpc_client = RpcClient::new(&rpc_url);

            // Try to send the transaction with retries
            let mut retries = 3;
            let signature;
            let mut success = false;

            while retries > 0 {
                match rpc_client.send_transaction(&transaction) {
                    Ok(sig) => {
                        signature = Some(sig);
                        println!("Trade executed! Tx signature: {:?}", signature);
                        success = true;
                        break;
                    }
                    Err(e) => {
                        let error_msg = e.to_string();
                        eprintln!("Transaction failed (attempt {}/3): {}", 4 - retries, e);

                        // Provide specific guidance for common Jupiter errors
                        if error_msg.contains("0x1788") || error_msg.contains("6008") {
                            eprintln!("Error 0x1788 (6008) detected - This usually means:");
                            eprintln!("  - Insufficient SOL balance for transaction fees");
                            eprintln!("  - Associated token account creation issues");
                            eprintln!("  - Insufficient token balance for the swap");
                            eprintln!("  - Account rent requirements not met");
                        }

                        retries -= 1;
                        if retries > 0 {
                            thread::sleep(Duration::from_secs(1));
                        }
                    }
                }
            }

            if success {
                // Update state only on successful transaction
                last_trade_time = Instant::now();
                last_trade_price = current_price;
                holding_usdc = !holding_usdc; // flip holding state (if we bought SOL, now holding SOL; if sold, now holding USDC)
                println!(
                    "Successfully switched to holding {}",
                    if holding_usdc { "USDC" } else { "SOL" }
                );
            } else {
                eprintln!("All transaction attempts failed. Will retry on next iteration.");
            }
        }

        // Wait for the next iteration
        thread::sleep(check_interval);
    }
}
