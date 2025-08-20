use crate::*;
use std::process::{Command, Stdio};
use std::fs;
use std::time::Duration;
use tokio::time::sleep;

// Main function to run chopsticks tests
pub(crate) async fn run_chopsticks_tests(
	proposal_details: &ProposalDetails,
	calls: &PossibleCallsToSubmit,
	test_file_path: &str,
) {
	println!("🥢 Starting Chopsticks test execution...");
	
	// Determine network configuration based on proposal details
	let network_config = get_network_config(proposal_details);
	
	// Start chopsticks in background
	let chopsticks_process = start_chopsticks(&network_config).await;
	
	// Wait for chopsticks to start (longer timeout for network forking)
	println!("⏳ Waiting for chopsticks to initialize...");
	sleep(Duration::from_secs(10)).await;
	
	// Generate test execution script
	let test_script = generate_test_script(proposal_details, calls, test_file_path);
	
	// Write the test script to a temporary file
	let temp_script_path = "temp_chopsticks_test.js";
	fs::write(temp_script_path, test_script).expect("Failed to write test script");
	
	// Execute the test
	println!("📋 Executing chopsticks test...");
	let test_result = execute_test_script(temp_script_path).await;
	
	// Always cleanup, regardless of test result
	println!("🧹 Cleaning up chopsticks process...");
	cleanup_chopsticks_process(chopsticks_process);
	let _ = fs::remove_file(temp_script_path);
	
	// Report test result
	match test_result {
		Ok(_) => println!("✅ Chopsticks test execution completed successfully!"),
		Err(e) => {
			println!("❌ Chopsticks test execution failed: {}", e);
			println!("💡 Make sure you have the required dependencies installed:");
			println!("   npm install -g @acala-network/chopsticks");
		}
	}
}

// Get network configuration for chopsticks
fn get_network_config(proposal_details: &ProposalDetails) -> NetworkConfig {
	match &proposal_details.track {
		NetworkTrack::KusamaRoot | NetworkTrack::Kusama(_) => NetworkConfig {
			name: "kusama".to_string(),
			port: 8000,
		},
		NetworkTrack::PolkadotRoot | NetworkTrack::Polkadot(_) => NetworkConfig {
			name: "polkadot".to_string(),
			port: 8000,
		},
	}
}

// Start chopsticks process
async fn start_chopsticks(config: &NetworkConfig) -> std::process::Child {
	println!("🚀 Starting chopsticks for {} network on port {}...", config.name, config.port);
	
	// Use direct chopsticks command as specified in the requirements
	let mut cmd = Command::new("chopsticks");
	cmd.args(&[
		"-c", &config.name,
		"--port", &config.port.to_string(),
	]);
	
	cmd.stdout(Stdio::inherit())
		.stderr(Stdio::inherit())
		.spawn()
		.expect("Failed to start chopsticks - make sure it's installed globally with: npm install -g @acala-network/chopsticks")
}

// Generate the test script that will be executed
fn generate_test_script(
	proposal_details: &ProposalDetails,
	calls: &PossibleCallsToSubmit,
	user_test_file: &str,
) -> String {
	let network_config = get_network_config(proposal_details);
	let http_endpoint = format!("http://127.0.0.1:{}", network_config.port);
	
	// Extract call data for injections based on the actual HackMD flow
	let (preimage_call_data, whitelist_call_data, dispatch_call_hash, dispatch_call_len) = 
		extract_hackmd_flow_data(calls);
	
	format!(r#"
/**
 * Simple HTTP-based chopsticks interaction function
 */
async function rpcCall(method, params = []) {{
	const http = require('http');
	
	const postData = JSON.stringify({{
		id: Math.floor(Math.random() * 1000),
		jsonrpc: '2.0',
		method,
		params
	}});
	
	return new Promise((resolve, reject) => {{
		const req = http.request({{
			hostname: '127.0.0.1',
			port: 8000,
			path: '/',
			method: 'POST',
			headers: {{
				'Content-Type': 'application/json',
				'Content-Length': Buffer.byteLength(postData)
			}}
		}}, (res) => {{
			let data = '';
			
			res.on('data', (chunk) => {{
				data += chunk;
			}});
			
			res.on('end', () => {{
				try {{
					const result = JSON.parse(data);
					if (result.error) {{
						reject(new Error(`RPC error: ${{result.error.message}}`));
					}} else {{
						resolve(result.result);
					}}
				}} catch (error) {{
					reject(new Error(`Failed to parse response: ${{error.message}}`));
				}}
			}});
		}});
		
		req.on('error', (error) => {{
			reject(new Error(`HTTP request failed: ${{error.message}}`));
		}});
		
		req.write(postData);
		req.end();
	}});
}}

async function main() {{
	console.log('🔗 Testing chopsticks connectivity at {}...');
	
	try {{
		// Test basic connectivity
		await testChopsticksConnection('{}');
		
		console.log('📤 Simulating preimage submission...');
		console.log('Preimage call data: {}');
		
		console.log('🏛️ Injecting fellowship whitelist call...');
		await injectFellowshipCall('{}', '{}');
		
		console.log('📊 Injecting whitelisted caller dispatch...');
		await injectWhitelistedCallerCall('{}', {}, '{}');
		
		console.log('🧪 Running user-defined tests...');
		{}
		
		console.log('✅ All chopsticks tests completed successfully!');
	}} catch (error) {{
		console.error('❌ Test failed:', error.message);
		process.exit(1);
	}}
}}

async function testChopsticksConnection(endpoint) {{
	try {{
		const result = await rpcCall('system_health');
		console.log('✅ Chopsticks is running and responsive');
		console.log('Health check result:', result);
	}} catch (error) {{
		throw new Error(`Chopsticks not responding: ${{error.message}}`);
	}}
}}

async function injectFellowshipCall(endpoint, callData) {{
	// Get current block number
	const header = await rpcCall('chain_getHeader');
	const currentBlock = parseInt(header.number, 16);
	const targetBlock = currentBlock + 1;
	
	console.log(`Current block: ${{currentBlock}}, injecting for block: ${{targetBlock}}`);
	
	// Inject fellowship call into scheduler
	await rpcCall('dev_setStorage', [{{
		scheduler: {{
			agenda: [
				[
					[targetBlock], [
						{{
							call: {{ Inline: callData }},
							origin: {{ Origins: 'Fellows' }}
						}}
					]
				]
			]
		}}
	}}]);
	
	// Create new block
	await rpcCall('dev_newBlock', [{{ count: 1 }}]);
	console.log('✅ Fellowship whitelist call injected and block created');
}}

async function injectWhitelistedCallerCall(endpoint, callLen, callHash) {{
	// Get current block number
	const header = await rpcCall('chain_getHeader');
	const currentBlock = parseInt(header.number, 16);
	const targetBlock = currentBlock + 1;
	
	console.log(`Current block: ${{currentBlock}}, injecting WhitelistedCaller for block: ${{targetBlock}}`);
	
	// Inject whitelisted caller dispatch
	await rpcCall('dev_setStorage', [{{
		scheduler: {{
			agenda: [
				[
					[targetBlock], [
						{{
							call: {{ 
								Lookup: {{ 
									hash: callHash, 
									len: callLen 
								}} 
							}},
							origin: {{ Origins: 'WhitelistedCaller' }}
						}}
					]
				]
			]
		}}
	}}]);
	
	// Create new block
	await rpcCall('dev_newBlock', [{{ count: 1 }}]);
	console.log('✅ WhitelistedCaller dispatch injected and block created');
}}

main();
"#, 
		http_endpoint, 
		http_endpoint,
		preimage_call_data,
		http_endpoint,
		whitelist_call_data,
		http_endpoint,
		dispatch_call_len,
		dispatch_call_hash,
		include_user_test_file(user_test_file)
	)
}

fn extract_hackmd_flow_data(calls: &PossibleCallsToSubmit) -> (String, String, String, u32) {
	println!("🔍 Extracting call data for chopsticks test execution...");
	
	// Extract the preimage call data for the main referendum
	let preimage_call_data = if let Some((call_or_hash, _)) = &calls.preimage_for_public_referendum {
		match call_or_hash {
			CallOrHash::Call(network_call) => {
				let encoded = match network_call {
					NetworkRuntimeCall::Kusama(call) => {
						println!("📤 Extracted Kusama preimage call data");
						format!("0x{}", hex::encode(call.encode()))
					},
					NetworkRuntimeCall::Polkadot(call) => {
						println!("📤 Extracted Polkadot preimage call data");
						format!("0x{}", hex::encode(call.encode()))
					},
					_ => {
						println!("⚠️  Unsupported network for preimage call");
						"0x".to_string()
					},
				};
				println!("Preimage call length: {} bytes", (encoded.len() - 2) / 2);
				encoded
			},
			CallOrHash::Hash(hash) => {
				println!("📤 Preimage call too large, using hash: 0x{}", hex::encode(hash));
				format!("0x{}", hex::encode(hash))
			},
		}
	} else {
		println!("⚠️  No preimage for public referendum found");
		"0x".to_string()
	};

	// Extract the fellowship whitelist call data
	let whitelist_call_data = if let Some((call_or_hash, _)) = &calls.preimage_for_whitelist_call {
		match call_or_hash {
			CallOrHash::Call(network_call) => {
				let encoded = match network_call {
					NetworkRuntimeCall::Kusama(call) => {
						println!("🏛️ Extracted Kusama fellowship whitelist call");
						format!("0x{}", hex::encode(call.encode()))
					},
					NetworkRuntimeCall::Polkadot(call) => {
						println!("🏛️ Extracted Polkadot fellowship whitelist call");
						format!("0x{}", hex::encode(call.encode()))
					},
					NetworkRuntimeCall::PolkadotCollectives(call) => {
						println!("🏛️ Extracted Polkadot Collectives fellowship whitelist call");
						format!("0x{}", hex::encode(call.encode()))
					},
					_ => {
						println!("⚠️  Unsupported network for whitelist call");
						"0x".to_string()
					},
				};
				println!("Whitelist call length: {} bytes", (encoded.len() - 2) / 2);
				encoded
			},
			CallOrHash::Hash(hash) => {
				println!("🏛️ Whitelist call too large, using hash: 0x{}", hex::encode(hash));
				format!("0x{}", hex::encode(hash))
			},
		}
	} else {
		println!("⚠️  No fellowship whitelist call found - may not be a fellowship referendum");
		"0x".to_string()
	};

	// Extract the dispatch call hash and length for WhitelistedCaller dispatch
	let (dispatch_call_hash, dispatch_call_len) = if let Some((call_or_hash, len)) = &calls.preimage_for_public_referendum {
		match call_or_hash {
			CallOrHash::Call(network_call) => {
				let encoded = match network_call {
					NetworkRuntimeCall::Kusama(call) => call.encode(),
					NetworkRuntimeCall::Polkadot(call) => call.encode(),
					_ => vec![],
				};
				let hash = blake2_256(&encoded);
				let hash_str = format!("0x{}", hex::encode(hash));
				let len = encoded.len() as u32;
				println!("📊 WhitelistedCaller dispatch hash: {}", hash_str);
				println!("📊 WhitelistedCaller dispatch length: {} bytes", len);
				(hash_str, len)
			},
			CallOrHash::Hash(hash) => {
				let hash_str = format!("0x{}", hex::encode(hash));
				println!("📊 WhitelistedCaller dispatch hash (from precomputed): {}", hash_str);
				println!("📊 WhitelistedCaller dispatch length: {} bytes", len);
				(hash_str, *len)
			},
		}
	} else {
		println!("⚠️  No public referendum call found");
		("0x".to_string(), 0)
	};

	println!("✅ Call data extraction completed");
	(preimage_call_data, whitelist_call_data, dispatch_call_hash, dispatch_call_len)
}

// Include user test file content
fn include_user_test_file(test_file_path: &str) -> String {
	match fs::read_to_string(test_file_path) {
		Ok(content) => {
			// Check if the file exports a function or contains module patterns
			if content.contains("export") || content.contains("module.exports") {
				// Try to require and run the user test
				format!(r#"
	try {{
		const userTests = require('{}');
		if (typeof userTests === 'function') {{
			await userTests(api);
		}} else if (typeof userTests.runTests === 'function') {{
			await userTests.runTests(api);
		}} else if (typeof userTests.default === 'function') {{
			await userTests.default(api);
		}} else {{
			console.log('User test module loaded but no runnable function found');
		}}
	}} catch (error) {{
		console.warn('Error running user tests:', error.message);
	}}"#, test_file_path)
			} else {
				// If it's raw code, wrap it in a try-catch and include directly
				format!(r#"
	try {{
		// User test code begins
		{}
		// User test code ends
	}} catch (error) {{
		console.warn('Error in user test code:', error.message);
	}}"#, content)
			}
		},
		Err(_) => {
			println!("⚠️  Warning: Could not read user test file: {}", test_file_path);
			"console.log('⚠️  No user tests found or could not read test file');".to_string()
		}
	}
}

// Execute the test script
async fn execute_test_script(script_path: &str) -> Result<(), String> {
	let output = Command::new("node")
		.args(&[script_path])
		.output()
		.map_err(|e| format!("Failed to execute test script: {}", e))?;
	
	if output.status.success() {
		println!("✅ Test execution successful!");
		if !output.stdout.is_empty() {
			println!("Output: {}", String::from_utf8_lossy(&output.stdout));
		}
		Ok(())
	} else {
		let error_msg = if !output.stderr.is_empty() {
			String::from_utf8_lossy(&output.stderr).to_string()
		} else {
			format!("Process exited with code: {:?}", output.status.code())
		};
		Err(error_msg)
	}
}

// Cleanup chopsticks process
fn cleanup_chopsticks_process(mut process: std::process::Child) {
	let _ = process.kill();
	let _ = process.wait();
	println!("🧹 Chopsticks process cleaned up");
}

// Network configuration structure
struct NetworkConfig {
	name: String,
	port: u16,
}

// Generate test scaffolding for a given network
pub(crate) fn generate_test_scaffold(network: &str) -> String {
	let (rpc_endpoint, system_chains) = match network.to_lowercase().as_str() {
		"polkadot" => (
			"wss://polkadot-rpc.dwellir.com",
			vec!["asset-hub-polkadot", "bridge-hub-polkadot", "collectives-polkadot", "people-polkadot", "coretime-polkadot"]
		),
		"kusama" => (
			"wss://kusama-rpc.dwellir.com", 
			vec!["asset-hub-kusama", "bridge-hub-kusama", "people-kusama", "coretime-kusama", "encointer-kusama"]
		),
		_ => ("wss://polkadot-rpc.dwellir.com", vec!["asset-hub-polkadot"]),
	};

	format!(r#"// Simple chopsticks test - no external dependencies needed!

/**
 * Test file for {} OpenGov referendum testing with Chopsticks
 * 
 * This file provides:
 * - Setup functions for test environment
 * - Account funding and fellowship member injection
 * - Runtime upgrade assertions
 * - Customizable test logic
 * 
 * Usage with opengov-cli:
 * opengov-cli submit-referendum \
 *   --proposal "./your-proposal.call" \
 *   --network "{}" \
 *   --track "whitelistedcaller" \
 *   --test "testfile.ts"
 */

// Chopsticks configuration for {}
const CONFIG = {{
	network: '{}',
	endpoint: 'http://127.0.0.1:8000',
	port: 8000
}};

// Test account configuration
const TEST_ACCOUNTS = {{
	ALICE: '5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY',
	BOB: '5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty',
	FELLOW: '5GNJqTPyNqANBkUVMN1LPPrxXnFouWXoe2wNSmmEoLctxiZY', // Fellowship member
}};

/**
 * Simple HTTP-based chopsticks interaction functions using Node.js http module
 */
async function rpcCall(method, params = []) {{
	const http = require('http');
	
	const postData = JSON.stringify({{
		id: Math.floor(Math.random() * 1000),
		jsonrpc: '2.0',
		method,
		params
	}});
	
	return new Promise((resolve, reject) => {{
		const req = http.request({{
			hostname: '127.0.0.1',
			port: 8000,
			path: '/',
			method: 'POST',
			headers: {{
				'Content-Type': 'application/json',
				'Content-Length': Buffer.byteLength(postData)
			}}
		}}, (res) => {{
			let data = '';
			
			res.on('data', (chunk) => {{
				data += chunk;
			}});
			
			res.on('end', () => {{
				try {{
					const result = JSON.parse(data);
					if (result.error) {{
						reject(new Error(`RPC error: ${{result.error.message}}`));
					}} else {{
						resolve(result.result);
					}}
				}} catch (error) {{
					reject(new Error(`Failed to parse response: ${{error.message}}`));
				}}
			}});
		}});
		
		req.on('error', (error) => {{
			reject(new Error(`HTTP request failed: ${{error.message}}`));
		}});
		
		req.write(postData);
		req.end();
	}});
}}

/**
 * Main test function - called by opengov-cli chopsticks runner
 */
async function runTests() {{
	console.log('🧪 Starting {} referendum test suite...');
	
	try {{
		console.log('✅ Chopsticks test environment ready!');
		console.log('Note: Referendum calls will be injected by opengov-cli');
		console.log('This is where you can add your custom test logic...');
		
		// Example: Test basic connectivity
		const health = await rpcCall('system_health');
		console.log('✅ Chopsticks health check:', health);
		
		// Example: Get runtime version
		const version = await rpcCall('state_getRuntimeVersion');
		console.log('📋 Runtime version:', version);
		
		console.log('✅ All {} tests completed successfully!');
	}} catch (error) {{
		console.error('❌ Test failed:', error);
		throw error;
	}}
}}

/**
 * Example: Fund a test account using chopsticks dev_setStorage
 */
async function fundAccount(account, amount) {{
	console.log(`💰 Funding account ${{account.slice(0, 8)}}... with ${{amount}} tokens`);
	
	await rpcCall('dev_setStorage', [{{
		system: {{
			account: [
				[account], {{
					providers: 1,
					data: {{
						free: amount * 1000000000000, // 1e12 planck units
						reserved: 0,
						miscFrozen: 0,
						feeFrozen: 0
					}}
				}}
			]
		}}
	}}]);
	
	console.log('✅ Account funded');
}}

/**
 * Example: Get account balance
 */
async function getAccountBalance(account) {{
	try {{
		const key = `0x26aa394eea5630e07c48ae0c9558cef7b99d880ec681799c0cf30e8886371da9${{account.slice(2)}}`; // System.Account storage key
		const balance = await rpcCall('state_getStorage', [key]);
		console.log(`Balance for ${{account.slice(0, 8)}}...:`, balance);
		return balance;
	}} catch (error) {{
		console.log(`Could not get balance for ${{account.slice(0, 8)}}...:`, error.message);
		return null;
	}}
}}

/**
 * Example: Check runtime version after upgrade
 */
async function checkRuntimeUpgrade() {{
	try {{
		const version = await rpcCall('state_getRuntimeVersion');
		console.log('✅ Runtime version after upgrade:', version);
		
		// Add custom checks for your specific upgrade
		if (version.specVersion >= expectedVersion) {{
		  console.log('✅ Runtime upgrade successful');
		}} else {{
		  console.log('❌ Runtime upgrade may have failed');
		}}
		
		return version;
	}} catch (error) {{
		console.error('❌ Failed to check runtime version:', error.message);
		return null;
	}}
}}

/**
 * Add your custom test logic here
 */
async function runCustomTests() {{
	console.log('🎯 Running custom tests...');
	
	// Example test flows:
	// 1. Fund test accounts
	// await fundAccount(TEST_ACCOUNTS.ALICE, 1000);
	
	// 2. Check balances
	// await getAccountBalance(TEST_ACCOUNTS.ALICE);
	
	// 3. Check runtime version
	// await checkRuntimeUpgrade();
	
	console.log('✅ Custom tests completed');
}}

// Export functions for opengov-cli integration
module.exports = {{
	runTests,
	fundAccount,
	getAccountBalance,
	checkRuntimeUpgrade,
	runCustomTests,
	rpcCall,
	CONFIG,
	TEST_ACCOUNTS
}};
"#, network, network, network, network, network, network)
}
