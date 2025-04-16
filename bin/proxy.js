#!/usr/bin/env node

/**
 * V-Tunnel - Lightweight Tunnel Routing Solution
 *
 * A 100% free and open-source alternative to commercial tunneling solutions
 * like Ngrok, Cloudflare Tunnel, and others.
 *
 * @file        proxy.js
 * @description Enhanced Tunnel Routing Proxy for provide domain host
 * @author      Cengiz AKCAN <me@cengizakcan.com>
 * @copyright   Copyright (c) 2025, Cengiz AKCAN
 * @license     MIT
 * @version     1.0.9
 * @link        https://github.com/wwwakcan/V-Tunnel
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

// proxy.js
const httpProxy = require('http-proxy');
const path = require('path');
const fs = require('fs');
const os = require('os');
const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');
const inquirer = require('inquirer');
const Table = require('cli-table3');
const colors = require('colors/safe');
const { spawn, execSync } = require('child_process');

// Define config directory
const CONFIG_DIR = path.join(__dirname, '.vtunnel-proxy');
const DEFAULT_CONFIG_PATH = path.join(CONFIG_DIR, 'config.json');
const BACKGROUND_INFO_PATH = path.join(CONFIG_DIR, 'background.json');
const LOG_OUT_PATH = path.join(CONFIG_DIR, 'proxy-output.log');
const LOG_ERR_PATH = path.join(CONFIG_DIR, 'proxy-error.log');

// Parse command line arguments using commands instead of options
const argv = yargs(hideBin(process.argv))
    .command('setup', 'Initialize configuration file interactively', {}, (argv) => {
        argv.doSetup = true;
    })
    .command('show', 'Show current configuration', {}, (argv) => {
        argv.doShow = true;
    })
    .command('background [action]', 'Run proxy server in background mode', (yargs) => {
        return yargs
            .positional('action', {
                describe: 'Background action: start, stop, or status',
                type: 'string',
                choices: ['start', 'stop', 'status'],
                demandOption: true
            });
    }, (argv) => {
        argv.background = true;
    })
    .option('config', {
        alias: 'c',
        description: 'Path to config file',
        type: 'string',
        default: DEFAULT_CONFIG_PATH
    })
    .option('verbose', {
        alias: 'v',
        description: 'Enable verbose logging',
        type: 'boolean'
    })
    .help()
    .alias('help', 'h')
    .version('1.0.0')
    .alias('version', 'V')
    .strict()
    .argv;

// Function to create config.json through interactive prompts
async function createConfigInteractively() {
    console.log(colors.cyan("\n🔧 Dynamic Proxy with SSL - Configuration Setup 🔧\n"));

    const answers = await inquirer.prompt([
        {
            type: 'input',
            name: 'mainDomain',
            message: 'Enter your main domain:',
            default: 'connect.vobo.cloud',
            validate: input => input.trim() !== '' ? true : 'Domain cannot be empty'
        },
        {
            type: 'input',
            name: 'dynamicDomainFormat',
            message: 'Enter dynamic domain format (subdomain pattern):',
            default: (answers) => `*.${answers.mainDomain || 'connect.vobo.cloud'}`,
            validate: input => input.includes('*') ? true : 'Format should include a wildcard (*)'
        },
        {
            type: 'list',
            name: 'extractRule',
            message: 'Select how to extract port from subdomain:',
            choices: [
                { name: 'Prefix (e.g., 8080.domain.com → port 8080)', value: 'prefix' },
                { name: 'Custom regex pattern', value: 'regex' }
            ],
            default: 'prefix'
        },
        {
            type: 'input',
            name: 'dynamicDomainPattern',
            message: 'Enter regex pattern with capture group for port:',
            default: (answers) => `^(\\d+)\\.${(answers.mainDomain || 'connect.vobo.cloud').replace(/\./g, '\\.')}`,
            when: answers => answers.extractRule === 'regex',
            validate: input => {
                try {
                    new RegExp(input);
                    if (!input.includes('(') || !input.includes(')')) {
                        return 'Pattern must include a capture group ()';
                    }
                    return true;
                } catch (e) {
                    return 'Invalid regex pattern';
                }
            }
        },
        {
            type: 'input',
            name: 'targetIP',
            message: 'Enter target IP to forward requests to:',
            default: '127.0.0.1'
        },
        {
            type: 'input',
            name: 'adminEmail',
            message: 'Enter admin email (for SSL certificates):',
            default: 'admin@example.com',
            validate: input => {
                const valid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input);
                return valid ? true : 'Please enter a valid email address';
            }
        },
        {
            type: 'number',
            name: 'httpPort',
            message: 'Enter HTTP port:',
            default: 80,
            validate: input => {
                if (isNaN(input) || input < 1 || input > 65535) {
                    return 'Port must be between 1-65535';
                }
                return true;
            }
        },
        {
            type: 'number',
            name: 'httpsPort',
            message: 'Enter HTTPS port:',
            default: 443,
            validate: input => {
                if (isNaN(input) || input < 1 || input > 65535) {
                    return 'Port must be between 1-65535';
                }
                return true;
            }
        },
        {
            type: 'confirm',
            name: 'confirmSave',
            message: 'Save this configuration?',
            default: true
        }
    ]);

    if (!answers.confirmSave) {
        console.log(colors.yellow('\nConfiguration not saved. Exiting...'));
        process.exit(0);
    }

    // Create config object
    const config = {
        mainDomain: answers.mainDomain,
        dynamicDomainFormat: answers.dynamicDomainFormat,
        extractRule: answers.extractRule
    };

    // Add regex pattern if using custom regex
    if (answers.extractRule === 'regex' && answers.dynamicDomainPattern) {
        config.dynamicDomainPattern = answers.dynamicDomainPattern;
    }

    // Add remaining config options
    Object.assign(config, {
        targetIP: answers.targetIP,
        adminEmail: answers.adminEmail,
        httpPort: answers.httpPort,
        httpsPort: answers.httpsPort
    });

    // Ensure config directory exists
    if (!fs.existsSync(CONFIG_DIR)) {
        fs.mkdirSync(CONFIG_DIR, { recursive: true });
    }

    // Write config to file
    fs.writeFileSync(DEFAULT_CONFIG_PATH, JSON.stringify(config, null, 2));

    console.log(colors.green(`\n✓ Configuration saved to ${DEFAULT_CONFIG_PATH}\n`));
    displayConfig(config);

    return config;
}

// Display current configuration
function displayConfig(config) {
    const table = new Table({
        head: [colors.cyan('Setting'), colors.cyan('Value')],
        colWidths: [30, 50]
    });

    for (const [key, value] of Object.entries(config)) {
        table.push([colors.yellow(key), colors.green(value.toString())]);
    }

    console.log(table.toString());
}

// Create default config if not exists
function createDefaultConfig() {
    const defaultConfig = {
        mainDomain: 'connect.vobo.cloud',
        dynamicDomainFormat: '*.connect.vobo.cloud',
        extractRule: 'prefix',
        targetIP: '127.0.0.1',
        adminEmail: 'admin@example.com',
        httpPort: 80,
        httpsPort: 443
    };

    // Ensure config directory exists
    if (!fs.existsSync(CONFIG_DIR)) {
        fs.mkdirSync(CONFIG_DIR, { recursive: true });
    }

    // Write default config
    fs.writeFileSync(DEFAULT_CONFIG_PATH, JSON.stringify(defaultConfig, null, 2));
    console.log(colors.yellow(`Created default configuration at ${DEFAULT_CONFIG_PATH}`));
    console.log(colors.yellow('Please edit this file with your settings or run with "setup" command to configure interactively'));

    return defaultConfig;
}

// Load or create configuration
async function loadOrCreateConfig() {
    // Show configuration if requested
    if (argv.doShow) {
        try {
            if (!fs.existsSync(DEFAULT_CONFIG_PATH)) {
                console.error(colors.red(`Configuration file not found at ${DEFAULT_CONFIG_PATH}`));
                process.exit(1);
            }

            const config = JSON.parse(fs.readFileSync(DEFAULT_CONFIG_PATH, 'utf8'));
            console.log(colors.cyan("\n📋 Current Configuration 📋\n"));
            displayConfig(config);
            process.exit(0);
        } catch (err) {
            console.error(colors.red(`Error loading configuration: ${err.message}`));
            process.exit(1);
        }
    }

    // Initialize configuration if requested
    if (argv.doSetup) {
        return await createConfigInteractively();
    }

    try {
        // Check if config file exists
        if (fs.existsSync(DEFAULT_CONFIG_PATH)) {
            const config = JSON.parse(fs.readFileSync(DEFAULT_CONFIG_PATH, 'utf8'));
            if (argv.verbose) {
                console.log(colors.green(`Configuration loaded from ${DEFAULT_CONFIG_PATH}`));
                displayConfig(config);
            } else {
                console.log(colors.green(`Configuration loaded successfully from ${DEFAULT_CONFIG_PATH}`));
            }
            return config;
        } else {
            // Create default config
            return createDefaultConfig();
        }
    } catch (err) {
        console.error(colors.red(`Error with configuration file: ${err.message}`));
        return createDefaultConfig();
    }
}

// Check if process is running
function isProcessRunning(pid) {
    try {
        process.kill(pid, 0);
        return true;
    } catch (e) {
        return false;
    }
}

// Get process name by PID
function getProcessName(pid) {
    try {
        if (process.platform === 'win32') {
            const result = execSync(`tasklist /FI "PID eq ${pid}" /FO CSV /NH`).toString();
            const match = /"([^"]+)"/.exec(result);
            return match ? match[1] : 'Unknown';
        } else {
            return execSync(`ps -p ${pid} -o comm=`).toString().trim();
        }
    } catch (e) {
        return 'Unknown';
    }
}

// Start process in background
function startBackgroundProcess() {
    // Ensure config directory exists
    if (!fs.existsSync(CONFIG_DIR)) {
        fs.mkdirSync(CONFIG_DIR, { recursive: true });
    }

    // Check if already running
    if (fs.existsSync(BACKGROUND_INFO_PATH)) {
        try {
            const info = JSON.parse(fs.readFileSync(BACKGROUND_INFO_PATH, 'utf8'));
            if (isProcessRunning(info.pid)) {
                const processName = getProcessName(info.pid);
                console.log(colors.yellow(`✓ Proxy server is already running (PID: ${info.pid}, Process: ${processName})`));
                console.log(colors.yellow(`  Started: ${info.startTime}`));
                return true;
            }
        } catch (err) {
            // Ignore error, will start a new process
        }
    }

    // Get the path to the current script
    const scriptPath = process.argv[1];

    // Convert to absolute path if needed
    const fullScriptPath = path.isAbsolute(scriptPath)
        ? scriptPath
        : path.join(process.cwd(), scriptPath);

    // Create background script
    const startScript = path.join(CONFIG_DIR, 'start-proxy.js');

    // Create a small script that will be used to start the proxy
    const scriptContent = `
// Auto-generated start script for VTunnel Proxy
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

// Open log files
const out = fs.openSync('${LOG_OUT_PATH}', 'a');
const err = fs.openSync('${LOG_ERR_PATH}', 'a');

// Start the main proxy process
const child = spawn('node', ['${fullScriptPath.replace(/\\/g, '\\\\')}'], {
    detached: true,
    stdio: ['ignore', out, err]
});

// Disconnect from parent
child.unref();

// Write the PID to a file so the parent process can read it
fs.writeFileSync('${path.join(CONFIG_DIR, 'proxy.pid')}', child.pid.toString());

// Exit this process
process.exit(0);
    `;

    fs.writeFileSync(startScript, scriptContent);

    try {
        // Execute the start script
        const result = execSync(`node "${startScript}"`, {
            stdio: ['ignore', 'pipe', 'pipe']
        });

        // Wait a bit for the child process to start and write its PID
        setTimeout(() => {}, 1000);

        // Read the PID from the file
        const pidFile = path.join(CONFIG_DIR, 'proxy.pid');
        if (fs.existsSync(pidFile)) {
            const pid = parseInt(fs.readFileSync(pidFile, 'utf8').trim());

            // Save background process info
            const backgroundInfo = {
                pid: pid,
                startTime: new Date().toISOString(),
                command: `node ${fullScriptPath}`,
                logsPath: CONFIG_DIR
            };

            fs.writeFileSync(BACKGROUND_INFO_PATH, JSON.stringify(backgroundInfo, null, 2));
            console.log(colors.green(`✓ Proxy server started in background mode (PID: ${pid})`));
            console.log(colors.green(`  Logs available at:`));
            console.log(colors.gray(`    Output: ${LOG_OUT_PATH}`));
            console.log(colors.gray(`    Errors: ${LOG_ERR_PATH}`));

            // Clean up the PID file
            try { fs.unlinkSync(pidFile); } catch(e) {}

            return true;
        } else {
            console.error(colors.red('Failed to start background process: PID file not created'));
            return false;
        }
    } catch (error) {
        console.error(colors.red(`Failed to start background process: ${error.message}`));
        if (error.stdout) console.error(colors.gray(error.stdout.toString()));
        if (error.stderr) console.error(colors.red(error.stderr.toString()));
        return false;
    }
}

// Handle background service commands
function handleBackgroundCommands() {
    if (!argv.background) return false;

    const action = argv.action;

    // Background start command
    if (action === 'start') {
        return startBackgroundProcess();
    }

    // Background stop command
    if (action === 'stop') {
        if (!fs.existsSync(BACKGROUND_INFO_PATH)) {
            console.log(colors.yellow('✗ No background proxy server found'));
            return true;
        }

        try {
            const info = JSON.parse(fs.readFileSync(BACKGROUND_INFO_PATH, 'utf8'));
            if (isProcessRunning(info.pid)) {
                process.kill(info.pid);
                console.log(colors.green(`✓ Proxy server stopped (PID: ${info.pid})`));
            } else {
                console.log(colors.yellow(`✗ Proxy server is not running (previous PID: ${info.pid})`));
            }
            fs.unlinkSync(BACKGROUND_INFO_PATH);
            return true;
        } catch (err) {
            console.error(colors.red(`Error stopping background server: ${err.message}`));
            return true;
        }
    }

    // Background status command
    if (action === 'status') {
        if (!fs.existsSync(BACKGROUND_INFO_PATH)) {
            console.log(colors.yellow('✗ No background proxy server found'));
            return true;
        }

        try {
            const info = JSON.parse(fs.readFileSync(BACKGROUND_INFO_PATH, 'utf8'));
            if (isProcessRunning(info.pid)) {
                const processName = getProcessName(info.pid);

                console.log(colors.green(`✓ Proxy server is running`));
                console.log(colors.gray(`  PID: ${info.pid}`));
                console.log(colors.gray(`  Process: ${processName}`));
                console.log(colors.gray(`  Started: ${info.startTime}`));
                console.log(colors.gray(`  Command: ${info.command}`));
                console.log(colors.gray(`  Logs: ${info.logsPath}`));

                // Show recent logs
                try {
                    if (fs.existsSync(LOG_OUT_PATH)) {
                        const stats = fs.statSync(LOG_OUT_PATH);
                        const size = stats.size;
                        const maxBytes = 500; // Show last 500 bytes

                        console.log(colors.gray(`\n  Recent logs:`));

                        const fd = fs.openSync(LOG_OUT_PATH, 'r');
                        const buffer = Buffer.alloc(Math.min(size, maxBytes));
                        fs.readSync(fd, buffer, 0, buffer.length, Math.max(0, size - maxBytes));
                        fs.closeSync(fd);

                        const lines = buffer.toString().split('\n').filter(line => line.trim());
                        const lastLines = lines.slice(-5); // Show last 5 lines

                        if (lastLines.length > 0) {
                            lastLines.forEach(line => {
                                console.log(colors.gray(`    ${line}`));
                            });
                        } else {
                            console.log(colors.gray(`    (No log output yet)`));
                        }
                    }
                } catch (e) {
                    // Ignore log reading errors
                }
            } else {
                console.log(colors.red(`✗ Proxy server is not running (previous PID: ${info.pid})`));
                console.log(colors.gray(`  Last started: ${info.startTime}`));
            }
            return true;
        } catch (err) {
            console.error(colors.red(`Error checking status: ${err.message}`));
            return true;
        }
    }

    return false;
}

// Create a proxy server instance
const proxy = httpProxy.createProxyServer({});

// Handle proxy errors
proxy.on('error', function(err, req, res) {
    console.error(colors.red(`Proxy error: ${err.message}`));
    if (res.writeHead) {
        res.writeHead(500, {
            'Content-Type': 'text/plain'
        });
        res.end('Proxy error');
    }
});

// Create a function to extract the port or identifier from the hostname
function extractIdentifier(hostname, config) {
    if (!hostname) return null;

    // Get the main domain and remove any periods from the beginning
    const mainDomain = config.mainDomain.replace(/^\./, '');

    // If extractRule is "prefix", extract the portion before the domain
    if (config.extractRule === "prefix") {
        const pattern = new RegExp(`^(.+)\\.${mainDomain.replace(/\./g, '\\.')}$`);
        const match = hostname.match(pattern);
        return match ? match[1] : null;
    }

    // If dynamicDomainPattern is provided directly, use it
    if (config.dynamicDomainPattern) {
        const regex = new RegExp(config.dynamicDomainPattern);
        const match = hostname.match(regex);
        return match && match[1] ? match[1] : null;
    }

    // Default: extract numeric port from hostname
    const pattern = new RegExp(`^(\\d+)\\.${mainDomain.replace(/\./g, '\\.')}$`);
    const match = hostname.match(pattern);
    return match ? match[1] : null;
}

// Create request handler function for both HTTP and HTTPS
function createRequestHandler(config) {
    return function handleRequest(req, res) {
        // Get the host from the request headers
        const host = req.headers.host;

        // Extract identifier (port) from subdomain
        const identifier = extractIdentifier(host, config);

        // If we couldn't extract an identifier, respond with an error
        if (!identifier) {
            console.error(colors.yellow(`Invalid host format: ${host}`));
            const expectedFormat = config.dynamicDomainFormat
                ? config.dynamicDomainFormat.replace('*', '12345')
                : `12345.${config.mainDomain}`;
            res.writeHead(400, { 'Content-Type': 'text/plain' });
            res.end(`Invalid host: Expected format like ${expectedFormat}`);
            return;
        }

        // Log the request
        if (argv.verbose) {
            console.log(colors.gray(`Request: ${req.method} ${req.url} from ${req.socket.remoteAddress}`));
            console.log(colors.gray(`Forwarding ${host} (port: ${identifier}) → ${config.targetIP}:${identifier}`));
        }

        // Target where we're forwarding the request to
        const target = `http://${config.targetIP}:${identifier}`;

        // Forward the request to the target
        proxy.web(req, res, { target });
    };
}

// Create initial site for Greenlock
function setupGreenlock(config, greenlockDir) {
    // Create a basic site configuration file
    const siteFile = path.join(greenlockDir, 'config.json');

    try {
        // Create a minimal Greenlock config if it doesn't exist
        if (!fs.existsSync(siteFile)) {
            const greenlockConfig = {
                sites: [
                    {
                        subject: config.mainDomain,
                        altnames: [config.mainDomain, `*.${config.mainDomain}`]
                    }
                ],
                defaults: {
                    challenges: {
                        "http-01": {
                            module: "acme-http-01-standalone"
                        }
                    },
                    renewOffset: "-45d",
                    renewStagger: "3d",
                    accountKeyType: "EC-P256",
                    serverKeyType: "RSA-2048",
                    subscriberEmail: config.adminEmail
                }
            };

            fs.writeFileSync(siteFile, JSON.stringify(greenlockConfig, null, 2));
        }
    } catch (err) {
        console.warn(colors.yellow(`Note: Could not create Greenlock configuration: ${err.message}`));
    }
}

// Intercept console.log to filter Greenlock warnings
const originalConsoleLog = console.log;
const originalConsoleWarn = console.warn;

// Override console.log to filter out specific Greenlock messages
console.log = function() {
    const args = Array.from(arguments);
    const msgStr = args.join(' ');

    // Skip specific Greenlock warnings and messages
    if (msgStr.includes('Warning: `find({})` returned 0 sites') ||
        msgStr.includes('Does `@greenlock/manager` implement `find({})`') ||
        msgStr.includes('Did you add sites?') ||
        msgStr.includes('npx greenlock add')) {
        return;
    }

    originalConsoleLog.apply(console, args);
};

// Override console.warn similarly
console.warn = function() {
    const args = Array.from(arguments);
    const msgStr = args.join(' ');

    // Skip specific Greenlock warnings
    if (msgStr.includes('Warning: `find({})` returned 0 sites') ||
        msgStr.includes('Does `@greenlock/manager` implement `find({})`') ||
        msgStr.includes('Did you add sites?') ||
        msgStr.includes('npx greenlock add')) {
        return;
    }

    originalConsoleWarn.apply(console, args);
};

// Main function to start the proxy server
async function startProxyServer() {
    // Process background mode commands if provided
    if (argv.background) {
        const handled = handleBackgroundCommands();
        if (handled) {
            return;
        }
    }

    // Check if we're running from the correct directory with package.json
    const packagePath = path.join(__dirname, 'package.json');
    if (!fs.existsSync(packagePath)) {
        console.warn(colors.yellow('\n⚠️  package.json not found in the current directory'));
        console.warn(colors.yellow('   Creating a minimal package.json file for greenlock'));

        // Create a minimal package.json file
        const packageJson = {
            name: "vtunnel-proxy",
            version: "1.0.0",
            description: "Dynamic proxy server with automatic SSL certificate management"
        };

        fs.writeFileSync(packagePath, JSON.stringify(packageJson, null, 2));
        console.warn(colors.green('✓ Created package.json\n'));
    }

    // Load the configuration
    const config = await loadOrCreateConfig();

    // Create directory for Greenlock configuration
    const greenlockDir = path.join(CONFIG_DIR, 'greenlock');
    if (!fs.existsSync(greenlockDir)) {
        fs.mkdirSync(greenlockDir, { recursive: true });
    }

    // Setup initial Greenlock configuration
    setupGreenlock(config, greenlockDir);

    // Prepare the domain list for SSL
    const domains = [config.mainDomain];
    if (config.dynamicDomainFormat && config.dynamicDomainFormat.includes('*')) {
        domains.push(`*.${config.mainDomain}`);
    } else {
        domains.push(`*.${config.mainDomain}`);
    }

    // Create the request handler with the loaded configuration
    const handleRequest = createRequestHandler(config);

    // Import and initialize Greenlock for SSL/HTTPS
    require('greenlock-express')
        .init({
            packageRoot: __dirname,
            configDir: greenlockDir,
            maintainerEmail: config.adminEmail || process.env.EMAIL,
            cluster: false,
            packageAgent: `vtunnel-proxy/1.0.0`,
            notify: (event, details) => {
                if (event === 'error' && !String(details).includes('find({})')) {
                    console.error(colors.red(`Greenlock SSL error: ${details}`));
                }
            }
        })
        .serve(handleRequest, {
            // Handle HTTP-01 challenge requests
            agreeTos: true,
            communityMember: true,
            telemetry: false,

            // Define our domain/site configuration
            servername: config.mainDomain,
            servernames: domains,

            // Use our ports
            plainHttpPort: config.httpPort,
            secureHttpsPort: config.httpsPort
        });

    const formatMessage = config.dynamicDomainFormat || `[PORT].${config.mainDomain}`;
    console.log(colors.cyan('\n🚀 Dynamic Proxy Server with SSL is starting...\n'));
    console.log(colors.green(`✓ Forwarding: ${colors.bold(formatMessage)} → ${colors.bold(`${config.targetIP}:[PORT]`)}`));
    console.log(colors.green(`✓ HTTP port: ${colors.bold(config.httpPort)}`));
    console.log(colors.green(`✓ HTTPS port: ${colors.bold(config.httpsPort)}`));
    console.log(colors.green(`✓ Admin email: ${colors.bold(config.adminEmail)}`));
    console.log(colors.green(`✓ Certificate domains: ${colors.bold(domains.join(', '))}`));
    console.log(colors.cyan('\n🔒 SSL certificates will be automatically issued and renewed\n'));
}

// Start the proxy server
startProxyServer().catch(err => {
    console.error(colors.red('\n❌ Error starting proxy server:'));
    console.error(colors.red(err.stack || err.message));
    process.exit(1);
});
