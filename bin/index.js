#!/usr/bin/env node

/**
 * V-Tunnel - Lightweight Tunnel Routing Solution
 *
 * A 100% free and open-source alternative to commercial tunneling solutions
 * like Ngrok, Cloudflare Tunnel, and others.
 *
 * @file        index.js
 * @description Router
 * @author      Cengiz AKCAN <me@cengizakcan.com>
 * @copyright   Copyright (c) 2025, Cengiz AKCAN
 * @license     MIT
 * @version     1.1.3
 * @link        https://github.com/wwwakcan/V-Tunnel
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

const args = process.argv.slice(2);
const command = args[0];

// Handle no arguments
if (!args.length) {
    console.log('V-Tunnel - Manageable multi-tunnel and port forwarding system');
    console.log('');
    console.log('Usage:');
    console.log('  vtunnel client [options]   Start V-Tunnel in client mode');
    console.log('  vtunnel server [options]   Start V-Tunnel in server mode');
    process.exit(0);
}

// Determine which script to run based on the first argument
switch (command) {
    case 'client':
        // Remove 'client' from args and run client.js
        const clientArgs = args.slice(1);

        // Reset process.argv to pass to client.js
        process.argv = [process.argv[0], process.argv[1], ...clientArgs];

        // Run the client script
        require('./client.js');
        break;

    case 'server':
        // Remove 'server' from args and run server.js
        const serverArgs = args.slice(1);

        // Reset process.argv to pass to server.js
        process.argv = [process.argv[0], process.argv[1], ...serverArgs];

        // Run the server script
        require('./server.js');
        break;

    default:
        console.log(`Unknown command: ${command}`);
        console.log('');
        console.log('Usage:');
        console.log('  vtunnel client [options]   Start V-Tunnel in client mode');
        console.log('  vtunnel server [options]   Start V-Tunnel in server mode');
        process.exit(1);
}
