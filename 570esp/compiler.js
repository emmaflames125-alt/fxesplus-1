#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

// Import libcompiler functions
const libcompiler = require('../libcompiler.js');

// Change to script directory
const scriptDir = __dirname;

// Helper function to read font file
function getFont(filename = 'font') {
	const filepath = path.join(scriptDir, filename);
	const content = fs.readFileSync(filepath, 'utf8');
	const lines = content.split('\n');
	
	let font = '';
	for (let lineIndex = 0; lineIndex < 16 && lineIndex < lines.length; lineIndex++) {
		let line = lines[lineIndex];
		
		if (line.endsWith('\n')) {
			line = line.slice(0, -1);
		}
		
		if (line.length > 16) {
			throw new Error(`Line ${lineIndex} in font file ${filename} has more than 16 chars: "${line}"`);
		}
		font += line.padEnd(16);
	}
	
	if (lines.length < 16) {
		throw new Error(`Font file ${filename} has less than 16 lines`);
	}
	
	return font;
}

// Setup font
libcompiler.setFont(getFont());

// Npress array for 570esp calculator
const npress = [
	999,4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4,
	100,100,100,100,100,100,100,100,100,100,100,100,100,4,  4,  4,
	100,100,4,  4,  4,  2,  4,  4,  1,  1,  4,  1,  1,  1,  1,  100,
	1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  2,  4,  100,2,  100,100,
	4,  2,  2,  2,  2,  2,  2,  100,100,100,100,100,100,100,1,  1,
	100,100,100,100,2,  100,100,2,  2,  2,  100,100,1,  100,1,  100,
	1,  100,100,2,  100,100,100,100,1,  2,  1,  2,  2,  2,  100,100,
	2,  2,  2,  2,  1,  1,  2,  1,  4,  4,  4,  100,100,100,100,100,
	100,2,  2,  100,100,3,  3,  3,  100,100,100,1,  2,  100,100,100,
	2,  2,  2,  2,  100,100,100,100,1,  100,100,100,100,100,100,2,
	1,  1,  1,  1,  100,100,100,100,2,  100,100,100,100,100,1,  100,
	2,  2,  2,  2,  4,  4,  4,  4,  100,100,100,100,100,100,2,  2,
	100,100,2,  100,4,  4,  4,  4,  100,100,100,100,100,100,100,100,
	100,100,100,100,4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4,
	4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4,
	4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  100,
];
libcompiler.setNpressArray(npress);

// Load ROM
function getBinary(filename) {
	const filepath = path.join(scriptDir, filename);
	return fs.readFileSync(filepath);
}

let rom;
try {
	rom = getBinary('rom.bin');
} catch (e) {
	console.error('Warning: ROM file not found. Some features may not work.');
	rom = Buffer.alloc(0);
}

// Extract symbols from ROM
function getSymbols(romData) {
	const symbols = Array(256).fill('');
	
	if (romData.length === 0) {
		return symbols;
	}
	
	for (let i = 1; i < 256; i++) {
		const ptrAdr = 0x10F2 + 2 * i;
		if (ptrAdr + 1 >= romData.length) break;
		
		const ptr = (romData[ptrAdr + 1] << 8) | romData[ptrAdr];
		
		if (0x12F2 + i >= romData.length) break;
		const info = romData[0x12F2 + i];
		const symbolLen = info & 0xF;
		let symbolType = info >> 4; // if 15 then func else normal
		
		if (symbolType !== 15) {
			symbolType = (ptr + symbolType);
		} else {
			symbolType = ptr;
		}
		
		let result = '';
		if (symbolType + symbolLen <= romData.length) {
			const symbolBytes = Array.from(romData.slice(symbolType, symbolType + symbolLen));
			result = libcompiler.toFont(symbolBytes);
		}
		
		if ((info >> 4) === 15) result = result + '(';
		symbols[i] = result;
	}
	
	return symbols;
}

const symbols = getSymbols(rom);
let symbolrepr = [...symbols];

// Add constants
const consts = [...Array(15).keys()].map(i => i + 1);
if (rom.length > 0x160E + 25) {
	for (let i = 0; i < 25; i++) {
		consts.push(rom[0x160E + i]);
	}
}
for (let i = 0; i < consts.length; i++) {
	const x = consts[i];
	if (x < symbolrepr.length) {
		symbolrepr[x] = 'cs' + (i + 1);
	}
}

// Add conversions
const convs = Array.from({length: 40}, (_, i) => 0xD7 + i);
for (let i = 0; i < convs.length; i++) {
	const x = convs[i];
	if (x < symbolrepr.length) {
		symbolrepr[x] = 'cv' + (i + 1);
	}
}

libcompiler.setSymbolrepr(symbolrepr);

// Main compilation function
function compile(programText, target = 'overflow', format = 'key') {
	const args = {
		target: target,
		format: format
	};
	
	const program = programText.split('\n');
	
	// Capture console output
	const oldLog = console.log;
	let output = '';
	console.log = function(...args) {
		output += args.join(' ') + '\n';
	};
	
	try {
		libcompiler.processProgram(args, program, 0x8DA4);
	} catch (e) {
		console.log = oldLog;
		throw e;
	}
	
	console.log = oldLog;
	return output.trim();
}

// Export functions for web use
if (typeof module !== 'undefined' && module.exports) {
	module.exports = {
		compile,
		getFont,
		symbols,
		symbolrepr,
		npress
	};
}

// Command-line interface
if (require.main === module) {
	const args = process.argv.slice(2);
	let target = 'overflow';
	let format = 'key';
	
	for (let i = 0; i < args.length; i++) {
		if (args[i] === '-t' || args[i] === '--target') {
			target = args[i + 1];
			i++;
		} else if (args[i] === '-f' || args[i] === '--format') {
			format = args[i + 1];
			i++;
		}
	}
	
	// Read from stdin
	let input = '';
	process.stdin.setEncoding('utf8');
	process.stdin.on('data', chunk => {
		input += chunk;
	});
	
	process.stdin.on('end', () => {
		try {
			const result = compile(input, target, format);
			console.log(result);
		} catch (e) {
			console.error('Error:', e.message);
			process.exit(1);
		}
	});
}
