// Max call address constant
const MAX_CALL_ADR = 0x3ffff;

// Global variables
let font = '';
let fontAssoc = {};
let npress = [];
let symbolrepr = [];
let commands = {};
let datalabels = {};
let result = [];
let labels = {};
let adrOfCmds = [];
let home = null;
let disasm = [];
let rom = null;

// Simple LRU cache implementation for byte_to_key
class LRUCache {
	constructor(maxSize = 256) {
		this.maxSize = maxSize;
		this.cache = new Map();
	}

	get(key) {
		if (this.cache.has(key)) {
			const value = this.cache.get(key);
			// Move to end (most recently used)
			this.cache.delete(key);
			this.cache.set(key, value);
			return value;
		}
		return undefined;
	}

	set(key, value) {
		if (this.cache.has(key)) {
			this.cache.delete(key);
		} else if (this.cache.size >= this.maxSize) {
			// Remove least recently used (first item)
			const firstKey = this.cache.keys().next().value;
			this.cache.delete(firstKey);
		}
		this.cache.set(key, value);
	}
}

const byteToKeyCache = new LRUCache(256);

function setFont(fontParam) {
	font = fontParam;
	fontAssoc = {};
	for (let i = 0; i < font.length; i++) {
		fontAssoc[font[i]] = i;
	}
}

function fromFont(st) {
	return Array.from(st).map(char => fontAssoc[char]);
}

function toFont(charcodes) {
	return charcodes.map(charcode => font[charcode]).join('');
}

function setNpressArray(npressParam) {
	npress = npressParam;
}

function setSymbolrepr(symbolreprParam) {
	symbolrepr = symbolreprParam;
}

function byteToKey(byte) {
	const cached = byteToKeyCache.get(byte);
	if (cached !== undefined) return cached;

	let result;
	if (byte === 0) {
		result = '<NUL>';
	} else {
		// TODO hack for classwiz without unstable
		const sym = symbolrepr[byte];
		result = (sym === '@' || sym === '') ? `<${byte.toString(16).padStart(2, '0')}>` : sym;
	}

	byteToKeyCache.set(byte, result);
	return result;
}

function getNpress(charcodes) {
	if (typeof charcodes === 'number') charcodes = [charcodes];
	return charcodes.reduce((sum, charcode) => sum + npress[charcode], 0);
}

function getNpressAdr(adrs) {
	if (typeof adrs === 'number') adrs = [adrs];
	if (!adrs.every(adr => 0 <= adr && adr <= MAX_CALL_ADR)) {
		throw new Error('Address out of range');
	}
	return adrs.reduce((sum, adr) => sum + getNpress([(adr & 0xFF), ((adr >> 8) & 0xFF)]), 0);
}

function optimizeAdrForNpress(adr) {
	/**
	 * For a 'POP PC' command, the lowest significant bit in the address
	 * does not matter. This function uses that fact to minimize number
	 * of key strokes used to enter the hackstring.
	 */
	const adr1 = adr;
	const adr2 = adr ^ 1;
	return getNpressAdr(adr1) <= getNpressAdr(adr2) ? adr1 : adr2;
}

function optimizeSumForNpress(total) {
	/**
	 * Return (a, b) such that a + b == total.
	 */
	let bestPair = null;
	let bestNpress = Infinity;

	for (let x = 0x0101; x < 0x10000; x++) {
		const y = (total - x) & 0xffff;
		const nprVal = getNpressAdr([x, y]);
		if (nprVal < bestNpress) {
			bestNpress = nprVal;
			bestPair = [x, y];
		}
	}

	return bestPair.map(x => '0x' + x.toString(16).padStart(4, '0'));
}

function note(st) {
	/** Print st to stderr. Used for additional information (note, warning) */
	if (typeof process !== 'undefined' && process.stderr) {
		process.stderr.write(st);
	}
}

function canonicalize(st) {
	/** Make (st) canonical. */
	st = st.toLowerCase();
	st = st.trim();
	// remove spaces around non alphanumeric
	st = st.replace(/ *([^a-z0-9]) */g, '$1');
	return st;
}

function delInlineComment(line) {
	const idx = line.indexOf('#');
	if (idx >= 0) {
		return line.substring(0, idx).trimEnd();
	}
	return line;
}

function addCommand(commandDict, address, command, tags, debugInfo = '') {
	/** Add a command to commandDict. */
	if (!command) throw new Error(`Empty command ${debugInfo}`);
	if (typeof commandDict !== 'object') throw new Error('commandDict must be an object');

	const disallowedPrefixes = ['0x', 'call', 'goto', 'adr_of'];
	for (const prefix of disallowedPrefixes) {
		if (command.startsWith(prefix)) {
			throw new Error(`Command starts with "${prefix}" ${debugInfo}`);
		}
	}
	if (command.endsWith(':')) {
		throw new Error(`Command ends with ":" ${debugInfo}`);
	}
	if (command.includes(';')) {
		throw new Error(`Command contains ";" ${debugInfo}`);
	}

	// Check for duplicates
	for (const [prevCommand, [prevAdr, prevTags]] of Object.entries(commandDict)) {
		if (prevCommand === command || prevAdr === address) {
			throw new Error(
				`Command appears twice - first: ${prevCommand} -> ${prevAdr.toString(16).padStart(5, '0')} ${prevTags}, ` +
				`second: ${command} -> ${address.toString(16).padStart(5, '0')} ${tags} - ${debugInfo}`
			);
		}
	}

	commandDict[command] = [address, Array.from(tags)];
}

function getCommands(filename) {
	/** Read a list of gadget names. */
	const fs = require('fs');
	const data = fs.readFileSync(filename, 'utf8').split('\n');

	let inComment = false;
	const lineRegex = /([0-9a-fA-F]+)\s+(.+)/;
	for (let lineIndex = 0; lineIndex < data.length; lineIndex++) {
		let line = data[lineIndex].trim();

		// multi-line comments
		if (line === '/*') {
			inComment = true;
			continue;
		}
		if (line === '*/') {
			inComment = false;
			continue;
		}
		if (inComment) continue;

		line = delInlineComment(line);
		if (!line) continue;

		const match = line.match(lineRegex);
		if (!match) throw new Error(`Invalid line format at line ${lineIndex + 1}`);

		let address = match[1];
		let command = match[2];

		command = canonicalize(command);

		const tags = [];
		while (command && command[0] === '{') {
			const i = command.indexOf('}');
			if (i < 0) {
				throw new Error(`Line ${lineIndex + 1} has unmatched "{"`);
			}
			tags.push(command.substring(1, i));
			command = command.substring(i + 1);
		}

		try {
			address = parseInt(address, 16);
		} catch (e) {
			throw new Error(`Line ${lineIndex + 1} has invalid address: ${address}`);
		}

		addCommand(commands, address, command, tags, `at ${filename}:${lineIndex + 1}`);
	}
}

function getDisassembly(filename) {
	/**
	 * Try to parse a disassembly file with annotated address.
	 * Each line should look like this:
	 * 		mov r2, 1                      ; 0A0A2 | 0201
	 */
	const fs = require('fs');
	const data = fs.readFileSync(filename, 'utf8').split('\n');

	const lineRegex = /\t(.*?)\s*; ([0-9a-fA-F]*) \|/;
	disasm = [];
	for (const line of data) {
		const match = line.match(lineRegex);
		if (match) {
			const addr = parseInt(match[2], 16);
			while (addr >= disasm.length) disasm.push('');
			disasm[addr] = match[1];
		}
	}
}

function readRenameList(filename) {
	/**
	 * Try to parse a rename list.
	 * If the rename list is ambiguous without disassembly, it raises an error.
	 */
	const fs = require('fs');
	const data = fs.readFileSync(filename, 'utf8').split('\n');

	const lineRegex = /^\s*([\w_.]+)\s+([\w_.]+)/;
	const globalRegex = /f_([0-9a-fA-F]+)/;
	const localRegex = /.l_([0-9a-fA-F]+)/;
	const dataRegex = /d_([0-9a-fA-F]+)/;
	const hexadecimal = /^[0-9a-fA-F]+$/;

	let lastGlobalLabel = null;
	for (let lineIndex = 0; lineIndex < data.length; lineIndex++) {
		const line = data[lineIndex];
		const match = line.match(lineRegex);
		if (!match) continue;

		let raw = match[1];
		const real = match[2];

		if (real.startsWith('.')) {
			continue;
		}

		let dataMatch = raw.match(dataRegex);
		if (dataMatch && dataMatch[0] === raw) {
			const addr = parseInt(dataMatch[1], 16);
			datalabels[real] = addr;
			continue;
		}

		let addr = null;
		if (hexadecimal.test(raw)) {
			addr = parseInt(raw, 16);
			lastGlobalLabel = null;
		} else {
			const globalMatch = raw.match(globalRegex);
			if (globalMatch) {
				addr = parseInt(globalMatch[1], 16);
				if (globalMatch[0].length === raw.length) {
					lastGlobalLabel = addr;
				} else {
					const localMatch = raw.substring(globalMatch[0].length).match(localRegex);
					if (localMatch && localMatch[0] === raw.substring(globalMatch[0].length)) {
						addr += parseInt(localMatch[1], 16);
					}
				}
			} else {
				const localMatch = raw.match(localRegex);
				if (localMatch && localMatch[0] === raw) {
					if (lastGlobalLabel === null) {
						console.log('Label cannot be read: ', line);
						continue;
					} else {
						addr = lastGlobalLabel + parseInt(localMatch[1], 16);
					}
				}
			}
		}

		if (addr !== null) {
			if (addr >= disasm.length) throw new Error(`Address out of range: ${addr.toString(16).padStart(5, '0')}`);

			let tags;
			if (disasm[addr] && disasm[addr].startsWith('push lr')) {
				tags = ['del lr'];
				addr += 2;
			} else {
				tags = ['rt'];
				let a1 = addr + 2;
				while (a1 < disasm.length && !['push lr', 'pop pc', 'rt'].some(x => (disasm[a1] || '').startsWith(x))) {
					a1 += 2;
				}
				if (a1 < disasm.length && !(disasm[a1] || '').startsWith('rt')) {
					tags.push('del lr');
				}
			}

			if (real in commands) {
				const [cmdAddr, cmdTags] = commands[real];
				if (cmdTags.includes('override rename list')) {
					continue;
				}
				if (cmdAddr === addr && JSON.stringify(cmdTags) === JSON.stringify(tags)) {
					note(`Warning: Duplicated command ${real}\n`);
					continue;
				}
			}

			addCommand(commands, addr, real, tags, `at ${filename}:${lineIndex + 1}`);
		} else {
			throw new Error('Invalid line: ' + JSON.stringify(line));
		}
	}
}

function sizeofRegister(regName) {
	// assume regName is a valid register name
	const sizeMap = { 'r': 1, 'e': 2, 'x': 4, 'q': 8 };
	return sizeMap[regName[0]] || 1;
}

function process(line) {
	// the processing result will affect global variables

	if (!line) {
		// empty line
		return;
	} else if (line.includes(';')) {
		// Compound statement
		for (const command of line.split(';')) {
			process(command);
		}
	} else if (line[line.length - 1] === ':') {
		// Label definition
		const label = line.slice(0, -1);
		if (label in labels) throw new Error(`Duplicated label: ${label}`);
		labels[label] = result.length;
	} else if (line.startsWith('0x')) {
		// Hexadecimal data
		if (line.length % 2 !== 0) throw new Error('Invalid data length');
		const nByte = line.length / 2 - 1;
		let data = parseInt(line, 16);
		for (let i = 0; i < nByte; i++) {
			result.push(data & 0xFF);
			data >>= 8;
		}
	} else if (line.startsWith('call')) {
		// Call command
		let adr;
		try {
			adr = parseInt(line.substring(4), 16);
		} catch (e) {
			const cmdName = line.substring(4).trim();
			if (!(cmdName in commands)) throw new Error(`Unknown command: ${cmdName}`);
			const [cmdAdr, tags] = commands[cmdName];
			adr = cmdAdr;
			for (const tag of tags) {
				if (tag.startsWith('warning')) {
					note(tag + '\n');
				}
			}
		}

		if (!(0 <= adr && adr <= MAX_CALL_ADR)) throw new Error(`Invalid address: ${adr}`);
		adr = optimizeAdrForNpress(adr);
		process(`0x${(adr + 0x30300000).toString(16).padStart(8, '0')}`);
	} else if (line.startsWith('goto')) {
		// Goto command
		const label = line.substring(4);
		process(`er14 = adr_of [-2] ${label}`);
		process('call sp=er14,pop er14');
	} else if (line.startsWith('adr_of')) {
		// Address of command
		let remaining = line.substring(6).trim();
		let offset = 0;
		let label;

		if (remaining[0] === '[') {
			const i = remaining.indexOf(']');
			offset = parseInt(remaining.substring(1, i), 0);
			label = remaining.substring(i + 1).trim();
		} else {
			label = remaining.trim();
		}

		adrOfCmds.push([result.length, offset, label]);
		result.push(0, 0);
	} else if (line in datalabels) {
		// Data label
		process(`${line}+0`);
	} else if (line.includes('+') && line.substring(0, line.indexOf('+')) in datalabels) {
		// Label with offset
		const plusIdx = line.indexOf('+');
		const labelName = line.substring(0, plusIdx);
		const offset = parseInt(line.substring(plusIdx + 1), 0);
		process(`0x${(datalabels[labelName] + offset).toString(16).padStart(4, '0')}`);
	} else if (line in commands) {
		// Built-in command
		process(`call ${line}`);
	} else if (line.includes('=')) {
		// Assignment
		const eqIdx = line.indexOf('=');
		const register = line.substring(0, eqIdx);
		let value = line.substring(eqIdx + 1).trimStart();

		if (value.includes('=')) throw new Error(`Nested assignment in ${line}`);
		value = value.replace(/,/g, ';');

		process(`call pop ${register}`);

		const l1 = result.length;
		process(value);
		if (result.length - l1 !== sizeofRegister(register)) {
			throw new Error(`Line ${line} source/destination target mismatches`);
		}
	} else if (line[0] === '$') {
		// JavaScript eval
		try {
			const x = eval(line.substring(1));
			if (typeof x === 'string') {
				process(x);
			} else if (Array.isArray(x)) {
				for (const command of x) {
					process(command);
				}
			}
		} catch (e) {
			throw new Error(`Eval error: ${e.message}`);
		}
	} else if (line.startsWith('org')) {
		// Origin/address specification
		const hx = eval(line.substring(3));
		const home1 = hx - result.length;
		if (home !== null && home !== home1) {
			throw new Error('Inconsistent value of `home`');
		}
		home = home1;
	} else {
		throw new Error(`Unrecognized command: ${line}`);
	}
}

function processProgram(args, program, overflowInitialSp) {
	/**
	 * Take a program (list of command lines) and process the compiled program
	 * to the console.
	 */
	for (const inputLine of program) {
		const line = canonicalize(delInlineComment(inputLine));

		let noteLog = '';
		const oldNote = note;
		const originalNote = note;

		// Temporarily redirect notes
		const noteFunc = (st) => {
			noteLog += st;
		};

		const oldLenResult = result.length;
		try {
			process(line);
		} catch (e) {
			originalNote(`While processing line\n${inputLine}\n`);
			throw e;
		}

		if (args.format === 'key' && 
			result.slice(oldLenResult).some(x => x !== 0 && getNpress(x) > 10)) {
			originalNote('Line generates many keypresses\n');
		}

		if (noteLog) {
			originalNote(`While processing line\n${inputLine}\n`);
			originalNote(noteLog);
		}
	}

	// Resolve adr_of_cmds with actual label addresses
	adrOfCmds = adrOfCmds.map(([sourceAdr, offset, targetLabel]) => 
		[sourceAdr, labels[targetLabel] + offset]
	);

	if (args.target === 'none' || args.target === 'overflow') {
		if (args.target === 'overflow') {
			if (result.length > 100) throw new Error('Program too long');
		}

		if (home === null) {
			// compute value of `home`
			home = overflowInitialSp;
			if ('home' in labels) {
				home -= labels['home'];
			}
			if (home + result.length > 0x8e00) {
				note(`Warning: Program length after home = ${result.length} bytes > ${0x8e00 - home} bytes\n`);
			}

			let minHome = home;
			while (minHome >= 0x8154 + 200) minHome -= 100;
			while (home + result.length <= 0x8e00) home += 100;

			const homeRange = [];
			for (let h = minHome; h < home; h += 100) {
				homeRange.push(h);
			}

			home = homeRange.reduce((best, h) => {
				const bestScore = [
					adrOfCmds.filter(([, homeOffset]) => getNpressAdr(best + homeOffset) >= 100).length,
					-best
				];
				const hScore = [
					adrOfCmds.filter(([, homeOffset]) => getNpressAdr(h + homeOffset) >= 100).length,
					-h
				];
				return (hScore[0] < bestScore[0] || (hScore[0] === bestScore[0] && hScore[1] > bestScore[1])) ? h : best;
			}, minHome);
		}
	} else if (args.target === 'loader') {
		if (home === null) {
			home = 0x85b0 - result.length;
			const entry = home + (labels['home'] || 0) - 2;
			result.push(0x6a, 0x4f, 0, 0, entry & 255, entry >> 8, 0x68, 0x4f, 0, 0);
			while (home + result.length < 0x85d7) {
				result.push(0);
			}
			result.push(0xff, 0xae, 0x85);
			let home2 = 0;
			if ((home - home2) < 0x8501) throw new Error('Program too long');
			while (getNpressAdr(home - home2) >= 100) {
				home2 += 1;
			}
		}
	} else {
		throw new Error('Internal error: unsupported target');
	}

	// Substitute addresses in result
	if (home === null) throw new Error('Internal error: home is null');
	for (const [sourceAdr, homeOffset] of adrOfCmds) {
		const targetAdr = home + homeOffset;
		if (result[sourceAdr] !== 0) throw new Error(`Result[${sourceAdr}] should be 0`);
		result[sourceAdr] = targetAdr & 0xFF;
		if (result[sourceAdr + 1] !== 0) throw new Error(`Result[${sourceAdr + 1}] should be 0`);
		result[sourceAdr + 1] = targetAdr >> 8;
	}

	// Debug print label location
	for (const [label, homeOffset] of Object.entries(labels)) {
		note(`Label ${label} is at address ${(home + homeOffset).toString(16).padStart(4, '0').toUpperCase()}\n`);
	}

	if (args.target === 'overflow') {
		// Scroll it around
		const hackstring = Array(100).fill(0).map((_, i) => '1234567890'.charCodeAt(i % 10));
		for (let homeOffset = 0; homeOffset < result.length; homeOffset++) {
			const byte = result[homeOffset];
			if (typeof byte !== 'number') throw new Error(`Invalid byte at ${homeOffset}: ${byte}`);
			hackstring[(home + homeOffset - 0x8154) % 100] = byte;
		}
		result = hackstring;
	}

	// Output results
	if (args.target === 'overflow' && args.format === 'hex') {
		console.log(result.map(byte => byte.toString(16).padStart(2, '0')).join(''));
	} else if (args.target === 'none' && args.format === 'hex') {
		console.log(`0x${home.toString(16).padStart(4, '0')}:`, result.map(x => x.toString(16).padStart(2, '0')).join(' '));
	} else if (args.target === 'none' && args.format === 'key') {
		console.log(`${home.toString(16)}:`, result.map(byte => byteToKey(byte)).join(' '));
	} else if (args.target === 'loader' && args.format === 'key') {
		// NOTE: loader target may be specific to 570es+/991es+
		console.log(`Address to load: ${byteToKey((home - (home % 100)) & 255)} ${byteToKey((home - (home % 100)) >> 8)}`);
		for (let i = 0; i < (home % 100); i++) {
			result.unshift(0);
		}
		// Would need keypairs module
		console.log('(keypairs.format not available)');
	} else if (args.target === 'overflow' && args.format === 'key') {
		console.log(result.map(x => byteToKey(x)).join(' '));
	} else {
		throw new Error('Unsupported target/format combination');
	}
}

function getRom(x) {
	const fs = require('fs');
	if (typeof x === 'string') {
		rom = fs.readFileSync(x);
	} else if (Buffer.isBuffer(x)) {
		rom = x;
	} else {
		throw new TypeError('ROM must be a file path (string) or Buffer');
	}
}

function findEquivalentAddresses(romData, q) {
	// handles BL / POP PC, BC AL, B
	const comefrom = {};

	for (let i = 0; i < romData.length - 1; i += 2) {
		// BC AL
		if (romData[i + 1] === 0xce) {
			let offset = romData[i];
			if (offset >= 128) offset -= 256;
			const target = (i >> 16) | (((i + (offset + 1) * 2) & 0xffff));
			if (!comefrom[target]) comefrom[target] = [];
			comefrom[target].push(i);
		}
	}

	for (let i = 0; i < romData.length - 3; i += 2) {
		// B
		if (romData[i] === 0x00 && (romData[i + 1] & 0xf0) === 0xf0) {
			const target = ((romData[i + 1] & 0x0f) << 16) | (romData[i + 3] << 8) | romData[i + 2];
			if (!comefrom[target]) comefrom[target] = [];
			comefrom[target].push(i);
		}
	}

	for (let i = 0; i < romData.length - 5; i += 2) {
		// BL / POP PC
		if (romData[i] === 0x01 && 
			(romData[i + 1] & 0xf0) === 0xf0 &&
			(romData[i + 4] & 0xf0) === 0x8e &&
			(romData[i + 5] & 0xf0) === 0xf2) {
			const target = ((romData[i + 1] & 0x0f) << 16) | (romData[i + 3] << 8) | romData[i + 2];
			if (!comefrom[target]) comefrom[target] = [];
			comefrom[target].push(i);
		}
	}

	const ans = new Set();
	const queue = new Set(q);
	while (queue.size > 0) {
		const adr = queue.values().next().value;
		queue.delete(adr);
		if (ans.has(adr)) continue;
		ans.add(adr);

		if (comefrom[adr]) {
			for (const addr of comefrom[adr]) {
				queue.add(addr);
			}
		}
	}

	return ans;
}

function optimizeGadgetF(romData, gadget) {
	if (gadget.length % 2 !== 0) throw new Error('Gadget length must be even');
	const q = new Set();

	// Find occurrences of gadget in rom
	for (let i = 0; i <= romData.length - gadget.length; i += 2) {
		let match = true;
		for (let j = 0; j < gadget.length; j++) {
			if (romData[i + j] !== gadget[j]) {
				match = false;
				break;
			}
		}
		if (match) q.add(i);
	}

	return findEquivalentAddresses(romData, q);
}

function optimizeGadget(gadget) {
	if (!rom) throw new Error('ROM not loaded');
	return optimizeGadgetF(rom, gadget);
}

function printAddresses(adrs, nPreview) {
	// Helper function for printing gadget addresses
	adrs = Array.from(adrs).map(optimizeAdrForNpress);
	const sorted = [...adrs].sort((a, b) => getNpressAdr(a) - getNpressAdr(b));

	for (const adr of sorted) {
		const keys = [adr & 0xff, (adr >> 8) & 0xff, 0x30 | (adr >> 16)]
			.map(byteToKey)
			.join(' ');
		console.log(`${adr.toString(16).padStart(5, '0')}  ${getNpressAdr(adr).toString().padStart(3)}    ${keys.padEnd(20)}`);

		let i = adr & 0xffffe;
		for (let p = 0; p < nPreview; p++) {
			if (i < disasm.length && disasm[i]) {
				console.log('    ' + disasm[i]);
			}
			i += 2;
			while (i < disasm.length && !disasm[i]) {
				i += 2;
			}
			if (i >= disasm.length) break;
		}
	}
}

// Export for use as module
if (typeof module !== 'undefined' && module.exports) {
	module.exports = {
		setFont,
		fromFont,
		toFont,
		setNpressArray,
		setSymbolrepr,
		byteToKey,
		getNpress,
		getNpressAdr,
		optimizeAdrForNpress,
		optimizeSumForNpress,
		note,
		canonicalize,
		delInlineComment,
		addCommand,
		getCommands,
		getDisassembly,
		readRenameList,
		sizeofRegister,
		process,
		processProgram,
		getRom,
		findEquivalentAddresses,
		optimizeGadgetF,
		optimizeGadget,
		printAddresses,
		getGlobals: () => ({
			font,
			fontAssoc,
			npress,
			symbolrepr,
			commands,
			datalabels,
			result,
			labels,
			adrOfCmds,
			home,
			disasm,
			rom,
			MAX_CALL_ADR
		})
	};
}
