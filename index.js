const keccak256 = require('keccak256');
const sigUtil = require('eth-sig-util');
const utf8 = require('utf8');


const stripHexPrefix = (s) => {
	return s.substring(0, 2) === '0x' ? s.slice(2) : s;
};

const toChecksumAddress = (address, chainId = null) => {

	const stripAddress = stripHexPrefix(address).toLowerCase();
	const prefix = chainId != null ? chainId.toString() + '0x' : '';
	const keccakHash = keccak256(prefix + stripAddress).toString('hex').replace(/^0x/i, '');
	let checksumAddress = '0x';

	for (let i = 0; i < stripAddress.length; i++) {
		checksumAddress += parseInt(keccakHash[i], 16) >= 8 ? stripAddress[i].toUpperCase() : stripAddress[i];
	}

	return checksumAddress;
}

const isChecksumAddress = (address, chainId = null) => {

	const stripAddress = stripHexPrefix(address).toLowerCase();
	const prefix = chainId != null ? chainId.toString() + '0x' : '';
	const keccakHash = keccak256(prefix + stripAddress).toString('hex').replace(/^0x/i, '');

	for (let i = 0; i < stripAddress.length; i++) {
		let output = parseInt(keccakHash[i], 16) >= 8 ? stripAddress[i].toUpperCase() : stripAddress[i];
		if (stripHexPrefix(address)[i] !== output) {
			return false;
		}
	}

	return true;
}

const isAddress = (address) => {
	if (!/^(0x)?[0-9a-f]{40}$/i.test(address)) {
		return false;
	} else if (/^(0x)?[0-9a-f]{40}$/.test(address) || /^(0x)?[0-9A-F]{40}$/.test(address)) {
		return true;
	} else {
		return isChecksumAddress(address);
	}
};

const utf8ToHex = (str) => {

	let hex = '';

	str = utf8.encode(str);
	str = str.replace(/^(?:\u0000)*/,'');
	str = str.split('').reverse().join('');
	str = str.replace(/^(?:\u0000)*/,'');
	str = str.split('').reverse().join('');

	for (let i = 0; i < str.length; i++) {
		let code = str.charCodeAt(i);
		let n = code.toString(16);
		hex += n.length < 2 ? '0' + n : n;
	}

	return '0x' + hex;
};

const hexToUtf8 = (hex) => {

	let str = '';
	let code = 0;

	hex = hex.replace(/^0x/i,'');
	hex = hex.replace(/^(?:00)*/,'');
	hex = hex.split('').reverse().join('');
	hex = hex.replace(/^(?:00)*/,'');
	hex = hex.split('').reverse().join('');

	let l = hex.length;

	for (let i = 0; i < l; i += 2) {
		code = parseInt(hex.substr(i, 2), 16);
		str += String.fromCharCode(code);
	}

	return utf8.decode(str);
};

const zcut = (s) => {
	for (let i = 66; i >= 0; i--) {
		if (s[i - 1] !== '0') {
			return i % 2 === 0 ? s.substring(2, i) : s.substring(2, i + 1);
		}
	}
};

const utf8ToBytes32 = (utf8) => {
	const zeros = '0000000000000000000000000000000000000000000000000000000000000000';
	const hex = utf8ToHex(utf8);
	return hex + zeros.substring(0, 66 - hex.length);
};

const utf8ByteLength = (utf8) => {
	return utf8ToBytes32(utf8).length - 2;
};

const isAliasBytes32 = (alias) => {
	return utf8ByteLength(alias) <= 64;
};

const addressEqual = (a, b) => {
	return a.toLowerCase() === b.toLowerCase();
};

const getMessageUUID = (message) => {
	const { _params_ } = message;
	if (!_params_ || !_params_.sig) {
		throw Error('Invalid input: Must include \'_params_.sig\'');
	}
	return _params_.sig.substring(0, 40);
};

// As per EIP-712
const packData = (message, _domain = []) => {

	const EIP712Domain = [{ name: 'chainId', type: 'uint256' }];
	const domain = { chainId: 1 };

	for (let item of _domain) {
		domain[item.name] = item.value;
		EIP712Domain.push({
			name: item.name,
			type: item.type
		});
	}

	return {
		domain,
		message,
		primaryType: 'Message',
		types: {
			EIP712Domain,
			Message: Object.keys(message).map(name => {
				return { name, type: 'string' };
			}).sort((a, b) => {

				// Prevent verification from failing due to the
				// object properties being in a different order.
				// Sorting special chars is unstandardized, so
				// using the hex representation is a safer bet.
				const _a = utf8ToHex(a.name);
				const _b = utf8ToHex(b.name);
				return _a.localeCompare(_b);
			})
		}
	};
}

// Compute the address that signed data
const addressData = (data, signature, domain = []) => {

	let address;

	try { // Get Ethereum address that signed data

		const sig = signature.substring(0, 2) === '0x' ? signature : '0x' + signature;
		address = sigUtil.recoverTypedSignature({
			data: packData(data, domain),
			sig
		});

	} catch (decodeErr) {
		throw Error('Failed to recover signing address');
	}

	return address;
}

module.exports = {
	ZERO_ADDRESS: '0x0000000000000000000000000000000000000000',
	packData,
	addressData,
	hexToUtf8,
	utf8ToHex,
	isAddress,
	utf8ToBytes32,
	utf8ByteLength,
	isAliasBytes32,
	stripHexPrefix,
	addressEqual,
	isChecksumAddress,
	toChecksumAddress,
	zcut
};
