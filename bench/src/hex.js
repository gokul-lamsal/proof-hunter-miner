export function decodeHex(value, bytes, name) {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]+$/.test(value)) {
    throw new Error(`${name} must be 0x-prefixed hexadecimal`);
  }
  if (value.length !== 2 + bytes * 2) {
    throw new Error(`${name} must be exactly ${bytes} bytes`);
  }

  const output = new Uint8Array(bytes);
  for (let index = 0; index < bytes; index += 1) {
    output[index] = Number.parseInt(value.slice(2 + index * 2, 4 + index * 2), 16);
  }
  return output;
}

export function encodeHex(value) {
  let output = "0x";
  for (const byte of value) {
    output += byte.toString(16).padStart(2, "0");
  }
  return output;
}

