#!/usr/bin/env node
// Build NSIS-safe BMP-only ICO files from build/icon.png.
//
// NSIS (makensis) rejects an ICO when any image's dwBytesInRes is > 1MB
// ("invalid icon file size") and also chokes on PNG-compressed 256px
// images that many converters put in an .ico. The installer therefore
// gets only 16/32/48 BMP images. The app icon may also include 256.

"use strict";

const fs = require("fs");
const path = require("path");
const zlib = require("zlib");

const root = path.join(__dirname, "..");
const pngPath = path.join(root, "build", "icon.png");
const appIcoPath = path.join(root, "build", "icon.ico");
const installerIcoPath = path.join(root, "build", "installerIcon.ico");

function decodePng(buf) {
  if (buf.length < 24 || buf[0] !== 0x89 || buf.toString("ascii", 1, 4) !== "PNG") {
    throw new Error("not a PNG: " + pngPath);
  }
  let off = 8;
  let width = 0;
  let height = 0;
  let depth = 0;
  let colorType = 0;
  let palette = null;
  const idat = [];
  while (off + 12 <= buf.length) {
    const len = buf.readUInt32BE(off);
    const type = buf.toString("ascii", off + 4, off + 8);
    const chunk = buf.slice(off + 8, off + 8 + len);
    off += 12 + len;
    if (type === "IHDR") {
      width = chunk.readUInt32BE(0);
      height = chunk.readUInt32BE(4);
      depth = chunk[8];
      colorType = chunk[9];
    } else if (type === "PLTE") {
      palette = chunk;
    } else if (type === "IDAT") {
      idat.push(chunk);
    } else if (type === "IEND") {
      break;
    }
  }
  if (!width || !height) throw new Error("PNG missing IHDR");
  if (depth !== 8) throw new Error("PNG bit depth " + depth + " not supported");
  const inflated = zlib.inflateSync(Buffer.concat(idat));
  const bpp = colorType === 6 ? 4 : colorType === 2 ? 3 : colorType === 3 ? 1 : colorType === 4 ? 2 : 0;
  if (!bpp) throw new Error("PNG color type " + colorType + " not supported");
  const stride = 1 + width * bpp;
  if (inflated.length < stride * height) throw new Error("PNG IDAT too short");

  const rgba = Buffer.alloc(width * height * 4);
  let prev = Buffer.alloc(width * bpp);
  for (let y = 0; y < height; y++) {
    const filter = inflated[y * stride];
    const row = inflated.slice(y * stride + 1, y * stride + stride);
    const recon = Buffer.alloc(width * bpp);
    for (let i = 0; i < row.length; i++) {
      const a = i >= bpp ? recon[i - bpp] : 0;
      const b = prev[i];
      const c = i >= bpp ? prev[i - bpp] : 0;
      let v = row[i];
      if (filter === 1) v = (v + a) & 255;
      else if (filter === 2) v = (v + b) & 255;
      else if (filter === 3) v = (v + Math.floor((a + b) / 2)) & 255;
      else if (filter === 4) {
        const p = a + b - c;
        const pa = Math.abs(p - a);
        const pb = Math.abs(p - b);
        const pc = Math.abs(p - c);
        const pr = pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
        v = (v + pr) & 255;
      } else if (filter !== 0) {
        throw new Error("PNG filter " + filter + " not supported");
      }
      recon[i] = v;
    }
    prev = recon;
    for (let x = 0; x < width; x++) {
      const dst = (y * width + x) * 4;
      if (colorType === 6) {
        recon.copy(rgba, dst, x * 4, x * 4 + 4);
      } else if (colorType === 2) {
        rgba[dst] = recon[x * 3];
        rgba[dst + 1] = recon[x * 3 + 1];
        rgba[dst + 2] = recon[x * 3 + 2];
        rgba[dst + 3] = 255;
      } else if (colorType === 4) {
        rgba[dst] = recon[x * 2];
        rgba[dst + 1] = recon[x * 2];
        rgba[dst + 2] = recon[x * 2];
        rgba[dst + 3] = recon[x * 2 + 1];
      } else {
        const pi = recon[x] * 3;
        rgba[dst] = palette[pi];
        rgba[dst + 1] = palette[pi + 1];
        rgba[dst + 2] = palette[pi + 2];
        rgba[dst + 3] = 255;
      }
    }
  }
  return { width, height, rgba };
}

function scaleRgba(src, size) {
  const out = Buffer.alloc(size * size * 4);
  for (let y = 0; y < size; y++) {
    const sy = Math.min(src.height - 1, Math.floor((y + 0.5) * src.height / size));
    for (let x = 0; x < size; x++) {
      const sx = Math.min(src.width - 1, Math.floor((x + 0.5) * src.width / size));
      src.rgba.copy(out, (y * size + x) * 4, (sy * src.width + sx) * 4, (sy * src.width + sx) * 4 + 4);
    }
  }
  return out;
}

function makeDib(rgba, size) {
  const xor = Buffer.alloc(size * size * 4);
  for (let y = 0; y < size; y++) {
    const srcY = size - 1 - y;
    for (let x = 0; x < size; x++) {
      const s = (srcY * size + x) * 4;
      const d = (y * size + x) * 4;
      xor[d] = rgba[s + 2];
      xor[d + 1] = rgba[s + 1];
      xor[d + 2] = rgba[s];
      xor[d + 3] = rgba[s + 3];
    }
  }
  const maskStride = Math.ceil(size / 32) * 4;
  const and = Buffer.alloc(maskStride * size);
  for (let y = 0; y < size; y++) {
    const srcY = size - 1 - y;
    for (let x = 0; x < size; x++) {
      if (rgba[(srcY * size + x) * 4 + 3] >= 128) continue;
      const bit = 7 - (x % 8);
      and[y * maskStride + Math.floor(x / 8)] |= 1 << bit;
    }
  }
  const header = Buffer.alloc(40);
  header.writeUInt32LE(40, 0);
  header.writeInt32LE(size, 4);
  header.writeInt32LE(size * 2, 8);
  header.writeUInt16LE(1, 12);
  header.writeUInt16LE(32, 14);
  header.writeUInt32LE(xor.length + and.length, 20);
  return Buffer.concat([header, xor, and]);
}

function writeIco(filePath, sizes, src) {
  const images = sizes.map((s) => makeDib(scaleRgba(src, s), s));
  let offset = 6 + 16 * sizes.length;
  const dir = Buffer.alloc(offset);
  dir.writeUInt16LE(0, 0);
  dir.writeUInt16LE(1, 2);
  dir.writeUInt16LE(sizes.length, 4);
  for (let i = 0; i < sizes.length; i++) {
    const o = 6 + i * 16;
    const s = sizes[i];
    dir[o] = s >= 256 ? 0 : s;
    dir[o + 1] = s >= 256 ? 0 : s;
    dir.writeUInt16LE(1, o + 4);
    dir.writeUInt16LE(32, o + 6);
    dir.writeUInt32LE(images[i].length, o + 8);
    dir.writeUInt32LE(offset, o + 12);
    offset += images[i].length;
  }
  fs.writeFileSync(filePath, Buffer.concat([dir].concat(images)));
  const max = Math.max.apply(null, images.map((im) => im.length));
  if (max > 1048576) {
    throw new Error(filePath + " has an image of " + max + " bytes; NSIS rejects anything over 1MB");
  }
  console.log("Wrote " + filePath + " (" + fs.statSync(filePath).size + " bytes, max image " + max + ")");
}

const png = decodePng(fs.readFileSync(pngPath));
writeIco(appIcoPath, [16, 24, 32, 48, 64, 256], png);
writeIco(installerIcoPath, [16, 32, 48], png);
