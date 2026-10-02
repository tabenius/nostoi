import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, copyFile, rm, stat } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { test } from 'node:test';

// Exercise the installed weval downloader itself with synthetic tar.xz releases.
// Copy it into an isolated directory so its executable cache cannot bypass the
// extraction and hostile fixtures cannot overwrite the real build-tool binary.
const require = createRequire(import.meta.url);
const weval = require.resolve('@bytecodealliance/weval');
const toolRequire = createRequire(weval);
const xz = toolRequire('@napi-rs/lzma/xz');

function archive(entries) {
  const blocks = [];
  for (const { name, type = '0', link = '', content = '' } of entries) {
    const data = Buffer.from(content);
    const header = Buffer.alloc(512);
    header.write(name, 0, 100);
    header.write('0000755\0', 100);
    header.write('0000000\0', 108);
    header.write('0000000\0', 116);
    header.write(data.length.toString(8).padStart(11, '0') + '\0', 124);
    header.write('00000000000\0', 136);
    header.fill(32, 148, 156);
    header.write(type, 156);
    header.write(link, 157, 100);
    header.write('ustar\0', 257);
    header.write('00', 263);
    const sum = header.reduce((a, b) => a + b, 0);
    header.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
    blocks.push(header, data, Buffer.alloc((512 - data.length % 512) % 512));
  }
  return Buffer.concat([...blocks, Buffer.alloc(1024)]);
}

test('weval release extraction preserves the executable and contains hostile links',
  { skip: process.platform !== 'linux' || process.arch !== 'x64' }, async (t) => {
    const cases = {
      normal: [{ name: 'release/weval', content: 'safe executable' }],
      traversal: [{ name: 'release/../outside/weval', content: 'escaped' }],
      hardlink: [{ name: 'release/weval', type: '1', link: '../outside/weval' }],
      symlinkChain: [
        { name: 'release/weval', type: '2', link: '../outside' },
        { name: 'release/weval/weval', type: '2', link: '..' },
        { name: 'release/weval/weval/weval', content: 'escaped' },
      ],
      duplicateSymlink: [
        { name: 'release/weval', type: '2', link: '../outside/weval' },
        { name: 'release/weval', content: 'escaped' },
      ],
    };
    for (const [name, entries] of Object.entries(cases)) {
      await t.test(name, async () => {
        const root = await mkdtemp(join(dirname(weval), '../weval-fixture-'));
        const originalFetch = globalThis.fetch;
        try {
          await mkdir(join(root, 'tool'));
          await mkdir(join(root, 'tool', 'outside'));
          const sentinel = join(root, 'tool', 'outside', 'weval');
          await writeFile(sentinel, 'untouched');
          await copyFile(weval, join(root, 'tool', 'index.mjs'));
          const compressed = await xz.compress(archive(entries));
          globalThis.fetch = async (url) => {
            assert.match(url, /weval\/releases\/download\/v0\.5\.0\/.*tar\.xz$/);
            return new Response(compressed);
          };
          const { default: getWeval } = await import(pathToFileURL(join(root, 'tool', 'index.mjs')));
          if (name === 'normal') {
            const binary = await getWeval();
            assert.equal(await readFile(binary, 'utf8'), 'safe executable');
            assert.ok((await stat(binary)).mode & 0o111);
          } else {
            // tar may either reject or skip hostile entries; containment is the contract.
            await getWeval().catch(() => {});
          }
          assert.equal(await readFile(sentinel, 'utf8'), 'untouched');
          assert.equal((await stat(sentinel)).nlink, 1, 'no hardlink to outside file');
        } finally {
          globalThis.fetch = originalFetch;
          await rm(root, { recursive: true, force: true });
        }
      });
    }
  });
