const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const operation = JSON.parse(fs.readFileSync(path.join(__dirname, 'multiplier-filter.json'), 'utf8'));
assert.equal(operation.args.keep, false);
const pattern = new RegExp(operation.args.regex[0].replace(/^\(\?i\)/, ''), 'i');
for (const name of ['香港 1x', '东京 0.2x', '美国 0.01x', '69YUN 香港 2x', 'MESL-日本 2.0X', 'LX-2.000倍', 'WWMM-BW', '日本 1.3x', '香港 1.03x', '×2', '倍率:2.000', '2.00×', '香港 02x']) {
  assert.equal(pattern.test(name), false, 'must preserve ' + name);
}
for (const name of ['香港 2.01x', '日本 2.5X', '美国 3x', '69YUN 日本 5x', '新加坡 12倍', '台湾 100x', '2.00001倍', '×2.5', '倍率：3', '倍率:2.01', '英国 03x', '2.1×']) {
  assert.equal(pattern.test(name), true, 'must remove ' + name);
}
console.log('PASS multiplier boundary: 2x allowed, all tested values above 2x excluded');
