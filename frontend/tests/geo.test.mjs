import test from 'node:test';
import assert from 'node:assert/strict';
import { getGeoMapData, visibleProviders } from '../src/utils/geo.js';
import { generatePdfDocument } from '../src/utils/pdfGenerator.js';

test('empty and unusable locations do not produce a map or navigation count', () => {
  assert.equal(getGeoMapData().pointCount, 0);
  assert.equal(getGeoMapData([{ ip: '10.0.0.1', geo: null }]).pointCount, 0);
  const data = getGeoMapData([], [
    { ip: 'missing' }, { lat: null, lon: null }, { lat: '12', lon: '34' },
    { lat: NaN, lon: 0 }, { lat: 91, lon: 0 }, { lat: 0, lon: -181 },
  ]);
  assert.equal(data.pointCount, 0);
});

test('count, map and export use actual located hops even without a legacy geo array', () => {
  const hops = [
    { ip: '209.85.220.41', geo: { lat: 37.4, lon: -122.1, country: 'US' } },
    { ip: '10.0.0.1', geo: null },
  ];
  const data = getGeoMapData(hops);
  assert.equal(data.pointCount, 1);
  assert.deepEqual(data.mapPoints, [[37.4, -122.1]]);
  assert.equal(data.points[0].ip, '209.85.220.41');
  const pdf = generatePdfDocument({ headers: { hops }, threat_intel: {} }).output();
  assert.ok(pdf.includes('6. Mail-server IP Locations'));
  assert.ok(pdf.includes('209.85.220.41'));
  assert.ok(!pdf.includes('Triangulat'));
});

test('old reports can still map valid legacy coordinates, including zero', () => {
  const data = getGeoMapData([], [{ ip: 'example', lat: 0, lon: 0 }]);
  assert.equal(data.useLegacy, true);
  assert.deepEqual(data.mapPoints, [[0, 0]]);
});

test('unlocated route hops do not become an unrelated legacy location', () => {
  const data = getGeoMapData([{ ip: '10.0.0.1', geo: null }], [{ lat: 20, lon: 30 }]);
  assert.equal(data.pointCount, 0);
});

test('hide only the unused geolocation card; preserve failures and disabled coverage', () => {
  const providers = { ip_geolocation: { status: 'not_needed' }, virustotal: { status: 'not_needed' } };
  assert.deepEqual(visibleProviders(providers).map(([id]) => id), ['virustotal']);
  assert.equal(providers.ip_geolocation.status, 'not_needed');
  for (const status of ['available', 'partial', 'unavailable', 'timeout', 'disabled', 'unknown']) {
    assert.equal(visibleProviders({ ip_geolocation: { status } }).length, 1);
  }
});

test('PDF omits the location section without real coordinates', () => {
  const pdf = generatePdfDocument({ threat_intel: { geo: [{ ip: '10.0.0.1', lat: null, lon: null }] } }).output();
  assert.ok(!pdf.includes('6. Mail-server IP Locations'));
  assert.ok(!pdf.includes('Geographic Threat Origin'));
});
