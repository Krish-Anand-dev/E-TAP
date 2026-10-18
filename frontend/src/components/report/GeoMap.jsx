import React, { useMemo, useEffect } from 'react';
import { MapContainer, TileLayer, Marker, Popup, Polyline, useMap } from 'react-leaflet';
import L from 'leaflet';
import { getGeoMapData } from '../../utils/geo.js';

// Hop kinds -> colour + label. Provider relays are deliberately NOT red:
// they are infrastructure, not the sender.
const KIND = {
  origin:         { color: '#D9534F', label: 'Header origin candidate' },
  anonymizer:     { color: '#A78BFA', label: 'Tor / VPN / proxy exit' },
  provider_relay: { color: '#E0A800', label: 'Mail provider relay' },
  relay:          { color: '#5B9BD5', label: 'Relay' },
  private:        { color: '#6B7280', label: 'Internal / private' },
};

const pinIcon = (n, color, ring) =>
  L.divIcon({
    className: 'custom-geo-pin',
    html: `<div style="
      width:22px;height:22px;border-radius:50%;background:${color};
      border:2px solid ${ring ? '#fff' : '#12151C'};color:#12151C;
      font:700 11px/18px Inter,sans-serif;text-align:center;
      box-shadow:0 0 8px ${color}">${n}</div>`,
    iconSize: [22, 22],
    iconAnchor: [11, 11],
  });

function FitBounds({ points }) {
  const map = useMap();
  useEffect(() => {
    if (points.length > 1) map.fitBounds(points, { padding: [40, 40], maxZoom: 6 });
    else if (points.length === 1) map.setView(points[0], 4);
  }, [points, map]);
  return null;
}

const fmtDelay = (s) => (s == null ? '' : s < 0 ? `${s}s ⚠` : s < 120 ? `+${s}s` : `+${Math.round(s / 60)}m`);

function OriginBanner({ origin }) {
  if (!origin || origin.origin_kind === 'none' || !origin.origin_kind) return null;
  const masked = origin.origin_kind === 'provider_relay_only';
  const anon = origin.origin_kind === 'anonymizer_exit';
  const color = masked ? '#E0A800' : anon ? '#A78BFA' : '#D9534F';
  const title = masked
    ? `Only ${origin.origin_provider || 'mail provider'} infrastructure is visible`
    : anon
      ? 'Trail ends at an anonymizer'
      : origin.true_origin_ip
        ? `Header origin candidate: ${origin.true_origin_ip}`
        : 'Origin unresolved';
  return (
    <div style={{
      borderLeft: `3px solid ${color}`, background: 'rgba(255,255,255,0.03)',
      padding: '10px 12px', margin: '0 0 12px', fontSize: 'var(--fs-xs)', lineHeight: 1.5,
    }}>
      <div style={{ fontWeight: 700, color, marginBottom: 2 }}>{title}</div>
      <div style={{ color: 'var(--text-muted)' }}>{origin.explanation}</div>
      {origin.origin_source && (
        <div style={{ marginTop: 4, color: 'var(--text-muted)' }}>
          Source: <code>{origin.origin_source}</code> · Confidence: {origin.confidence}
        </div>
      )}
    </div>
  );
}

export function GeoMap({ hops = [], origin = null, geoPoints = [] }) {
  // Highlight a header candidate without claiming it identifies the person.
  const decorated = useMemo(
    () =>
      hops.map((h) => ({
        ...h,
        displayKind:
          origin?.origin_kind === 'sender_client' && h.ip === origin.true_origin_ip
            && !['provider_relay', 'anonymizer', 'private'].includes(h.kind) ? 'origin' : h.kind,
      })),
    [hops, origin],
  );

  const { located, legacy, useLegacy, pointCount, mapPoints } = useMemo(
    () => getGeoMapData(decorated, geoPoints), [decorated, geoPoints],
  );
  const path = mapPoints;

  if (pointCount === 0) return null;

  return (
    <div className="forensic-panel">
      <div className="forensic-panel-header">
        <div className="panel-title-group">
          <span className="panel-title">Mail-server IP Locations</span>
          <span className="panel-subtitle">Approximate network locations; these do not establish the sender's physical location.</span>
        </div>
        <span className="rail-item-badge">{pointCount} Geocoded</span>
      </div>

      {!useLegacy && <OriginBanner origin={origin} />}

      {(
        <div
          id="geo-map-capture-container"
          style={{ width: '100%', height: 320, borderRadius: 'var(--radius-xs)', overflow: 'hidden',
                   border: '1px solid var(--border-hairline)' }}
        >
          <MapContainer center={mapPoints[0]} zoom={3} scrollWheelZoom={false}
                        style={{ width: '100%', height: '100%', backgroundColor: '#12151C' }}>
            <TileLayer
              attribution='&copy; <a href="https://www.esri.com/">Esri</a>'
              url="https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}"
              maxZoom={16} crossOrigin="anonymous"
            />
            <TileLayer
              attribution='&copy; <a href="https://www.esri.com/">Esri</a>'
              url="https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Reference/MapServer/tile/{z}/{y}/{x}"
              maxZoom={16} crossOrigin="anonymous"
            />
            <FitBounds points={mapPoints} />

            {useLegacy
              ? legacy.map((p, i) => (
                  <Marker key={i} position={[p.lat, p.lon]} icon={pinIcon(i + 1, KIND.relay.color, false)}>
                    <Popup>{p.ip} · {p.country || 'Unknown'} · Approximate IP network location</Popup>
                  </Marker>
                ))
              : (
                <>
                  {path.length > 1 && (
                    <Polyline positions={path} pathOptions={{ color: '#9CA3AF', weight: 2, dashArray: '6 6', opacity: 0.8 }} />
                  )}
                  {located.map((h) => {
                    const k = KIND[h.displayKind] || KIND.relay;
                    return (
                      <Marker key={h.index} position={[h.geo.lat, h.geo.lon]}
                              icon={pinIcon(h.index + 1, k.color, h.displayKind === 'origin')}>
                        <Popup>
                          <div style={{ color: '#12151C', fontFamily: 'Inter, sans-serif', fontSize: 12 }}>
                            <div style={{ fontWeight: 700 }}>Hop {h.index + 1} · {h.ip}</div>
                            <div>{k.label}{h.provider ? ` (${h.provider})` : ''}</div>
                            <div>{h.from_host || h.from_helo || 'unknown host'} · {h.geo.country || '??'}</div>
                            {h.geo.org && <div style={{ color: '#555' }}>{h.geo.org}</div>}
                            {h.displayKind === 'provider_relay' && (
                              <div style={{ color: '#8a6d00', marginTop: 4 }}>
                                Provider data-centre location, not the sender's.
                              </div>
                            )}
                          </div>
                        </Popup>
                      </Marker>
                    );
                  })}
                </>
              )}
          </MapContainer>
        </div>
      )}

      <p style={{ color: 'var(--text-muted)', fontSize: 'var(--fs-xs)', marginTop: 10 }}>
        Mail-provider pins identify infrastructure. Lines connect observed hops in header order;
        they do not show a measured physical network path or a person's location.
      </p>

      {!useLegacy && decorated.length > 0 && (
        <div style={{ marginTop: 12, overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 'var(--fs-xs)' }}>
            <thead>
              <tr style={{ textAlign: 'left', color: 'var(--text-muted)' }}>
                <th style={{ padding: '4px 6px' }}>#</th>
                <th style={{ padding: '4px 6px' }}>Host</th>
                <th style={{ padding: '4px 6px' }}>IP</th>
                <th style={{ padding: '4px 6px' }}>Role</th>
                <th style={{ padding: '4px 6px' }}>Where</th>
                <th style={{ padding: '4px 6px' }}>Δt</th>
              </tr>
            </thead>
            <tbody>
              {decorated.map((h) => {
                const k = KIND[h.displayKind] || KIND.relay;
                return (
                  <tr key={h.index} style={{ borderTop: '1px solid var(--border-hairline)' }}>
                    <td style={{ padding: '4px 6px' }}>
                      <span style={{ display: 'inline-block', width: 8, height: 8, borderRadius: '50%', background: k.color, marginRight: 6 }} />
                      {h.index + 1}
                    </td>
                    <td style={{ padding: '4px 6px', wordBreak: 'break-all' }}>{h.from_host || h.from_helo || '—'}</td>
                    <td style={{ padding: '4px 6px', fontFamily: 'JetBrains Mono, monospace' }}>{h.ip || '—'}</td>
                    <td style={{ padding: '4px 6px' }}>{k.label}{h.provider ? ` · ${h.provider}` : ''}</td>
                    <td style={{ padding: '4px 6px' }}>
                      {h.geo ? `${h.geo.country || '??'}${h.geo.org ? ` · ${h.geo.org}` : ''}` : '—'}
                    </td>
                    <td style={{ padding: '4px 6px', color: h.out_of_order ? '#D9534F' : 'inherit' }}>{fmtDelay(h.delay_s)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default GeoMap;
