import React, { useMemo } from 'react';
import { MapContainer, TileLayer, Marker, Popup } from 'react-leaflet';
import L from 'leaflet';

// Simple SVG icon for forensic map pins
const createPinIcon = (color = '#D9534F') => {
  return L.divIcon({
    className: 'custom-geo-pin',
    html: `<div style="
      width: 14px;
      height: 14px;
      background-color: ${color};
      border: 2px solid #12151C;
      border-radius: 50%;
      box-shadow: 0 0 8px ${color};
    "></div>`,
    iconSize: [14, 14],
    iconAnchor: [7, 7],
  });
};

export function GeoMap({ geoPoints = [] }) {
  // Filter valid points with lat and lon
  const validPoints = useMemo(() => {
    return geoPoints.filter(
      (p) => typeof p.lat === 'number' && typeof p.lon === 'number' && !isNaN(p.lat) && !isNaN(p.lon)
    );
  }, [geoPoints]);

  const center = validPoints.length > 0
    ? [validPoints[0].lat, validPoints[0].lon]
    : [20, 0]; // Default world view

  const zoom = validPoints.length > 0 ? 3 : 2;
  const pinIcon = useMemo(() => createPinIcon('#D9534F'), []);

  return (
    <div className="forensic-panel">
      <div className="forensic-panel-header">
        <div className="panel-title-group">
          <span className="panel-title">Geographic Threat Origin & Relay Footprint</span>
          <span className="panel-subtitle">Stage B2 GeoIP Triangulation</span>
        </div>
        <span className="rail-item-badge">{validPoints.length} Geocoded Points</span>
      </div>

      {validPoints.length === 0 ? (
        <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)', fontSize: 'var(--fs-xs)' }}>
          No geographic coordinates resolved for extracted IP addresses.
        </div>
      ) : (
        <div
          id="geo-map-capture-container"
          style={{
            width: '100%',
            height: '300px',
            borderRadius: 'var(--radius-xs)',
            overflow: 'hidden',
            border: '1px solid var(--border-hairline)',
          }}
        >
          <MapContainer
            center={center}
            zoom={zoom}
            scrollWheelZoom={false}
            style={{ width: '100%', height: '100%', backgroundColor: '#12151C' }}
          >
            {/* Esri World Dark Gray Canvas: keyless, dark, watermark-free map */}
            <TileLayer
              attribution='&copy; <a href="https://www.esri.com/">Esri</a>'
              url="https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}"
              maxZoom={16}
              crossOrigin="anonymous"
            />
            <TileLayer
              attribution='&copy; <a href="https://www.esri.com/">Esri</a>'
              url="https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Reference/MapServer/tile/{z}/{y}/{x}"
              maxZoom={16}
              crossOrigin="anonymous"
            />
            {validPoints.map((point, idx) => (
              <Marker key={idx} position={[point.lat, point.lon]} icon={pinIcon}>
                <Popup>
                  <div style={{ color: '#12151C', fontFamily: 'Inter, sans-serif', fontSize: '12px' }}>
                    <div style={{ fontWeight: 700 }}>{point.ip}</div>
                    <div>Country: {point.country || 'Unknown'}</div>
                    <div style={{ fontSize: '11px', color: '#555', fontFamily: 'JetBrains Mono' }}>
                      {point.lat.toFixed(4)}, {point.lon.toFixed(4)}
                    </div>
                  </div>
                </Popup>
              </Marker>
            ))}
          </MapContainer>
        </div>
      )}
    </div>
  );
}

export default GeoMap;
