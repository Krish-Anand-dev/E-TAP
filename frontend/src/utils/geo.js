// Use the same valid points for the dashboard, map and exported report.
export function hasCoordinates(point) {
  return Number.isFinite(point?.lat) && Math.abs(point.lat) <= 90
    && Number.isFinite(point?.lon) && Math.abs(point.lon) <= 180;
}

export function getGeoMapData(hops = [], geoPoints = []) {
  const route = Array.isArray(hops) ? hops : [];
  const useLegacy = route.length === 0;
  const located = route.filter((hop) => hasCoordinates(hop?.geo));
  const legacy = (Array.isArray(geoPoints) ? geoPoints : []).filter(hasCoordinates);
  const points = useLegacy ? legacy : located.map((hop) => ({ ...hop.geo, ip: hop.ip }));
  return {
    useLegacy, located, legacy, points,
    mapPoints: points.map((point) => [point.lat, point.lon]),
    pointCount: points.length,
  };
}

export function visibleProviders(providers = {}) {
  // Keep actual failures/disabled checks visible. An unused geo provider card
  // provides no location evidence and need not occupy a report panel.
  return Object.entries(providers).filter(([id, provider]) =>
    id !== 'ip_geolocation' || provider?.status !== 'not_needed');
}
