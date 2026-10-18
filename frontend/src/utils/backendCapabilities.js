/** Optional hosted features are shown only when the connected API supports them. */
export function capabilitiesFromSpec(spec = {}) {
  const paths = spec.paths || {};
  const has = (path, method) => Boolean(paths[path]?.[method]);
  const investigationPath = Object.keys(paths).find(path => /^\/investigations\/\{[^}]+\}$/.test(path));
  const child = suffix => `${investigationPath || '/investigations/{email_id}'}/${suffix}`;
  return {
    storedReports: has('/investigations', 'get'),
    workspace: has('/analytics', 'get') && has('/baselines', 'get') && has('/baselines', 'put'),
    workflow: has('/recovery', 'get') && has(child('workflow'), 'get') && has(child('workflow'), 'patch')
      && has(child('related'), 'get') && has(child('feedback'), 'put') && has(child('case'), 'put'),
    retention: has('/preferences', 'put') && has(child('share'), 'get')
      && has(investigationPath, 'delete') && has('/investigations', 'delete'),
  };
}
