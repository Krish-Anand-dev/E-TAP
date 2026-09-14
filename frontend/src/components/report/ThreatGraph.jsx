import React, { useMemo, useRef, useState, useEffect } from 'react';
import ForceGraph2D from 'react-force-graph-2d';

export function ThreatGraph({
  emailId = 'email_0',
  correlation = {},
  iocs = {},
  threatIntel = {},
  graphDiffusion = {},
}) {
  const fgRef = useRef();
  const containerRef = useRef(null);
  const [dimensions, setDimensions] = useState({ width: 800, height: 400 });
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [activeNode, setActiveNode] = useState(null);
  const [diffusionLayerActive, setDiffusionLayerActive] = useState(false);

  const isDiffusionAvailable = Boolean(graphDiffusion && graphDiffusion.available);

  const graphData = useMemo(() => {
    const nodes = [];
    const links = [];

    // Root Email Node
    nodes.push({
      id: emailId,
      name: 'Current Email Artifact',
      type: 'email',
      val: 14,
      color: '#E8A23D', // Evidence Amber
    });

    // Campaign Node (if present)
    if (correlation.campaign_id) {
      nodes.push({
        id: correlation.campaign_id,
        name: `Campaign: ${correlation.campaign_id}`,
        type: 'campaign',
        val: 16,
        color: '#D9534F',
      });
      links.push({
        source: emailId,
        target: correlation.campaign_id,
        label: 'part of',
      });
    }

    // Related Emails
    (correlation.related_emails || []).forEach((relId) => {
      nodes.push({
        id: relId,
        name: `Related: ${relId.substring(0, 10)}...`,
        type: 'related_email',
        val: 9,
        color: '#8B92A5',
      });
      links.push({
        source: emailId,
        target: relId,
        label: 'correlates with',
      });
      if (correlation.campaign_id) {
        links.push({
          source: relId,
          target: correlation.campaign_id,
          label: 'campaign link',
        });
      }
    });

    // Shared Infrastructure Nodes
    (correlation.shared_infrastructure || []).forEach((infra) => {
      if (!nodes.some((n) => n.id === infra)) {
        nodes.push({
          id: infra,
          name: `Shared Infra: ${infra}`,
          type: 'shared_infra',
          val: 11,
          color: '#3B82F6',
        });
      }
      links.push({
        source: emailId,
        target: infra,
        label: 'shared infrastructure',
      });
      // Also link related emails to shared infrastructure
      (correlation.related_emails || []).forEach((relId) => {
        links.push({
          source: relId,
          target: infra,
          label: 'correlates with infra',
        });
      });
    });

    // Domains
    (iocs.domains || []).forEach((domain) => {
      nodes.push({
        id: domain,
        name: `Domain: ${domain}`,
        type: 'domain',
        val: 9,
        color: '#10B981',
      });
      links.push({
        source: emailId,
        target: domain,
        label: 'referenced domain',
      });
    });

    // IPs
    (iocs.ips || []).forEach((ip) => {
      nodes.push({
        id: ip,
        name: `IP: ${ip}`,
        type: 'ip',
        val: 10,
        color: '#EF4444',
      });
      links.push({
        source: emailId,
        target: ip,
        label: 'originating/relay IP',
      });
    });

    // Compute Graph Diffusion scores and colors
    const getNodeDiffusionScore = (nid) => {
      if (!graphDiffusion?.node_scores) return null;
      if (graphDiffusion.node_scores[nid] !== undefined) return graphDiffusion.node_scores[nid];
      if (graphDiffusion.node_scores[`ip_${nid}`] !== undefined) return graphDiffusion.node_scores[`ip_${nid}`];
      if (graphDiffusion.node_scores[`domain_${nid}`] !== undefined) return graphDiffusion.node_scores[`domain_${nid}`];
      if (graphDiffusion.node_scores[`url_${nid}`] !== undefined) return graphDiffusion.node_scores[`url_${nid}`];
      if (graphDiffusion.node_scores[`hash_${nid}`] !== undefined) return graphDiffusion.node_scores[`hash_${nid}`];
      if (graphDiffusion.node_scores[`infra_${nid}`] !== undefined) return graphDiffusion.node_scores[`infra_${nid}`];
      return null;
    };

    const getDiffusionColor = (score, defaultColor) => {
      if (!diffusionLayerActive || score === null || score === undefined) return defaultColor;
      if (score >= 0.7) return '#EF4444'; // high risk red
      if (score >= 0.3) return '#F59E0B'; // medium risk amber
      if (score > 0.05) return '#06B6D4'; // low risk cyan
      return '#475569'; // baseline slate
    };

    const contributingSeeds = new Set(graphDiffusion?.contributing_seeds || []);

    nodes.forEach((n) => {
      n.diffusionScore = getNodeDiffusionScore(n.id);
      n.color = getDiffusionColor(n.diffusionScore, n.color);
    });

    links.forEach((l) => {
      const sId = typeof l.source === 'object' ? l.source?.id : l.source;
      const tId = typeof l.target === 'object' ? l.target?.id : l.target;
      l.isDiffusionLink = contributingSeeds.has(sId) || contributingSeeds.has(tId) ||
        contributingSeeds.has(`ip_${sId}`) || contributingSeeds.has(`ip_${tId}`) ||
        contributingSeeds.has(`domain_${sId}`) || contributingSeeds.has(`domain_${tId}`);
    });

    return { nodes, links };
  }, [emailId, correlation, iocs, graphDiffusion, diffusionLayerActive]);

  // Measure container width and height dynamically via ResizeObserver
  useEffect(() => {
    if (!containerRef.current) return;

    const measure = () => {
      if (containerRef.current) {
        const rect = containerRef.current.getBoundingClientRect();
        const w = Math.floor(rect.width);
        const h = isFullscreen ? Math.floor(window.innerHeight - 90) : 400;
        if (w > 0) {
          setDimensions({ width: w, height: h });
        }
      }
    };

    measure();

    const ro = new ResizeObserver(() => measure());
    ro.observe(containerRef.current);
    window.addEventListener('resize', measure);

    return () => {
      ro.disconnect();
      window.removeEventListener('resize', measure);
    };
  }, [isFullscreen]);

  // Smooth re-center and fit whenever dimensions change
  useEffect(() => {
    const timer = setTimeout(() => {
      if (fgRef.current) {
        fgRef.current.zoomToFit(400, isFullscreen ? 60 : 30);
      }
    }, 150);
    return () => clearTimeout(timer);
  }, [dimensions.width, dimensions.height, isFullscreen, graphData]);

  // Lock document body scroll when fullscreen is active and listen for Escape key to exit
  useEffect(() => {
    if (isFullscreen) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = '';
    }

    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && isFullscreen) {
        setIsFullscreen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => {
      document.body.style.overflow = '';
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [isFullscreen]);

  const handleZoomIn = () => {
    if (fgRef.current) {
      fgRef.current.zoom(fgRef.current.zoom() * 1.35, 300);
    }
  };

  const handleZoomOut = () => {
    if (fgRef.current) {
      fgRef.current.zoom(fgRef.current.zoom() * 0.75, 300);
    }
  };

  const handleZoomReset = () => {
    if (fgRef.current) {
      fgRef.current.zoomToFit(400, isFullscreen ? 60 : 30);
    }
  };

  const toggleFullscreen = () => {
    setIsFullscreen((prev) => !prev);
  };

  return (
    <div
      className="forensic-panel"
      style={
        isFullscreen
          ? {
              position: 'fixed',
              top: 0,
              left: 0,
              width: '100vw',
              height: '100vh',
              zIndex: 99999,
              backgroundColor: 'var(--bg-base)',
              display: 'flex',
              flexDirection: 'column',
              padding: '16px 24px',
              boxSizing: 'border-box',
              overflow: 'hidden',
              margin: 0,
              borderRadius: 0,
              border: 'none',
            }
          : {}
      }
    >
      <div className="forensic-panel-header" style={{ marginBottom: '12px' }}>
        <div className="panel-title-group">
          <span className="panel-title">
            Infrastructure Threat &amp; Correlation Graph
            {isFullscreen && (
              <span
                style={{
                  marginLeft: '10px',
                  fontSize: 'var(--fs-micro)',
                  padding: '2px 8px',
                  backgroundColor: 'var(--bg-surface-elevated)',
                  border: '1px solid var(--border-hairline)',
                  borderRadius: 'var(--radius-xs)',
                  color: 'var(--accent-amber)',
                  fontFamily: 'var(--font-mono)',
                  letterSpacing: '0.05em',
                }}
              >
                FULLSCREEN MODE (ESC TO MINIMIZE)
              </span>
            )}
          </span>
          <span className="panel-subtitle">
            Stage F Adversary Network Clustered Topology &bull; {graphData.nodes.length} Nodes &bull; {graphData.links.length} Link Correlations
          </span>
        </div>

        <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
          {/* Legend */}
          <div style={{ display: 'flex', gap: '10px', alignItems: 'center', marginRight: '8px' }}>
            <span style={{ fontSize: 'var(--fs-micro)', color: '#E8A23D', fontFamily: 'var(--font-mono)' }}>
              ● Artifact
            </span>
            <span style={{ fontSize: 'var(--fs-micro)', color: '#EF4444', fontFamily: 'var(--font-mono)' }}>
              ● Threat IP
            </span>
            <span style={{ fontSize: 'var(--fs-micro)', color: '#10B981', fontFamily: 'var(--font-mono)' }}>
              ● Domain
            </span>
            <span style={{ fontSize: 'var(--fs-micro)', color: '#3B82F6', fontFamily: 'var(--font-mono)' }}>
              ● Infra
            </span>
            <span style={{ fontSize: 'var(--fs-micro)', color: '#8B92A5', fontFamily: 'var(--font-mono)' }}>
              ● Related
            </span>
          </div>

          {/* Zoom In Button */}
          <button
            type="button"
            className="btn-ghost"
            onClick={handleZoomIn}
            title="Zoom in graph"
            style={{ padding: '5px 10px', fontSize: 'var(--fs-xs)', fontFamily: 'var(--font-mono)' }}
          >
            +
          </button>

          {/* Zoom Out Button */}
          <button
            type="button"
            className="btn-ghost"
            onClick={handleZoomOut}
            title="Zoom out graph"
            style={{ padding: '5px 10px', fontSize: 'var(--fs-xs)', fontFamily: 'var(--font-mono)' }}
          >
            &minus;
          </button>

          {/* Reset / Fit View Button */}
          <button
            type="button"
            className="btn-ghost"
            onClick={handleZoomReset}
            title="Fit graph to canvas"
            style={{ padding: '5px 10px', fontSize: 'var(--fs-micro)', fontFamily: 'var(--font-mono)' }}
          >
            FIT
          </button>

          {/* Graph Diffusion Layer Toggle Button */}
          <button
            type="button"
            id="threat-graph-diffusion-toggle-btn"
            disabled={!isDiffusionAvailable}
            className={diffusionLayerActive ? 'btn-primary-action' : 'btn-ghost'}
            onClick={() => setDiffusionLayerActive((prev) => !prev)}
            title={
              isDiffusionAvailable
                ? (diffusionLayerActive ? 'Disable Graph Diffusion Layer' : 'Enable Graph Diffusion Layer (Stage F′)')
                : (graphDiffusion?.reason || 'Not enough correlated history yet')
            }
            style={{
              padding: '6px 14px',
              fontSize: 'var(--fs-micro)',
              fontFamily: 'var(--font-mono)',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              fontWeight: 600,
              opacity: isDiffusionAvailable ? 1 : 0.45,
              cursor: isDiffusionAvailable ? 'pointer' : 'not-allowed',
              backgroundColor: diffusionLayerActive ? 'rgba(16, 185, 129, 0.2)' : undefined,
              borderColor: diffusionLayerActive ? '#10B981' : undefined,
              color: diffusionLayerActive ? '#10B981' : undefined,
            }}
          >
            <span
              style={{
                display: 'inline-block',
                width: '7px',
                height: '7px',
                borderRadius: '50%',
                backgroundColor: diffusionLayerActive ? '#10B981' : '#8B92A5',
                boxShadow: diffusionLayerActive ? '0 0 8px #10B981' : 'none',
              }}
            />
            DIFFUSION LAYER
          </button>

          {/* Fullscreen / Minimize Toggle Button */}
          <button
            type="button"
            id="threat-graph-fullscreen-btn"
            className={isFullscreen ? 'btn-primary-action' : 'btn-ghost'}
            onClick={toggleFullscreen}
            style={{
              padding: '6px 14px',
              fontSize: 'var(--fs-micro)',
              fontFamily: 'var(--font-mono)',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              fontWeight: 600,
            }}
          >
            {isFullscreen ? (
              <>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                  <polyline points="4 14 10 14 10 20" />
                  <polyline points="20 10 14 10 14 4" />
                  <line x1="14" y1="10" x2="21" y2="3" />
                  <line x1="3" y1="21" x2="10" y2="14" />
                </svg>
                MINIMIZE (ESC)
              </>
            ) : (
              <>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                  <polyline points="15 3 21 3 21 9" />
                  <polyline points="9 21 3 21 3 15" />
                  <line x1="21" y1="3" x2="14" y2="10" />
                  <line x1="3" y1="21" x2="10" y2="14" />
                </svg>
                EXPAND FULLSCREEN
              </>
            )}
          </button>
        </div>
      </div>

      {/* Graph Diffusion Summary Banner (when available) */}
      {graphDiffusion?.available && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '8px',
            marginBottom: '10px',
            padding: '8px 14px',
            background: 'rgba(59, 130, 246, 0.08)',
            border: '1px solid rgba(59, 130, 246, 0.25)',
            borderRadius: 'var(--radius-xs)',
            fontSize: 'var(--fs-micro)',
            fontFamily: 'var(--font-mono)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
            <span style={{ color: '#60A5FA', fontWeight: 700, letterSpacing: '0.05em' }}>
              STAGE F′ GRAPH DIFFUSION SCORE:
            </span>
            <span
              style={{
                color: (graphDiffusion.diffusion_score || 0) >= 0.5 ? '#F87171' : '#34D399',
                fontWeight: 800,
                fontSize: '12px',
              }}
            >
              {Math.round((graphDiffusion.diffusion_score || 0) * 100)}% Risk
            </span>
            <span style={{ color: 'var(--text-muted)' }}>&bull; {graphDiffusion.explanation}</span>
          </div>
          <span style={{ color: '#93C5FD', fontSize: '10px' }}>
            {graphDiffusion.hops_used}-hop PageRank Diffusion &bull; {graphDiffusion.contributing_seeds?.length || 0} seed(s)
          </span>
        </div>
      )}

      {/* Graph Canvas Container with Dynamic Width */}
      <div
        ref={containerRef}
        style={{
          width: '100%',
          flex: isFullscreen ? 1 : 'none',
          height: isFullscreen ? 'calc(100vh - 100px)' : '400px',
          backgroundColor: '#12151C',
          border: '1px solid var(--border-hairline)',
          borderRadius: 'var(--radius-xs)',
          overflow: 'hidden',
          position: 'relative',
        }}
      >
        {/* Floating Active Node Detail Pill */}
        {activeNode && (
          <div
            style={{
              position: 'absolute',
              top: '12px',
              left: '12px',
              zIndex: 10,
              backgroundColor: 'rgba(18, 21, 28, 0.94)',
              border: `1px solid ${activeNode.color || 'var(--border-hairline)'}`,
              borderRadius: 'var(--radius-xs)',
              padding: '8px 14px',
              backdropFilter: 'blur(8px)',
              boxShadow: '0 4px 16px rgba(0,0,0,0.6)',
              display: 'flex',
              alignItems: 'center',
              gap: '12px',
              maxWidth: '85%',
            }}
          >
            <div style={{ width: '10px', height: '10px', borderRadius: '50%', backgroundColor: activeNode.color }} />
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontSize: 'var(--fs-micro)', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>
                  {activeNode.type || 'NODE'}
                </span>
                {activeNode.diffusionScore !== undefined && activeNode.diffusionScore !== null && (
                  <span
                    style={{
                      fontSize: '10px',
                      padding: '1px 6px',
                      borderRadius: '3px',
                      backgroundColor: activeNode.diffusionScore >= 0.5 ? 'rgba(239, 68, 68, 0.2)' : 'rgba(52, 211, 153, 0.2)',
                      color: activeNode.diffusionScore >= 0.5 ? '#F87171' : '#34D399',
                      fontFamily: 'var(--font-mono)',
                      fontWeight: 700,
                    }}
                  >
                    Diffusion Risk: {Math.round(activeNode.diffusionScore * 100)}%
                  </span>
                )}
              </div>
              <div style={{ fontSize: 'var(--fs-xs)', color: '#E8EAF0', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                {activeNode.name || activeNode.id}
              </div>
            </div>
            <button
              type="button"
              onClick={() => setActiveNode(null)}
              style={{
                background: 'none',
                border: 'none',
                color: 'var(--text-muted)',
                cursor: 'pointer',
                fontSize: '14px',
                marginLeft: '8px',
                padding: '2px 4px',
              }}
              title="Close inspect chip"
            >
              &times;
            </button>
          </div>
        )}

        <ForceGraph2D
          ref={fgRef}
          width={dimensions.width}
          height={dimensions.height}
          graphData={graphData}
          backgroundColor="#12151C"
          nodeColor={(node) => node.color}
          nodeRelSize={7}
          linkColor={(link) => (diffusionLayerActive && link.isDiffusionLink ? '#EF4444' : '#2A303C')}
          linkWidth={(link) => (diffusionLayerActive && link.isDiffusionLink ? 2.5 : 1.5)}
          linkDirectionalParticles={(link) => (diffusionLayerActive && link.isDiffusionLink ? 3 : 0)}
          linkDirectionalParticleSpeed={0.008}
          linkDirectionalArrowLength={3.5}
          linkDirectionalArrowRelPos={1}
          linkCurvature={0.12}
          onNodeHover={(node) => {
            if (node) setActiveNode(node);
          }}
          onNodeClick={(node) => {
            setActiveNode(node);
            if (fgRef.current) {
              fgRef.current.centerAt(node.x, node.y, 400);
            }
          }}
          nodeCanvasObject={(node, ctx, globalScale) => {
            const label = node.name || node.id;
            const fontSize = Math.max(9 / globalScale, 2.5);
            ctx.font = `${fontSize}px Inter, sans-serif`;

            // Draw Diffusion Halo & Score if active
            if (diffusionLayerActive && node.diffusionScore > 0.05) {
              const haloRadius = 7 + (node.diffusionScore * 10);
              
              // Draw filled aura
              ctx.beginPath();
              ctx.arc(node.x, node.y, haloRadius, 0, 2 * Math.PI, false);
              ctx.fillStyle = node.diffusionScore >= 0.7 ? 'rgba(239, 68, 68, 0.25)' // Red aura
                : node.diffusionScore >= 0.3 ? 'rgba(245, 158, 11, 0.25)' // Amber aura
                : 'rgba(6, 182, 212, 0.25)'; // Cyan aura
              ctx.fill();
              
              // Draw aura border
              ctx.strokeStyle = node.diffusionScore >= 0.7 ? 'rgba(239, 68, 68, 0.8)'
                : node.diffusionScore >= 0.3 ? 'rgba(245, 158, 11, 0.8)'
                : 'rgba(6, 182, 212, 0.8)';
              ctx.lineWidth = 1 / globalScale;
              ctx.stroke();

              // Draw percentage score above node
              ctx.textAlign = 'center';
              ctx.textBaseline = 'bottom';
              ctx.fillStyle = node.diffusionScore >= 0.7 ? '#F87171' 
                : node.diffusionScore >= 0.3 ? '#FBBF24' 
                : '#67E8F9';
              ctx.font = `bold ${Math.max(8 / globalScale, 2.5)}px monospace`;
              ctx.fillText(`${Math.round(node.diffusionScore * 100)}%`, node.x, node.y - haloRadius - 2);
            }

            // Node Circle
            ctx.beginPath();
            ctx.arc(node.x, node.y, activeNode?.id === node.id ? 8 : 6, 0, 2 * Math.PI, false);
            ctx.fillStyle = node.color;
            ctx.fill();

            // Active node halo glow
            if (activeNode?.id === node.id) {
              ctx.beginPath();
              ctx.arc(node.x, node.y, 11, 0, 2 * Math.PI, false);
              ctx.strokeStyle = node.color;
              ctx.lineWidth = 1.5 / globalScale;
              ctx.stroke();
            }

            // Label text below node
            ctx.textAlign = 'center';
            ctx.textBaseline = 'top';
            ctx.font = `${fontSize}px Inter, sans-serif`;
            ctx.fillStyle = '#E8EAF0';
            ctx.fillText(label, node.x, node.y + (activeNode?.id === node.id ? 10 : 8));
          }}
        />
      </div>
    </div>
  );
}

export default ThreatGraph;
