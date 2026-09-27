import React, { useEffect, useRef, useState, useMemo } from "react";
import * as d3 from "d3";
import * as topojson from "topojson-client";
// Bundled locally (not fetched from a CDN) so the map renders with no outbound network access
import worldTopology from "world-atlas/countries-110m.json";
import { Target } from "../types";
import { getOnlineGeoEnabled } from "../services/prefs";

interface GeoMapProps {
  targets: Target[];
  /** Called after a successful IP-geolocation enrichment so the parent can refetch. */
  onEnriched?: () => void;
  apiUrl?: string;
}

const GeoMap: React.FC<GeoMapProps> = ({
  targets,
  onEnriched,
  apiUrl = "http://localhost:5000",
}) => {
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [containerWidth, setContainerWidth] = useState(0);

  // IP-geolocation provider availability + enrichment state
  const [offlineAvailable, setOfflineAvailable] = useState<boolean>(false);
  const [onlineAvailable, setOnlineAvailable] = useState<boolean>(true);
  const [enriching, setEnriching] = useState<null | "offline" | "online">(null);
  const [enrichMsg, setEnrichMsg] = useState<string | null>(null);

  // Aggregate every subdomain that has geo data — WHOIS (country centroid) AND
  // IP-based (MaxMind city-level). The group key includes the source so a WHOIS
  // country dot and a precise IP city dot never merge into one.
  const { locations, sourceCounts } = useMemo(() => {
    const geoAgg: Record<string, any> = {};
    const srcCounts = { whois: 0, ip: 0 };
    targets.forEach((t) => {
      (t.subdomains || []).forEach((s: any) => {
        if (s.geo && typeof s.geo.lat === "number") {
          const src = s.geo.source || "whois";
          srcCounts[src as "whois" | "ip"] =
            (srcCounts[src as "whois" | "ip"] || 0) + 1;
          const key = [src, s.geo.country || "", s.geo.city || ""].join("|");
          if (!geoAgg[key]) {
            geoAgg[key] = {
              ...s.geo,
              source: src,
              count: 0,
              hosts: [],
              targetDomain: t.domain,
              _latSum: 0,
              _lngSum: 0,
            };
          }
          geoAgg[key].count++;
          geoAgg[key]._latSum += s.geo.lat;
          geoAgg[key]._lngSum += s.geo.lng;
          geoAgg[key].hosts.push(s.hostname);
        }
      });
    });
    const locs = Object.values(geoAgg).map((d: any) => ({
      ...d,
      lat: d._latSum / d.count,
      lng: d._lngSum / d.count,
    }));
    return { locations: locs, sourceCounts: srcCounts };
  }, [targets]);

  // Check which geolocation providers the bridge can use
  useEffect(() => {
    fetch(`${apiUrl}/api/geo/status`)
      .then((r) => r.json())
      .then((d) => {
        setOfflineAvailable(Boolean(d.offlineAvailable ?? d.available));
        // Online provider is offered only if the bridge allows it AND the user
        // hasn't disabled it in Settings (privacy opt-out).
        setOnlineAvailable(
          d.onlineAvailable !== false && getOnlineGeoEnabled(),
        );
      })
      .catch(() => {
        setOfflineAvailable(false);
        setOnlineAvailable(getOnlineGeoEnabled());
      });
  }, [apiUrl]);

  const runEnrich = async (provider: "offline" | "online") => {
    setEnriching(provider);
    setEnrichMsg(null);
    try {
      const res = await fetch(`${apiUrl}/api/geo/enrich`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ doDns: true, provider }),
      });
      const data = await res.json();
      if (!res.ok) {
        setEnrichMsg(data.error || "Enrichment failed");
      } else {
        const via = provider === "online" ? " (ip-api.com)" : "";
        setEnrichMsg(
          `Located ${data.located} host${data.located === 1 ? "" : "s"}${via}` +
            (data.resolved ? ` · resolved ${data.resolved} via DNS` : ""),
        );
        if (data.located || data.resolved) onEnriched?.();
      }
    } catch (e: any) {
      setEnrichMsg(`Enrichment error: ${e?.message || e}`);
    } finally {
      setEnriching(null);
    }
  };

  // Track container size so the map always has something to draw into, even before
  // layout has settled on first mount, and redraws on window/panel resize.
  useEffect(() => {
    if (!containerRef.current) return;
    const el = containerRef.current;
    const update = () => setContainerWidth(el.clientWidth);
    update();
    const observer = new ResizeObserver(update);
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    if (!svgRef.current || !containerRef.current) return;

    const width = containerWidth || containerRef.current.clientWidth || 600;
    const height = 480;

    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();

    svg.attr("viewBox", `0 0 ${width} ${height}`);

    // Ocean: radial gradient instead of a flat fill, plus a soft glow filter for the dots
    const defs = svg.append("defs");
    const ocean = defs
      .append("radialGradient")
      .attr("id", "ocean-gradient")
      .attr("cx", "50%")
      .attr("cy", "38%")
      .attr("r", "75%");
    ocean.append("stop").attr("offset", "0%").attr("stop-color", "#16213b");
    ocean.append("stop").attr("offset", "100%").attr("stop-color", "#0a0f1e");

    const glow = defs
      .append("filter")
      .attr("id", "geo-dot-glow")
      .attr("x", "-100%")
      .attr("y", "-100%")
      .attr("width", "300%")
      .attr("height", "300%");
    glow
      .append("feGaussianBlur")
      .attr("stdDeviation", "3")
      .attr("result", "blur");
    const glowMerge = glow.append("feMerge");
    glowMerge.append("feMergeNode").attr("in", "blur");
    glowMerge.append("feMergeNode").attr("in", "SourceGraphic");

    svg
      .append("rect")
      .attr("width", width)
      .attr("height", height)
      .attr("fill", "url(#ocean-gradient)");

    const projection = d3
      .geoMercator()
      .scale(width / 6.5)
      .translate([width / 2, height / 1.5]);

    const path = d3.geoPath().projection(projection);
    const g = svg.append("g");

    // Faint lat/long graticule for a techy "satellite overlay" feel
    const graticule = d3.geoGraticule();
    g.append("path")
      .datum(graticule())
      .attr("d", path as any)
      .attr("fill", "none")
      .attr("stroke", "#1e293b")
      .attr("stroke-width", 0.4)
      .attr("stroke-dasharray", "1,2.5");

    // Draw countries — topology is bundled locally, so this is always available
    const countries = topojson.feature(
      worldTopology as any,
      (worldTopology as any).objects.countries,
    );
    g.selectAll("path.country")
      .data((countries as any).features)
      .enter()
      .append("path")
      .attr("class", "country")
      .attr("d", path as any)
      .attr("fill", "#1e293b")
      .attr("stroke", "#334155")
      .attr("stroke-width", 0.5);

    // Color scale: green (few) → yellow → red (many)
    const maxCount = Math.max(1, ...locations.map((d: any) => d.count));
    const colorScale = d3
      .scaleSequential((t) =>
        d3.interpolateRgbBasis(["#10b981", "#f59e0b", "#ef4444"])(t),
      )
      .domain([1, maxCount]);

    // Base visual radius in screen-space pixels (before zoom)
    const baseR = (d: any) => Math.min(16, 4 + Math.sqrt(d.count) * 2);

    // Radar-style pulsing ring behind each dot
    g.selectAll("circle.geo-pulse-ring")
      .data(locations)
      .enter()
      .append("circle")
      .attr("class", "geo-pulse-ring")
      .attr("cx", (d: any) => projection([d.lng, d.lat])?.[0] ?? 0)
      .attr("cy", (d: any) => projection([d.lng, d.lat])?.[1] ?? 0)
      .attr("r", (d: any) => baseR(d))
      .attr("fill", "none")
      .attr("stroke", (d: any) => colorScale(d.count))
      .attr("stroke-width", 1.5)
      .style("animation-delay", () => `${Math.random() * 2.4}s`);

    // Draw dots — IP-located dots get a cyan ring, WHOIS a white ring
    const circles = g
      .selectAll("circle.geo-dot")
      .data(locations)
      .enter()
      .append("circle")
      .attr("class", "geo-dot")
      .attr("cx", (d: any) => projection([d.lng, d.lat])?.[0] ?? 0)
      .attr("cy", (d: any) => projection([d.lng, d.lat])?.[1] ?? 0)
      .attr("r", (d: any) => baseR(d))
      .attr("fill", (d: any) => colorScale(d.count))
      .attr("fill-opacity", 0.9)
      .attr("stroke", (d: any) => (d.source === "ip" ? "#22d3ee" : "#fff"))
      .attr("stroke-width", 1)
      .attr("filter", "url(#geo-dot-glow)")
      .style("cursor", "pointer");

    circles
      .append("title")
      .text(
        (d: any) =>
          `${d.count} asset${d.count > 1 ? "s" : ""} in ${d.city ? d.city + ", " : ""}${d.country} ` +
          `[${d.source === "ip" ? "IP geo" : "WHOIS"}] ` +
          `(${d.hosts.slice(0, 5).join(", ")}${d.count > 5 ? ", ..." : ""})`,
      );

    // Zoom: keep dots at constant screen size by inverting the scale factor
    const zoom = d3
      .zoom()
      .scaleExtent([1, 8])
      .on("zoom", (event) => {
        g.attr("transform", event.transform);
        const k = event.transform.k;
        g.selectAll<SVGCircleElement, any>("circle.geo-dot")
          .attr("r", (d) => baseR(d) / k)
          .attr("stroke-width", 1 / k);
        g.selectAll<SVGCircleElement, any>("circle.geo-pulse-ring")
          .attr("r", (d) => baseR(d) / k)
          .attr("stroke-width", 1.5 / k);
      });

    svg.call(zoom as any);
  }, [locations, containerWidth]);

  return (
    <div
      ref={containerRef}
      className="w-full relative rounded-lg overflow-hidden border border-cyan-500/20 bg-card map-ambient-glow"
    >
      <div className="absolute top-4 left-4 z-10 bg-background/90 px-3 py-1 rounded border border-border text-xs font-mono text-muted-foreground">
        ASSET GEOLOCATION
      </div>

      {/* Source summary + enrich control */}
      <div className="absolute top-4 right-4 z-10 flex items-center gap-2">
        <div className="bg-background/70 px-2.5 py-1 rounded border border-border/60 text-[13px] font-mono text-muted-foreground flex items-center gap-3">
          <span className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-white inline-block" />
            WHOIS {sourceCounts.whois}
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 inline-block" />
            IP {sourceCounts.ip}
          </span>
        </div>
        {offlineAvailable && (
          <button
            onClick={() => runEnrich("offline")}
            disabled={enriching !== null}
            title="Resolve hosts and geolocate their IPs offline (MaxMind GeoLite2) — no IPs leave your machine"
            className="bg-cyan-600/80 hover:bg-cyan-600 disabled:opacity-50 disabled:cursor-not-allowed text-foreground text-xs font-mono px-3 py-1.5 rounded border border-cyan-500/60 transition-colors"
          >
            {enriching === "offline" ? "Locating…" : "Locate by IP"}
          </button>
        )}
        {onlineAvailable && (
          <button
            onClick={() => runEnrich("online")}
            disabled={enriching !== null}
            title="Geolocate host IPs via ip-api.com — no signup, but your target IPs are sent to a third-party service"
            className={
              (offlineAvailable
                ? "bg-card/80 hover:bg-secondary border-border text-muted-foreground"
                : "bg-cyan-600/80 hover:bg-cyan-600 border-cyan-500/60 text-foreground") +
              " disabled:opacity-50 disabled:cursor-not-allowed text-xs font-mono px-3 py-1.5 rounded border transition-colors"
            }
          >
            {enriching === "online"
              ? "Locating…"
              : offlineAvailable
                ? "Online ↗"
                : "Locate by IP (online) ↗"}
          </button>
        )}
      </div>

      {enrichMsg && (
        <div className="absolute top-14 right-4 z-10 bg-background/90 px-3 py-1.5 rounded border border-border text-[13px] font-mono text-cyan-300 max-w-xs">
          {enrichMsg}
        </div>
      )}

      {locations.length === 0 && (
        <div className="absolute inset-0 flex flex-col items-center justify-center z-10 pointer-events-none">
          <p className="text-muted-foreground text-sm font-mono">No geo data yet</p>
          <p className="text-muted-foreground text-xs mt-1 text-center px-6">
            Import WHOIS output for country-level dots, or{" "}
            {offlineAvailable
              ? 'click "Locate by IP" to geolocate resolved hosts offline'
              : 'click "Locate by IP (online)" to geolocate hosts via ip-api.com'}
          </p>
        </div>
      )}

      {/* Map Legend */}
      <div className="absolute bottom-4 right-4 z-10 bg-background/90 px-3 py-2.5 rounded-lg border border-border text-xs font-mono select-none">
        <div className="text-muted-foreground uppercase tracking-wider text-[13px] mb-2 font-semibold">
          Legend
        </div>
        <div className="flex items-center gap-2 mb-1.5">
          <svg width="12" height="12" viewBox="0 0 12 12">
            <circle
              cx="6"
              cy="6"
              r="4"
              fill="#10b981"
              fillOpacity="0.7"
              stroke="#fff"
              strokeWidth="1"
            />
          </svg>
          <span className="text-muted-foreground">1 asset</span>
        </div>
        <div className="flex items-center gap-2 mb-2">
          <svg width="18" height="18" viewBox="0 0 18 18">
            <circle
              cx="9"
              cy="9"
              r="8"
              fill="#10b981"
              fillOpacity="0.7"
              stroke="#fff"
              strokeWidth="1"
            />
          </svg>
          <span className="text-muted-foreground">Multiple assets</span>
        </div>
        <div className="flex items-center gap-2 mb-2">
          <svg width="12" height="12" viewBox="0 0 12 12">
            <circle
              cx="6"
              cy="6"
              r="4"
              fill="#64748b"
              fillOpacity="0.7"
              stroke="#22d3ee"
              strokeWidth="1.5"
            />
          </svg>
          <span className="text-muted-foreground">IP-located (cyan ring)</span>
        </div>
        <div className="text-muted-foreground text-[13px]">
          Scroll to zoom · Drag to pan
        </div>
      </div>
      <svg ref={svgRef} className="w-full h-[480px] block"></svg>
    </div>
  );
};

export default GeoMap;
