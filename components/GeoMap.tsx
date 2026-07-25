import React, { useEffect, useRef, useState, useMemo } from "react";
import * as d3 from "d3";
import * as topojson from "topojson-client";
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
  const [worldData, setWorldData] = useState<any>(null);

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
          const key = [
            src,
            s.geo.country || "",
            s.geo.city || "",
          ].join("|");
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
        setOnlineAvailable(d.onlineAvailable !== false && getOnlineGeoEnabled());
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

  useEffect(() => {
    // Fetch world topology
    fetch("https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json")
      .then((response) => response.json())
      .then((data) => setWorldData(data))
      .catch((err) => console.error("Failed to load map data", err));
  }, []);

  useEffect(() => {
    if (!svgRef.current || !worldData || !containerRef.current) return;

    const width = containerRef.current.clientWidth;
    const height = 450;

    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();

    svg
      .attr("viewBox", `0 0 ${width} ${height}`)
      .style("background-color", "#0f172a");

    const projection = d3
      .geoMercator()
      .scale(width / 6.5)
      .translate([width / 2, height / 1.5]);

    const path = d3.geoPath().projection(projection);
    const g = svg.append("g");

    // Draw countries
    const countries = topojson.feature(worldData, worldData.objects.countries);
    g.selectAll("path")
      .data((countries as any).features)
      .enter()
      .append("path")
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

    // Draw dots — IP-located dots get a cyan ring, WHOIS a white ring
    const circles = g
      .selectAll("circle")
      .data(locations)
      .enter()
      .append("circle")
      .attr("cx", (d: any) => projection([d.lng, d.lat])?.[0] ?? 0)
      .attr("cy", (d: any) => projection([d.lng, d.lat])?.[1] ?? 0)
      .attr("r", (d: any) => baseR(d))
      .attr("fill", (d: any) => colorScale(d.count))
      .attr("fill-opacity", 0.85)
      .attr("stroke", (d: any) => (d.source === "ip" ? "#22d3ee" : "#fff"))
      .attr("stroke-width", 1)
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
        g.selectAll<SVGCircleElement, any>("circle")
          .attr("r", (d) => baseR(d) / k)
          .attr("stroke-width", 1 / k);
      });

    svg.call(zoom as any);
  }, [worldData, locations]);

  return (
    <div
      ref={containerRef}
      className="w-full relative rounded-lg overflow-hidden border border-dark-700 bg-dark-800"
    >
      <div className="absolute top-4 left-4 z-10 bg-dark-900/90 px-3 py-1 rounded border border-dark-700 text-xs font-mono text-dark-300">
        ASSET GEOLOCATION
      </div>

      {/* Source summary + enrich control */}
      <div className="absolute top-4 right-4 z-10 flex items-center gap-2">
        <div className="bg-dark-900/70 px-2.5 py-1 rounded border border-dark-700/60 text-[13px] font-mono text-dark-400 flex items-center gap-3">
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
            className="bg-cyan-600/80 hover:bg-cyan-600 disabled:opacity-50 disabled:cursor-not-allowed text-white text-xs font-mono px-3 py-1.5 rounded border border-cyan-500/60 transition-colors"
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
                ? "bg-dark-800/80 hover:bg-dark-700 border-dark-600 text-dark-200"
                : "bg-cyan-600/80 hover:bg-cyan-600 border-cyan-500/60 text-white") +
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
        <div className="absolute top-14 right-4 z-10 bg-dark-900/90 px-3 py-1.5 rounded border border-dark-700 text-[13px] font-mono text-cyan-300 max-w-xs">
          {enrichMsg}
        </div>
      )}

      {locations.length === 0 && (
        <div className="absolute inset-0 flex flex-col items-center justify-center z-10 pointer-events-none">
          <p className="text-dark-500 text-sm font-mono">No geo data yet</p>
          <p className="text-dark-600 text-xs mt-1 text-center px-6">
            Import WHOIS output for country-level dots, or{" "}
            {offlineAvailable
              ? 'click "Locate by IP" to geolocate resolved hosts offline'
              : 'click "Locate by IP (online)" to geolocate hosts via ip-api.com'}
          </p>
        </div>
      )}

      {/* Map Legend */}
      <div className="absolute bottom-4 right-4 z-10 bg-dark-900/90 px-3 py-2.5 rounded-lg border border-dark-700 text-xs font-mono select-none">
        <div className="text-dark-500 uppercase tracking-wider text-[13px] mb-2 font-semibold">
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
          <span className="text-dark-300">1 asset</span>
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
          <span className="text-dark-300">Multiple assets</span>
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
          <span className="text-dark-300">IP-located (cyan ring)</span>
        </div>
        <div className="text-dark-600 text-[13px]">
          Scroll to zoom · Drag to pan
        </div>
      </div>
      <svg ref={svgRef} className="w-full h-[450px] block"></svg>
    </div>
  );
};

export default GeoMap;
