import React, { useEffect, useRef, useState, useMemo } from "react";
import * as d3 from "d3";
import * as topojson from "topojson-client";
import { Target } from "../types";

interface GeoMapProps {
  targets: Target[];
}

const GeoMap: React.FC<GeoMapProps> = ({ targets }) => {
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [worldData, setWorldData] = useState<any>(null);

  // Aggregate subdomains with geo data — only from WHOIS scans
  // Coordinates are averaged across all entries in each country group so the
  // dot always lands at the centroid, not a randomly-jittered position.
  const locations = useMemo(() => {
    const geoAgg: Record<string, any> = {};
    targets.forEach((t) => {
      const isWhois =
        t.programName === "WHOIS Scan" ||
        (t.sources || []).some((s: string) =>
          s.toLowerCase().startsWith("whois"),
        );
      if (!isWhois) return;
      (t.subdomains || []).forEach((s: any) => {
        if (s.geo) {
          const key = [s.geo.country, s.geo.state || "", s.geo.city || ""].join(
            "|",
          );
          if (!geoAgg[key]) {
            geoAgg[key] = {
              ...s.geo,
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
    // Average coordinates → dot lands at true country centroid
    return Object.values(geoAgg).map((d: any) => ({
      ...d,
      lat: d._latSum / d.count,
      lng: d._lngSum / d.count,
    }));
  }, [targets]);

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

    // Draw dots
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
      .attr("stroke", "#fff")
      .attr("stroke-width", 1)
      .style("cursor", "pointer");

    circles
      .append("title")
      .text(
        (d: any) =>
          `${d.count} asset${d.count > 1 ? "s" : ""} in ${d.city ? d.city + ", " : ""}${d.state ? d.state + ", " : ""}${d.country} (${d.hosts.slice(0, 5).join(", ")}${d.count > 5 ? ", ..." : ""})`,
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
      <div className="absolute top-4 left-[calc(100%/2-60px)] z-10 bg-dark-900/70 px-2.5 py-1 rounded border border-dark-700/60 text-[13px] font-mono text-dark-500 flex items-center gap-1.5">
        <span className="w-1.5 h-1.5 rounded-full bg-cyan-500/60 inline-block" />
        WHOIS data only
      </div>
      {locations.length === 0 && (
        <div className="absolute inset-0 flex flex-col items-center justify-center z-10 pointer-events-none">
          <p className="text-dark-500 text-sm font-mono">No WHOIS geo data</p>
          <p className="text-dark-600 text-xs mt-1">
            Import whois scan output to see dots on the map
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
        <div className="text-dark-600 text-[13px]">
          Scroll to zoom · Drag to pan
        </div>
      </div>
      <svg ref={svgRef} className="w-full h-[450px] block"></svg>
    </div>
  );
};

export default GeoMap;
