import React, { useEffect, useRef } from 'react';
import * as d3 from 'd3';
import { Target } from '../types';

interface TopologyGraphProps {
  target: Target;
}

const TopologyGraph: React.FC<TopologyGraphProps> = ({ target }) => {
  const svgRef = useRef<SVGSVGElement>(null);

  useEffect(() => {
    if (!svgRef.current) return;

    const width = 600;
    const height = 400;

    // Clear previous
    d3.select(svgRef.current).selectAll("*").remove();

    const svg = d3.select(svgRef.current)
      .attr("viewBox", `0 0 ${width} ${height}`)
      .style("background-color", "#0f172a") // Slate 900
      .style("border-radius", "0.5rem");

    // Prepare data
    // Root node: Domain
    const nodes: any[] = [{ id: target.domain, group: 1 }];
    const links: any[] = [];

    // Level 1: Subdomains
    target.subdomains.forEach((sub, i) => {
      nodes.push({ id: sub.hostname, group: 2, ip: sub.ip });
      links.push({ source: target.domain, target: sub.hostname });
      
      // Level 2: Ports (Simplified to avoid clutter, maybe just connect to IP node if we had one, but sticking to hostname)
      // sub.ports.forEach(p => {
      //   const portId = `${sub.hostname}:${p.port}`;
      //   nodes.push({ id: portId, group: 3 });
      //   links.push({ source: sub.hostname, target: portId });
      // });
    });

    const simulation = d3.forceSimulation(nodes)
      .force("link", d3.forceLink(links).id((d: any) => d.id).distance(100))
      .force("charge", d3.forceManyBody().strength(-300))
      .force("center", d3.forceCenter(width / 2, height / 2));

    const link = svg.append("g")
      .attr("stroke", "#475569") // Slate 600
      .attr("stroke-opacity", 0.6)
      .selectAll("line")
      .data(links)
      .join("line")
      .attr("stroke-width", 1.5);

    const node = svg.append("g")
      .attr("stroke", "#fff")
      .attr("stroke-width", 1.5)
      .selectAll("circle")
      .data(nodes)
      .join("circle")
      .attr("r", (d) => d.group === 1 ? 15 : 8)
      .attr("fill", (d) => d.group === 1 ? "#3b82f6" : "#10b981") // Blue for root, Green for Subs
      .call(d3.drag<any, any>()
        .on("start", dragstarted)
        .on("drag", dragged)
        .on("end", dragended));

    // Labels
    const text = svg.append("g")
      .selectAll("text")
      .data(nodes)
      .join("text")
      .text((d) => d.id)
      .attr("font-size", "10px")
      .attr("fill", "#cbd5e1") // Slate 300
      .attr("dx", 12)
      .attr("dy", 4);

    node.append("title").text((d) => d.id);

    simulation.on("tick", () => {
      link
        .attr("x1", (d: any) => d.source.x)
        .attr("y1", (d: any) => d.source.y)
        .attr("x2", (d: any) => d.target.x)
        .attr("y2", (d: any) => d.target.y);

      node
        .attr("cx", (d: any) => d.x)
        .attr("cy", (d: any) => d.y);
      
      text
        .attr("x", (d: any) => d.x)
        .attr("y", (d: any) => d.y);
    });

    function dragstarted(event: any) {
      if (!event.active) simulation.alphaTarget(0.3).restart();
      event.subject.fx = event.subject.x;
      event.subject.fy = event.subject.y;
    }

    function dragged(event: any) {
      event.subject.fx = event.x;
      event.subject.fy = event.y;
    }

    function dragended(event: any) {
      if (!event.active) simulation.alphaTarget(0);
      event.subject.fx = null;
      event.subject.fy = null;
    }

    return () => {
      simulation.stop();
    };
  }, [target]);

  return (
    <div className="w-full h-full flex flex-col items-center">
      <h3 className="text-slate-400 text-sm mb-2 font-mono uppercase tracking-wider">Infrastructure Topology</h3>
      <div className="border border-slate-700 rounded-lg overflow-hidden w-full">
        <svg ref={svgRef} className="w-full h-auto block"></svg>
      </div>
    </div>
  );
};

export default TopologyGraph;
