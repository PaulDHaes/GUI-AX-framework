import React, { useState, useEffect } from "react";
import { fetchFleet } from "../services/axiomProvider";
import { FleetInstance } from "../types";
import {
  Server,
  Terminal,
  Trash2,
  Cpu,
  RefreshCw,
  Plus,
  Tag,
  Check,
  AlertCircle,
  Loader2,
  Filter,
} from "lucide-react";

const INSTANCE_DETAILS: Record<
  string,
  { vcpu: number; ram: string; cost: string; desc: string }
> = {
  "s-1vcpu-1gb": {
    vcpu: 1,
    ram: "1 GB",
    cost: "$0.009/hr",
    desc: "General Purpose",
  },
  "t3.micro": {
    vcpu: 2,
    ram: "1 GB",
    cost: "$0.0104/hr",
    desc: "Burstable Perf",
  },
  "g6-standard-1": {
    vcpu: 1,
    ram: "2 GB",
    cost: "$0.018/hr",
    desc: "Shared CPU",
  },
  Standard_B1s: {
    vcpu: 1,
    ram: "1 GB",
    cost: "$0.011/hr",
    desc: "Low Priority",
  },
};

const FleetManager = () => {
  const [instances, setInstances] = useState<FleetInstance[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [filterMode, setFilterMode] = useState<string>("managed"); // "managed", "all", or custom prefix

  useEffect(() => {
    loadData();
  }, [filterMode]);

  const loadData = async () => {
    setLoading(true);
    try {
      const data = await fetchFleet(filterMode);
      setInstances(data);
    } catch (error) {
      console.error("Failed to load fleet:", error);
      setInstances([]);
    }
    setLoading(false);
  };

  const activeCount = instances.filter((f) => f.status === "running").length;
  const idleCount = instances.filter((f) => f.status === "idle").length;
  const costPerHour = (instances.length * 0.04).toFixed(2); // Mock calculation

  const toggleSelectAll = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.checked) {
      setSelectedIds(new Set(instances.map((f) => f.id)));
    } else {
      setSelectedIds(new Set());
    }
  };

  const toggleSelect = (id: string) => {
    const newSet = new Set(selectedIds);
    if (newSet.has(id)) {
      newSet.delete(id);
    } else {
      newSet.add(id);
    }
    setSelectedIds(newSet);
  };

  const isAllSelected =
    instances.length > 0 && selectedIds.size === instances.length;
  const isIndeterminate =
    selectedIds.size > 0 && selectedIds.size < instances.length;

  const handleBulkAction = (action: string) => {
    console.log(
      `Executing ${action} on ${selectedIds.size} instances:`,
      Array.from(selectedIds),
    );
    if (
      confirm(
        `Are you sure you want to ${action} ${selectedIds.size} instances?`,
      )
    ) {
      setSelectedIds(new Set());
    }
  };

  if (loading) {
    return (
      <div className="flex h-96 items-center justify-center text-slate-500">
        <Loader2 className="w-8 h-8 animate-spin mr-2" />
        <span>Loading Fleet Status...</span>
      </div>
    );
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header with Quick Actions */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Server className="text-primary-500" />
            Fleet Management
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            Manage distributed scanning instances
          </p>
        </div>
        <div className="flex flex-wrap gap-2 items-center">
          {/* Filter Dropdown */}
          <div className="relative">
            <select
              value={filterMode}
              onChange={(e) => setFilterMode(e.target.value)}
              className="appearance-none bg-slate-800 hover:bg-slate-700 text-white border border-slate-600 px-3 py-2 pr-8 rounded-lg text-sm transition-colors cursor-pointer"
            >
              <option value="managed">AX Managed</option>
              <option value="all">All Instances</option>
            </select>
            <Filter className="w-4 h-4 absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none" />
          </div>
          <button
            onClick={loadData}
            className="bg-slate-800 hover:bg-slate-700 text-white border border-slate-600 px-3 py-2 rounded-lg flex items-center gap-2 text-sm transition-colors"
          >
            <RefreshCw className="w-4 h-4" /> Sync
          </button>
          <button className="bg-primary-600 hover:bg-primary-500 text-white px-3 py-2 rounded-lg flex items-center gap-2 text-sm font-medium transition-colors shadow-lg shadow-primary-900/20">
            <Plus className="w-4 h-4" /> Spin Up Fleet
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-slate-800 p-4 rounded-lg border border-slate-700">
          <p className="text-slate-500 text-xs font-mono mb-1">
            Total Instances
          </p>
          <p className="text-xl font-bold text-white">{instances.length}</p>
        </div>
        <div className="bg-slate-800 p-4 rounded-lg border border-slate-700">
          <p className="text-slate-500 text-xs font-mono mb-1">
            Active Scanners
          </p>
          <p className="text-xl font-bold text-emerald-400">{activeCount}</p>
        </div>
        <div className="bg-slate-800 p-4 rounded-lg border border-slate-700">
          <p className="text-slate-500 text-xs font-mono mb-1">Idle Agents</p>
          <p className="text-xl font-bold text-amber-400">{idleCount}</p>
        </div>
        <div className="bg-slate-800 p-4 rounded-lg border border-slate-700">
          <p className="text-slate-500 text-xs font-mono mb-1">Est. Cost</p>
          <p className="text-xl font-bold text-slate-200">
            ${costPerHour}
            <span className="text-sm font-normal text-slate-500">/hr</span>
          </p>
        </div>
      </div>

      {/* Bulk Actions Bar */}
      {selectedIds.size > 0 && (
        <div className="bg-primary-900/10 border border-primary-500/30 p-4 rounded-lg flex flex-col sm:flex-row justify-between items-center animate-fade-in gap-4">
          <div className="flex items-center gap-3 text-primary-200">
            <div className="bg-primary-500/20 p-2 rounded-full">
              <Check className="w-4 h-4 text-primary-400" />
            </div>
            <span className="font-medium">
              <span className="font-bold text-white">{selectedIds.size}</span>{" "}
              instances selected
            </span>
          </div>
          <div className="flex gap-3">
            <button
              onClick={() => handleBulkAction("restart")}
              className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-white text-xs font-medium rounded border border-slate-600 flex items-center gap-2 transition-colors"
            >
              <RefreshCw className="w-3 h-3" /> Restart Selected
            </button>
            <button
              onClick={() => handleBulkAction("tag")}
              className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-white text-xs font-medium rounded border border-slate-600 flex items-center gap-2 transition-colors"
            >
              <Tag className="w-3 h-3" /> Tag Selected
            </button>
            <div className="w-px bg-primary-500/30 mx-1"></div>
            <button
              onClick={() => handleBulkAction("terminate")}
              className="px-3 py-2 bg-red-500/10 hover:bg-red-500/20 text-white-400 text-xs font-medium rounded border border-red-500/30 flex items-center gap-2 transition-colors"
            >
              <Trash2 className="w-3 h-3" /> Terminate Selected
            </button>
          </div>
        </div>
      )}

      {/* Instance List */}
      <div className="bg-slate-800 rounded-lg border border-slate-700 overflow-hidden">
        <div className="p-4 border-b border-slate-700 flex justify-between items-center bg-slate-900/50">
          <h3 className="text-sm font-semibold text-white uppercase tracking-wider">
            Instance Inventory
          </h3>
          <div className="flex gap-2 text-xs">
            <span className="flex items-center gap-1 text-slate-400">
              <div className="w-2 h-2 rounded-full bg-emerald-500"></div>{" "}
              Running
            </span>
            <span className="flex items-center gap-1 text-slate-400 ml-2">
              <div className="w-2 h-2 rounded-full bg-amber-500"></div> Idle
            </span>
            <span className="flex items-center gap-1 text-slate-400 ml-2">
              <div className="w-2 h-2 rounded-full bg-blue-500"></div> Init
            </span>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left table-fixed">
            <thead className="bg-slate-900 text-slate-400 text-xs uppercase font-medium">
              <tr>
                <th className="px-6 py-4 w-12">
                  <div className="flex items-center">
                    <input
                      type="checkbox"
                      className="w-4 h-4 rounded border-slate-600 bg-slate-700 text-primary-600 focus:ring-primary-500 focus:ring-offset-slate-900 cursor-pointer"
                      checked={isAllSelected}
                      ref={(input) => {
                        if (input) input.indeterminate = isIndeterminate;
                      }}
                      onChange={toggleSelectAll}
                    />
                  </div>
                </th>
                <th className="px-6 py-4 w-1/4">Instance Name</th>
                <th className="px-6 py-4 w-1/6">Provider / Region</th>
                <th className="px-6 py-4 w-1/6">IP Address</th>
                <th className="px-6 py-4 w-1/6">Resources</th>
                <th className="px-6 py-4 w-1/8">Status</th>
                <th className="px-6 py-4 w-32 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700 text-sm">
              {instances.map((instance) => {
                const isSelected = selectedIds.has(instance.id);
                const details = INSTANCE_DETAILS[instance.instanceType] || {
                  vcpu: 0,
                  ram: "?",
                  cost: "?",
                  desc: "Unknown",
                };

                return (
                  <tr
                    key={instance.id}
                    className={`transition-colors group ${
                      isSelected
                        ? "bg-primary-900/5 hover:bg-primary-900/10"
                        : "hover:bg-slate-700/30"
                    }`}
                  >
                    <td className="px-6 py-4">
                      <div className="flex items-center">
                        <input
                          type="checkbox"
                          className="w-4 h-4 rounded border-slate-600 bg-slate-700 text-primary-600 focus:ring-primary-500 focus:ring-offset-slate-900 cursor-pointer"
                          checked={isSelected}
                          onChange={() => toggleSelect(instance.id)}
                        />
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="font-medium text-white flex items-center gap-2">
                        <Terminal
                          className={`w-4 h-4 ${
                            isSelected ? "text-primary-400" : "text-slate-500"
                          }`}
                        />
                        {instance.name}
                      </div>
                      {instance.currentTask && (
                        <div className="text-xs text-slate-500 mt-1 font-mono pl-6">
                          Running: {instance.currentTask}
                        </div>
                      )}
                    </td>
                    <td className="px-6 py-4">
                      <div className="text-slate-200">{instance.provider}</div>
                      <div className="text-xs text-slate-500">
                        {instance.region}
                      </div>
                    </td>
                    <td className="px-6 py-4 font-mono text-slate-400">
                      {instance.ip}
                    </td>
                    <td className="px-6 py-4">
                      <div className="relative group/tooltip flex items-center w-max">
                        <div className="flex items-center gap-1.5 text-slate-300 cursor-help border-b border-dotted border-slate-500 pb-0.5">
                          <Cpu className="w-3 h-3 text-slate-500" />
                          {instance.instanceType}
                        </div>

                        {/* Tooltip */}
                        <div className="absolute left-full top-1/2 -translate-y-1/2 ml-3 w-52 hidden group-hover/tooltip:block z-50 pointer-events-none">
                          <div className="bg-slate-900 border border-slate-600 rounded-lg p-3 relative">
                            {/* Arrow */}
                            <div className="w-2 h-2 bg-slate-900 border-l border-b border-slate-600 rotate-45 absolute -left-1 top-1/2 -translate-y-1/2"></div>

                            <div className="font-semibold text-white text-xs mb-2 border-b border-slate-800 pb-1 flex justify-between">
                              <span>{instance.instanceType}</span>
                              <span className="text-slate-500 font-normal">
                                {instance.provider}
                              </span>
                            </div>
                            <div className="grid grid-cols-2 gap-x-2 gap-y-1.5 text-[13px] text-slate-400">
                              <span>vCPUs:</span>{" "}
                              <span className="text-slate-200 text-right font-mono">
                                {details.vcpu}
                              </span>
                              <span>Memory:</span>{" "}
                              <span className="text-slate-200 text-right font-mono">
                                {details.ram}
                              </span>
                              <span>Cost:</span>{" "}
                              <span className="text-emerald-400 text-right font-mono">
                                {details.cost}
                              </span>
                              <div className="col-span-2 text-slate-500 italic mt-1 border-t border-slate-800 pt-1">
                                {details.desc}
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <span
                        className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium capitalize
                        ${
                          instance.status === "running"
                            ? "bg-emerald-500/10 text-emerald-500"
                            : instance.status === "idle"
                              ? "bg-amber-500/10 text-amber-500"
                              : instance.status === "initializing"
                                ? "bg-blue-500/10 text-blue-500"
                                : "bg-red-500/10 text-red-500"
                        }`}
                      >
                        {instance.status}
                      </span>
                      <div className="text-[13px] text-slate-600 mt-1 ml-1">
                        Up: {instance.uptime}
                      </div>
                    </td>
                    <td className="px-6 py-4 text-right">
                      <div className="flex justify-end gap-2 opacity-60 group-hover:opacity-100 transition-opacity">
                        <button
                          className="p-1.5 hover:bg-slate-700 rounded text-slate-400 hover:text-white"
                          title="SSH"
                        >
                          <Terminal className="w-4 h-4" />
                        </button>
                        <button
                          className="p-1.5 hover:bg-slate-700 rounded text-slate-400 hover:text-amber-400"
                          title="Restart"
                        >
                          <RefreshCw className="w-4 h-4" />
                        </button>
                        <button
                          className="p-1.5 hover:bg-slate-700 rounded text-slate-400 hover:text-red-400"
                          title="Terminate"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default FleetManager;
