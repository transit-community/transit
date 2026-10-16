import { useQuery } from "@tanstack/react-query";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useEffect, useRef, useState } from "react";
import { Panel, PanelGroup, PanelResizeHandle } from "react-resizable-panels";

import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  ANALYSIS,
  bytesHuman,
  durationHuman,
  pcapConversations,
  pcapFindings,
  pcapOverview,
  pcapPacketBytes,
  pcapPacketDetail,
  pcapProtocolTree,
  pcapRows,
  pcapValidateFilter,
} from "@/lib/pcap";

/** Rows fetched per page. The virtualizer asks for windows; this is how
 *  big each one is. */
const PAGE = 300;

interface Props {
  captureId: string;
  active: boolean;
}

/**
 * The capture explorer.
 *
 * Three panes — list, detail tree, bytes — plus an analysis drawer. The
 * three-pane arrangement long predates any particular analyzer (Sniffer
 * and Observer had it, and it is the obvious layout for "many rows, one
 * selected, its bytes"), and the naming here is deliberately Transit's
 * own: **Findings** rather than expert information, **View filter**
 * rather than display filter (plan §11).
 *
 * The packet list is virtualized over windowed `pcap_rows` calls. Rows
 * are never bulk-loaded: a 1.5-million-packet capture would be 1.5
 * million objects in the webview, and the whole point of the index
 * holding byte offsets is that it does not have to be.
 */
export function PcapPane({ captureId, active }: Props) {
  const [filter, setFilter] = useState("");
  const [appliedFilter, setAppliedFilter] = useState<string | null>(null);
  const [filterError, setFilterError] = useState<string | null>(null);
  const [selected, setSelected] = useState<number | null>(null);
  const [offset, setOffset] = useState(0);
  const listRef = useRef<HTMLDivElement>(null);

  // Validate as the user types, so a typo is a red border rather than an
  // empty packet list — an empty list reads as "there is no such
  // traffic", which is the wrong conclusion to hand someone mid-outage.
  useEffect(() => {
    if (!filter.trim()) {
      setFilterError(null);
      return;
    }
    let cancelled = false;
    const t = setTimeout(() => {
      pcapValidateFilter(filter)
        .then(() => !cancelled && setFilterError(null))
        .catch((e) => !cancelled && setFilterError(String(e)));
    }, 200);
    return () => {
      cancelled = true;
      clearTimeout(t);
    };
  }, [filter]);

  const page = useQuery({
    queryKey: ["pcapRows", captureId, appliedFilter, offset],
    queryFn: () => pcapRows(captureId, appliedFilter, offset, PAGE),
    enabled: active,
    staleTime: Infinity,
  });

  const rows = page.data?.rows ?? [];
  const total = page.data?.total_matched ?? 0;

  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => listRef.current,
    estimateSize: () => 22,
    overscan: 12,
  });

  const detail = useQuery({
    queryKey: ["pcapDetail", captureId, selected],
    queryFn: () => pcapPacketDetail(captureId, selected as number),
    enabled: active && selected !== null,
    staleTime: Infinity,
  });

  const bytes = useQuery({
    queryKey: ["pcapBytes", captureId, selected],
    queryFn: () => pcapPacketBytes(captureId, selected as number),
    enabled: active && selected !== null,
    staleTime: Infinity,
  });

  const applyFilter = () => {
    if (filterError) return;
    setOffset(0);
    setSelected(null);
    setAppliedFilter(filter.trim() || null);
  };

  return (
    <div className="flex h-full min-h-0 flex-col" data-testid="pcap-pane">
      {/* View filter */}
      <div className="flex items-center gap-2 border-b border-border p-2">
        <Input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && applyFilter()}
          placeholder="View filter — e.g. tcp.port == 443 and ip.src == 10.0.0.0/24"
          className={
            "h-8 font-mono text-xs " +
            (filterError ? "border-destructive focus-visible:ring-destructive" : "")
          }
          aria-label="View filter"
          aria-invalid={filterError !== null}
        />
        <span className="shrink-0 text-xs tabular-nums text-muted-foreground">
          {total.toLocaleString()} packets
        </span>
      </div>
      {filterError && (
        <p className="border-b border-border bg-destructive/10 px-2 py-1 text-xs text-destructive">
          {filterError}
        </p>
      )}

      <PanelGroup direction="horizontal" className="min-h-0 flex-1">
        <Panel defaultSize={62} minSize={30}>
          <PanelGroup direction="vertical" className="min-h-0">
            {/* Packet list */}
            <Panel defaultSize={55} minSize={20}>
              <div className="flex h-full min-h-0 flex-col">
                {/* Column headers. Outside the scroll container so they stay
                  put while the list scrolls under them. Widths are
                  duplicated from the row below deliberately — the row is
                  absolutely positioned by the virtualizer, so the two
                  cannot share a table layout. */}
                <div
                  className="flex shrink-0 items-center gap-2 border-b border-border bg-muted/30 px-2 py-1 font-mono text-[11px] font-medium text-muted-foreground"
                  aria-hidden
                >
                  <span className="w-14 shrink-0">no.</span>
                  <span className="w-24 shrink-0">time</span>
                  <span className="w-36 shrink-0">source</span>
                  <span className="w-36 shrink-0">destination</span>
                  <span className="w-12 shrink-0">proto</span>
                  <span className="w-12 shrink-0 text-right">len</span>
                  <span className="pl-2">info</span>
                </div>
                <div ref={listRef} className="min-h-0 flex-1 overflow-auto font-mono text-xs">
                  <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
                    {virtualizer.getVirtualItems().map((v) => {
                      const r = rows[v.index];
                      const flagged = r.analysis !== 0;
                      return (
                        <button
                          key={r.number}
                          type="button"
                          onClick={() => setSelected(r.number)}
                          style={{
                            position: "absolute",
                            top: 0,
                            left: 0,
                            width: "100%",
                            height: v.size,
                            transform: `translateY(${v.start}px)`,
                          }}
                          className={
                            "flex items-center gap-2 px-2 text-left hover:bg-accent " +
                            (selected === r.number ? "bg-accent " : "") +
                            // A retransmission or a reset is what the analyst
                            // is scanning for; colour is the fastest way to
                            // find it in ten thousand rows.
                            (flagged ? "text-amber-600 dark:text-amber-400" : "")
                          }
                        >
                          <span className="w-14 shrink-0 tabular-nums text-muted-foreground">
                            {r.number}
                          </span>
                          <span className="w-24 shrink-0 tabular-nums text-muted-foreground">
                            {r.time.slice(11)}
                          </span>
                          <span className="w-36 shrink-0 truncate">{r.src}</span>
                          <span className="w-36 shrink-0 truncate">{r.dst}</span>
                          <span className={"w-12 shrink-0 uppercase " + protocolClass(r.protocol)}>
                            {r.protocol}
                          </span>
                          <span className="w-12 shrink-0 text-right tabular-nums">{r.length}</span>
                          <span className="truncate">{r.info}</span>
                        </button>
                      );
                    })}
                  </div>
                  {total > rows.length && (
                    <div className="flex items-center justify-between border-t border-border p-2 text-xs">
                      <button
                        type="button"
                        className="text-primary disabled:text-muted-foreground"
                        disabled={offset === 0}
                        onClick={() => setOffset(Math.max(0, offset - PAGE))}
                      >
                        ← previous
                      </button>
                      <span className="text-muted-foreground">
                        {offset + 1}–{offset + rows.length} of {total.toLocaleString()}
                      </span>
                      <button
                        type="button"
                        className="text-primary disabled:text-muted-foreground"
                        disabled={offset + PAGE >= total}
                        onClick={() => setOffset(offset + PAGE)}
                      >
                        next →
                      </button>
                    </div>
                  )}
                </div>
              </div>
            </Panel>

            <PanelResizeHandle className="h-px bg-border" />

            {/* Detail tree + bytes */}
            <Panel defaultSize={45} minSize={15}>
              <PanelGroup direction="horizontal" className="min-h-0">
                <Panel defaultSize={60} minSize={25}>
                  <div className="h-full overflow-auto p-2 font-mono text-xs">
                    {selected === null ? (
                      <p className="text-muted-foreground">Select a packet to see its fields.</p>
                    ) : (
                      (detail.data ?? []).map((layer) => (
                        <details key={layer.protocol + layer.label} open>
                          <summary className="cursor-pointer py-0.5 font-medium">
                            {layer.label}
                          </summary>
                          <ul className="ml-4">
                            {layer.fields.map((f) => (
                              <li key={f.name} className="py-px">
                                <span className="text-muted-foreground">{f.label}</span>
                                {": "}
                                <span>{f.value}</span>{" "}
                                <span className="text-muted-foreground/60">({f.name})</span>
                              </li>
                            ))}
                          </ul>
                        </details>
                      ))
                    )}
                  </div>
                </Panel>
                <PanelResizeHandle className="w-px bg-border" />
                <Panel defaultSize={40} minSize={20}>
                  <pre className="h-full overflow-auto p-2 font-mono text-[11px] leading-tight">
                    {selected === null ? "" : hexDump(bytes.data ?? [])}
                  </pre>
                </Panel>
              </PanelGroup>
            </Panel>
          </PanelGroup>
        </Panel>

        <PanelResizeHandle className="w-px bg-border" />

        {/* Analysis drawer */}
        <Panel defaultSize={38} minSize={20}>
          <AnalysisDrawer
            captureId={captureId}
            active={active}
            onUseFilter={(f) => {
              setFilter(f);
              setOffset(0);
              setSelected(null);
              setAppliedFilter(f);
            }}
          />
        </Panel>
      </PanelGroup>
    </div>
  );
}

function AnalysisDrawer({
  captureId,
  active,
  onUseFilter,
}: {
  captureId: string;
  active: boolean;
  onUseFilter: (filter: string) => void;
}) {
  const overview = useQuery({
    queryKey: ["pcapOverview", captureId],
    queryFn: () => pcapOverview(captureId),
    enabled: active,
    staleTime: Infinity,
  });
  const findings = useQuery({
    queryKey: ["pcapFindings", captureId],
    queryFn: () => pcapFindings(captureId),
    enabled: active,
    staleTime: Infinity,
  });
  const flows = useQuery({
    queryKey: ["pcapFlows", captureId],
    queryFn: () => pcapConversations(captureId, "bytes", 100),
    enabled: active,
    staleTime: Infinity,
  });
  const protos = useQuery({
    queryKey: ["pcapProtos", captureId],
    queryFn: () => pcapProtocolTree(captureId),
    enabled: active,
    staleTime: Infinity,
  });

  return (
    <Tabs defaultValue="findings" className="flex h-full min-h-0 flex-col">
      <TabsList className="m-2 self-start">
        <TabsTrigger value="findings">
          Findings
          {findings.data && findings.data.length > 0 ? ` (${findings.data.length})` : ""}
        </TabsTrigger>
        <TabsTrigger value="overview">Overview</TabsTrigger>
        <TabsTrigger value="conversations">Conversations</TabsTrigger>
        <TabsTrigger value="protocols">Protocols</TabsTrigger>
      </TabsList>

      <TabsContent value="findings" className="min-h-0 flex-1 overflow-auto px-2 pb-2">
        {(findings.data ?? []).length === 0 ? (
          <p className="text-xs text-muted-foreground">
            No findings. Transit checked for MTU black holes, retransmission rates, zero-window
            stalls, refused and unanswered connections, duplicate addresses, DNS and TLS failures,
            and capture quality.
          </p>
        ) : (
          <ul className="flex flex-col gap-2">
            {(findings.data ?? []).map((f, i) => (
              <li key={`${f.rule}-${i}`} className="rounded border border-border p-2 text-xs">
                <span
                  className={
                    "mr-2 rounded px-1 py-px text-[10px] font-semibold uppercase " +
                    severityClass(f.severity)
                  }
                >
                  {f.severity}
                </span>
                <span>{f.detail}</span>
                {f.filter && (
                  <button
                    type="button"
                    className="mt-1 block font-mono text-[11px] text-primary hover:underline"
                    onClick={() => onUseFilter(f.filter as string)}
                  >
                    show me → {f.filter}
                  </button>
                )}
              </li>
            ))}
          </ul>
        )}
      </TabsContent>

      <TabsContent value="overview" className="min-h-0 flex-1 overflow-auto px-2 pb-2">
        <pre className="whitespace-pre-wrap font-mono text-[11px] leading-snug">
          {overview.data ?? "…"}
        </pre>
      </TabsContent>

      <TabsContent value="conversations" className="min-h-0 flex-1 overflow-auto px-2 pb-2">
        <table className="w-full font-mono text-[11px]">
          <thead className="text-muted-foreground">
            <tr>
              <th className="text-left">endpoints</th>
              <th className="text-right">bytes</th>
              <th className="text-right">pkts</th>
              <th className="text-right">rtt</th>
              <th className="text-right">retx</th>
            </tr>
          </thead>
          <tbody>
            {(flows.data ?? []).map((f) => (
              <tr key={f.flow_id} className="hover:bg-accent">
                <td className="truncate">{f.endpoints}</td>
                <td className="text-right tabular-nums">{bytesHuman(f.bytes)}</td>
                <td className="text-right tabular-nums">{f.packets.toLocaleString()}</td>
                <td className="text-right tabular-nums">
                  {f.rtt_p50_us === null ? "–" : `${(f.rtt_p50_us / 1000).toFixed(1)}ms`}
                </td>
                <td className="text-right tabular-nums">{f.retransmit_pct.toFixed(1)}%</td>
              </tr>
            ))}
          </tbody>
        </table>
      </TabsContent>

      <TabsContent value="protocols" className="min-h-0 flex-1 overflow-auto px-2 pb-2">
        <table className="w-full font-mono text-[11px]">
          <tbody>
            {(protos.data ?? []).map(([name, packets, bytes]) => (
              <tr key={name}>
                <td className="uppercase">{name}</td>
                <td className="text-right tabular-nums">{packets.toLocaleString()}</td>
                <td className="text-right tabular-nums">{bytesHuman(bytes)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </TabsContent>
    </Tabs>
  );
}

/**
 * Colour for a protocol label in the packet list.
 *
 * Grouped by what the protocol is FOR, not alphabetically, so a screenful
 * of packets reads as bands of activity: name resolution, encrypted
 * transport, cleartext application, routing control, link-layer
 * housekeeping, diagnostics. Scanning for "where does the routing chatter
 * start" is then a colour search rather than a read.
 *
 * This is Transit's own palette, chosen from the existing theme tokens.
 * It is deliberately NOT modelled on any other analyzer's colouring rules
 * (plan §11) — and ours is a per-protocol tint on one column rather than
 * whole-row background rules.
 *
 * Rows flagged by TCP analysis keep their amber, which wins over this: a
 * retransmission matters more than which protocol carried it.
 */
export function protocolClass(proto: string): string {
  switch (proto.toLowerCase()) {
    // Name resolution and service discovery.
    case "dns":
    case "mdns":
    case "llmnr":
      return "text-violet-500 dark:text-violet-400";
    // Encrypted transport.
    case "tls":
    case "ssl":
    case "quic":
      return "text-emerald-600 dark:text-emerald-400";
    // Cleartext application traffic — worth noticing that it IS cleartext.
    case "http":
    case "ftp":
    case "telnet":
    case "syslog":
      return "text-orange-600 dark:text-orange-400";
    // Routing and redundancy control planes.
    case "bgp":
    case "ospf":
    case "vrrp":
    case "hsrp":
      return "text-sky-600 dark:text-sky-400";
    // Link-layer housekeeping and address assignment.
    case "arp":
    case "dhcp":
    case "lldp":
    case "cdp":
    case "stp":
      return "text-teal-600 dark:text-teal-400";
    // Diagnostics and management.
    case "icmp":
    case "icmpv6":
    case "snmp":
    case "ntp":
    case "radius":
    case "tacacs":
      return "text-rose-500 dark:text-rose-400";
    // Bare transport with nothing above it recognized.
    case "tcp":
    case "udp":
      return "text-muted-foreground";
    default:
      return "";
  }
}

function severityClass(sev: string): string {
  switch (sev) {
    case "high":
      return "bg-destructive/15 text-destructive";
    case "med":
      return "bg-amber-500/15 text-amber-700 dark:text-amber-400";
    case "low":
      return "bg-muted text-muted-foreground";
    default:
      return "bg-muted text-muted-foreground";
  }
}

/** Classic offset / hex / ASCII dump. */
export function hexDump(bytes: number[]): string {
  const lines: string[] = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    const hex = chunk
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(" ")
      .padEnd(47, " ");
    const ascii = chunk.map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join("");
    lines.push(`${i.toString(16).padStart(4, "0")}  ${hex}  ${ascii}`);
  }
  return lines.join("\n");
}

export { ANALYSIS, durationHuman };
