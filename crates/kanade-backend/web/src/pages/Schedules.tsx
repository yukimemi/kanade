import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  ChevronDown,
  ChevronRight,
  FilePlus2,
  GitBranch,
  Loader2,
  Pencil,
  Power,
  PowerOff,
  Search,
  Tags,
  Trash2,
  X,
  Zap,
} from 'lucide-react';
import { Fragment, useState } from 'react';
import { Trans, useTranslation } from 'react-i18next';
import { toast } from 'sonner';

import { ErrorCard } from '@/components/ErrorCard';
import { type EditorMode, type RepoOrigin, YamlEditorDialog } from '@/components/YamlEditorDialog';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { useConfirm } from '@/components/ui/confirm-dialog';
import { DetailItem, DetailList } from '@/components/ui/detail-list';
import { Input } from '@/components/ui/input';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { apiFetch, formatError } from '@/lib/api';
import { useAuth } from '@/lib/auth';

// #418: the cadence is the single `when` field — a reconcile shape
// (`per_pc` / `per_target`, either the bare keyword `once` or
// `{ every: <humantime> }`) or a calendar time trigger (Phase 2:
// `{ at, days }`, repeating or one-shot). Mirrors the
// externally-tagged Rust enum's JSON.
type WhenPolicy = 'once' | 'once_per_version' | { every: string };
type CalendarSpec = { at: string; days?: string[] };
type OnTrigger = 'startup' | 'logon' | 'lock' | 'unlock' | 'network_change';
export type WhenSpec =
  | { per_pc: WhenPolicy }
  | { per_target: WhenPolicy }
  | { calendar: CalendarSpec }
  | { on: OnTrigger[] };

type ScheduleRow = {
  id: string;
  when: WhenSpec;
  job_id: string;
  target: { all: boolean; groups: string[]; pcs: string[] };
  rollout: { waves: { group: string; delay: string }[] } | null;
  jitter: string | null;
  // Optional validity window; the key is absent when the schedule
  // has no window (Rust skips serialising the empty struct).
  active?: { from?: string; until?: string };
  // #418 operational constraints; key absent when none are set
  // (Rust elides the empty struct). All four sub-fields are optional
  // and individually `skip_serializing_if`-elided.
  constraints?: {
    window?: string;
    // #418 fleet-wide concurrency cap (backend-only).
    max_concurrent?: number;
    // #418 holiday / blackout dates the schedule must not fire on.
    skip_dates?: string[];
    require?: { ac_power?: boolean; idle?: string; cpu_below?: number; network?: boolean };
  };
  // #418 Phase 4: post-failure policy; key absent when no retry is set.
  on_failure?: { retry?: { max: number; backoff: string } };
  // #418 Phase 2: timezone for `when.at` + `active` bounds.
  tz: 'local' | 'utc';
  starting_deadline: string | null;
  runs_on: 'backend' | 'agent';
  enabled: boolean;
  /** Free-form operator taxonomy (schedule manifest `tags:`). Absent /
   *  empty for most schedules — drives the tag-filter chips + search,
   *  orthogonal to the id-prefix grouping. */
  tags?: string[];
  /** GitOps provenance (#695). Present when the schedule was applied
   *  from a Git work tree via `kanade schedule create` — drives the
   *  read-only Edit modal + the per-row git badge. Absent / null for
   *  SPA-born schedules, which stay editable. */
  origin?: RepoOrigin | null;
};

// #418 rollout coverage. One agent's standing in a schedule's rollout
// + the per-schedule rollups served by `/api/schedules[/{id}]/coverage`.
type AgentRun = {
  pc_id: string;
  state: 'ok' | 'fail' | 'running' | 'pending';
  version?: string;
  finished_at?: string;
};
type CoverageResponse = {
  id: string;
  when: string;
  job_id: string;
  runs_on: string;
  total: number;
  ok: number;
  fail: number;
  running: number;
  pending: number;
  agents: AgentRun[];
};
type CoverageCounts = {
  total: number;
  ok: number;
  fail: number;
  running: number;
  pending: number;
};
type CoverageSummary = CoverageCounts & { id: string };

// Map agent state → Badge variant (badge.tsx exposes
// default|success|danger|violet|amber — no info/warning).
const COVERAGE_VARIANT: Record<AgentRun['state'], 'success' | 'danger' | 'violet' | 'default'> = {
  ok: 'success',
  fail: 'danger',
  running: 'violet',
  pending: 'default',
};

// Max not-done agents rendered in the drawer before collapsing to a
// "+N more" line — keeps a thousands-PC fleet from freezing the DOM.
const COVERAGE_DETAIL_CAP = 100;

// Compact stacked progress bar: ok (green) / fail (red) / running
// (violet); pending is the uncolored remainder of the track. Total 0 →
// an em-dash. The `title` carries the full breakdown for hover.
function CoverageBar({ total, ok, fail, running, pending }: CoverageCounts) {
  if (total === 0) return <span className="text-muted text-xs">—</span>;
  const pct = (n: number) => `${(n / total) * 100}%`;
  return (
    <div className="flex items-center gap-2">
      <div
        className="flex h-2 w-24 overflow-hidden rounded-full bg-muted/20"
        title={`${ok} ok · ${fail} fail · ${running} running · ${pending} pending`}
      >
        {ok > 0 && <div className="bg-success" style={{ width: pct(ok) }} />}
        {fail > 0 && <div className="bg-danger" style={{ width: pct(fail) }} />}
        {running > 0 && <div className="bg-violet" style={{ width: pct(running) }} />}
      </div>
      <span className="text-xs tabular-nums text-muted whitespace-nowrap">{ok}/{total}</span>
    </div>
  );
}

function summariseTarget(target: ScheduleRow['target'], allLabel: string): string {
  if (target.all) return allLabel;
  const parts: string[] = [];
  if (target.groups.length) parts.push(`groups: ${target.groups.join(', ')}`);
  if (target.pcs.length) parts.push(`pcs: ${target.pcs.join(', ')}`);
  return parts.join(' · ') || '—';
}

// Same one-liner the backend's `When` Display impl produces
// (`per_pc once` / `per_pc every 6h` / `at 09:00 [mon-fri]` /
// `at 2026-06-10 09:00`) so logs, audit payloads and the SPA all
// read identically.
export function summariseWhen(when: WhenSpec): string {
  const policy = (p: WhenPolicy) => (typeof p === 'string' ? p : `every ${p.every}`);
  if ('per_pc' in when) return `per_pc ${policy(when.per_pc)}`;
  if ('per_target' in when) return `per_target ${policy(when.per_target)}`;
  if ('on' in when) return `on [${when.on.join(',')}]`;
  const c = when.calendar;
  return c.days?.length ? `at ${c.at} [${c.days.join(',')}]` : `at ${c.at}`;
}

function summariseActive(active: ScheduleRow['active']): string | null {
  if (!active || (!active.from && !active.until)) return null;
  return `${active.from ?? '…'} → ${active.until ?? '…'}`;
}

export function Schedules() {
  const { t } = useTranslation('schedules');
  const { hasRole } = useAuth();
  const canOperate = hasRole('operator');
  const qc = useQueryClient();
  const confirm = useConfirm();
  const { data, error, isLoading } = useQuery({
    queryKey: ['schedules'],
    queryFn: () => apiFetch<ScheduleRow[]>('/api/schedules'),
  });
  // #418 rollout coverage — one batch request feeds every row's
  // progress bar (no N+1). The per-schedule detail (per-agent list) is
  // fetched lazily only when a drawer opens, below.
  const coverageList = useQuery({
    queryKey: ['schedule-coverage'],
    queryFn: () => apiFetch<CoverageSummary[]>('/api/schedules/coverage'),
  });
  const coverageById = new Map((coverageList.data ?? []).map((c) => [c.id, c]));

  // Master-detail split (#374) — same shape as the Jobs page. The
  // table used to spread all schedule fields across columns;
  // now it keeps the scannable five (id+job_id / when / target /
  // enabled / actions) and the long tail lives in a right-edge
  // Sheet opened by clicking the row. Stores the id (not the row)
  // so the drawer follows query refetches.
  const [selectedId, setSelectedId] = useState<string | null>(null);

  // Catalog organisation — mirrors the Jobs page: free-text search, a
  // set of active tag filters (OR), and the set of collapsed id-prefix
  // groups. Pure view state; none touch the server.
  const [search, setSearch] = useState('');
  const [activeTags, setActiveTags] = useState<Set<string>>(new Set());
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  function toggleTag(tag: string) {
    setActiveTags((prev) => {
      const next = new Set(prev);
      if (next.has(tag)) next.delete(tag);
      else next.add(tag);
      return next;
    });
  }
  function toggleGroup(key: string) {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  // Per-schedule coverage detail (per-agent list) — fires only when a
  // drawer is open, keyed by the selected id so it follows selection.
  const coverageDetail = useQuery({
    queryKey: ['schedule-coverage', selectedId],
    queryFn: () =>
      apiFetch<CoverageResponse>(`/api/schedules/${encodeURIComponent(selectedId!)}/coverage`),
    enabled: selectedId !== null,
  });

  const del = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/schedules/${encodeURIComponent(id)}`, { method: 'DELETE' }),
    onSuccess: (_d, id) => {
      qc.invalidateQueries({ queryKey: ['schedules'] });
      // Drop the stale coverage entry too — otherwise recreating a
      // schedule with the same id would serve old coverage until the
      // query goes stale (claude #617).
      qc.invalidateQueries({ queryKey: ['schedule-coverage'] });
      // Close the drawer if it was showing the row we just deleted.
      setSelectedId((prev) => (prev === id ? null : prev));
      toast.success(t('toast.deleted', { id }));
    },
    onError: (e) => toast.error(t('toast.deleteFailed', { error: formatError(e) })),
  });

  // v0.27 (SPEC §2.6.4 (c)): disable goes through the dedicated
  // endpoint that can also cascade-revoke the referenced Job.
  // ?cascade=true = "hard disable" — stops the cron AND writes
  // script_status.{job_id} = REVOKED so any in-flight Command gets
  // skipped at agent fire time. ?cascade=false (default) = "soft
  // disable" — just stops the cron, in-flight Commands run.
  //
  // Round 2 review (CodeRabbit #38): per-row pending tracked via a
  // Set<string> so concurrent disable/enable clicks across rows
  // don't grey each other out — `mutation.variables` is a single
  // value, useless for per-row gating.
  const [pendingDisable, setPendingDisable] = useState<Set<string>>(new Set());
  const [pendingEnable, setPendingEnable] = useState<Set<string>>(new Set());

  // v0.32 / PR-B: shared Monaco-backed YAML editor — same state shape
  // and behaviour as the Jobs page.
  const [editor, setEditor] = useState<EditorMode | null>(null);
  const disable = useMutation({
    mutationFn: ({ id, cascade }: { id: string; cascade: boolean }) =>
      apiFetch(`/api/schedules/${encodeURIComponent(id)}/disable?cascade=${cascade}`, {
        method: 'POST',
      }),
    onMutate: ({ id }) => {
      setPendingDisable((prev) => new Set(prev).add(id));
    },
    onSettled: (_d, _e, { id }) => {
      setPendingDisable((prev) => {
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
    },
    onSuccess: (_d, { id, cascade }) => {
      qc.invalidateQueries({ queryKey: ['schedules'] });
      toast.success(cascade ? t('toast.hardDisabled', { id }) : t('toast.softDisabled', { id }));
    },
    onError: (e) => toast.error(t('toast.disableFailed', { error: formatError(e) })),
  });
  // v0.27 (gemini #38 review): symmetrical /enable endpoint so we
  // don't clobber concurrent edits with a full row re-POST. Backend
  // uses kv.entry().revision + update() the same way disable does.
  const enable = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/schedules/${encodeURIComponent(id)}/enable`, { method: 'POST' }),
    onMutate: (id) => {
      setPendingEnable((prev) => new Set(prev).add(id));
    },
    onSettled: (_d, _e, id) => {
      setPendingEnable((prev) => {
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
    },
    onSuccess: (_d, id) => {
      qc.invalidateQueries({ queryKey: ['schedules'] });
      toast.success(t('toast.enabled', { id }));
    },
    onError: (e) => toast.error(t('toast.enableFailed', { error: formatError(e) })),
  });

  function enabledBadge(s: ScheduleRow) {
    return s.enabled
      ? <Badge variant="success">{t('status.on')}</Badge>
      : <Badge variant="danger">{t('status.off')}</Badge>;
  }

  // One action strip, two render sites: icon-only in the table rows,
  // icon+label in the drawer footer. Non-operators get a read-only
  // view — the write controls (edit / enable-disable / delete) don't
  // render at all, matching the backend RBAC that would 403 the writes.
  function renderActions(s: ScheduleRow, withLabels = false) {
    if (!canOperate) return null;
    return (
      <>
        <Button
          variant="secondary"
          size="sm"
          onClick={() => setEditor({ type: 'edit', id: s.id })}
          title={t('actions.editTitle')}
          aria-label={t('actions.editAria', { id: s.id })}
        >
          <Pencil className="size-3.5" />
          {withLabels && t('actions.edit')}
        </Button>
        {s.enabled ? (
          // v0.33 — merged the two "disable" buttons (Soft + Hard
          // cascade) into one split-button dropdown so the Actions
          // column stops wrapping to two rows. The dropdown puts both
          // choices on screen at the same time with a one-line
          // explainer, which reads more safely than two adjacent
          // buttons where the operator might mistake the destructive
          // variant for the soft one.
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="secondary"
                size="sm"
                disabled={pendingDisable.has(s.id)}
                title={t('actions.disableMenuTitle')}
                aria-label={t('actions.disableMenuAria', { id: s.id })}
              >
                <PowerOff className="size-3.5" />
                {withLabels && t('actions.disable')}
                <ChevronDown className="size-3" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem
                onSelect={() => disable.mutate({ id: s.id, cascade: false })}
              >
                <PowerOff className="size-4 mt-0.5 shrink-0" />
                <div className="flex flex-col gap-0.5">
                  <span>{t('actions.softDisable')}</span>
                  <span className="text-xs text-muted">
                    {t('actions.softDisableHint')}
                  </span>
                </div>
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem
                variant="danger"
                onSelect={async () => {
                  const ok = await confirm({
                    title: t('confirm.hardDisableTitle', { id: s.id }),
                    description: t('confirm.hardDisableDescription', { id: s.id, jobId: s.job_id }),
                    confirmLabel: t('confirm.hardDisableLabel'),
                    danger: true,
                  });
                  if (ok) disable.mutate({ id: s.id, cascade: true });
                }}
              >
                <Zap className="size-4 mt-0.5 shrink-0" />
                <div className="flex flex-col gap-0.5">
                  <span>{t('actions.hardDisable')}</span>
                  <span className="text-xs text-muted">
                    {t('actions.hardDisableHint')}
                  </span>
                </div>
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        ) : (
          <Button
            variant="secondary"
            size="sm"
            disabled={pendingEnable.has(s.id)}
            onClick={() => enable.mutate(s.id)}
            title={t('actions.enableTitle')}
            aria-label={t('actions.enableAria', { id: s.id })}
          >
            <Power className="size-3.5" />
            {withLabels && t('actions.enable')}
          </Button>
        )}
        <Button
          variant="danger"
          size="sm"
          disabled={del.isPending}
          onClick={async () => {
            const ok = await confirm({
              title: t('confirm.deleteTitle', { id: s.id }),
              description: t('confirm.deleteDescription'),
              confirmLabel: t('confirm.deleteLabel'),
              danger: true,
            });
            if (ok) del.mutate(s.id);
          }}
          title={t('actions.deleteTitle')}
          aria-label={t('actions.deleteAria', { id: s.id })}
        >
          <Trash2 className="size-3.5" />
          {withLabels && t('actions.delete')}
        </Button>
      </>
    );
  }

  // One table row. Extracted from the old inline `.map` so the
  // id-prefix groups below render their slices without duplicating the
  // cell layout. Tag badges under the job_id double as filter toggles.
  function renderScheduleRow(s: ScheduleRow) {
    return (
      <TableRow
        key={s.id}
        tabIndex={0}
        className="cursor-pointer focus-visible:outline-none focus-visible:bg-muted/10"
        onClick={() => setSelectedId(s.id)}
        // Keyboard path for the clickable row — currentTarget
        // guard so Enter/Space on a focused action button
        // doesn't bubble up and also open the drawer.
        onKeyDown={(e) => {
          if (e.target === e.currentTarget && (e.key === 'Enter' || e.key === ' ')) {
            e.preventDefault();
            setSelectedId(s.id);
          }
        }}
        aria-label={t('row.openAria', { id: s.id })}
      >
        {/* `w-full max-w-0` — this cell soaks up the leftover
            width and truncates, same as the Jobs id+description
            cell. */}
        <TableCell label={t('columns.schedule')} className="w-full max-w-0">
          <div className="flex flex-col gap-0.5">
            <code className="text-xs font-medium">{s.id}</code>
            <span className="block truncate text-xs text-muted" title={s.job_id}>
              {s.job_id}
            </span>
            {/* Git provenance marker (#695) + operator tags share one
                flex-wrap row so the git badge no longer eats a whole
                line of its own — the row stays compact when a schedule
                carries both. The container carries NO onClick: stopping
                propagation there would turn the git badge + the gap/
                padding between chips into a dead zone that swallows the
                row click. Each tag button stops propagation itself, so
                only a tag toggles the filter without also opening the
                drawer; everywhere else in the row still opens it. */}
            {(s.origin || (s.tags && s.tags.length > 0)) && (
              <div className="mt-0.5 flex flex-wrap items-center gap-1">
                {s.origin && (
                  // #695: this schedule is managed in Git, so the Edit
                  // modal opens read-only. Tooltip carries the
                  // repo-relative .yaml path.
                  <span
                    className="inline-flex"
                    title={t('git.badgeTitle', { path: s.origin.path })}
                  >
                    <Badge
                      // Amber tint so the read-only Git-provenance marker
                      // is set apart by hue from the muted tag-filter chips
                      // it now sits beside (and from the violet an *active*
                      // tag turns) — same row, distinct role at a glance.
                      variant="amber"
                      className="gap-1 px-1.5 py-0 text-[10px]"
                    >
                      <GitBranch className="size-3" />
                      {t('git.badge')}
                    </Badge>
                  </span>
                )}
                {(s.tags ?? []).map((tag) => (
                  <button
                    key={tag}
                    type="button"
                    onClick={(e) => {
                      // Stop here (not on the container) so the drawer
                      // opens everywhere except on a tag chip itself.
                      e.stopPropagation();
                      toggleTag(tag);
                    }}
                    title={t('tags.filterByTitle', { tag })}
                    aria-pressed={activeTags.has(tag)}
                    className="cursor-pointer"
                  >
                    <Badge
                      variant={activeTags.has(tag) ? 'violet' : 'default'}
                      className="px-1.5 py-0 text-[10px] transition-colors hover:bg-violet/15 hover:text-violet"
                    >
                      {tag}
                    </Badge>
                  </button>
                ))}
              </div>
            )}
          </div>
        </TableCell>
        <TableCell label={t('columns.when')}><code className="text-xs whitespace-nowrap">{summariseWhen(s.when)}</code></TableCell>
        <TableCell label={t('columns.target')} className="text-xs max-w-48 truncate" title={summariseTarget(s.target, t('target.all'))}>
          {summariseTarget(s.target, t('target.all'))}
        </TableCell>
        <TableCell label={t('columns.coverage')}>
          {(() => {
            const c = coverageById.get(s.id);
            return c ? <CoverageBar {...c} /> : <span className="text-muted text-xs">…</span>;
          })()}
        </TableCell>
        <TableCell label={t('columns.enabled')}>{enabledBadge(s)}</TableCell>
        {/* stopPropagation so action clicks don't also open
            the drawer underneath the confirm dialog. */}
        <TableCell onClick={(e) => e.stopPropagation()}>
          <div className="flex flex-nowrap gap-2">{renderActions(s)}</div>
        </TableCell>
      </TableRow>
    );
  }

  if (isLoading) return <div className="flex items-center gap-2 text-muted"><Loader2 className="size-4 animate-spin" />{t('loading')}</div>;
  if (error) return <ErrorCard title={t('errorTitle')} error={error} />;
  const rows = data ?? [];
  const selected = rows.find((s) => s.id === selectedId) ?? null;
  // Gemini review (#376): same stale-selection guard as the Jobs
  // page — a refetch that drops the selected row closes the drawer
  // without firing onOpenChange, so reset during render to keep the
  // next click on that row a real state transition.
  if (selectedId !== null && selected === null) {
    setSelectedId(null);
  }

  // #695: Git provenance of the row being edited (if any), so the dialog
  // renders a Git-managed schedule read-only. `null` for create mode and
  // for SPA-born schedules.
  const editingOrigin: RepoOrigin | null =
    editor?.type === 'edit'
      ? (rows.find((s) => s.id === editor.id)?.origin ?? null)
      : null;

  // ---- id-prefix grouping + search / tag filtering (mirrors Jobs) ----
  // Prefix = everything before the first hyphen of the SCHEDULE id
  // (`check-bitlocker` → `check`). Single-member prefixes fold into a
  // single "Other" group, computed over the full set so membership
  // stays stable while filtering.
  const OTHER = ' other'; // sentinel that can't collide with a real prefix
  const prefixOf = (id: string) => {
    const i = id.indexOf('-');
    return i > 0 ? id.slice(0, i) : id;
  };
  const prefixCounts = new Map<string, number>();
  for (const s of rows) {
    const p = prefixOf(s.id);
    prefixCounts.set(p, (prefixCounts.get(p) ?? 0) + 1);
  }
  const groupKeyOf = (id: string) => {
    const p = prefixOf(id);
    return (prefixCounts.get(p) ?? 0) >= 2 ? p : OTHER;
  };

  const allTags = Array.from(new Set(rows.flatMap((s) => s.tags ?? []))).sort((a, b) =>
    a.localeCompare(b),
  );

  // Search matches id / job_id / any tag (case-insensitive); tag filter
  // is OR across the active set. Both must hold.
  const q = search.trim().toLowerCase();
  const matches = (s: ScheduleRow) => {
    const tagHit = activeTags.size === 0 || (s.tags ?? []).some((tag) => activeTags.has(tag));
    if (!tagHit) return false;
    if (q === '') return true;
    return (
      s.id.toLowerCase().includes(q) ||
      s.job_id.toLowerCase().includes(q) ||
      (s.tags ?? []).some((tag) => tag.toLowerCase().includes(q))
    );
  };
  const visibleRows = rows.filter(matches);
  const filtering = q !== '' || activeTags.size > 0;

  const realPrefixes = Array.from(prefixCounts.entries())
    .filter(([, n]) => n >= 2)
    .map(([p]) => p)
    .sort((a, b) => a.localeCompare(b));
  const orderedKeys = [...realPrefixes, OTHER];
  const groups = orderedKeys
    .map((key) => ({
      key,
      label: key === OTHER ? t('groups.other') : key,
      rows: visibleRows.filter((s) => groupKeyOf(s.id) === key),
    }))
    .filter((g) => g.rows.length > 0);

  if (rows.length === 0) {
    return (
      <>
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle>{t('empty.title')}</CardTitle>
              {canOperate && (
                <Button
                  variant="default"
                  size="sm"
                  onClick={() => setEditor({ type: 'create' })}
                >
                  <FilePlus2 className="size-3.5" />
                  {t('newSchedule')}
                </Button>
              )}
            </div>
          </CardHeader>
          <CardContent className="text-muted">
            <Trans
              ns="schedules"
              i18nKey="empty.body"
              components={{
                code: <code />,
                strong: <strong />,
              }}
            />
          </CardContent>
        </Card>
        {editor !== null && (
          <YamlEditorDialog
            open
            onOpenChange={(next) => {
              if (!next) setEditor(null);
            }}
            kind="schedule"
            mode={editor}
          />
        )}
      </>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-baseline justify-between">
        <h2 className="text-xl">{t('title')}</h2>
        <div className="flex items-center gap-2">
          {canOperate && (
            <Button
              variant="default"
              size="sm"
              onClick={() => setEditor({ type: 'create' })}
              title={t('newScheduleTitle')}
            >
              <FilePlus2 className="size-3.5" />
              {t('newSchedule')}
            </Button>
          )}
          <Badge variant="violet">
            {filtering ? `${visibleRows.length} / ${rows.length}` : rows.length}
          </Badge>
        </div>
      </div>
      {/* Filter bar: free-text search + (when any schedule is tagged)
          the tag-toggle chips. Both narrow the grouped table below. */}
      <div className="space-y-2">
        <div className="relative max-w-sm">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted" />
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={t('search.placeholder')}
            aria-label={t('search.placeholder')}
            className="pl-8 pr-8"
          />
          {search !== '' && (
            <button
              type="button"
              onClick={() => setSearch('')}
              title={t('search.clear')}
              aria-label={t('search.clear')}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-muted hover:text-fg"
            >
              <X className="size-4" />
            </button>
          )}
        </div>
        {allTags.length > 0 && (
          <div className="flex flex-wrap items-center gap-1.5">
            <Tags className="size-4 text-muted" />
            {allTags.map((tag) => (
              <button
                key={tag}
                type="button"
                onClick={() => toggleTag(tag)}
                aria-pressed={activeTags.has(tag)}
                className="cursor-pointer"
              >
                <Badge
                  variant={activeTags.has(tag) ? 'violet' : 'default'}
                  className="transition-colors hover:bg-violet/15 hover:text-violet"
                >
                  {tag}
                </Badge>
              </button>
            ))}
            {activeTags.size > 0 && (
              <button
                type="button"
                onClick={() => setActiveTags(new Set())}
                className="text-xs text-muted hover:text-fg"
              >
                {t('tags.clear')}
              </button>
            )}
          </div>
        )}
      </div>
      <Table resizeKey="schedules" picker>
        <TableHeader>
          <TableRow>
            <TableHead>{t('columns.schedule')}</TableHead>
            <TableHead>{t('columns.when')}</TableHead>
            <TableHead>{t('columns.target')}</TableHead>
            <TableHead>{t('columns.coverage')}</TableHead>
            <TableHead>{t('columns.enabled')}</TableHead>
            <TableHead>{t('columns.actions')}</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {groups.length === 0 ? (
            <TableRow>
              <TableCell colSpan={6} className="py-8 text-center text-sm text-muted">
                {t('noMatch')}
              </TableCell>
            </TableRow>
          ) : (
            groups.map((g) => {
              const isCollapsed = collapsed.has(g.key);
              return (
                <Fragment key={g.key}>
                  {/* Group header — clicking (or Enter/Space when
                      focused) toggles collapse for the whole prefix.
                      colSpan covers all six columns. */}
                  <TableRow
                    tabIndex={0}
                    role="button"
                    aria-expanded={!isCollapsed}
                    aria-label={`${isCollapsed ? t('groups.expand') : t('groups.collapse')} ${g.label}`}
                    className="cursor-pointer bg-muted/5 hover:bg-muted/10 focus-visible:outline-none focus-visible:bg-muted/10"
                    onClick={() => toggleGroup(g.key)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        toggleGroup(g.key);
                      }
                    }}
                  >
                    <TableCell colSpan={6} className="py-1.5">
                      <div className="flex items-center gap-1.5 text-xs font-medium">
                        {isCollapsed ? (
                          <ChevronRight className="size-3.5 text-muted" />
                        ) : (
                          <ChevronDown className="size-3.5 text-muted" />
                        )}
                        <span>{g.label}</span>
                        <Badge variant="default" className="px-1.5 py-0 text-[10px]">
                          {g.rows.length}
                        </Badge>
                      </div>
                    </TableCell>
                  </TableRow>
                  {!isCollapsed && g.rows.map((s) => renderScheduleRow(s))}
                </Fragment>
              );
            })
          )}
        </TableBody>
      </Table>
      <Sheet
        open={selected !== null}
        onOpenChange={(next) => {
          if (!next) setSelectedId(null);
        }}
      >
        {selected !== null && (
          <SheetContent>
            <SheetHeader>
              <SheetTitle>
                <code className="break-all">{selected.id}</code>
              </SheetTitle>
              <SheetDescription>
                {t('detail.jobRef', { jobId: selected.job_id })}
              </SheetDescription>
            </SheetHeader>
            <div className="flex flex-wrap items-center gap-1.5">
              {enabledBadge(selected)}
            </div>
            <DetailList>
              <DetailItem label={t('columns.when')}>
                <code className="text-xs">{summariseWhen(selected.when)}</code>
              </DetailItem>
              <DetailItem label={t('columns.jobId')}>
                <code className="text-xs break-all">{selected.job_id}</code>
              </DetailItem>
              <DetailItem label={t('columns.target')} className="text-xs">
                {summariseTarget(selected.target, t('target.all'))}
              </DetailItem>
              <DetailItem label={t('columns.runsOn')}>
                <code className="text-xs">{selected.runs_on}</code>
              </DetailItem>
              <DetailItem label={t('columns.tz')}>
                <code className="text-xs">{selected.tz}</code>
              </DetailItem>
              <DetailItem label={t('columns.active')}>
                {summariseActive(selected.active)
                  ? <code className="text-xs">{summariseActive(selected.active)}</code>
                  : <span className="text-muted text-xs">—</span>}
              </DetailItem>
              <DetailItem label={t('columns.window')}>
                {selected.constraints?.window
                  ? <code className="text-xs">{selected.constraints.window}</code>
                  : <span className="text-muted text-xs">—</span>}
              </DetailItem>
              <DetailItem label={t('columns.maxConcurrent')}>
                {selected.constraints?.max_concurrent != null
                  ? <code className="text-xs">{selected.constraints.max_concurrent}</code>
                  : <span className="text-muted text-xs">—</span>}
              </DetailItem>
              <DetailItem label={t('columns.skipDates')}>
                {(() => {
                  const dates = selected.constraints?.skip_dates;
                  if (!dates || dates.length === 0)
                    return <span className="text-muted text-xs">—</span>;
                  // Compact summary for long blackout lists (a weekly
                  // freeze can be 50+ dates); full list in the tooltip.
                  const full = dates.join(', ');
                  const display =
                    dates.length <= 3
                      ? full
                      : t('skipDatesSummary', { first: dates[0], count: dates.length - 1 });
                  return (
                    <code className="text-xs" title={full}>
                      {display}
                    </code>
                  );
                })()}
              </DetailItem>
              <DetailItem label={t('columns.require')}>
                {(() => {
                  const r = selected.constraints?.require;
                  const parts: string[] = [];
                  if (r?.ac_power) parts.push(t('require.ac'));
                  if (r?.idle) parts.push(t('require.idle', { duration: r.idle }));
                  if (r?.cpu_below != null) parts.push(t('require.cpu', { pct: r.cpu_below }));
                  if (r?.network) parts.push(t('require.network'));
                  return parts.length
                    ? <code className="text-xs">{parts.join(' · ')}</code>
                    : <span className="text-muted text-xs">—</span>;
                })()}
              </DetailItem>
              <DetailItem label={t('columns.onFailure')}>
                {selected.on_failure?.retry
                  ? (
                    <code className="text-xs">
                      {t('retry', {
                        max: selected.on_failure.retry.max,
                        backoff: selected.on_failure.retry.backoff,
                      })}
                    </code>
                  )
                  : <span className="text-muted text-xs">—</span>}
              </DetailItem>
              {/* Field coverage (#688): every persisted Schedule field above is
                  shown except two, intentionally:
                  - `deadline_at` (FanoutPlan) — scheduler-computed per-Command
                    (`tick_at + starting_deadline`), not an operator-set schedule
                    field; the operator-facing `starting_deadline` is shown below.
                  - `origin` (#695) — surfaced as the per-row git badge + the
                    read-only Edit modal, not as a detail row. */}
              <DetailItem label={t('columns.deadline')}>
                <code className="text-xs">{selected.starting_deadline ?? '—'}</code>
              </DetailItem>
              <DetailItem label={t('columns.jitter')}>
                <code className="text-xs">{selected.jitter ?? '—'}</code>
              </DetailItem>
              <DetailItem label={t('columns.rollout')} className="text-xs">
                {selected.rollout
                  ? t('rollout', { count: selected.rollout.waves.length })
                  : <span className="text-muted">—</span>}
              </DetailItem>
              <DetailItem label={t('columns.tags')}>
                {selected.tags && selected.tags.length > 0 ? (
                  <div className="flex flex-wrap gap-1">
                    {selected.tags.map((tag) => (
                      // Clickable filter toggle, same as the row tags.
                      <button
                        key={tag}
                        type="button"
                        onClick={() => toggleTag(tag)}
                        title={t('tags.filterByTitle', { tag })}
                        aria-pressed={activeTags.has(tag)}
                        className="cursor-pointer"
                      >
                        <Badge
                          variant={activeTags.has(tag) ? 'violet' : 'default'}
                          className="px-1.5 py-0 text-[10px] transition-colors hover:bg-violet/15 hover:text-violet"
                        >
                          {tag}
                        </Badge>
                      </button>
                    ))}
                  </div>
                ) : (
                  <span className="text-muted text-xs">—</span>
                )}
              </DetailItem>
            </DetailList>
            <Card>
              <CardHeader>
                <CardTitle className="text-sm">{t('coverage.title')}</CardTitle>
              </CardHeader>
              <CardContent>
                {coverageDetail.isLoading && <span className="text-muted text-xs">…</span>}
                {coverageDetail.error && (
                  <span className="text-danger text-xs">{formatError(coverageDetail.error)}</span>
                )}
                {coverageDetail.data && (() => {
                  const c = coverageDetail.data;
                  const notDone = c.agents.filter((a) => a.state !== 'ok');
                  return (
                    <div className="space-y-3">
                      <CoverageBar {...c} />
                      <div className="text-xs text-muted">
                        {t('coverage.summary', {
                          ok: c.ok,
                          total: c.total,
                          fail: c.fail,
                          running: c.running,
                          pending: c.pending,
                        })}
                      </div>
                      {notDone.length > 0 && (
                        <div className="space-y-1">
                          {/* Cap the DOM list so a thousands-PC fleet
                              doesn't freeze the drawer (gemini #617);
                              the overflow count is shown below. */}
                          {notDone.slice(0, COVERAGE_DETAIL_CAP).map((a) => (
                            <div
                              key={a.pc_id}
                              className="flex items-center justify-between gap-2 text-xs"
                            >
                              <code className="truncate">{a.pc_id}</code>
                              <span className="flex items-center gap-2 whitespace-nowrap">
                                <Badge variant={COVERAGE_VARIANT[a.state]}>
                                  {t(`coverage.state.${a.state}`)}
                                </Badge>
                                <span className="text-muted">{a.version ?? '—'}</span>
                              </span>
                            </div>
                          ))}
                          {notDone.length > COVERAGE_DETAIL_CAP && (
                            <div className="text-muted text-xs">
                              {t('coverage.more', { count: notDone.length - COVERAGE_DETAIL_CAP })}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })()}
              </CardContent>
            </Card>
            <SheetFooter>
              <div className="flex flex-wrap justify-end gap-2">
                {renderActions(selected, true)}
              </div>
            </SheetFooter>
          </SheetContent>
        )}
      </Sheet>
      {del.error && <ErrorCard title={t('errors.deleteFailed')} error={del.error} />}
      {disable.error && <ErrorCard title={t('errors.disableFailed')} error={disable.error} />}
      {enable.error && <ErrorCard title={t('errors.enableFailed')} error={enable.error} />}
      {editor !== null && (
        <YamlEditorDialog
          open
          onOpenChange={(next) => {
            if (!next) setEditor(null);
          }}
          kind="schedule"
          mode={editor}
          gitOrigin={editingOrigin}
        />
      )}
    </div>
  );
}
