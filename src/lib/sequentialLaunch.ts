/**
 * Launch many things ONE AT A TIME — the shared engine behind the sidebar's
 * bulk "Launch all" (SSH connect in `mutations.ts::useConnectManyDevices` and
 * SFTP connect in `files.ts::useOpenFilesSessions`).
 *
 * ⭐ SAFETY — this is deliberately sequential and MUST stay so. Both callers
 * run a connect handshake whose host-key (TOFU / changed-key) and weak-crypto
 * prompts are SINGLE-SLOT on both ends: the frontend holds one pending payload
 * and the backend responder maps are keyed `(host, port)`. Two concurrent
 * launches would clobber a pending prompt. Do NOT swap this for
 * `Promise.all`/parallelism without first making both prompt paths queue.
 * (The connect timeout's clock also pauses while a prompt is up, so an
 * unanswered dialog never times out the batch.)
 *
 * Failures do NOT abort the batch — they are collected and returned so the
 * caller can fold them into ONE summary toast instead of N. `shouldStop` is
 * polled BEFORE each launch (an in-flight IPC invoke can't be aborted), so a
 * stop takes effect after the in-flight one and leaves everything already
 * launched in place.
 *
 * Extracted from the two hooks (which were a ~45-line fork carrying this exact
 * invariant twice — a drift hazard); each hook now keeps only its own toast
 * strings, its `run` body (connect + the per-success side effect), and its own
 * result-type shape.
 */

export interface SequentialLaunchInput {
  /** Ids to launch, in order. */
  ids: string[];
  /** Launch ONE id. Resolve on success; reject to record a failure (its
   *  message is captured and the batch continues). Any per-success side
   *  effect (append the tab, seed the pane) belongs here. */
  run: (id: string) => Promise<void>;
  /** Called after each id settles (launched OR failed) with how many have
   *  settled so far — drives the sidebar's progress banner. */
  onProgress?: (done: number, total: number) => void;
  /** Polled before each launch; returning true stops the batch after the
   *  in-flight one. */
  shouldStop?: () => boolean;
}

export interface SequentialLaunchResult {
  /** How many `run`s resolved. */
  opened: number;
  /** One entry per rejected `run`, in launch order. */
  failures: { id: string; message: string }[];
  /** True when `shouldStop` cut the batch short. */
  stopped: boolean;
  total: number;
}

export async function sequentialLaunch({
  ids,
  run,
  onProgress,
  shouldStop,
}: SequentialLaunchInput): Promise<SequentialLaunchResult> {
  const failures: { id: string; message: string }[] = [];
  let opened = 0;
  let stopped = false;
  for (let i = 0; i < ids.length; i++) {
    if (shouldStop?.()) {
      stopped = true;
      break;
    }
    const id = ids[i];
    try {
      await run(id);
      opened += 1;
    } catch (err) {
      failures.push({ id, message: err instanceof Error ? err.message : String(err) });
    }
    onProgress?.(i + 1, ids.length);
  }
  return { opened, failures, stopped, total: ids.length };
}
