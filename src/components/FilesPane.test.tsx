import { QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/api", () => ({
  filesListDir: vi.fn(),
  filesLocalListDir: vi.fn(),
  filesLocalRoots: vi.fn().mockResolvedValue([]),
  filesMkdir: vi.fn().mockResolvedValue(undefined),
  filesRename: vi.fn().mockResolvedValue(undefined),
  filesDelete: vi.fn().mockResolvedValue(undefined),
  filesLocalMkdir: vi.fn().mockResolvedValue(undefined),
  filesLocalRename: vi.fn().mockResolvedValue(undefined),
  filesLocalDelete: vi.fn().mockResolvedValue(undefined),
  filesConnect: vi.fn(),
  filesReconnect: vi.fn(),
  filesDisconnect: vi.fn().mockResolvedValue(undefined),
  filesCheckConflicts: vi.fn().mockResolvedValue([]),
  filesEnqueue: vi.fn().mockResolvedValue([]),
  filesCancel: vi.fn().mockResolvedValue(undefined),
}));

// Tauri intercepts native file drags before the DOM sees them, so an OS drop
// arrives through the webview API — mocked here so a test can fire one.
type DragDropHandler = (event: { payload: unknown }) => void;
const dragDropHandlers: DragDropHandler[] = [];

vi.mock("@tauri-apps/api/webview", () => ({
  getCurrentWebview: () => ({
    onDragDropEvent: vi.fn(async (handler: DragDropHandler) => {
      dragDropHandlers.push(handler);
      return () => {
        const i = dragDropHandlers.indexOf(handler);
        if (i >= 0) dragDropHandlers.splice(i, 1);
      };
    }),
  }),
}));

// Capture per-topic listeners so a test can fire the backend's synthesized
// `files:{id}:closed` signal.
type Handler = (event: { payload: unknown }) => void;
const listeners = new Map<string, Handler[]>();

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async (topic: string, handler: Handler) => {
    listeners.set(topic, [...(listeners.get(topic) ?? []), handler]);
    return () => {
      listeners.set(
        topic,
        (listeners.get(topic) ?? []).filter((h) => h !== handler),
      );
    };
  }),
  emit: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("@/lib/toast", () => ({
  toastError: vi.fn(),
  toastSuccess: vi.fn(),
  toastInfo: vi.fn(),
}));

import {
  filesCheckConflicts,
  filesDelete,
  filesEnqueue,
  filesListDir,
  filesLocalListDir,
  filesLocalMkdir,
  filesLocalRoots,
  filesMkdir,
  filesReconnect,
  filesRename,
  type DirListing,
  type FileEntry,
} from "@/lib/api";
import { FILES_DND_MIME } from "@/lib/fileDnd";
import { queryClient } from "@/lib/queryClient";
import { useFilesStore } from "@/stores/filesStore";
import { useUiStore } from "@/stores/uiStore";

import { FilesPane } from "./FilesPane";

const mockedRemoteList = vi.mocked(filesListDir);
const mockedConflicts = vi.mocked(filesCheckConflicts);
const mockedEnqueue = vi.mocked(filesEnqueue);
const mockedLocalList = vi.mocked(filesLocalListDir);
const mockedRoots = vi.mocked(filesLocalRoots);
const mockedMkdir = vi.mocked(filesMkdir);
const mockedRename = vi.mocked(filesRename);
const mockedDelete = vi.mocked(filesDelete);
const mockedLocalMkdir = vi.mocked(filesLocalMkdir);
const mockedReconnect = vi.mocked(filesReconnect);

class StubResizeObserver {
  observe() {}
  disconnect() {}
  unobserve() {}
}
(globalThis as unknown as { ResizeObserver: typeof StubResizeObserver }).ResizeObserver =
  StubResizeObserver;

// happy-dom reports 0 for every layout box, and @tanstack/react-virtual sizes
// its visible window from the scroll element's box — `offsetHeight` up to
// virtual-core 3.19.5, `clientHeight` from 3.19.6 ("measure the scroll
// viewport using client dimensions so borders and scrollbars do not obscure
// end-aligned items") — so without a stub the virtualizer renders ZERO rows
// and nothing about the listing is assertable. Give elements a viewport-
// sized box, both flavours, for the whole file.
for (const [prop, px] of [
  ["offsetHeight", 600],
  ["clientHeight", 600],
  ["offsetWidth", 800],
  ["clientWidth", 800],
] as const) {
  Object.defineProperty(HTMLElement.prototype, prop, { configurable: true, get: () => px });
}

// The OS-drop hit-test (F1) measures the pane with `getBoundingClientRect`,
// which happy-dom returns all-zero. Give every element the same 800×600
// viewport box the offset stubs above imply, so a drop position inside
// 0–800 × 0–600 counts as "over the pane" and one outside does not.
Object.defineProperty(HTMLElement.prototype, "getBoundingClientRect", {
  configurable: true,
  value: () => ({ left: 0, top: 0, right: 800, bottom: 600, width: 800, height: 600, x: 0, y: 0 }),
});

function entry(partial: Partial<FileEntry> & Pick<FileEntry, "name">): FileEntry {
  return {
    kind: "file",
    size: 100,
    mtime: 1_754_300_000,
    perms: "rw-r--r--",
    symlink_target: null,
    ...partial,
  };
}

function listing(partial: Partial<DirListing> & Pick<DirListing, "path">): DirListing {
  return { parent: "/", entries: [], truncated: false, ...partial };
}

const REMOTE_HOME = "/var/home/lab";
const LOCAL_HOME = "/Users/alice";

function remoteListing(): DirListing {
  return listing({
    path: REMOTE_HOME,
    parent: "/var/home",
    entries: [
      entry({ name: "configs", kind: "dir", size: null, perms: "rwxr-xr-x" }),
      entry({ name: "juniper.conf", size: 4096 }),
      entry({ name: "big.log", size: 5 * 1024 * 1024 }),
      entry({ name: ".profile", size: 12 }),
    ],
  });
}

function localListing(): DirListing {
  return listing({
    path: LOCAL_HOME,
    parent: "/Users",
    entries: [entry({ name: "Downloads", kind: "dir", size: null }), entry({ name: "notes.txt" })],
  });
}

function renderPane(props?: Partial<Parameters<typeof FilesPane>[0]>) {
  // The app's SINGLETON client, deliberately: the mutation hooks invalidate
  // through `@/lib/queryClient`, so a test-local QueryClient would never see
  // the refetch that invalidation is supposed to trigger.
  const ui: ReactElement = (
    <QueryClientProvider client={queryClient}>
      <FilesPane sessionId="s1" deviceId="vEX1" ended={false} active {...props} />
    </QueryClientProvider>
  );
  return render(ui);
}

/** Fire the backend's `files:{id}:closed` signal. */
function fireClosed(sessionId: string) {
  act(() => {
    for (const h of listeners.get(`files:${sessionId}:closed`) ?? []) {
      h({ payload: { session_id: sessionId, reason: "the connection closed" } });
    }
  });
}

/**
 * A minimal `DataTransfer` stand-in for the drag payload round-trip.
 *
 * ⭐ Testing-library copies this object's OWN properties onto a real
 * happy-dom `DataTransfer`, so only mutations that travel through a shared
 * reference are observable here: `setData`/`getData` (which write into the
 * captured `data` / `types` objects) work, while a plain assignment the
 * handler makes — `effectAllowed` / `dropEffect` — lands on the copy and is
 * invisible. Assert the payload and the resulting behavior, not those two.
 */
function fakeDataTransfer() {
  const data: Record<string, string> = {};
  return {
    effectAllowed: "",
    dropEffect: "",
    types: [] as string[],
    setData(type: string, value: string) {
      data[type] = value;
      if (!this.types.includes(type)) this.types.push(type);
    },
    getData(type: string) {
      return data[type] ?? "";
    },
  };
}

/** Fire one Tauri OS-drag event at the mounted pane. enter/over/drop carry a
 *  physical-pixel position; default it INSIDE the pane rect (F1) unless the
 *  caller overrides it (a `leave` has no position). */
function fireOsDrag(payload: {
  type: string;
  paths?: string[];
  position?: { x: number; y: number };
}) {
  const withPosition =
    payload.type === "leave" ? payload : { position: { x: 100, y: 100 }, ...payload };
  act(() => {
    for (const h of [...dragDropHandlers]) h({ payload: withPosition });
  });
}

beforeEach(() => {
  listeners.clear();
  dragDropHandlers.length = 0;
  queryClient.clear();
  queryClient.setDefaultOptions({ queries: { retry: false, gcTime: 0, staleTime: 0 } });
  useUiStore.setState({
    sessions: [{ sessionId: "s1", deviceId: "vEX1", ended: false, kind: "files" }],
    activeTabId: "s1",
  });
  useFilesStore.setState({ panes: {}, transfers: new Map(), transferTargets: new Map() });
  useFilesStore.getState().ensurePane("s1", REMOTE_HOME);
  mockedConflicts.mockResolvedValue([]);
  mockedEnqueue.mockResolvedValue([]);
  // The backend echoes the canonical path it resolved, so a navigation to a
  // different directory must come back with THAT path — otherwise the pane's
  // canonical write-back would drag the cwd straight back to home.
  mockedRemoteList.mockImplementation(async (_sessionId: string, path: string) =>
    path === REMOTE_HOME ? remoteListing() : listing({ path, parent: "/var/home", entries: [] }),
  );
  mockedLocalList.mockImplementation(async (path?: string | null) =>
    !path || path === LOCAL_HOME ? localListing() : listing({ path, parent: "/", entries: [] }),
  );
  mockedRoots.mockResolvedValue([{ path: "/Users/alice", label: "Home" }]);
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("FilesPane", () => {
  it("renders both panes, seeded at the server's home and the local default", async () => {
    renderPane();
    await waitFor(() => expect(mockedRemoteList).toHaveBeenCalledWith("s1", REMOTE_HOME));
    // The local pane asks for the backend default (home) with no path.
    expect(mockedLocalList).toHaveBeenCalledWith(null);

    const remote = screen.getByTestId("files-pane-remote");
    expect(await within(remote).findByText("juniper.conf")).toBeInTheDocument();
    // Remote-only column: POSIX permissions.
    expect(within(remote).getByText("rwxr-xr-x")).toBeInTheDocument();
    expect(within(remote).getByText("4.0 KiB")).toBeInTheDocument();

    const local = screen.getByTestId("files-pane-local");
    expect(await within(local).findByText("notes.txt")).toBeInTheDocument();
    // No Perms column on the local side.
    expect(within(local).queryByText("Perms")).toBeNull();
  });

  it("hides dotfiles until the .hidden toggle is pressed", async () => {
    renderPane();
    const remote = screen.getByTestId("files-pane-remote");
    await within(remote).findByText("juniper.conf");
    expect(within(remote).queryByText(".profile")).toBeNull();

    await userEvent.click(screen.getByTestId("files-remote-hidden"));
    expect(await within(remote).findByText(".profile")).toBeInTheDocument();
    expect(useFilesStore.getState().panes["s1"].showHiddenRemote).toBe(true);
  });

  it("orders directories first and re-sorts on a column click", async () => {
    renderPane();
    const remote = screen.getByTestId("files-pane-remote");
    await within(remote).findByText("juniper.conf");

    const names = () =>
      within(remote)
        .getAllByRole("option")
        .map((r) => r.querySelector("span[title]")?.textContent);
    // dirs-first, then name-asc.
    expect(names()).toEqual(["configs", "big.log", "juniper.conf"]);

    // Size ascending: juniper.conf (4 KiB) before big.log (5 MiB).
    await userEvent.click(screen.getByTestId("files-remote-sort-size"));
    expect(useFilesStore.getState().panes["s1"].remoteSort).toEqual({ key: "size", asc: true });
    expect(names()).toEqual(["configs", "juniper.conf", "big.log"]);

    // Clicking the same header flips direction.
    await userEvent.click(screen.getByTestId("files-remote-sort-size"));
    expect(useFilesStore.getState().panes["s1"].remoteSort).toEqual({ key: "size", asc: false });
  });

  it("double-clicking a DIRECTORY navigates into it, never transfers it", async () => {
    renderPane();
    const remote = screen.getByTestId("files-pane-remote");
    await within(remote).findByText("juniper.conf");
    mockedRemoteList.mockClear();

    await userEvent.dblClick(within(remote).getByText("configs"));
    await waitFor(() =>
      expect(mockedRemoteList).toHaveBeenCalledWith("s1", `${REMOTE_HOME}/configs`),
    );
    expect(mockedEnqueue).not.toHaveBeenCalled();
  });

  it("the path bar navigates on Enter and then adopts the backend's CANONICAL path", async () => {
    renderPane();
    await waitFor(() => expect(mockedRemoteList).toHaveBeenCalledWith("s1", REMOTE_HOME));
    // The server canonicalizes the sloppy path the user typed.
    mockedRemoteList.mockResolvedValue(
      listing({ path: "/etc/ssh", parent: "/etc", entries: [entry({ name: "sshd_config" })] }),
    );

    const bar = screen.getByTestId("files-remote-path");
    await userEvent.clear(bar);
    await userEvent.type(bar, "/etc/ssh/{Enter}");

    await waitFor(() => expect(mockedRemoteList).toHaveBeenCalledWith("s1", "/etc/ssh/"));
    // The response's `path` is authoritative — the store (and so the query
    // key every mutation invalidates) follows it, not the typed string.
    await waitFor(() => expect(useFilesStore.getState().panes["s1"].remoteCwd).toBe("/etc/ssh"));
    expect(bar).toHaveValue("/etc/ssh");
  });

  it("Up walks to the listing's parent; Home returns to the login directory", async () => {
    renderPane();
    // Up reads `parent` from the RESOLVED listing, so wait for it to land.
    await within(screen.getByTestId("files-pane-remote")).findByText("configs");

    await userEvent.click(screen.getByTestId("files-remote-up"));
    await waitFor(() => expect(useFilesStore.getState().panes["s1"].remoteCwd).toBe("/var/home"));

    await userEvent.click(screen.getByTestId("files-remote-home"));
    await waitFor(() => expect(useFilesStore.getState().panes["s1"].remoteCwd).toBe(REMOTE_HOME));
  });

  it("disables Up at a root (no parent in the listing)", async () => {
    mockedRemoteList.mockResolvedValue(listing({ path: "/", parent: null, entries: [] }));
    useFilesStore.setState({ panes: {} });
    useFilesStore.getState().ensurePane("s1", "/");
    renderPane();
    await waitFor(() => expect(screen.getByTestId("files-remote-up")).toBeDisabled());
  });

  it("New folder creates the child under the CURRENT directory and refreshes it", async () => {
    renderPane();
    await waitFor(() => expect(mockedRemoteList).toHaveBeenCalledTimes(1));

    await userEvent.click(screen.getByTestId("files-remote-mkdir"));
    await userEvent.type(await screen.findByTestId("file-name-input"), "backups");
    await userEvent.click(screen.getByTestId("file-name-save"));

    await waitFor(() => expect(mockedMkdir).toHaveBeenCalledWith("s1", `${REMOTE_HOME}/backups`));
    // The affected directory's listing is invalidated → refetched.
    await waitFor(() => expect(mockedRemoteList).toHaveBeenCalledTimes(2));
  });

  it("routes the LOCAL pane's New folder to the local IPC, never the remote one", async () => {
    renderPane();
    await waitFor(() => expect(mockedLocalList).toHaveBeenCalled());

    await userEvent.click(screen.getByTestId("files-local-mkdir"));
    await userEvent.type(await screen.findByTestId("file-name-input"), "staging");
    await userEvent.click(screen.getByTestId("file-name-save"));

    await waitFor(() => expect(mockedLocalMkdir).toHaveBeenCalledWith("/Users/alice/staging"));
    expect(mockedMkdir).not.toHaveBeenCalled();
  });

  it("rejects a name with a path separator before any IPC fires", async () => {
    renderPane();
    await userEvent.click(screen.getByTestId("files-remote-mkdir"));
    await userEvent.type(await screen.findByTestId("file-name-input"), "../../.ssh");
    await userEvent.click(screen.getByTestId("file-name-save"));

    expect(await screen.findByText(/path separator/)).toBeInTheDocument();
    expect(mockedMkdir).not.toHaveBeenCalled();
  });

  it("F2 renames the selected entry in place", async () => {
    renderPane();
    const remote = screen.getByTestId("files-pane-remote");
    await userEvent.click(await within(remote).findByText("juniper.conf"));
    fireEvent.keyDown(screen.getByTestId("files-remote-list"), { key: "F2" });

    const input = await screen.findByTestId("file-name-input");
    expect(input).toHaveValue("juniper.conf");
    await userEvent.clear(input);
    await userEvent.type(input, "juniper.conf.bak");
    await userEvent.click(screen.getByTestId("file-name-save"));

    await waitFor(() =>
      expect(mockedRename).toHaveBeenCalledWith(
        "s1",
        `${REMOTE_HOME}/juniper.conf`,
        `${REMOTE_HOME}/juniper.conf.bak`,
      ),
    );
  });

  it("deleting a DIRECTORY confirms with the recursive blast radius and passes recursive:true", async () => {
    renderPane();
    const remote = screen.getByTestId("files-pane-remote");
    await userEvent.click(await within(remote).findByText("configs"));
    fireEvent.keyDown(screen.getByTestId("files-remote-list"), { key: "Delete" });

    expect(await screen.findByText(/Delete "configs"\?/)).toBeInTheDocument();
    expect(screen.getByText(/all its contents on the device/)).toBeInTheDocument();
    expect(mockedDelete).not.toHaveBeenCalled();

    await userEvent.click(screen.getByRole("button", { name: /^delete$/i }));
    await waitFor(() =>
      expect(mockedDelete).toHaveBeenCalledWith("s1", `${REMOTE_HOME}/configs`, true),
    );
  });

  it("deleting a FILE passes recursive:false", async () => {
    renderPane();
    const remote = screen.getByTestId("files-pane-remote");
    await userEvent.click(await within(remote).findByText("juniper.conf"));
    fireEvent.keyDown(screen.getByTestId("files-remote-list"), { key: "Delete" });
    await userEvent.click(await screen.findByRole("button", { name: /^delete$/i }));
    await waitFor(() =>
      expect(mockedDelete).toHaveBeenCalledWith("s1", `${REMOTE_HOME}/juniper.conf`, false),
    );
  });

  it("multi-select: cmd-click adds a row, shift-click extends over render order", async () => {
    renderPane();
    const remote = screen.getByTestId("files-pane-remote");
    await within(remote).findByText("juniper.conf");
    const rows = within(remote).getAllByRole("option"); // configs, big.log, juniper.conf

    fireEvent.click(rows[1]);
    fireEvent.click(rows[2], { metaKey: true });
    expect(rows[1]).toHaveAttribute("data-selected", "true");
    expect(rows[2]).toHaveAttribute("data-selected", "true");
    expect(rows[0]).not.toHaveAttribute("data-selected");

    // Cmd-clicking a selected row toggles it back out.
    fireEvent.click(rows[2], { metaKey: true });
    expect(rows[2]).not.toHaveAttribute("data-selected");

    // Shift extends from the anchor over the rendered order.
    fireEvent.click(rows[0]);
    fireEvent.click(rows[2], { shiftKey: true });
    for (const r of rows) expect(r).toHaveAttribute("data-selected", "true");

    // Deleting the multi-selection names the count, and folders are called out.
    fireEvent.keyDown(screen.getByTestId("files-remote-list"), { key: "Delete" });
    expect(await screen.findByText(/Delete 3 items\?/)).toBeInTheDocument();
    expect(screen.getByText(/1 of them is a folder/)).toBeInTheDocument();
  });

  it("Backspace walks up; Cmd+Backspace deletes the selection instead", async () => {
    renderPane();
    const remote = screen.getByTestId("files-pane-remote");
    await within(remote).findByText("configs");
    const list = screen.getByTestId("files-remote-list");

    // The macOS delete gesture must NOT be read as "walk up".
    fireEvent.click(within(remote).getAllByRole("option")[0]);
    fireEvent.keyDown(list, { key: "Backspace", metaKey: true });
    expect(await screen.findByText(/^Delete "configs"\?$/)).toBeInTheDocument();
    expect(useFilesStore.getState().panes["s1"].remoteCwd).toBe(REMOTE_HOME);
    await userEvent.click(screen.getByRole("button", { name: /cancel/i }));

    // A bare Backspace is the file-manager "up" binding.
    fireEvent.keyDown(list, { key: "Backspace" });
    await waitFor(() => expect(useFilesStore.getState().panes["s1"].remoteCwd).toBe("/var/home"));
  });

  it("surfaces the truncation flag ABOVE the scroller so it stays visible (F5)", async () => {
    mockedRemoteList.mockResolvedValue({ ...remoteListing(), truncated: true });
    renderPane();
    const banner = await screen.findByTestId("files-remote-truncated");
    expect(banner).toHaveTextContent(/truncated/i);
    // It must NOT live inside the virtualized scroll container, where it used
    // to sit below the ~480,000px spacer and render off-screen.
    const scroller = screen.getByTestId("files-remote-list");
    expect(scroller.contains(banner)).toBe(false);
  });

  it("Up recovers from a listing ERROR by deriving the parent from the path (F6)", async () => {
    renderPane();
    const remote = screen.getByTestId("files-pane-remote");
    await within(remote).findByText("configs");
    // A subdir the user can see but not list (permission denied) — so the
    // response carries no `parent` to walk back with.
    mockedRemoteList.mockImplementation(async (_sessionId: string, path: string) => {
      if (path === `${REMOTE_HOME}/configs`) throw new Error("permission denied");
      return path === REMOTE_HOME
        ? remoteListing()
        : listing({ path, parent: "/var/home", entries: [] });
    });

    await userEvent.dblClick(within(remote).getByText("configs"));
    expect(await within(remote).findByText("permission denied")).toBeInTheDocument();

    // Up stays enabled (parent derived from the path string) and walks up,
    // instead of trapping the user in a directory that failed to list.
    const up = screen.getByTestId("files-remote-up");
    expect(up).not.toBeDisabled();
    await userEvent.click(up);
    await waitFor(() => expect(useFilesStore.getState().panes["s1"].remoteCwd).toBe(REMOTE_HOME));
  });

  it("shows an empty-folder notice and a distinct all-hidden notice", async () => {
    mockedRemoteList.mockResolvedValue(listing({ path: REMOTE_HOME, entries: [] }));
    const { unmount } = renderPane();
    expect(await screen.findByText("This folder is empty.")).toBeInTheDocument();
    unmount();

    mockedRemoteList.mockResolvedValue(
      listing({ path: REMOTE_HOME, entries: [entry({ name: ".only-hidden" })] }),
    );
    renderPane();
    expect(await screen.findByText(/Only hidden entries here/)).toBeInTheDocument();
  });

  it("renders the listing error inline", async () => {
    mockedRemoteList.mockRejectedValue(new Error("permission denied"));
    renderPane();
    expect(await screen.findByText("permission denied")).toBeInTheDocument();
  });

  it("the closed event ends the tab and raises the reconnect banner", async () => {
    renderPane();
    await waitFor(() => expect(listeners.has("files:s1:closed")).toBe(true));
    fireClosed("s1");
    expect(useUiStore.getState().sessions[0].ended).toBe(true);
  });

  it("Reconnect re-establishes under the SAME id, keeps both cwds, and refetches", async () => {
    mockedReconnect.mockResolvedValue({ home: REMOTE_HOME });
    useFilesStore.getState().setCwd("s1", "remote", "/etc");
    useUiStore.setState({
      sessions: [{ sessionId: "s1", deviceId: "vEX1", ended: true, kind: "files" }],
    });
    renderPane({ ended: true });

    expect(await screen.findByTestId("files-ended-banner")).toBeInTheDocument();
    // The dead remote pane doesn't keep hammering a closed channel...
    expect(mockedRemoteList).not.toHaveBeenCalled();
    // ...says so instead of claiming the folder is empty...
    expect(
      within(screen.getByTestId("files-pane-remote")).getByText(/Disconnected — reconnect/),
    ).toBeInTheDocument();
    // ...and is read-only while the banner is up.
    expect(screen.getByTestId("files-remote-mkdir")).toBeDisabled();
    // The LOCAL pane keeps working — it has nothing to do with the link.
    expect(
      await within(screen.getByTestId("files-pane-local")).findByText("notes.txt"),
    ).toBeInTheDocument();

    await userEvent.click(screen.getByTestId("files-reconnect"));
    await waitFor(() => expect(mockedReconnect).toHaveBeenCalledWith("s1"));
    // Same session id — the tab un-ends and the cwd is preserved.
    await waitFor(() => expect(useUiStore.getState().sessions[0].ended).toBe(false));
    expect(useFilesStore.getState().panes["s1"].remoteCwd).toBe("/etc");
  });

  it("a failed reconnect keeps the banner up", async () => {
    mockedReconnect.mockRejectedValue(new Error("connection refused"));
    useUiStore.setState({
      sessions: [{ sessionId: "s1", deviceId: "vEX1", ended: true, kind: "files" }],
    });
    renderPane({ ended: true });
    await userEvent.click(await screen.findByTestId("files-reconnect"));
    await waitFor(() => expect(mockedReconnect).toHaveBeenCalled());
    expect(screen.getByTestId("files-ended-banner")).toBeInTheDocument();
    expect(useUiStore.getState().sessions[0].ended).toBe(true);
  });

  it("offers the local roots menu (and not on the remote side)", async () => {
    mockedRoots.mockResolvedValue([
      { path: "/Users/alice", label: "Home" },
      { path: "/", label: "Root" },
    ]);
    renderPane();
    await waitFor(() => expect(screen.getByTestId("files-local-roots")).toBeInTheDocument());
    expect(screen.queryByTestId("files-remote-roots")).toBeNull();

    await userEvent.click(screen.getByTestId("files-local-roots"));
    await userEvent.click(await screen.findByText("Root"));
    await waitFor(() => expect(mockedLocalList).toHaveBeenCalledWith("/"));
  });
});

describe("FilesPane — transfers (v5.0.0 Commit C)", () => {
  /** Wait for both panes' first listing, so `dirOf` has canonical paths. */
  async function renderReady() {
    const result = renderPane();
    await within(screen.getByTestId("files-pane-remote")).findByText("juniper.conf");
    await within(screen.getByTestId("files-pane-local")).findByText("notes.txt");
    return result;
  }

  it("double-clicking a FILE downloads it to the LOCAL pane's cwd", async () => {
    await renderReady();
    await userEvent.dblClick(
      within(screen.getByTestId("files-pane-remote")).getByText("juniper.conf"),
    );

    await waitFor(() =>
      expect(mockedConflicts).toHaveBeenCalledWith({
        session_id: "s1",
        direction: "download",
        items: [{ source_path: `${REMOTE_HOME}/juniper.conf`, dest_dir: LOCAL_HOME }],
      }),
    );
    // No conflict → no dialog, straight to the queue.
    expect(screen.queryByTestId("files-overwrite-dialog")).toBeNull();
    await waitFor(() =>
      expect(mockedEnqueue).toHaveBeenCalledWith({
        session_id: "s1",
        direction: "download",
        policy: "overwrite",
        items: [{ source_path: `${REMOTE_HOME}/juniper.conf`, dest_dir: LOCAL_HOME }],
      }),
    );
  });

  it("double-clicking a LOCAL file uploads it to the REMOTE pane's cwd", async () => {
    await renderReady();
    await userEvent.dblClick(within(screen.getByTestId("files-pane-local")).getByText("notes.txt"));

    await waitFor(() =>
      expect(mockedEnqueue).toHaveBeenCalledWith({
        session_id: "s1",
        direction: "upload",
        policy: "overwrite",
        items: [{ source_path: `${LOCAL_HOME}/notes.txt`, dest_dir: REMOTE_HOME }],
      }),
    );
  });

  it("the toolbar Transfer button moves the whole selection and is disabled without one", async () => {
    await renderReady();
    const remote = screen.getByTestId("files-pane-remote");
    expect(screen.getByTestId("files-remote-transfer")).toBeDisabled();

    const rows = within(remote).getAllByRole("option"); // configs, big.log, juniper.conf
    fireEvent.click(rows[1]);
    fireEvent.click(rows[2], { metaKey: true });
    await userEvent.click(screen.getByTestId("files-remote-transfer"));

    await waitFor(() =>
      expect(mockedEnqueue).toHaveBeenCalledWith(
        expect.objectContaining({
          direction: "download",
          items: [
            { source_path: `${REMOTE_HOME}/big.log`, dest_dir: LOCAL_HOME },
            { source_path: `${REMOTE_HOME}/juniper.conf`, dest_dir: LOCAL_HOME },
          ],
        }),
      ),
    );
  });

  it("offers Download in the remote context menu and Upload in the local one", async () => {
    await renderReady();
    const remote = screen.getByTestId("files-pane-remote");
    fireEvent.click(within(remote).getByText("juniper.conf"));
    fireEvent.contextMenu(within(remote).getByText("juniper.conf"));

    await userEvent.click(await screen.findByTestId("files-remote-ctx-transfer"));
    await waitFor(() =>
      expect(mockedEnqueue).toHaveBeenCalledWith(
        expect.objectContaining({ direction: "download" }),
      ),
    );
    expect(screen.getByTestId("files-remote-transfer")).toHaveAttribute(
      "aria-label",
      "Download selected",
    );
    expect(screen.getByTestId("files-local-transfer")).toHaveAttribute(
      "aria-label",
      "Upload selected",
    );
  });

  it("a top-level conflict raises ONE batch dialog; Overwrite all enqueues with overwrite", async () => {
    mockedConflicts.mockResolvedValue([`${LOCAL_HOME}/juniper.conf`, `${LOCAL_HOME}/big.log`]);
    await renderReady();
    await userEvent.dblClick(
      within(screen.getByTestId("files-pane-remote")).getByText("juniper.conf"),
    );

    const dialog = await screen.findByTestId("files-overwrite-dialog");
    expect(within(dialog).getByText("juniper.conf")).toBeInTheDocument();
    expect(within(dialog).getByText("big.log")).toBeInTheDocument();
    // Nothing is queued until the user decides.
    expect(mockedEnqueue).not.toHaveBeenCalled();

    await userEvent.click(screen.getByTestId("files-overwrite-all"));
    await waitFor(() =>
      expect(mockedEnqueue).toHaveBeenCalledWith(expect.objectContaining({ policy: "overwrite" })),
    );
  });

  it("Skip existing enqueues with the skip policy", async () => {
    mockedConflicts.mockResolvedValue([`${LOCAL_HOME}/juniper.conf`]);
    await renderReady();
    await userEvent.dblClick(
      within(screen.getByTestId("files-pane-remote")).getByText("juniper.conf"),
    );
    await userEvent.click(await screen.findByTestId("files-overwrite-skip"));
    await waitFor(() =>
      expect(mockedEnqueue).toHaveBeenCalledWith(expect.objectContaining({ policy: "skip" })),
    );
  });

  it("Cancel queues nothing at all", async () => {
    mockedConflicts.mockResolvedValue([`${LOCAL_HOME}/juniper.conf`]);
    await renderReady();
    await userEvent.dblClick(
      within(screen.getByTestId("files-pane-remote")).getByText("juniper.conf"),
    );
    await userEvent.click(await screen.findByTestId("files-overwrite-cancel"));
    await waitFor(() => expect(screen.queryByTestId("files-overwrite-dialog")).toBeNull());
    expect(mockedEnqueue).not.toHaveBeenCalled();
  });

  it("summarizes a long conflict list instead of rendering all of it", async () => {
    mockedConflicts.mockResolvedValue(
      Array.from({ length: 11 }, (_, i) => `${LOCAL_HOME}/f${i}.conf`),
    );
    await renderReady();
    await userEvent.dblClick(
      within(screen.getByTestId("files-pane-remote")).getByText("juniper.conf"),
    );
    const dialog = await screen.findByTestId("files-overwrite-dialog");
    expect(within(dialog).getByText("f7.conf")).toBeInTheDocument();
    expect(within(dialog).queryByText("f8.conf")).toBeNull();
    expect(within(dialog).getByText("and 3 more")).toBeInTheDocument();
  });

  it("records the transfer's destination so a finished transfer refreshes the right listing", async () => {
    mockedEnqueue.mockResolvedValue([{ id: "t1", direction: "download", name: "juniper.conf" }]);
    await renderReady();
    await userEvent.dblClick(
      within(screen.getByTestId("files-pane-remote")).getByText("juniper.conf"),
    );

    await waitFor(() =>
      expect(useFilesStore.getState().transferTargets.get("t1")).toEqual({
        sessionId: "s1",
        // A download lands in the LOCAL pane, whose query key is its cwd.
        side: "local",
        destKey: LOCAL_HOME,
        deviceLabel: "vEX1",
      }),
    );
  });

  it("surfaces an enqueue failure as a toast and no queue row", async () => {
    const { toastError } = await import("@/lib/toast");
    mockedEnqueue.mockRejectedValue(new Error("session closed"));
    await renderReady();
    await userEvent.dblClick(
      within(screen.getByTestId("files-pane-remote")).getByText("juniper.conf"),
    );
    await waitFor(() =>
      expect(vi.mocked(toastError)).toHaveBeenCalledWith(
        "Couldn't start the transfer",
        expect.objectContaining({ description: "session closed" }),
      ),
    );
  });

  it("refuses to transfer FROM a dead remote pane", async () => {
    useUiStore.setState({
      sessions: [{ sessionId: "s1", deviceId: "vEX1", ended: true, kind: "files" }],
    });
    renderPane({ ended: true });
    await within(screen.getByTestId("files-pane-local")).findByText("notes.txt");
    // The whole remote toolbar is read-only while the banner is up.
    expect(screen.getByTestId("files-remote-transfer")).toBeDisabled();
    // …and an upload has nowhere to land, so it never reaches the backend.
    await userEvent.dblClick(within(screen.getByTestId("files-pane-local")).getByText("notes.txt"));
    expect(mockedConflicts).not.toHaveBeenCalled();
  });

  it("gates transfers on a dead session but keeps LOCAL browsing working (F4)", async () => {
    const { toastError } = await import("@/lib/toast");
    useUiStore.setState({
      sessions: [{ sessionId: "s1", deviceId: "vEX1", ended: true, kind: "files" }],
    });
    renderPane({ ended: true });
    const local = screen.getByTestId("files-pane-local");
    await within(local).findByText("notes.txt");

    // Transfer is disabled on BOTH sides — a clear affordance, not a silent
    // no-op (remote is fully read-only; local browses but can't upload to a
    // closed session).
    expect(screen.getByTestId("files-local-transfer")).toBeDisabled();
    expect(screen.getByTestId("files-remote-transfer")).toBeDisabled();

    // A local file double-click still reaches `transferEntries`, which now
    // surfaces a toast instead of silently doing nothing.
    await userEvent.dblClick(within(local).getByText("notes.txt"));
    expect(vi.mocked(toastError)).toHaveBeenCalledWith(
      "Reconnect before transferring — this file transfer session is closed.",
    );
    expect(mockedConflicts).not.toHaveBeenCalled();

    // But LOCAL browsing is untouched — navigating into a folder still lists.
    await userEvent.dblClick(within(local).getByText("Downloads"));
    await waitFor(() => expect(mockedLocalList).toHaveBeenCalledWith(`${LOCAL_HOME}/Downloads`));
  });

  it("refuses a SECOND transfer while the overwrite prompt is up, keeping the parked one (F1)", async () => {
    const { toastInfo } = await import("@/lib/toast");
    mockedConflicts.mockResolvedValue([`${LOCAL_HOME}/juniper.conf`]);
    await renderReady();
    const remote = screen.getByTestId("files-pane-remote");

    // First transfer raises the batch overwrite dialog and parks its plan.
    await userEvent.dblClick(within(remote).getByText("juniper.conf"));
    await screen.findByTestId("files-overwrite-dialog");

    // A second transfer while the dialog is up would clobber the single
    // `pendingTransfer` slot — refuse it with a nudge instead. (fireEvent, not
    // userEvent: the modal sets `pointer-events: none` on everything behind
    // it, which userEvent refuses to click through.)
    fireEvent.dblClick(within(remote).getByText("big.log"));
    expect(vi.mocked(toastInfo)).toHaveBeenCalledWith("Finish the current transfer prompt first");
    // The first plan is still parked (its dialog still up), not discarded.
    expect(screen.getByTestId("files-overwrite-dialog")).toBeInTheDocument();
  });

  it("renders the global queue strip once a transfer exists", async () => {
    await renderReady();
    expect(screen.queryByTestId("transfer-queue")).toBeNull();
    act(() => {
      useFilesStore.getState().applyTransferUpdate({
        session_id: "s1",
        id: "t1",
        direction: "download",
        state: "running",
        name: "juniper.conf",
        bytes_done: 1,
        bytes_total: 2,
        files_done: 0,
        files_total: null,
        rate_bps: 1,
        skipped: 0,
        warnings: [],
        error: null,
      });
    });
    expect(screen.getByTestId("transfer-queue")).toBeInTheDocument();
  });
});

describe("FilesPane — drag and drop (v5.0.0 Commit C)", () => {
  async function renderReady() {
    const result = renderPane();
    await within(screen.getByTestId("files-pane-remote")).findByText("juniper.conf");
    await within(screen.getByTestId("files-pane-local")).findByText("notes.txt");
    return result;
  }

  it("a row drag carries the side, session, and absolute paths under our own MIME type", async () => {
    await renderReady();
    const remote = screen.getByTestId("files-pane-remote");
    const rows = within(remote).getAllByRole("option");
    // Dragging an UNSELECTED row drags just it (the Finder convention).
    const dt = fakeDataTransfer();
    fireEvent.dragStart(rows[2], { dataTransfer: dt });

    expect(JSON.parse(dt.getData(FILES_DND_MIME))).toEqual({
      side: "remote",
      sessionId: "s1",
      paths: [`${REMOTE_HOME}/juniper.conf`],
    });
    expect(rows[2]).toHaveAttribute("data-selected", "true");
  });

  it("dragging a SELECTED row drags the whole selection", async () => {
    await renderReady();
    const rows = within(screen.getByTestId("files-pane-remote")).getAllByRole("option");
    fireEvent.click(rows[1]);
    fireEvent.click(rows[2], { metaKey: true });

    const dt = fakeDataTransfer();
    fireEvent.dragStart(rows[1], { dataTransfer: dt });
    expect(JSON.parse(dt.getData(FILES_DND_MIME)).paths).toEqual([
      `${REMOTE_HOME}/big.log`,
      `${REMOTE_HOME}/juniper.conf`,
    ]);
  });

  it("dropping remote rows on the LOCAL pane downloads them there", async () => {
    await renderReady();
    const local = screen.getByTestId("files-pane-local");
    const rows = within(screen.getByTestId("files-pane-remote")).getAllByRole("option");

    const dt = fakeDataTransfer();
    fireEvent.dragStart(rows[2], { dataTransfer: dt });
    // The drop target only lights up while a drag from the OTHER pane is live.
    fireEvent.dragOver(local, { dataTransfer: dt });
    expect(local).toHaveAttribute("data-drop-target", "true");

    fireEvent.drop(local, { dataTransfer: dt });
    await waitFor(() =>
      expect(mockedEnqueue).toHaveBeenCalledWith(
        expect.objectContaining({
          direction: "download",
          items: [{ source_path: `${REMOTE_HOME}/juniper.conf`, dest_dir: LOCAL_HOME }],
        }),
      ),
    );
    expect(local).not.toHaveAttribute("data-drop-target");
  });

  it("dropping local rows on the REMOTE pane uploads them there", async () => {
    await renderReady();
    const remote = screen.getByTestId("files-pane-remote");
    const rows = within(screen.getByTestId("files-pane-local")).getAllByRole("option");

    const dt = fakeDataTransfer();
    fireEvent.dragStart(rows[1], { dataTransfer: dt }); // notes.txt
    fireEvent.dragOver(remote, { dataTransfer: dt });
    expect(remote).toHaveAttribute("data-drop-target", "true");
    fireEvent.drop(remote, { dataTransfer: dt });

    await waitFor(() =>
      expect(mockedEnqueue).toHaveBeenCalledWith(
        expect.objectContaining({
          direction: "upload",
          items: [{ source_path: `${LOCAL_HOME}/notes.txt`, dest_dir: REMOTE_HOME }],
        }),
      ),
    );
  });

  it("a SAME-side drop is a no-op — and never highlights", async () => {
    await renderReady();
    const remote = screen.getByTestId("files-pane-remote");
    const rows = within(remote).getAllByRole("option");

    const dt = fakeDataTransfer();
    fireEvent.dragStart(rows[2], { dataTransfer: dt });
    fireEvent.dragOver(remote, { dataTransfer: dt });
    expect(remote).not.toHaveAttribute("data-drop-target");
    fireEvent.drop(remote, { dataTransfer: dt });
    expect(mockedConflicts).not.toHaveBeenCalled();
  });

  it("a drop with no active row drag is a no-op", async () => {
    // The transfer is completed from the stashed drag payload, never from
    // `dataTransfer` — so a stray drop with nothing dragged (or a foreign
    // payload another app put on the pasteboard) transfers nothing. The
    // `canAcceptDrop` gate (only true while OUR drag is live) refuses it.
    await renderReady();
    const local = screen.getByTestId("files-pane-local");
    fireEvent.drop(local, { dataTransfer: fakeDataTransfer() });
    expect(mockedConflicts).not.toHaveBeenCalled();
    expect(mockedEnqueue).not.toHaveBeenCalled();
  });

  it("completes an internal drag via the NATIVE drop (the macOS/wry path)", async () => {
    // On macOS wry consumes the DOM drop, so the transfer must ride the
    // native drag event. Drag a local row, then fire a native drop over the
    // pane → it uploads to the remote cwd (target = side opposite the source).
    await renderReady();
    await waitFor(() => expect(dragDropHandlers.length).toBe(1));
    const rows = within(screen.getByTestId("files-pane-local")).getAllByRole("option");
    fireEvent.dragStart(rows[1], { dataTransfer: fakeDataTransfer() }); // notes.txt
    fireOsDrag({ type: "drop", paths: [] }); // default position is inside the pane
    await waitFor(() =>
      expect(mockedEnqueue).toHaveBeenCalledWith(
        expect.objectContaining({
          direction: "upload",
          items: [{ source_path: `${LOCAL_HOME}/notes.txt`, dest_dir: REMOTE_HOME }],
        }),
      ),
    );
  });

  it("lights the opposite pane's drop-ring from the native drag event", async () => {
    // The DOM `dragover` that normally lights the ring never fires under wry;
    // the native over event drives it onto the OPPOSITE (target) pane.
    await renderReady();
    await waitFor(() => expect(dragDropHandlers.length).toBe(1));
    const local = screen.getByTestId("files-pane-local");
    const remote = screen.getByTestId("files-pane-remote");
    fireEvent.dragStart(within(local).getAllByRole("option")[1], {
      dataTransfer: fakeDataTransfer(),
    });
    fireOsDrag({ type: "over" });
    expect(remote).toHaveAttribute("data-drop-target", "true");
    expect(local).not.toHaveAttribute("data-drop-target");
  });

  it("completes an internal drag on dragEnd when released over the pane", async () => {
    // The PRIMARY trigger on macOS: the native `drop` is async and arrives
    // after `dragend`, so `dragend` (synchronous, reliable) does the transfer
    // when the pointer was over the pane (tracked via the native over event).
    await renderReady();
    await waitFor(() => expect(dragDropHandlers.length).toBe(1));
    const rows = within(screen.getByTestId("files-pane-local")).getAllByRole("option");
    fireEvent.dragStart(rows[1], { dataTransfer: fakeDataTransfer() }); // notes.txt
    fireOsDrag({ type: "over" }); // pointer over the pane
    fireEvent.dragEnd(rows[1]); // release
    await waitFor(() =>
      expect(mockedEnqueue).toHaveBeenCalledWith(
        expect.objectContaining({
          direction: "upload",
          items: [{ source_path: `${LOCAL_HOME}/notes.txt`, dest_dir: REMOTE_HOME }],
        }),
      ),
    );
  });

  it("cancels an internal drag released OUTSIDE the pane", async () => {
    await renderReady();
    await waitFor(() => expect(dragDropHandlers.length).toBe(1));
    const rows = within(screen.getByTestId("files-pane-local")).getAllByRole("option");
    fireEvent.dragStart(rows[1], { dataTransfer: fakeDataTransfer() });
    fireOsDrag({ type: "leave" }); // pointer left the pane before release
    fireEvent.dragEnd(rows[1]);
    expect(mockedEnqueue).not.toHaveBeenCalled();
    expect(mockedConflicts).not.toHaveBeenCalled();
  });

  it("a trailing native echo after an internal drag does NOT raise the OS overlay", async () => {
    // Tauri delivers the native drag events asynchronously, so an over/drop
    // echo of the in-app drag can land AFTER `dragend` cleared the internal
    // state. Carrying no file paths, it must not be mistaken for a Finder
    // drag and light the full-pane "Drop to upload" overlay.
    await renderReady();
    await waitFor(() => expect(dragDropHandlers.length).toBe(1));
    const rows = within(screen.getByTestId("files-pane-local")).getAllByRole("option");
    fireEvent.dragStart(rows[1], { dataTransfer: fakeDataTransfer() });
    fireOsDrag({ type: "over" }); // during the drag → internal branch (ring)
    fireEvent.dragEnd(rows[1]); // release → transfer, internal state cleared
    fireOsDrag({ type: "over" }); // trailing echo of the SAME drag (no paths)
    fireOsDrag({ type: "drop", paths: [] });
    expect(screen.queryByTestId("files-os-drop-overlay")).toBeNull();
  });

  it("the remote pane refuses drops while the session is dead", async () => {
    useUiStore.setState({
      sessions: [{ sessionId: "s1", deviceId: "vEX1", ended: true, kind: "files" }],
    });
    renderPane({ ended: true });
    const local = await screen.findByTestId("files-pane-local");
    await within(local).findByText("notes.txt");
    const remote = screen.getByTestId("files-pane-remote");

    const dt = fakeDataTransfer();
    fireEvent.dragStart(within(local).getAllByRole("option")[1], { dataTransfer: dt });
    fireEvent.dragOver(remote, { dataTransfer: dt });
    expect(remote).not.toHaveAttribute("data-drop-target");
    fireEvent.drop(remote, { dataTransfer: dt });
    expect(mockedConflicts).not.toHaveBeenCalled();
  });

  it("an OS file drag shows the upload overlay and enqueues to the remote cwd on drop", async () => {
    await renderReady();
    await waitFor(() => expect(dragDropHandlers.length).toBe(1));

    fireOsDrag({ type: "enter", paths: ["/Users/alice/from-finder.conf"] });
    const overlay = screen.getByTestId("files-os-drop-overlay");
    expect(overlay).toHaveTextContent("Drop to upload to vEX1");
    expect(overlay).toHaveTextContent(REMOTE_HOME);

    fireOsDrag({ type: "over" });
    expect(screen.getByTestId("files-os-drop-overlay")).toBeInTheDocument();

    fireOsDrag({ type: "drop", paths: ["/Users/alice/from-finder.conf", "/tmp/two.txt"] });
    expect(screen.queryByTestId("files-os-drop-overlay")).toBeNull();
    await waitFor(() =>
      expect(mockedEnqueue).toHaveBeenCalledWith(
        expect.objectContaining({
          direction: "upload",
          items: [
            { source_path: "/Users/alice/from-finder.conf", dest_dir: REMOTE_HOME },
            { source_path: "/tmp/two.txt", dest_dir: REMOTE_HOME },
          ],
        }),
      ),
    );
  });

  it("an OS drag that leaves hides the overlay without enqueueing", async () => {
    await renderReady();
    await waitFor(() => expect(dragDropHandlers.length).toBe(1));
    fireOsDrag({ type: "enter", paths: ["/tmp/a"] });
    expect(screen.getByTestId("files-os-drop-overlay")).toBeInTheDocument();
    fireOsDrag({ type: "leave" });
    expect(screen.queryByTestId("files-os-drop-overlay")).toBeNull();
    expect(mockedConflicts).not.toHaveBeenCalled();
  });

  it("only the ACTIVE Files tab listens for OS drops", async () => {
    // A backgrounded tab stays mounted (Radix forceMount), so without this
    // guard every open Files tab would enqueue the same dropped files.
    renderPane({ active: false });
    await within(screen.getByTestId("files-pane-local")).findByText("notes.txt");
    expect(dragDropHandlers).toHaveLength(0);
  });

  it("an OS drop on a dead session says to reconnect instead of queueing", async () => {
    const { toastError } = await import("@/lib/toast");
    useUiStore.setState({
      sessions: [{ sessionId: "s1", deviceId: "vEX1", ended: true, kind: "files" }],
    });
    renderPane({ ended: true });
    await waitFor(() => expect(dragDropHandlers.length).toBe(1));

    fireOsDrag({ type: "drop", paths: ["/tmp/a.conf"] });
    expect(vi.mocked(toastError)).toHaveBeenCalledWith(
      "Reconnect before uploading — this file transfer session is closed.",
    );
    expect(mockedConflicts).not.toHaveBeenCalled();
  });

  it("ignores an OS drop whose position is OUTSIDE the pane rect (F1)", async () => {
    await renderReady();
    await waitFor(() => expect(dragDropHandlers.length).toBe(1));

    // The webview event is window-scoped: a drop on the sidebar / chat / a
    // modal reports a position outside the pane's 800×600 box.
    fireOsDrag({ type: "enter", paths: ["/tmp/a"], position: { x: 4000, y: 4000 } });
    // Overlay only lights up when the pointer is over the pane.
    expect(screen.queryByTestId("files-os-drop-overlay")).toBeNull();

    fireOsDrag({ type: "drop", paths: ["/tmp/a"], position: { x: 4000, y: 4000 } });
    // A drop outside the pane must NOT upload to the device.
    expect(mockedConflicts).not.toHaveBeenCalled();
    expect(mockedEnqueue).not.toHaveBeenCalled();
  });

  it("an internal row drag does NOT raise the OS-upload overlay", async () => {
    // On macOS Tauri echoes an in-webview row drag as a native enter/over, so
    // without the internal-drag guard the full-pane "Drop to upload" overlay
    // would appear and swallow the intra-pane drop. Dragging between the panes
    // must stay a pure HTML5 transfer.
    await renderReady();
    await waitFor(() => expect(dragDropHandlers.length).toBe(1));
    const local = screen.getByTestId("files-pane-local");
    await within(local).findByText("notes.txt");

    // Start a row drag (sets the internal-drag ref synchronously).
    const rows = within(local).getAllByRole("option");
    fireEvent.dragStart(rows[1], { dataTransfer: fakeDataTransfer() });

    // The echoed native enter over the pane must be ignored — no overlay.
    fireOsDrag({ type: "enter", paths: ["/echoed/by/tauri"] });
    expect(screen.queryByTestId("files-os-drop-overlay")).toBeNull();

    // Once the row drag ends, a genuine Finder drop works again.
    fireEvent.dragEnd(rows[1]);
    fireOsDrag({ type: "enter", paths: ["/tmp/real.conf"] });
    expect(screen.getByTestId("files-os-drop-overlay")).toBeInTheDocument();
  });
});
