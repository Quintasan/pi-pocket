// Publishing Pi Pocket on the tailnet: tailscaled terminates HTTPS on 443 and proxies to the server on loopback, so the
// server keeps speaking plain http and every request arrives with X-Forwarded-Proto: https and the original Host.
import { spawnSync } from "node:child_process";

/** The first Tailscale that has `serve --bg`; older ones only have a positional form that was removed later. */
export const TAILSCALE_MIN_VERSION: readonly [number, number, number] = [1, 52, 0];
/** Tailscale serves a node on 443, the port every device expects https on. */
export const SERVE_PORT: number = 443;

const MINIMUM = `${TAILSCALE_MIN_VERSION[0]}.${TAILSCALE_MIN_VERSION[1]}`;
/** The Tailscale CLI has no timeout of its own and waits forever on a hung daemon, so every command gets this long. */
const TIMEOUT_MS = 10_000;
/** Reading the status of the daemon is local and quick, so a probe that hangs is abandoned sooner than a mount is. */
const PROBE_TIMEOUT_MS = 3_000;

const NOT_RUNNING = "Tailscale is not running or not signed in. Run: tailscale up";
const NOT_AUTHORIZED = "This machine is waiting for approval in the tailnet's admin console.";
const NO_CERTIFICATES =
    "HTTPS certificates are off in this tailnet. In the admin console, open DNS and enable MagicDNS and HTTPS certificates, then try again.";
const UNREADABLE =
    'Pi Pocket could not read the "tailscale serve status" output. Update Tailscale, then try again.';

/** What one run of the CLI said; `message` is set instead of the output when it failed. */
type Run = { ok: true; out: string; err: string } | { ok: false; message: string };
/** The serve config, as `tailscale serve status --json` printed it. */
type ConfigRun = { ok: true; config: unknown } | { ok: false; message: string };

export type PortState =
    | { kind: "free" }
    | { kind: "ours"; url: string }
    | { kind: "taken"; detail: string }
    | { kind: "funnel"; detail: string };

export interface ServeEvents {
    ready(url: string): void;
    problem(line: string): void;
}

export type ServeResult =
    { ok: true; url: string; adopted: boolean } | { ok: false; message: string };

/** The first `1.2.3` line of `tailscale version`, or of anything else that starts with one. */
export function parseTailscaleVersion(text: string): number[] | undefined {
    const match = /^(\d+)\.(\d+)\.(\d+)/m.exec(text);

    if (match === null) {
        return undefined;
    }

    return [Number(match[1]), Number(match[2]), Number(match[3])];
}

export function serveSupported(version: number[] | undefined): boolean {
    if (version === undefined) {
        return false;
    }

    for (let i = 0; i < TAILSCALE_MIN_VERSION.length; i += 1) {
        const found = version[i] ?? 0;
        const needed = TAILSCALE_MIN_VERSION[i] ?? 0;

        if (found !== needed) {
            return found > needed;
        }
    }

    return true;
}

/**
 * The address this node serves `port` on, when `tailscale serve status --json` has something to say about it there. The
 * status is read after mounting because only tailscaled knows whether the mount took, and a certificate whose name
 * differs from the node's own would change the address.
 */
export function serveUrlOf(config: unknown, dnsName: string, port: number): string | undefined {
    const host = tailnetHost(dnsName);

    if (host === undefined) {
        return undefined;
    }

    // The config spells the name the way the control plane gave it to tailscaled, which need not match the case here.
    if (entryKey(recordOf(recordOf(config)?.Web), host, port) === undefined) {
        return undefined;
    }

    return serveUrl(host, port);
}

/** Why this node cannot serve anything yet, in terms someone can act on; undefined when it can. */
export function preflightProblem(status: unknown): string | undefined {
    const settings = recordOf(status);

    if (settings === undefined) {
        return NOT_RUNNING;
    }

    const backend = settings.BackendState;

    // A node the tailnet has not admitted yet is signed in, so it waits on the admin console rather than on `tailscale up`.
    if (backend === "NeedsMachineAuth") {
        return NOT_AUTHORIZED;
    }

    // NeedsLogin, Stopped and NoState, like a missing backend state, all mean there is nothing to serve into.
    if (backend !== "Running") {
        return NOT_RUNNING;
    }

    // Self is null while the node is logged out, and a node that is not in the tailnet cannot be served into it.
    if (recordOf(settings.Self) === undefined) {
        return NOT_RUNNING;
    }

    // CertDomains comes from the control plane and is empty unless HTTPS certificates are enabled in the admin console:
    // the one safe preflight for the certificate the mount needs.
    const certificates = settings.CertDomains;

    if (!Array.isArray(certificates) || certificates.length === 0) {
        return NO_CERTIFICATES;
    }

    return undefined;
}

/**
 * Who holds `port` on this node, and whether that is this Pi Pocket's own mount at `/`. `localPort` is the server's own
 * port on loopback, which is what a mount of ours proxies to.
 */
export function portState(
    config: unknown,
    dnsName: string,
    port: number,
    localPort: number,
): PortState {
    const host = tailnetHost(dnsName);
    const settings = recordOf(config);
    const allowFunnel = recordOf(settings?.AllowFunnel);
    const funnelKey = host === undefined ? undefined : entryKey(allowFunnel, host, port);

    // Funnel comes before the mounts: it publishes the port to the whole internet, which matters more than who else, or
    // we ourselves, holds a path on it. Older and simple configs key AllowFunnel by port alone.
    if (
        allowFunnel?.[String(port)] === true ||
        (funnelKey !== undefined && allowFunnel?.[funnelKey] === true)
    ) {
        return { kind: "funnel", detail: webKey(host ?? dnsName, port) };
    }

    const mount = host === undefined ? undefined : mountAt(config, dnsName, port);

    if (host !== undefined && mount !== undefined) {
        // Our own mount can be spelled several ways, so the target is compared rather than the exact string: it is ours
        // while it points at this server's own loopback port, whoever wrote it down.
        if (sameLocalTarget(mount.Proxy, localPort)) {
            return { kind: "ours", url: serveUrl(host, port) };
        }

        return {
            kind: "taken",
            detail: typeof mount.Proxy === "string" ? mount.Proxy : 'another mount at "/"',
        };
    }

    // HTTPS on the port is how tailscaled terminates TLS for the mounts above, ours included, so on its own it holds
    // nothing. A TCP forward does: it hands the whole port to something that is not http.
    const forward = recordOf(recordOf(settings?.TCP)?.[String(port)])?.TCPForward;

    if (typeof forward === "string" && forward !== "") {
        return { kind: "taken", detail: `a TCP forward to ${forward}` };
    }

    return { kind: "free" };
}

/**
 * Whether `proxy` is a proxy target on this machine's own loopback at exactly `port`. Serve records a target as written,
 * so `localhost:8787`, `127.0.0.1:8787` and `http://[::1]:8787` all name the same local server as `http://127.0.0.1:8787`.
 */
export function sameLocalTarget(proxy: unknown, port: number): boolean {
    if (typeof proxy !== "string") {
        return false;
    }

    const text = proxy.trim();

    if (text === "") {
        return false;
    }

    const withScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(text) ? text : `http://${text}`;
    let target: URL;

    try {
        target = new URL(withScheme);
    } catch {
        return false;
    }

    if (!LOOPBACK_HOSTS.has(target.hostname.toLowerCase())) {
        return false;
    }

    const targetPort =
        target.port === "" ? (target.protocol === "https:" ? 443 : 80) : Number(target.port);

    return targetPort === port;
}

/**
 * Pi Pocket's address on the tailnet, served by tailscaled itself: one CLI command mounts it, and no process of ours
 * keeps running afterwards. A mount that is already ours is adopted rather than mounted again, so restarting Pi Pocket
 * leaves the address someone is using where it is.
 */
export class TailscaleServe {
    readonly #binary: string;
    readonly #port: number;
    readonly #events: ServeEvents;
    /**
     * Whether this run tried to put a mount at `/`, so a later stop removes only what this run is responsible for. An
     * attempt counts even when the CLI did not answer: only the scoped `off` can tell.
     */
    #published = false;

    /**
     * `binary` is the tailscale CLI to run, and `port` the local server it should proxy to: the tailnet port is always
     * SERVE_PORT.
     */
    constructor(binary: string, port: number, events: ServeEvents) {
        this.#binary = binary;
        this.#port = port;
        this.#events = events;
    }

    async start(): Promise<ServeResult> {
        const versionRun = this.#run(["version"]);

        if (!versionRun.ok) {
            return { ok: false, message: versionRun.message };
        }

        const version = parseTailscaleVersion(`${versionRun.out}\n${versionRun.err}`);

        if (version === undefined) {
            return {
                ok: false,
                message: `Pi Pocket could not tell which Tailscale is installed. Version ${MINIMUM} or newer is needed; update Tailscale.`,
            };
        }

        if (!serveSupported(version)) {
            return {
                ok: false,
                message: `Tailscale ${version.join(".")} is too old for serve. Version ${MINIMUM} or newer is needed; update Tailscale.`,
            };
        }

        const statusRun = this.#run(["status", "--json"]);

        if (!statusRun.ok) {
            return { ok: false, message: statusRun.message };
        }

        const status = parseJson(statusRun.out);
        const problem = preflightProblem(status);

        if (problem !== undefined) {
            return { ok: false, message: problem };
        }

        const dnsName = dnsNameOf(status) ?? "";
        // The node's own name is what every message about it should use; a node with none cannot be served by name.
        const servedName = tailnetHost(dnsName) ?? "this node";
        const proxy = loopback(this.#port);
        const before = this.#serveConfig();

        if (!before.ok) {
            return { ok: false, message: before.message };
        }

        const state = portState(before.config, dnsName, SERVE_PORT, this.#port);

        if (state.kind === "funnel") {
            // Mounting `/` under Funnel would put Pi Pocket on the internet, not just on the tailnet the menu promises.
            return {
                ok: false,
                message: `Tailscale Funnel is on for ${servedName}, which would publish Pi Pocket to the internet. Turn it off with "tailscale funnel --https=${SERVE_PORT} off", then try again.`,
            };
        }

        if (state.kind === "taken") {
            return {
                ok: false,
                message: `Port ${SERVE_PORT} is already served by ${state.detail}. Pi Pocket will not replace it. Free it with "tailscale serve --https=${SERVE_PORT} --set-path=/ off", or pick another access mode.`,
            };
        }

        const adopted = state.kind === "ours";

        // A mount command that timed out may still have been applied by tailscaled, and nothing else can tell us whether
        // it was: counting it as attempted before it runs is what lets stop() take it away again.
        this.#published = true;

        if (!adopted) {
            // --set-path=/ keeps the mount to this one path, so removing it later cannot take another mount with it.
            const mounted = this.#run([
                "serve",
                "--bg",
                `--https=${SERVE_PORT}`,
                "--set-path=/",
                proxy,
            ]);

            if (!mounted.ok) {
                return { ok: false, message: mounted.message };
            }
        }

        const after = this.#serveConfig();
        const url = after.ok ? serveUrlOf(after.config, dnsName, SERVE_PORT) : undefined;

        if (url === undefined) {
            // Only tailscaled's own report is worth opening: Self.DNSName would name an address nothing serves when the
            // mount did not take, or when someone removed it in between. main removes the mount after a failed start.
            return {
                ok: false,
                message: after.ok
                    ? `Tailscale Serve reports no mount for ${servedName}:${SERVE_PORT}. Check "tailscale serve status".`
                    : after.message,
            };
        }

        this.#events.ready(url);

        return { ok: true, url, adopted };
    }

    async stop(): Promise<void> {
        if (!this.#published) {
            return;
        }

        this.#published = false;

        const removed = this.#run(["serve", `--https=${SERVE_PORT}`, "--set-path=/", "off"]);

        // An `off` with no handler under it, or with no serve config at all, has nothing to remove: that is what a mount
        // that never took leaves behind, and it is not a problem to report.
        if (!removed.ok && !missingMount(removed.message)) {
            this.#events.problem(removed.message);
        }
    }

    #serveConfig(): ConfigRun {
        return readServeConfig(this.#binary);
    }

    #run(args: string[]): Run {
        return runTailscale(this.#binary, args);
    }
}

/**
 * Remove the mount a crashed launcher left at `/` for `port`, so the next start finds it free or adopts it instead of
 * refusing its own remains. This never throws: a problem is said through `events?.problem`, and the answer is whether a
 * mount of ours was there to remove.
 */
export async function removeStaleServe(
    binary: string,
    port: number,
    events?: ServeEvents,
): Promise<boolean> {
    try {
        const statusRun = runTailscale(binary, ["status", "--json"], PROBE_TIMEOUT_MS);

        if (!statusRun.ok) {
            events?.problem(statusRun.message);

            return false;
        }

        const dnsName = dnsNameOf(parseJson(statusRun.out));

        if (dnsName === undefined) {
            return false;
        }

        const before = readServeConfig(binary, PROBE_TIMEOUT_MS);

        if (!before.ok) {
            events?.problem(before.message);

            return false;
        }

        const mount = mountAt(before.config, dnsName, SERVE_PORT);

        // Only a `/` of ours is ours to remove: the scoped `off` cannot take another mount or another path with it.
        if (mount === undefined || !sameLocalTarget(mount.Proxy, port)) {
            return false;
        }

        const removed = runTailscale(binary, [
            "serve",
            `--https=${SERVE_PORT}`,
            "--set-path=/",
            "off",
        ]);

        if (!removed.ok) {
            events?.problem(removed.message);

            return false;
        }

        return true;
    } catch (error) {
        // A stale mount is tidying up before the real start, so nothing in here is worth failing the start over.
        events?.problem(error instanceof Error ? error.message : String(error));

        return false;
    }
}

function loopback(port: number): string {
    return `http://127.0.0.1:${port}`;
}

/** One CLI command, bounded by `timeout` so a hung daemon cannot hang Pi Pocket with it. */
function runTailscale(binary: string, args: string[], timeout = TIMEOUT_MS): Run {
    const result = spawnSync(binary, args, {
        timeout,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
    });
    const error = result.error;

    if (error !== undefined) {
        const timedOut = "code" in error && error.code === "ETIMEDOUT";

        return {
            ok: false,
            message: timedOut
                ? `"tailscale ${args.join(" ")}" did not answer within ${timeout / 1000} seconds. Tailscale may be hung: restart it, then try again.`
                : `Could not run ${binary}: ${error.message}`,
        };
    }

    const out = result.stdout;
    const err = result.stderr;

    if (result.status !== 0) {
        return { ok: false, message: complaint(err, out, args) };
    }

    return { ok: true, out, err };
}

function readServeConfig(binary: string, timeout = TIMEOUT_MS): ConfigRun {
    const run = runTailscale(binary, ["serve", "status", "--json"], timeout);

    if (!run.ok) {
        return run;
    }

    // `{}`, a missing Web, and `null` all mean nothing is served; unparsable output is not the same thing.
    const config = parseJson(run.out);

    if (config === undefined) {
        return { ok: false, message: UNREADABLE };
    }

    return { ok: true, config };
}

/** Whether a failed `off` is tailscaled saying there was nothing mounted under that path. */
function missingMount(message: string): boolean {
    const text = message.toLowerCase();

    return (
        text.includes("does not exist") ||
        text.includes("no handler") ||
        text.includes("no serve config")
    );
}

/** Why the CLI refused, in terms someone can act on, or its own last word. */
function complaint(err: string, out: string, args: string[]): string {
    if (err.includes("serve config denied")) {
        return 'Run "sudo tailscale set --operator=$USER" once, so Pi Pocket may configure serve.';
    }

    // Tailscale has reworded this more than once, and says it either way when nothing is listening on the socket.
    const said = `${err}\n${out}`.toLowerCase();

    if (
        said.includes("failed to connect to local tailscale daemon") ||
        said.includes("failed to connect to local tailscale service")
    ) {
        return "Tailscale is not running on this machine. Start it (or run: tailscale up), then try again.";
    }

    return (
        lastLine(err) ?? lastLine(out) ?? `"tailscale ${args.join(" ")}" failed without saying why.`
    );
}

function lastLine(text: string): string | undefined {
    const lines = text
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter((line) => line !== "");

    return lines.at(-1);
}

function parseJson(text: string): unknown {
    try {
        return JSON.parse(text);
    } catch {
        return undefined;
    }
}

function recordOf(value: unknown): Record<string, unknown> | undefined {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
        return undefined;
    }

    return value as Record<string, unknown>;
}

/** The hosts that name this machine itself; `URL` keeps the brackets on an IPv6 literal. */
const LOOPBACK_HOSTS: ReadonlySet<string> = new Set(["127.0.0.1", "localhost", "[::1]", "::1"]);

/** The node's name without Tailscale's trailing dot. */
function tailnetHost(dnsName: string): string | undefined {
    const host = dnsName.trim().replace(/\.+$/, "");

    return host === "" ? undefined : host;
}

/** ServeConfig keys its mounts by "<dnsname>:<port>". */
function webKey(host: string, port: number): string {
    return `${host}:${port}`;
}

/**
 * The key `record` holds for `host` and `port`, in the case it spells the name itself: Tailscale prints the DNS name the
 * way the control plane gave it, which need not match the case of the one read from `tailscale status`.
 */
function entryKey(
    record: Record<string, unknown> | undefined,
    host: string,
    port: number,
): string | undefined {
    if (record === undefined) {
        return undefined;
    }

    const wanted = webKey(host, port).toLowerCase();

    return Object.keys(record).find((key) => key.toLowerCase() === wanted);
}

/** The `/` mount this node holds on `port`, when `tailscale serve status --json` reports one. */
function mountAt(
    config: unknown,
    dnsName: string,
    port: number,
): Record<string, unknown> | undefined {
    const host = tailnetHost(dnsName);

    if (host === undefined) {
        return undefined;
    }

    const web = recordOf(recordOf(config)?.Web);
    const key = entryKey(web, host, port);
    const entry = key === undefined ? undefined : recordOf(web?.[key]);

    return recordOf(recordOf(entry?.Handlers)?.["/"]);
}

function serveUrl(host: string, port: number): string {
    return port === SERVE_PORT ? `https://${host}/` : `https://${host}:${port}/`;
}

function dnsNameOf(status: unknown): string | undefined {
    const name = recordOf(recordOf(status)?.Self)?.DNSName;

    return typeof name === "string" ? name : undefined;
}
