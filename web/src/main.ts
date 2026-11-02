import { FitAddon } from '@xterm/addon-fit';
import { Terminal } from '@xterm/xterm';
import '@xterm/xterm/css/xterm.css';
import './style.css';
import {
	currentDeviceId, MateKeyMismatchError, type PairedConnection, pairAndConnect,
	reconnectToMate, refreshRelayToken, RelayTokenExpiredError,
} from './pairing';
import { AxonClient } from './client';
import { deleteMate, getMate, listMates, type PairedMate } from './mateStore';
import { disableWakeNotifications, enableWakeNotifications } from './push';

/**
 * How often to check whether the active connection's device-scope relay
 * token needs renewing while connected. Checking on an interval (rather
 * than only right after connecting) covers long-lived sessions that
 * outlast a single token's lifetime.
 */
const RELAY_TOKEN_REFRESH_CHECK_MS = 10 * 60 * 1000;
/** Refresh once less than this much time remains before expiry. */
const RELAY_TOKEN_REFRESH_MARGIN_MS = 60 * 60 * 1000;

interface SessionSummary {
  id: string;
  name: string;
  state: string;
  target: { kind: string; args?: string[] };
  default_permission?: string;
  created_at?: string;
  last_activity_at?: string;
  exit_code?: number | null;
}

const STATE_LABELS: Record<string, string> = {
  idle: 'Idle',
  running: 'Running',
  waiting_input: 'Waiting for input',
  finished: 'Finished',
  error: 'Error',
};

function stateLabel(state: string): string {
  return STATE_LABELS[state] ?? state;
}

function isTerminalState(state: string): boolean {
  return state === 'finished' || state === 'error';
}

function relativeTime(iso?: string): string {
  if (!iso) return '';
  const diffMs = Date.now() - Date.parse(iso);
  if (!Number.isFinite(diffMs)) return '';
  const seconds = Math.round(Math.max(diffMs, 0) / 1000);
  if (seconds < 5) return 'just now';
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

interface MeshOptions {
  workspaces: string[];
  targets: string[];
}

// session.create may spawn a process (e.g. launching `mesh chat`), so give
// it more room than the client's default request timeout before giving up.
const SESSION_CREATE_TIMEOUT_MS = 30_000;

let serviceWorkerRegistration: ServiceWorkerRegistration | undefined;
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js').then((registration) => {
      serviceWorkerRegistration = registration;
    });
  });
}

const app = document.querySelector<HTMLElement>('#app');
if (!app) throw new Error('application root is missing');

app.innerHTML = `
  <header>
    <div><span class="mark" aria-hidden="true">AX</span><h1>Mesh Axon</h1></div>
    <span id="connection-state" class="status">Offline</span>
  </header>
  <section class="layout">
    <nav aria-label="Sessions">
      <h2>Sessions</h2>
      <div id="session-list"></div>
      <p id="session-empty" class="empty">Pair this client to load managed Mesh sessions.</p>
      <button type="button" id="nav-new-session" class="ghost">+ New session</button>
    </nav>
    <article class="terminal-panel">
      <p id="banner" class="banner" hidden></p>
      <section id="device-picker" class="picker" hidden>
        <h2>Known devices</h2>
        <p class="empty">Reconnect to a previously paired mate without scanning a QR code again.</p>
        <div id="mate-list" class="session-grid"></div>
        <button type="button" id="picker-pair-new" class="ghost">+ Pair a new device</button>
      </section>
      <details class="pairing" hidden>
        <summary>Pair this device</summary>
        <form id="pairing-form">
          <label for="pairing-payload">Pairing payload</label>
          <textarea id="pairing-payload" rows="3" required autocomplete="off"></textarea>
          <button class="primary" type="submit">Pair securely</button>
        </form>
      </details>
      <section id="landing" class="landing" hidden>
        <div class="landing-launch">
          <h2>Launch a new session</h2>
          <button type="button" id="quick-launch" class="ghost" disabled>⚡ Quick start (Mesh default)</button>
          <form id="session-form">
            <label for="session-name">Name <span>(optional)</span></label>
            <input id="session-name" autocomplete="off" placeholder="Generated automatically" />
            <label for="mesh-workspace">Workspace</label>
            <select id="mesh-workspace"><option value="">Current / default</option></select>
            <label for="mesh-target">Target</label>
            <select id="mesh-target"><option value="">Mesh default</option></select>
            <button class="primary" type="submit" disabled>Start Mesh chat</button>
          </form>
        </div>
        <div class="landing-sessions">
          <div class="landing-sessions-header">
            <h2>Remote sessions</h2>
            <button type="button" id="clear-finished" class="ghost small" hidden>Clear finished</button>
          </div>
          <div id="landing-session-list" class="session-grid"></div>
          <p id="landing-empty" class="empty">No managed sessions yet — launch one above.</p>
        </div>
      </section>
      <div id="session-view" hidden>
        <div class="shortcuts" aria-label="Session controls">
          <button type="button" data-action="back-to-sessions">← Sessions</button>
          <button type="button" data-action="toggle-focus" aria-pressed="false">⛶ Focus</button>
          <button type="button" data-action="close-session" class="danger">✕ Close session</button>
        </div>
        <div id="terminal" aria-label="Terminal output"></div>
        <div class="shortcuts" aria-label="Terminal shortcuts">
          <button type="button" data-action="terminal-bottom">Terminal ↓</button>
          <button type="button" data-action="controls">Controls ↓</button>
          <button type="button" data-sequence="\r">Enter</button>
          <button type="button" data-sequence="\u001b">Esc</button>
          <button type="button" data-sequence="\t">Tab</button>
          <button type="button" data-sequence="\u0003">Ctrl-C</button>
          <button type="button" data-sequence="\u0004">Ctrl-D</button>
          <button type="button" data-sequence="\u0012">Ctrl-R</button>
        </div>
        <form id="composer">
          <label for="prompt">Prompt composer</label>
          <textarea id="prompt" rows="4" placeholder="Write a prompt without fighting the mobile keyboard"></textarea>
          <div>
            <select id="submit-mode" aria-label="Submit mode">
              <option value="type">Type only</option>
              <option value="enter" selected>Type + Enter</option>
              <option value="bracketed">Bracketed paste</option>
            </select>
            <button class="primary" type="submit">Send prompt</button>
          </div>
        </form>
      </div>
    </article>
  </section>
`;

const terminal = new Terminal({
  cursorBlink: true,
  fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
  fontSize: 14,
  theme: { background: '#07101d', foreground: '#dce8f8', cursor: '#54e6b1' },
});
const fit = new FitAddon();
terminal.loadAddon(fit);
terminal.open(document.querySelector<HTMLElement>('#terminal')!);
fit.fit();
terminal.writeln('\x1b[38;2;84;230;177mMesh Axon\x1b[0m secure session client');
terminal.writeln('Pair a device to begin.');

let secureConnection: PairedConnection | undefined;
let axonClient: AxonClient | undefined;
let activeSessionId = '';
let activeEpoch = '';
let nextSequence = 0;
let sessions: SessionSummary[] = [];
let focusMode = false;
let relayTokenRefreshTimer = 0;

let fitFrame = 0;
const scheduleFit = (): void => {
  cancelAnimationFrame(fitFrame);
  fitFrame = requestAnimationFrame(() => fit.fit());
};

window.addEventListener('resize', scheduleFit, { passive: true });
window.visualViewport?.addEventListener('resize', scheduleFit, { passive: true });
scheduleFit();

document.querySelectorAll<HTMLButtonElement>('[data-sequence]').forEach((button) => {
  button.addEventListener('click', () => sendInput(button.dataset.sequence ?? '', true));
});

document.querySelector<HTMLButtonElement>('[data-action="terminal-bottom"]')!.addEventListener('click', () => {
  terminal.scrollToBottom();
  terminal.focus();
});

document.querySelector<HTMLButtonElement>('[data-action="controls"]')!.addEventListener('click', () => {
  document.querySelector<HTMLElement>('#composer')!.scrollIntoView({ behavior: 'smooth', block: 'start' });
  document.querySelector<HTMLTextAreaElement>('#prompt')!.focus({ preventScroll: true });
});

terminal.onData((data) => sendInput(data, false));

document.querySelector<HTMLFormElement>('#composer')!.addEventListener('submit', (event) => {
  event.preventDefault();
  const prompt = document.querySelector<HTMLTextAreaElement>('#prompt')!;
  const mode = document.querySelector<HTMLSelectElement>('#submit-mode')!.value;
  if (!prompt.value) return;
  const text = mode === 'bracketed' ? `\u001b[200~${prompt.value}\u001b[201~` : `${prompt.value}${mode === 'enter' ? '\r' : ''}`;
  sendInput(text, true);
  prompt.value = '';
});

document.querySelector<HTMLFormElement>('#session-form')!.addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = document.querySelector<HTMLButtonElement>('#session-form button')!;
  button.disabled = true;
  try {
    await createSession({
      template: 'mesh',
      name: document.querySelector<HTMLInputElement>('#session-name')!.value.trim(),
      workspace: document.querySelector<HTMLSelectElement>('#mesh-workspace')!.value,
      target: document.querySelector<HTMLSelectElement>('#mesh-target')!.value,
    });
  } catch {
    // already surfaced via the banner
  } finally {
    button.disabled = false;
  }
});

document.querySelector<HTMLButtonElement>('#quick-launch')!.addEventListener('click', async () => {
  const button = document.querySelector<HTMLButtonElement>('#quick-launch')!;
  button.disabled = true;
  try {
    await createSession({ template: 'mesh' });
  } catch {
    // already surfaced via the banner
  } finally {
    button.disabled = false;
  }
});

document.querySelector<HTMLButtonElement>('#nav-new-session')!.addEventListener('click', () => {
  showLanding();
  document.querySelector<HTMLElement>('#landing')!.scrollIntoView({ behavior: 'smooth', block: 'start' });
});

document.querySelector<HTMLButtonElement>('[data-action="back-to-sessions"]')!.addEventListener('click', () => {
  showLanding();
});

document.querySelector<HTMLButtonElement>('[data-action="toggle-focus"]')!.addEventListener('click', () => {
  setFocusMode(!focusMode);
});

document.querySelector<HTMLButtonElement>('[data-action="close-session"]')!.addEventListener('click', async () => {
  if (!axonClient || !activeSessionId) return;
  const session = sessions.find((candidate) => candidate.id === activeSessionId);
  if (!window.confirm(`End "${session?.name ?? activeSessionId}"? This stops the underlying process.`)) return;
  try {
    await axonClient.request('session.signal', { signal: 'TERM' }, activeSessionId);
    showLanding();
  } catch (error) {
    showBanner(error instanceof Error ? error.message : String(error), 'error');
  }
});

document.querySelector<HTMLButtonElement>('#clear-finished')!.addEventListener('click', async () => {
  const button = document.querySelector<HTMLButtonElement>('#clear-finished')!;
  const finished = sessions.filter((session) => isTerminalState(session.state));
  if (finished.length === 0) return;
  button.disabled = true;
  await Promise.allSettled(finished.map((session) => removeSession(session)));
  button.disabled = false;
});

document.querySelector<HTMLFormElement>('#pairing-form')!.addEventListener('submit', async (event) => {
	event.preventDefault();
	const state = document.querySelector<HTMLElement>('#connection-state')!;
	state.textContent = 'Pairing…';
	hideBanner();
	try {
		const paired = await pairAndConnect(document.querySelector<HTMLTextAreaElement>('#pairing-payload')!.value.trim());
		await onConnected(paired);
	} catch (error) {
		state.textContent = 'Pairing failed';
		showBanner(error instanceof Error ? error.message : String(error), 'error');
	}
});

document.querySelector<HTMLButtonElement>('#picker-pair-new')!.addEventListener('click', () => {
	document.querySelector<HTMLElement>('#device-picker')!.hidden = true;
	const pairing = document.querySelector<HTMLDetailsElement>('.pairing')!;
	pairing.hidden = false;
	pairing.open = true;
});

void refreshDevicePicker();

// Shared by both the QR-pairing flow and the device-picker's reconnect
// flow: once a secure transport exists, wiring the client up to the UI is
// identical regardless of how the connection was established.
//
// `paired.relayToken` -- the device-scope Relay Access Token this
// connection just authenticated with -- is also used, best-effort, to
// register this device for Web Push wake notifications. A browser without
// push support, a denied permission, or an unreachable relay must never
// affect an otherwise working connection, so that failure is swallowed
// silently.
async function onConnected(paired: PairedConnection): Promise<void> {
	const state = document.querySelector<HTMLElement>('#connection-state')!;
	axonClient?.close();
	window.clearInterval(relayTokenRefreshTimer);
	secureConnection = paired;
	activeSessionId = '';
	axonClient = new AxonClient(secureConnection.transport);
	axonClient.on<string>('session.output', (event) => {
		if (event.sid !== activeSessionId || (activeEpoch && event.epoch !== activeEpoch)) return;
		if (event.seq === undefined || event.seq < nextSequence || !event.data) return;
		terminal.write(fromBase64Text(event.data));
		nextSequence = event.seq + 1;
	});
	axonClient.on('session.closed', (event) => {
		if (event.sid !== activeSessionId) return;
		terminal.writeln('\r\n\x1b[33mSession finished.\x1b[0m');
		const session = sessions.find((candidate) => candidate.id === event.sid);
		if (session) session.state = 'finished';
		renderSessions();
	});
	axonClient.on('session.resync', (event) => {
		if (event.sid !== activeSessionId || (activeEpoch && event.epoch !== activeEpoch)) return;
		terminal.writeln('\r\n\x1b[33mLive output fell behind; resynchronizing…\x1b[0m');
		void subscribeSession(event.sid, nextSequence);
	});
	state.textContent = 'Encrypted';
	showBanner(`Paired with ${secureConnection.mateId}.`, 'info');
	scheduleRelayTokenRefresh(secureConnection.mateId);
	if (serviceWorkerRegistration && 'PushManager' in window) {
		void enableWakeNotifications(
			serviceWorkerRegistration,
			{
				relayUrl: secureConnection.relayUrl, relayToken: secureConnection.relayToken,
				mateId: secureConnection.mateId, deviceId: secureConnection.deviceId,
			},
			Notification,
		);
	}
	await loadMeshOptions();
	document.querySelector<HTMLButtonElement>('#session-form button')!.disabled = false;
	document.querySelector<HTMLButtonElement>('#quick-launch')!.disabled = false;
	document.querySelector<HTMLDetailsElement>('.pairing')!.open = false;
	document.querySelector<HTMLElement>('.pairing')!.hidden = true;
	document.querySelector<HTMLElement>('#device-picker')!.hidden = true;
	showLanding();
}

/**
 * Proactively renews the device-scope relay token before it expires, so a
 * later reload's reconnect doesn't find a stale or expired token in
 * mateStore. Checked on an interval rather than scheduled for the exact
 * expiry time, since the tab can be backgrounded or the connection can
 * drop and come back in between.
 */
function scheduleRelayTokenRefresh(mateId: string): void {
	const client = axonClient;
	if (!client) return;
	const maybeRefresh = async (): Promise<void> => {
		const mate = await getMate(mateId);
		if (!mate || mate.relayTokenExpiresAt - Date.now() > RELAY_TOKEN_REFRESH_MARGIN_MS) return;
		try {
			await refreshRelayToken(client, mateId);
		} catch (error) {
			terminal.writeln(`\r\n\x1b[33mRelay token refresh failed: ${error instanceof Error ? error.message : String(error)}\x1b[0m`);
		}
	};
	void maybeRefresh();
	relayTokenRefreshTimer = window.setInterval(() => void maybeRefresh(), RELAY_TOKEN_REFRESH_CHECK_MS);
}

// Shows the device picker when mates are already known, or falls back to
// the QR pairing form (e.g. first run, or IndexedDB unavailable/blocked).
async function refreshDevicePicker(): Promise<void> {
	let mates: PairedMate[] = [];
	try {
		mates = await listMates();
	} catch {
		// fall through to the pairing form below
	}
	const picker = document.querySelector<HTMLElement>('#device-picker')!;
	const pairing = document.querySelector<HTMLDetailsElement>('.pairing')!;
	if (mates.length === 0) {
		picker.hidden = true;
		pairing.hidden = false;
		pairing.open = true;
		return;
	}
	renderMateList(mates);
	picker.hidden = false;
	pairing.hidden = true;
}

function renderMateList(mates: PairedMate[]): void {
	const list = document.querySelector<HTMLElement>('#mate-list')!;
	list.replaceChildren(...mates.map((mate) => {
		const card = document.createElement('div');
		card.className = 'session-card mate-card';
		const header = document.createElement('div');
		header.className = 'session-card-header';
		const name = document.createElement('b');
		name.textContent = mate.mateId;
		header.append(name);
		const meta = document.createElement('small');
		meta.className = 'session-card-meta';
		meta.textContent = `Last connected ${relativeTime(new Date(mate.lastConnectedAt).toISOString())}`;
		const actions = document.createElement('div');
		actions.className = 'mate-card-actions';
		const connect = document.createElement('button');
		connect.type = 'button';
		connect.className = 'primary';
		connect.textContent = 'Connect';
		connect.addEventListener('click', () => void connectToMate(mate, connect));
		const forget = document.createElement('button');
		forget.type = 'button';
		forget.className = 'ghost';
		forget.textContent = 'Forget';
		forget.addEventListener('click', () => void forgetMate(mate));
		actions.append(connect, forget);
		card.append(header, meta, actions);
		return card;
	}));
}

async function connectToMate(mate: PairedMate, button: HTMLButtonElement): Promise<void> {
	const state = document.querySelector<HTMLElement>('#connection-state')!;
	button.disabled = true;
	state.textContent = 'Connecting…';
	hideBanner();
	try {
		const paired = await reconnectToMate(mate);
		await onConnected(paired);
	} catch (error) {
		state.textContent = 'Connection failed';
		if (error instanceof MateKeyMismatchError || error instanceof RelayTokenExpiredError) {
			showBanner(`${error.message} Use "Pair a new device" below to continue.`, 'error');
		} else {
			showBanner(error instanceof Error ? error.message : String(error), 'error');
		}
	} finally {
		button.disabled = false;
	}
}

// Forgetting a mate removes its local pairing record. Push-subscription
// cleanup is best-effort and layered on top -- it must never block or fail
// the forget action itself. mate.relayToken may itself have expired by now;
// if so the relay-side DELETE just comes back unauthorized and the row is
// instead pruned the next time the relay gets a 404/410 pushing to it.
async function forgetMate(mate: PairedMate): Promise<void> {
	try {
		await deleteMate(mate.mateId);
		await refreshDevicePicker();
	} catch (error) {
		showBanner(error instanceof Error ? error.message : String(error), 'error');
	}
	if (serviceWorkerRegistration && 'PushManager' in window) {
		void currentDeviceId()
			.then((deviceId) => disableWakeNotifications(
				serviceWorkerRegistration!,
				{ relayUrl: mate.relayUrl, relayToken: mate.relayToken, mateId: mate.mateId, deviceId },
			))
			.catch(() => {
				// Best-effort: see the comment above.
			});
	}
}

function bytesBase64(value: Uint8Array): string {
	let binary = '';
	for (const byte of value) binary += String.fromCharCode(byte);
	return btoa(binary);
}

function sendInput(text: string, confirmed: boolean): void {
	if (!axonClient || !activeSessionId || !text) return;
	void axonClient.request('session.input', {
		bytes: bytesBase64(new TextEncoder().encode(text)),
		confirmed,
	}, activeSessionId).catch((error) => terminal.writeln(`\r\n\x1b[31m${String(error)}\x1b[0m`));
}

async function loadMeshOptions(): Promise<void> {
  if (!axonClient) return;
  const response = await axonClient.request<MeshOptions>('mesh.options');
  const options = response.data;
  if (!options) return;
  replaceOptions('#mesh-workspace', 'Current / default', options.workspaces);
  replaceOptions('#mesh-target', 'Mesh default', options.targets);
}

function replaceOptions(selector: string, emptyLabel: string, values: string[]): void {
  const select = document.querySelector<HTMLSelectElement>(selector)!;
  select.replaceChildren(new Option(emptyLabel, ''), ...values.map((value) => new Option(value, value)));
}

function renderSessions(): void {
  renderNavSessionList();
  renderLandingSessions();
}

function renderNavSessionList(): void {
  const list = document.querySelector<HTMLElement>('#session-list')!;
  list.replaceChildren(...sessions.map((session) => {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = `session${session.id === activeSessionId ? ' active' : ''}`;
    const identity = document.createElement('span');
    const name = document.createElement('b');
    name.textContent = session.name;
    const target = document.createElement('small');
    target.textContent = [session.target.kind, ...(session.target.args ?? [])].join(' ');
    identity.append(name, target);
    const state = document.createElement('strong');
    state.textContent = stateLabel(session.state);
    button.append(identity, state);
    button.addEventListener('click', () => selectSession(session));
    return button;
  }));
  const empty = document.querySelector<HTMLElement>('#session-empty')!;
  empty.hidden = sessions.length > 0;
  if (sessions.length === 0) empty.textContent = axonClient ? 'No managed sessions.' : 'Pair this client to load managed Mesh sessions.';
}

function renderLandingSessions(): void {
  const list = document.querySelector<HTMLElement>('#landing-session-list')!;
  list.replaceChildren(...sessions.map((session) => {
    const card = document.createElement('button');
    card.type = 'button';
    card.className = `session-card${session.id === activeSessionId ? ' active' : ''}`;
    const header = document.createElement('div');
    header.className = 'session-card-header';
    const name = document.createElement('b');
    name.textContent = session.name;
    const badge = document.createElement('strong');
    badge.className = `state-badge state-${session.state}`;
    badge.textContent = stateLabel(session.state);
    const indicators = document.createElement('span');
    indicators.className = 'session-card-indicators';
    indicators.append(badge);
    if (isTerminalState(session.state)) {
      const dismiss = document.createElement('span');
      dismiss.className = 'session-card-dismiss';
      dismiss.textContent = '✕';
      dismiss.title = 'Remove from the list';
      dismiss.addEventListener('click', (event) => {
        event.stopPropagation();
        void removeSession(session);
      });
      indicators.append(dismiss);
    }
    header.append(name, indicators);
    const target = document.createElement('small');
    target.textContent = [session.target.kind, ...(session.target.args ?? [])].join(' ');
    const metaParts: string[] = [];
    if (session.last_activity_at) metaParts.push(`Active ${relativeTime(session.last_activity_at)}`);
    else if (session.created_at) metaParts.push(`Created ${relativeTime(session.created_at)}`);
    if (session.default_permission) metaParts.push(session.default_permission.replaceAll('_', ' '));
    if (typeof session.exit_code === 'number') metaParts.push(`exit ${session.exit_code}`);
    const meta = document.createElement('small');
    meta.className = 'session-card-meta';
    meta.textContent = metaParts.join(' · ');
    card.append(header, target, meta);
    card.addEventListener('click', () => selectSession(session));
    return card;
  }));
  const empty = document.querySelector<HTMLElement>('#landing-empty')!;
  empty.hidden = sessions.length > 0;
  document.querySelector<HTMLButtonElement>('#clear-finished')!.hidden = !sessions.some((session) => isTerminalState(session.state));
}

// Drops a single terminated session's bookkeeping. The backend refuses to
// remove anything still running, so this only ever touches sessions that
// have already finished or errored out.
async function removeSession(session: SessionSummary): Promise<void> {
  if (!axonClient) return;
  try {
    await axonClient.request('session.remove', undefined, session.id);
    sessions = sessions.filter((candidate) => candidate.id !== session.id);
    renderSessions();
  } catch (error) {
    showBanner(error instanceof Error ? error.message : String(error), 'error');
  }
}

function showBanner(message: string, kind: 'error' | 'info' = 'error'): void {
  const banner = document.querySelector<HTMLElement>('#banner')!;
  banner.textContent = message;
  banner.className = `banner ${kind}`;
  banner.hidden = false;
}

function hideBanner(): void {
  document.querySelector<HTMLElement>('#banner')!.hidden = true;
}

function showLanding(): void {
  activeSessionId = '';
  setFocusMode(false);
  document.querySelector<HTMLElement>('#landing')!.hidden = false;
  document.querySelector<HTMLElement>('#session-view')!.hidden = true;
  renderSessions();
  void refreshSessions();
}

// Focus mode hides the header and session sidebar so the terminal and
// composer — the actual chat area — get the full viewport. It only makes
// sense while a session is open, so leaving for the landing page clears it.
function setFocusMode(enabled: boolean): void {
  focusMode = enabled;
  document.body.classList.toggle('focus-mode', enabled);
  const button = document.querySelector<HTMLButtonElement>('[data-action="toggle-focus"]')!;
  button.textContent = enabled ? '⤢ Exit focus' : '⛶ Focus';
  button.setAttribute('aria-pressed', String(enabled));
  scheduleFit();
}

// Session state/activity can change while you're off viewing another
// session (or before you've ever opened one), so the landing page's cards
// refetch on every visit instead of showing whatever was true at pairing
// time. Failures are silent — keep showing the last known list rather than
// blow up the landing page over a transient refresh error.
async function refreshSessions(): Promise<void> {
  if (!axonClient) return;
  try {
    const response = await axonClient.request<SessionSummary[]>('sessions.list');
    sessions = response.data ?? [];
    renderSessions();
  } catch {
    // keep showing the last known list
  }
}

function showSessionView(): void {
  hideBanner();
  document.querySelector<HTMLElement>('#landing')!.hidden = true;
  document.querySelector<HTMLElement>('#session-view')!.hidden = false;
}

async function createSession(params: { template: string; name?: string; workspace?: string; target?: string }): Promise<void> {
  if (!axonClient) return;
  hideBanner();
  try {
    const response = await axonClient.request<SessionSummary>('session.create', params, undefined, SESSION_CREATE_TIMEOUT_MS);
    if (response.data) {
      sessions = [...sessions, response.data];
      selectSession(response.data);
    }
  } catch (error) {
    showBanner(error instanceof Error ? error.message : String(error), 'error');
    throw error;
  }
}

function selectSession(session: SessionSummary): void {
  showSessionView();
  if (activeSessionId === session.id) return;
  activeSessionId = session.id;
  activeEpoch = '';
  nextSequence = 0;
  renderSessions();
  terminal.reset();
  terminal.writeln(`\x1b[38;2;84;230;177m${session.name}\x1b[0m · ${session.target.kind}`);
  scheduleFit();
  void subscribeSession(session.id);
}

async function subscribeSession(sessionId: string, fromSequence = 0): Promise<void> {
	if (!axonClient || activeSessionId !== sessionId) return;
	try {
		const response = await axonClient.request<{
			chunks?: Array<{ seq: number; data: string }>;
			min_seq: number;
			max_seq: number;
			gap: boolean;
		}>('session.subscribe', { from_seq: fromSequence }, sessionId);
		if (activeSessionId !== sessionId) return;
		activeEpoch = response.epoch ?? '';
		const replay = response.data;
		if (replay?.gap) {
			terminal.writeln(`\r\n\x1b[33mOutput before sequence ${replay.min_seq} is no longer retained.\x1b[0m`);
			nextSequence = replay.min_seq;
			await subscribeSession(sessionId, replay.min_seq);
			return;
		}
		for (const chunk of replay?.chunks ?? []) {
			if (chunk.seq < nextSequence) continue;
			terminal.write(fromBase64Text(chunk.data));
			nextSequence = chunk.seq + 1;
		}
	} catch (error) {
		terminal.writeln(`\r\n\x1b[31m${String(error)}\x1b[0m`);
	}
}

function fromBase64Text(value: string): Uint8Array {
	const binary = atob(value);
	return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}
