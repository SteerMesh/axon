import { FitAddon } from '@xterm/addon-fit';
import { Terminal } from '@xterm/xterm';
import '@xterm/xterm/css/xterm.css';
import './style.css';
import { pairAndConnect } from './pairing';
import { AxonClient } from './client';

interface SessionSummary {
  id: string;
  name: string;
  state: string;
  target: { kind: string; args?: string[] };
}

interface MeshOptions {
  workspaces: string[];
  targets: string[];
}

if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => navigator.serviceWorker.register('/sw.js'));
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
      <details class="session-launch">
        <summary>New Mesh chat</summary>
        <form id="session-form">
          <label for="session-name">Name <span>(optional)</span></label>
          <input id="session-name" autocomplete="off" placeholder="Generated automatically" />
          <label for="mesh-workspace">Workspace</label>
          <select id="mesh-workspace"><option value="">Current / default</option></select>
          <label for="mesh-target">Target</label>
          <select id="mesh-target"><option value="">Mesh default</option></select>
          <button class="primary" type="submit" disabled>Start Mesh chat</button>
        </form>
      </details>
    </nav>
    <article class="terminal-panel">
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
		<details class="pairing" open>
			<summary>Pair this device</summary>
			<form id="pairing-form">
				<label for="pairing-payload">Pairing payload</label>
				<textarea id="pairing-payload" rows="3" required autocomplete="off"></textarea>
				<label for="relay-ticket">Relay access ticket</label>
				<input id="relay-ticket" type="password" required autocomplete="off" />
				<button class="primary" type="submit">Pair securely</button>
			</form>
		</details>
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

let secureConnection: Awaited<ReturnType<typeof pairAndConnect>> | undefined;
let axonClient: AxonClient | undefined;
let activeSessionId = '';
let activeEpoch = '';
let nextSequence = 0;
let sessions: SessionSummary[] = [];

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
  if (!axonClient) return;
  const button = document.querySelector<HTMLButtonElement>('#session-form button')!;
  button.disabled = true;
  try {
    const response = await axonClient.request<SessionSummary>('session.create', {
      template: 'mesh',
      name: document.querySelector<HTMLInputElement>('#session-name')!.value.trim(),
      workspace: document.querySelector<HTMLSelectElement>('#mesh-workspace')!.value,
      target: document.querySelector<HTMLSelectElement>('#mesh-target')!.value,
    });
    if (response.data) {
      sessions = [...sessions, response.data];
      renderSessions();
      selectSession(response.data);
      document.querySelector<HTMLDetailsElement>('.session-launch')!.open = false;
    }
  } catch (error) {
    terminal.writeln(`\r\n\x1b[31m${error instanceof Error ? error.message : String(error)}\x1b[0m`);
  } finally {
    button.disabled = false;
  }
});

document.querySelector<HTMLFormElement>('#pairing-form')!.addEventListener('submit', async (event) => {
	event.preventDefault();
	const state = document.querySelector<HTMLElement>('#connection-state')!;
	state.textContent = 'Pairing…';
	try {
		const paired = await pairAndConnect(
			document.querySelector<HTMLTextAreaElement>('#pairing-payload')!.value.trim(),
			document.querySelector<HTMLInputElement>('#relay-ticket')!.value,
		);
		axonClient?.close();
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
		terminal.writeln(`\r\nPaired with ${secureConnection.mateId}.`);
		await loadMeshOptions();
		const response = await axonClient.request<SessionSummary[]>('sessions.list');
		sessions = response.data ?? [];
		if (sessions.length === 0) {
			const created = await axonClient.request<SessionSummary>(
				'session.create',
				{ template: 'mesh', name: 'mesh' },
			);
			if (created.data) sessions = [created.data];
		}
		renderSessions();
		if (sessions[0]) selectSession(sessions[0]);
		document.querySelector<HTMLButtonElement>('#session-form button')!.disabled = false;
		document.querySelector<HTMLDetailsElement>('.pairing')!.open = false;
	} catch (error) {
		state.textContent = 'Pairing failed';
		terminal.writeln(`\r\n\x1b[31m${error instanceof Error ? error.message : String(error)}\x1b[0m`);
	}
});

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
    state.textContent = session.state;
    button.append(identity, state);
    button.addEventListener('click', () => selectSession(session));
    return button;
  }));
  const empty = document.querySelector<HTMLElement>('#session-empty')!;
  empty.hidden = sessions.length > 0;
  if (sessions.length === 0) empty.textContent = axonClient ? 'No managed sessions.' : 'Pair this client to load managed Mesh sessions.';
}

function selectSession(session: SessionSummary): void {
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
