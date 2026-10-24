import { FitAddon } from '@xterm/addon-fit';
import { Terminal } from '@xterm/xterm';
import '@xterm/xterm/css/xterm.css';
import './style.css';
import { pairAndConnect } from './pairing';
import { AxonClient } from './client';

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
      <button class="session active" type="button"><span>local</span><strong>Waiting</strong></button>
      <p class="empty">Pair this client to load live sessions.</p>
    </nav>
    <article class="terminal-panel">
      <div id="terminal" aria-label="Terminal output"></div>
      <div class="shortcuts" aria-label="Terminal shortcuts">
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
let nextSequence = 0;

new ResizeObserver(() => fit.fit()).observe(document.querySelector('#terminal')!);

document.querySelectorAll<HTMLButtonElement>('[data-sequence]').forEach((button) => {
  button.addEventListener('click', () => sendInput(button.dataset.sequence ?? '', true));
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

document.querySelector<HTMLFormElement>('#pairing-form')!.addEventListener('submit', async (event) => {
	event.preventDefault();
	const state = document.querySelector<HTMLElement>('#connection-state')!;
	state.textContent = 'Pairing…';
	try {
		secureConnection = await pairAndConnect(
			document.querySelector<HTMLTextAreaElement>('#pairing-payload')!.value.trim(),
			document.querySelector<HTMLInputElement>('#relay-ticket')!.value,
		);
		axonClient = new AxonClient(secureConnection.transport);
		state.textContent = 'Encrypted';
		terminal.writeln(`\r\nPaired with ${secureConnection.mateId}.`);
		const response = await axonClient.request<Array<{ id: string; name: string; state: string }>>('sessions.list');
		const sessions = response.data ?? [];
		activeSessionId = sessions[0]?.id ?? '';
		terminal.writeln(`Sessions: ${sessions.map((session) => `${session.name} (${session.state})`).join(', ') || 'none'}`);
		if (activeSessionId) void replayLoop(activeSessionId);
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

async function replayLoop(sessionId: string): Promise<void> {
	while (axonClient && activeSessionId === sessionId) {
		try {
			const response = await axonClient.request<{
				chunks?: Array<{ seq: number; data: string }>;
				min_seq: number;
				max_seq: number;
				gap: boolean;
			}>('session.replay', { from_seq: nextSequence }, sessionId);
			const replay = response.data;
			if (replay?.gap) {
				terminal.writeln(`\r\n\x1b[33mOutput before sequence ${replay.min_seq} is no longer retained.\x1b[0m`);
				nextSequence = replay.min_seq;
			} else {
				for (const chunk of replay?.chunks ?? []) {
					terminal.write(fromBase64Text(chunk.data));
					nextSequence = chunk.seq + 1;
				}
			}
		} catch (error) {
			terminal.writeln(`\r\n\x1b[31m${String(error)}\x1b[0m`);
			return;
		}
		await new Promise((resolve) => setTimeout(resolve, 250));
	}
}

function fromBase64Text(value: string): Uint8Array {
	const binary = atob(value);
	return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}
