import { useId, useState } from 'react';

import { Fingerprint, KeyRound, LockKeyhole, ShieldCheck, FlaskConical, ArrowRight, Copy, Check, RefreshCw, Play, AlertTriangle, Binary, Braces, FileUp, FileCheck2 } from 'lucide-react';
import ThemeSwitcher from './ThemeSwitcher.jsx';
import './styles.css';

const tabs = [
  { id: 'hash', name: 'Hash & HMAC', icon: Fingerprint, description: 'Turn any message into a fingerprint.', detail: 'Compare digest algorithms, or add a key to compute an HMAC.' },
  { id: 'pbkdf2', name: 'Key derivation', icon: KeyRound, description: 'From a password to a key.', detail: 'Explore how salt, iterations, and hash algorithms shape a derived key.' },
  { id: 'symmetric', name: 'Symmetric encryption', icon: LockKeyhole, description: 'One key. Two directions.', detail: 'Encrypt a message, then reuse the ciphertext to decrypt it with the same key and IV.' },
  { id: 'rsa', name: 'RSA & signatures', icon: ShieldCheck, description: 'Explore the public and private.', detail: 'Generate a key pair to encrypt, decrypt, sign, and verify messages.' },
];
const initial = { input: 'Hello, CryptographyHelper!', encoding: 'Text', algorithm: 'SHA256', hmac: false, key: '', keyEncoding: 'Text', password: 'my-playground-password', salt: '', iterations: 100000, length: 32, iv: '', operation: 'encrypt', mode: 'CBC', padding: 'PKCS7', format: 'Pem', size: 2048, signaturePadding: 'PSS', signature: '' };
async function api(path, body) {
  const response = await fetch(`/api/${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || data.title || `Request failed (${response.status}).`);
  return data;
}
function Field({ label, children, hint }) { return <label className="field"><span>{label}</span>{children}{hint && <small>{hint}</small>}</label>; }
const optionLabels = {
  SHA1: 'SHA-1', SHA256: 'SHA-256', SHA384: 'SHA-384', SHA512: 'SHA-512',
  TripleDES: 'Triple DES', PKCS1: 'PKCS#1', PKCS7: 'PKCS#7', ANSIX923: 'ANSI X9.23',
  Pem: 'PEM', Xml: 'XML', encrypt: 'Encrypt', decrypt: 'Decrypt',
  sign: 'Sign message', verify: 'Verify message', signHash: 'Sign hash', verifyHash: 'Verify hash',
};
const operationDetails = {
  encrypt: 'Create ciphertext', decrypt: 'Recover the original',
  sign: 'Sign the input data', verify: 'Check a data signature',
  signHash: 'Use a precomputed digest', verifyHash: 'Check a digest signature',
};
function Options({ name, label, values, value, onChange }) {
  const id = useId();
  const operation = name === 'operation';
  return <fieldset className={`choice-group${values.length > 3 || operation ? ' choice-wide' : ''}`}>
    <legend>{label}</legend>
    <div className={operation ? 'choice-cards' : 'choice-segments'}>
      {values.map(option => {
        const Icon = option === 'encrypt' || option === 'decrypt' ? LockKeyhole : ShieldCheck;
        return <label className="choice" key={option}>
          <input type="radio" name={id} value={option} checked={String(value) === String(option)} onChange={() => onChange(option)}/>
          <span className="choice-surface">
            {operation && <Icon size={18} aria-hidden="true"/>}
            <span className="choice-copy"><span>{optionLabels[option] || option}</span>{operation && <small>{operationDetails[option]}</small>}</span>
            <Check size={13} className="choice-check" aria-hidden="true"/>
          </span>
        </label>;
      })}
    </div>
  </fieldset>;
}
export default function App() {
  const [tab, setTab] = useState('hash');
  return <div className="shell">
    <aside><a className="brand" href="#"><span className="brand-icon"><FlaskConical size={23}/></span><span>Cryptography<span className="brand-light">Helper</span><small>THE PLAYGROUND</small></span></a>
      <div className="nav-label">EXPLORE THE LIBRARY</div><nav aria-label="Cryptography features">{tabs.map(t => <button key={t.id} aria-current={tab === t.id ? 'page' : undefined} className={tab === t.id ? 'active' : ''} onClick={() => setTab(t.id)}><t.icon size={19}/>{t.name}{tab === t.id && <ArrowRight size={15}/>}</button>)}</nav>
      <div className="sidebar-note"><Braces size={22}/><strong>Learn by doing.</strong><p>Real library calls.<br/>Editable inputs.<br/>Instant feedback.</p><span>.NET 10 <i/> React 19</span></div>
    </aside>
    <main><header><span><span className="status-dot"/> LOCAL PLAYGROUND</span><div className="header-actions"><span className="version">CryptographyHelper / v4</span><ThemeSwitcher/></div></header><Workspace key={tab} tab={tab}/><footer><FlaskConical size={15}/> A space to experiment. Use sample data and keys here.</footer></main>
  </div>;
}
function Workspace({ tab }) {
  const meta = tabs.find(t => t.id === tab);
  const [form, setForm] = useState({ ...initial, algorithm: tab === 'symmetric' ? 'AES' : 'SHA256', padding: tab === 'rsa' ? 'OAEP-SHA256' : 'PKCS7' });
  const [result, setResult] = useState(null);
  const [keys, setKeys] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState('');
  const [selectedFile, setSelectedFile] = useState(null);
  const [outputFormat, setOutputFormat] = useState('hex');
  const set = (name, value) => { if (name === 'input' || name === 'encoding') setSelectedFile(null); setForm(f => ({ ...f, [name]: value, ...(name === 'format' ? { key: '' } : {}) })); if (name === 'format') setKeys(null); setResult(null); setError(''); };
  const options = (name, label, values) => <Options name={name} label={label} values={values} value={form[name]} onChange={value => set(name, value)}/>;
  const input = (name, label, type = 'text', hint) => <Field label={label} hint={hint}><input aria-label={label} type={type} value={form[name]} onChange={e => set(name, type === 'number' ? Number(e.target.value) : e.target.value)} /></Field>;
  const area = (name, label, rows = 4) => <Field label={label}><textarea aria-label={label} rows={rows} value={form[name]} spellCheck="false" onChange={e => set(name, e.target.value)}/></Field>;
  async function run(action) { setBusy(true); setError(''); try { await action(); } catch (e) { setError(e.message === 'Failed to fetch' ? 'Cannot reach the API. Start it on http://localhost:5180 and try again.' : e.message); } finally { setBusy(false); } }
  async function random(name, length) { await run(async () => set(name, (await api('random', { length })).base64)); }
  async function generate() { await run(async () => {
    if (tab === 'rsa') { const pair = await api('rsa/keys', { size: Number(form.size), format: form.format }); setKeys(pair); set('key', form.operation === 'decrypt' || form.operation.startsWith('sign') ? pair.privateKey : pair.publicKey); }
    else { const length = form.algorithm === 'AES' ? 32 : form.algorithm === 'DES' ? 8 : 24; const key = await api('random', { length }); const iv = await api('random', { length: form.algorithm === 'AES' ? 16 : 8 }); setForm(f => ({ ...f, key: key.base64, iv: iv.base64 })); setResult(null); }
  }); }
  async function copy(value, name) { try { await navigator.clipboard.writeText(value); setCopied(name); setTimeout(() => setCopied(''), 1800); } catch { setError('Clipboard access is unavailable. Select and copy the output manually.'); } }
  async function upload(event) { const file = event.target.files?.[0]; if (!file) return; await run(async () => { if (file.size > 1_000_000) throw new Error('Choose a file smaller than 1 MB.'); const bytes = new Uint8Array(await file.arrayBuffer()); let binary = ''; for (const byte of bytes) binary += String.fromCharCode(byte); setForm(f => ({ ...f, input: btoa(binary), encoding: 'Base64' })); setSelectedFile({ name: file.name, size: file.size }); setResult(null); }); event.target.value = ''; }
  const signing = tab === 'rsa' && !['encrypt', 'decrypt'].includes(form.operation);
  const legacy = ['MD5', 'SHA1', 'DES', 'TripleDES'].includes(form.algorithm) || (tab === 'symmetric' && form.mode === 'ECB');
  const output = result ? (result[outputFormat] ?? result.base64 ?? '') : '';
  return <><section className="intro"><div className="eyebrow">THE CRYPTO LAB <span>/ {String(tabs.indexOf(meta) + 1).padStart(2, '0')}</span></div><h1>{meta.name}<span>.</span></h1><h2>{meta.description}</h2><p>{meta.detail}</p></section>
    <div className="workspace"><section className="card"><div className="card-heading"><span><meta.icon size={19}/> Configure experiment</span><span className="step">01 / INPUT</span></div>
      <form onSubmit={e => { e.preventDefault(); run(async () => { setResult(null); const data = await api(tab, form); setResult(data); setOutputFormat(data.text != null ? 'text' : tab === 'hash' || tab === 'pbkdf2' ? 'hex' : 'base64'); }); }}><fieldset disabled={busy}>
      {tab === 'hash' && <><div className="row">{options('algorithm', 'Hash algorithm', ['MD5', 'SHA1', 'SHA256', 'SHA384', 'SHA512'])}{options('encoding', 'Input encoding', ['Text', 'Base64', 'Hex'])}</div>{area('input', 'Message')}<label className={`upload-card${selectedFile ? ' has-file' : ''}`}>
        <input className="upload-input" type="file" aria-label="Choose a file to hash" aria-describedby="upload-description" onChange={upload}/>
        <span className="upload-icon" aria-hidden="true">{selectedFile ? <FileCheck2 size={23}/> : <FileUp size={23}/>}</span>
        <span className="upload-details" aria-live="polite">
          <strong title={selectedFile?.name}>{selectedFile ? selectedFile.name : 'Hash a file instead'}</strong>
          <span id="upload-description">{selectedFile ? `${selectedFile.size.toLocaleString()} bytes / Ready to hash` : 'Choose any file up to 1 MB'}</span>
        </span>
        <span className="upload-action" aria-hidden="true">{selectedFile ? 'Change file' : 'Browse files'}<ArrowRight size={14}/></span>
      </label><label className="toggle"><input type="checkbox" checked={form.hmac} onChange={e => set('hmac', e.target.checked)}/> Use HMAC <span>Add a secret key</span></label>{form.hmac && <><div className="row">{input('key', 'HMAC key')}{options('keyEncoding', 'Key encoding', ['Text', 'Base64', 'Hex'])}</div></>}</>}
      {tab === 'pbkdf2' && <>{input('password', 'Password')}{options('algorithm', 'Hash algorithm', ['SHA1', 'SHA256', 'SHA384', 'SHA512'])}{input('salt', 'Salt · Base64')}<button type="button" className="secondary" onClick={() => random('salt', 16)}><RefreshCw size={15}/> Generate salt</button><div className="row">{input('iterations', 'Iterations', 'number', '1–1,000,000')}{input('length', 'Output bytes', 'number', '1–128')}</div></>}
      {tab === 'symmetric' && <><div className="row">{options('algorithm', 'Algorithm', ['AES', 'DES', 'TripleDES'])}{options('operation', 'Operation', ['encrypt', 'decrypt'])}</div><div className="row">{options('mode', 'Cipher mode', ['CBC', 'ECB'])}{options('padding', 'Padding', ['PKCS7', 'None', 'Zeros', 'ANSIX923'])}</div>{input('key', 'Secret key · Base64', 'text', 'AES: 16/24/32 bytes · DES: 8 bytes · TripleDES: 16/24 bytes')}{form.mode !== 'ECB' && input('iv', 'IV · Base64', 'text', 'AES: 16 bytes · DES / TripleDES: 8 bytes')}<button type="button" className="secondary" onClick={generate}><RefreshCw size={15}/> Generate key & IV</button>{form.operation === 'encrypt' && options('encoding', 'Input encoding', ['Text', 'Base64', 'Hex'])}{area('input', form.operation === 'decrypt' ? 'Ciphertext · Base64' : 'Message')}</>}
      {tab === 'rsa' && <><div className="row">{options('operation', 'Operation', ['encrypt', 'decrypt', 'sign', 'verify', 'signHash', 'verifyHash'])}{options('format', 'Key format', ['Pem', 'Xml'])}</div><div className="row">{options('size', 'Generated key size', [2048, 3072, 4096])}<button type="button" className="secondary aligned" onClick={generate}><KeyRound size={15}/> Generate key pair</button></div>{keys && <div className="key-actions"><button type="button" onClick={() => set('key', keys.publicKey)}>Use public key</button><button type="button" onClick={() => set('key', keys.privateKey)}>Use private key</button><button type="button" onClick={() => copy(keys.publicKey, 'public')}>{copied === 'public' ? 'Copied' : 'Copy public'}</button><button type="button" onClick={() => copy(keys.privateKey, 'private')}>{copied === 'private' ? 'Copied' : 'Copy private'}</button></div>}{area('key', 'RSA key', 3)}{signing ? <div className="row">{options('algorithm', 'Hash algorithm', ['SHA256', 'SHA384', 'SHA512'])}{options('signaturePadding', 'Signature padding', ['PSS', 'PKCS1'])}</div> : options('padding', 'Encryption padding', ['OAEP-SHA256', 'OAEP-SHA1', 'PKCS1'])}{form.operation !== 'decrypt' && options('encoding', 'Input encoding', ['Text', 'Base64', 'Hex'])}{area('input', form.operation === 'decrypt' ? 'Ciphertext · Base64' : form.operation.endsWith('Hash') ? 'Precomputed digest (choose Hex or Base64 above)' : 'Message')}{form.operation.startsWith('verify') && area('signature', 'Signature · Base64', 3)}</>}
      {legacy && <p className="notice"><AlertTriangle size={16}/> Legacy algorithm or mode: included for experimentation.</p>}
      {error && <div role="alert" className="error"><AlertTriangle size={18}/><span>{error}</span></div>}
      <button className="primary" type="submit"><Play size={16}/>{busy ? 'Working…' : tab === 'hash' ? 'Compute hash' : tab === 'pbkdf2' ? 'Derive key' : 'Run experiment'}<ArrowRight size={17}/></button>
      </fieldset></form></section>
      <div className="result-column"><section className="card output-card"><div className="card-heading"><span><Binary size={20}/> Result</span><span className="step">02 / OUTPUT</span></div><div className="output-body" aria-live="polite">{!result ? <div className="empty"><div><Fingerprint size={38} strokeWidth={1.3}/></div><h3>Your result starts here</h3><p>Configure your inputs and run an experiment to see the library in action.</p><span>INPUT <ArrowRight size={13}/> CRYPTOGRAPHY <ArrowRight size={13}/> OUTPUT</span></div> : 'verified' in result ? <div className={`verification ${result.verified ? 'valid' : 'invalid'}`}><ShieldCheck size={38}/><h3>{result.verified ? 'Signature verified' : 'Signature does not match'}</h3><p>{result.verified ? 'This signature matches the input and public key.' : 'Check the message, key, signature, and padding.'}</p></div> : <><div className="result-toolbar"><div className="format-switch">{['hex', 'base64', ...(result.text != null ? ['text'] : [])].map(f => <button key={f} type="button" className={outputFormat === f ? 'selected' : ''} onClick={() => setOutputFormat(f)}>{f}</button>)}</div><span>{result.bytes} bytes</span></div><pre>{output}</pre><button type="button" className="secondary" onClick={() => copy(output, 'result')}>{copied === 'result' ? <Check size={15}/> : <Copy size={15}/>} {copied === 'result' ? 'Copied' : 'Copy result'}</button>{['symmetric', 'rsa'].includes(tab) && form.operation === 'encrypt' && <button className="reuse" onClick={() => { setForm(f => ({ ...f, input: result.base64, operation: 'decrypt', ...(tab === 'rsa' && keys ? { key: keys.privateKey } : {}) })); setResult(null); }}>Use as decryption input <ArrowRight size={15}/></button>}{tab === 'rsa' && form.operation.startsWith('sign') && <button className="reuse" onClick={() => { setForm(f => ({ ...f, signature: result.base64, operation: f.operation === 'signHash' ? 'verifyHash' : 'verify', ...(keys ? { key: keys.publicKey } : {}) })); setResult(null); }}>Verify this signature <ArrowRight size={15}/></button>}</>}</div></section><div className="insight"><span><Braces size={18}/> UNDER THE HOOD</span><p>Every experiment runs against the local <strong>CryptographyHelper</strong> library through the .NET API.</p><p>Inputs and keys stay in this tab's memory and are sent to your local API. Nothing is saved by the playground.</p></div></div>
    </div></>;
}






