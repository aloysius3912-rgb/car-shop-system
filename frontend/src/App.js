import React, { useEffect, useState, useCallback } from 'react';
import io from 'socket.io-client';

const API_BASE = 'https://car-shop-system.onrender.com';
const socket = io(API_BASE, { transports: ['websocket', 'polling'] });

// ── Theme tokens ──
const THEMES = {
  dark: {
    bg: '#0d0d1a', card: '#13132a', border: '#1e1e3f',
    text: '#ffffff', textDim: '#9a9ab0', textFaint: '#55556e',
    inputBg: '#0d0d1a', accent: '#10b981', scrollbar: '#1e1e3f',
  },
  light: {
    bg: '#f6f4ef', card: '#ffffff', border: '#e4e0d6',
    text: '#1a1a2e', textDim: '#6b6b7d', textFaint: '#a8a499',
    inputBg: '#faf9f5', accent: '#0d9268', scrollbar: '#e4e0d6',
  },
};

function getInitialTheme() {
  const saved = localStorage.getItem('carshop_theme');
  if (saved === 'light' || saved === 'dark') return saved;
  return window.matchMedia?.('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}

// ── Service presets ──
const SERVICE_PRESETS = [
  { label: 'Auto Suction Door', points: 200 },
  { label: 'LED Install', points: 150 },
  { label: 'Soundproofing', points: 300 },
  { label: 'Audio System', points: 400 },
  { label: '360 Camera', points: 250 },
  { label: 'Custom', points: '' },
];

const REDEEM_PRESETS = [
  { label: '$5 Off', points: -50 },
  { label: '$10 Off', points: -100 },
  { label: '$20 Off', points: -200 },
  { label: '$50 Off', points: -500 },
  { label: 'Free Gift', points: -100 },
  { label: 'Custom Redeem', points: '' },
];

let _setToast = () => {};
function toast(msg, type = 'success') { _setToast({ msg, type, id: Date.now() }); }

function Toast() {
  const [item, setItem] = useState(null);
  useEffect(() => { _setToast = setItem; }, []);
  useEffect(() => {
    if (!item) return;
    const t = setTimeout(() => setItem(null), 3200);
    return () => clearTimeout(t);
  }, [item]);
  if (!item) return null;
  return (
    <div style={{
      position: 'fixed', bottom: 28, right: 28, zIndex: 9999,
      background: item.type === 'error' ? '#ef4444' : item.type === 'warn' ? '#f59e0b' : '#10b981',
      color: '#fff', padding: '12px 22px', borderRadius: 10,
      fontFamily: "'JetBrains Mono', monospace", fontWeight: 600, fontSize: 14,
      boxShadow: '0 4px 20px rgba(0,0,0,0.25)', animation: 'slideUp 0.25s ease',
    }}>{item.msg}</div>
  );
}

const norm = (raw) => raw?.['0'] || raw;
let _onUnauthorized = () => {};

const apiFetch = (path, opts = {}) =>
  fetch(`${API_BASE}${path}`, {
    headers: {
      'Content-Type': 'application/json',
      'x-admin-token': localStorage.getItem('carshop_token') || '',
    },
    ...opts,
  }).then(async (res) => {
    if (res.status === 401) {
      localStorage.removeItem('carshop_token');
      _onUnauthorized();
      throw new Error('Session expired. Please log in again.');
    }
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `HTTP ${res.status}`);
    }
    return res.json();
  });

// ── Shared styles ──
const btnStyle = (bg, color, extra = {}) => ({
  padding: '10px 22px', borderRadius: 8, border: 'none', cursor: 'pointer',
  background: bg, color, fontWeight: 700, fontSize: 14,
  fontFamily: "'JetBrains Mono', monospace", ...extra,
});

function inputStyle(theme, extra = {}) {
  return {
    background: theme.inputBg, border: `1px solid ${theme.border}`,
    color: theme.text, padding: '11px 16px', borderRadius: 8,
    fontSize: 14, fontFamily: "'JetBrains Mono', monospace", ...extra,
  };
}

function formatDate(dateStr) {
  if (!dateStr) return 'Unknown';
  const d = new Date(dateStr);
  return d.toLocaleDateString('en-SG', { day: 'numeric', month: 'short', year: 'numeric' });
}

function formatDateTime(dateStr) {
  if (!dateStr) return '';
  const d = new Date(dateStr);
  return d.toLocaleDateString('en-SG', { day: 'numeric', month: 'short' }) + ', ' +
    d.toLocaleTimeString('en-SG', { hour: '2-digit', minute: '2-digit' });
}

// ── Theme toggle ──
function ThemeToggle({ theme, themeName, onToggle }) {
  const isDark = themeName === 'dark';
  return (
    <button onClick={onToggle} title={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
      style={{
        width: 52, height: 28, borderRadius: 14, border: `1px solid ${theme.border}`,
        background: isDark ? '#0a0a14' : '#eae6dc', position: 'relative', cursor: 'pointer',
        boxShadow: `inset 0 1px 3px rgba(0,0,0,${isDark ? 0.5 : 0.12})`,
        transition: 'background 0.25s ease', padding: 0,
      }}>
      <span style={{
        position: 'absolute', top: 2, left: isDark ? 2 : 26,
        width: 22, height: 22, borderRadius: '50%',
        background: isDark ? '#10b981' : '#f59e0b',
        boxShadow: isDark ? '0 0 8px rgba(16,185,129,0.7)' : '0 0 8px rgba(245,158,11,0.5)',
        transition: 'left 0.25s ease', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 11,
      }}>{isDark ? '🌙' : '☀️'}</span>
    </button>
  );
}

function StatusBadge({ connected }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 7, fontSize: 12, fontFamily: "'JetBrains Mono', monospace", color: connected ? '#10b981' : '#f59e0b' }}>
      <span style={{ width: 8, height: 8, borderRadius: '50%', background: connected ? '#10b981' : '#f59e0b', boxShadow: connected ? '0 0 6px #10b981' : '0 0 6px #f59e0b', display: 'inline-block' }} />
      {connected ? 'Live' : 'Connecting…'}
    </div>
  );
}

// ── Confirm dialog ──
function ConfirmDialog({ title, message, onConfirm, onCancel, theme, confirmLabel = 'Delete', confirmColor = '#ef4444' }) {
  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.55)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 8888 }}>
      <div style={{ background: theme.card, border: `1px solid ${confirmColor}`, borderRadius: 14, padding: '32px 36px', maxWidth: 360, width: '90%', textAlign: 'center', fontFamily: "'JetBrains Mono', monospace" }}>
        <div style={{ fontSize: 36, marginBottom: 12 }}>⚠️</div>
        <h3 style={{ color: theme.text, margin: '0 0 8px', fontSize: 18 }}>{title}</h3>
        <p style={{ color: theme.textDim, margin: '0 0 24px', fontSize: 14, lineHeight: 1.5 }}>{message}</p>
        <div style={{ display: 'flex', gap: 12, justifyContent: 'center' }}>
          <button onClick={onCancel} style={btnStyle('#374151', '#fff')}>Cancel</button>
          <button onClick={onConfirm} style={btnStyle(confirmColor, '#fff')}>{confirmLabel}</button>
        </div>
      </div>
    </div>
  );
}

// ── Change password modal ──
function ChangePasswordModal({ onClose, theme }) {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    if (newPassword.length < 4) { setError('New password must be at least 4 characters.'); return; }
    if (newPassword !== confirmPassword) { setError('New passwords do not match.'); return; }
    setLoading(true);
    try {
      const data = await apiFetch('/api/change-password', {
        method: 'POST',
        body: JSON.stringify({ currentPassword, newPassword }),
      });
      localStorage.setItem('carshop_token', data.token);
      toast('✅ Password changed successfully!');
      onClose();
    } catch (err) {
      setError(err.message || 'Could not change password.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.55)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 8888 }}>
      <form onSubmit={handleSubmit} style={{ background: theme.card, border: `1px solid ${theme.border}`, borderRadius: 14, padding: '32px 36px', maxWidth: 380, width: '90%', fontFamily: "'JetBrains Mono', monospace" }}>
        <h3 style={{ color: theme.text, margin: '0 0 18px', fontSize: 18, fontFamily: "'Space Grotesk', sans-serif" }}>Change Password</h3>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginBottom: 14 }}>
          <input type="password" placeholder="Current password" value={currentPassword} onChange={e => setCurrentPassword(e.target.value)} required autoFocus style={inputStyle(theme, { width: '100%' })} />
          <input type="password" placeholder="New password" value={newPassword} onChange={e => setNewPassword(e.target.value)} required style={inputStyle(theme, { width: '100%' })} />
          <input type="password" placeholder="Retype new password" value={confirmPassword} onChange={e => setConfirmPassword(e.target.value)} required style={inputStyle(theme, { width: '100%' })} />
        </div>
        {error && <div style={{ color: '#ef4444', fontSize: 13, marginBottom: 14 }}>{error}</div>}
        <div style={{ display: 'flex', gap: 12, justifyContent: 'flex-end' }}>
          <button type="button" onClick={onClose} style={btnStyle('#374151', '#fff')}>Cancel</button>
          <button type="submit" disabled={loading} style={{ ...btnStyle(theme.accent, theme.bg), opacity: loading ? 0.6 : 1 }}>
            {loading ? 'Saving…' : 'Save Password'}
          </button>
        </div>
      </form>
    </div>
  );
}

// ── Points panel with earn/redeem tabs ──
function PointsPanel({ memberId, theme, pointsValue, descriptionValue, onPointsChange, onDescriptionChange, onApply }) {
  const [tab, setTab] = useState('earn');
  const [selectedPreset, setSelectedPreset] = useState(null);
  const isRedeem = tab === 'redeem';
  const presets = isRedeem ? REDEEM_PRESETS : SERVICE_PRESETS;
  const tabAccent = isRedeem ? '#ef4444' : theme.accent;

  const choosePreset = (preset) => {
    setSelectedPreset(preset.label);
    const isCustom = preset.label === 'Custom' || preset.label === 'Custom Redeem';
    onDescriptionChange(isCustom ? '' : preset.label);
    if (preset.points !== '') onPointsChange(String(preset.points));
  };

  const switchTab = (t) => { setTab(t); setSelectedPreset(null); onPointsChange(''); onDescriptionChange(''); };

  return (
    <div style={{ marginTop: 14, paddingTop: 14, borderTop: `1px solid ${theme.border}`, animation: 'fadeIn 0.2s ease both' }}>
      <div style={{ display: 'flex', gap: 0, marginBottom: 14, background: theme.inputBg, borderRadius: 8, padding: 3, border: `1px solid ${theme.border}`, width: 'fit-content' }}>
        {[['earn', '＋ Earn Points'], ['redeem', '− Redeem Points']].map(([key, label]) => (
          <button key={key} onClick={() => switchTab(key)} style={{
            padding: '7px 16px', borderRadius: 6, fontSize: 12, fontWeight: 700,
            fontFamily: "'JetBrains Mono', monospace", cursor: 'pointer', border: 'none',
            background: tab === key ? (key === 'redeem' ? '#ef4444' : theme.accent) : 'transparent',
            color: tab === key ? (key === 'redeem' ? '#fff' : theme.bg) : theme.textDim,
            transition: 'all 0.15s ease',
          }}>{label}</button>
        ))}
      </div>

      <div style={{ fontSize: 11, color: tabAccent, letterSpacing: 2, marginBottom: 10, textTransform: 'uppercase' }}>
        {isRedeem ? 'Redeem Presets' : 'Quick-Tap Service'}
      </div>

      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 14 }}>
        {presets.map(preset => {
          const isActive = selectedPreset === preset.label;
          return (
            <button key={preset.label} onClick={() => choosePreset(preset)} style={{
              padding: '8px 14px', borderRadius: 8, fontSize: 13,
              fontFamily: "'JetBrains Mono', monospace", fontWeight: 600,
              cursor: 'pointer', whiteSpace: 'nowrap',
              border: `1px solid ${isActive ? tabAccent : theme.border}`,
              background: isActive ? `${tabAccent}18` : theme.inputBg,
              color: isActive ? tabAccent : theme.textDim,
              transition: 'all 0.15s ease',
            }}>
              {preset.label}{preset.points !== '' ? ` · ${preset.points}` : ''}
            </button>
          );
        })}
      </div>

      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        <input type="text" placeholder={isRedeem ? 'Redemption description…' : 'Description (e.g. LED Install)'}
          value={descriptionValue} onChange={e => { onDescriptionChange(e.target.value); setSelectedPreset(null); }}
          style={inputStyle(theme, { flex: '2 1 180px' })} />
        <input type="number" placeholder={isRedeem ? 'Points to deduct' : 'Points to add'}
          value={pointsValue} onChange={e => onPointsChange(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && onApply()}
          style={inputStyle(theme, { width: 130, textAlign: 'center', color: isRedeem && pointsValue && parseInt(pointsValue) < 0 ? '#ef4444' : theme.text })} />
        <button onClick={onApply} style={btnStyle(isRedeem ? '#ef4444' : theme.accent, isRedeem ? '#fff' : theme.bg)}>
          {isRedeem ? 'Redeem' : 'Apply'}
        </button>
      </div>
      {isRedeem && <p style={{ marginTop: 10, fontSize: 11, color: theme.textFaint }}>💡 Tap a preset or enter a negative number (e.g. -100) to deduct.</p>}
    </div>
  );
}

// ── Cars panel (expandable) ──
function CarsPanel({ member, theme, onCarAdded, onCarDeleted }) {
  const [isOpen, setIsOpen] = useState(false);
  const [showAddForm, setShowAddForm] = useState(false);
  const [newPlate, setNewPlate] = useState('');
  const [newModel, setNewModel] = useState('');
  const [adding, setAdding] = useState(false);
  const [confirmDeleteCar, setConfirmDeleteCar] = useState(null);

  const handleAddCar = async (e) => {
    e.preventDefault();
    if (!newPlate.trim() && !newModel.trim()) { toast('Enter a plate or model', 'warn'); return; }
    setAdding(true);
    try {
      const data = await apiFetch(`/api/add-car/${member.member_id}`, {
        method: 'POST',
        body: JSON.stringify({ carPlate: newPlate.trim().toUpperCase(), carModel: newModel.trim() }),
      });
      onCarAdded(member.member_id, data.car);
      toast(`✅ Car added to ${member.full_name}!`);
      setNewPlate(''); setNewModel(''); setShowAddForm(false);
    } catch (err) {
      toast(`Failed to add car: ${err.message}`, 'error');
    } finally {
      setAdding(false);
    }
  };

  const handleDeleteCar = async (carId) => {
    try {
      await apiFetch(`/api/delete-car/${carId}`, { method: 'DELETE' });
      onCarDeleted(member.member_id, carId);
      toast('Car removed.', 'warn');
    } catch (err) {
      toast(`Failed to remove car: ${err.message}`, 'error');
    }
    setConfirmDeleteCar(null);
  };

  const cars = member.cars || [];

  return (
    <div style={{ marginTop: 8 }}>
      <button onClick={() => setIsOpen(p => !p)} style={{
        background: 'none', border: 'none', color: theme.accent,
        fontFamily: "'JetBrains Mono', monospace", fontSize: 12,
        cursor: 'pointer', padding: 0, display: 'flex', alignItems: 'center', gap: 6, letterSpacing: 1,
      }}>
        <span style={{ display: 'inline-block', transition: 'transform 0.2s', transform: isOpen ? 'rotate(90deg)' : 'rotate(0deg)' }}>▶</span>
        {isOpen ? 'Hide Cars' : `View Cars (${cars.length})`}
      </button>

      {isOpen && (
        <div style={{ marginTop: 12, padding: '14px 16px', background: theme.inputBg, border: `1px solid ${theme.border}`, borderRadius: 10, animation: 'fadeIn 0.2s ease both' }}>
          <div style={{ fontSize: 11, color: theme.accent, letterSpacing: 2, marginBottom: 10, textTransform: 'uppercase' }}>Registered Cars</div>

          {cars.length === 0 ? (
            <p style={{ color: theme.textFaint, fontSize: 13, marginBottom: 12 }}>No cars registered yet.</p>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 12 }}>
              {cars.map(car => (
                <div key={car.car_id} style={{
                  display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                  background: theme.card, border: `1px solid ${theme.border}`, borderRadius: 8, padding: '10px 14px',
                }}>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                    {car.car_plate && (
                      <span style={{ background: '#f59e0b22', color: '#f59e0b', border: '1px solid #f59e0b55', padding: '2px 10px', borderRadius: 6, fontSize: 11, fontWeight: 600, letterSpacing: 2, width: 'fit-content' }}>
                        {car.car_plate.toUpperCase()}
                      </span>
                    )}
                    {car.car_model && <span style={{ fontSize: 12, color: theme.textDim }}>🚗 {car.car_model}</span>}
                  </div>
                  {cars.length > 1 && (
                    <button onClick={() => setConfirmDeleteCar(car)} style={{
                      background: 'none', border: `1px solid #ef444455`, color: '#ef4444',
                      borderRadius: 6, padding: '4px 10px', cursor: 'pointer', fontSize: 12,
                      fontFamily: "'JetBrains Mono', monospace",
                    }}>Remove</button>
                  )}
                </div>
              ))}
            </div>
          )}

          {showAddForm ? (
            <form onSubmit={handleAddCar} style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
              <input type="text" placeholder="Plate (e.g. SBC1234A)" value={newPlate}
                onChange={e => setNewPlate(e.target.value.toUpperCase())}
                style={inputStyle(theme, { flex: '1 1 130px', textTransform: 'uppercase' })} />
              <input type="text" placeholder="Car model" value={newModel}
                onChange={e => setNewModel(e.target.value)}
                style={inputStyle(theme, { flex: '2 1 160px' })} />
              <button type="submit" disabled={adding} style={{ ...btnStyle(theme.accent, theme.bg), opacity: adding ? 0.6 : 1 }}>
                {adding ? 'Adding…' : 'Add'}
              </button>
              <button type="button" onClick={() => { setShowAddForm(false); setNewPlate(''); setNewModel(''); }}
                style={btnStyle('#374151', '#fff')}>Cancel</button>
            </form>
          ) : (
            <button onClick={() => setShowAddForm(true)} style={{
              background: 'none', border: `1px solid ${theme.border}`, color: theme.accent,
              fontFamily: "'JetBrains Mono', monospace", fontSize: 12, letterSpacing: 1,
              padding: '6px 14px', borderRadius: 6, cursor: 'pointer',
            }}>＋ Add Another Car</button>
          )}
        </div>
      )}

      {confirmDeleteCar && (
        <ConfirmDialog
          title="Remove Car?"
          message={`Remove ${confirmDeleteCar.car_plate || confirmDeleteCar.car_model} from ${member.full_name}? Their points will not be affected.`}
          confirmLabel="Remove"
          confirmColor="#ef4444"
          theme={theme}
          onConfirm={() => handleDeleteCar(confirmDeleteCar.car_id)}
          onCancel={() => setConfirmDeleteCar(null)}
        />
      )}
    </div>
  );
}

// ── History drawer ──
function HistoryDrawer({ memberId, isOpen, transactions, loading, theme }) {
  if (!isOpen) return null;
  return (
    <div style={{ width: '100%', marginTop: 14, paddingTop: 14, borderTop: `1px solid ${theme.border}`, animation: 'fadeIn 0.2s ease both' }}>
      <div style={{ fontSize: 11, color: theme.accent, letterSpacing: 2, marginBottom: 10, textTransform: 'uppercase' }}>Transaction History</div>
      {loading ? (
        <div style={{ color: theme.textFaint, fontSize: 13, padding: '8px 0' }}>Loading history…</div>
      ) : transactions.length === 0 ? (
        <div style={{ color: theme.textFaint, fontSize: 13, padding: '8px 0' }}>No transactions yet.</div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 220, overflowY: 'auto', paddingRight: 6 }}>
          {transactions.map(tx => {
            const positive = tx.points_added >= 0;
            return (
              <div key={tx.transaction_id} style={{
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                background: theme.inputBg, border: `1px solid ${theme.border}`, borderRadius: 8, padding: '10px 14px', fontSize: 13,
              }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                  <span style={{ color: theme.text }}>{tx.description || 'No description'}</span>
                  <span style={{ color: theme.textFaint, fontSize: 11 }}>{formatDateTime(tx.transaction_date)}</span>
                </div>
                <span style={{ color: positive ? '#10b981' : '#ef4444', fontWeight: 700, fontSize: 14, whiteSpace: 'nowrap', marginLeft: 12 }}>
                  {positive ? '+' : ''}{tx.points_added} pts
                </span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── Login screen ──
function LoginScreen({ onSuccess, theme, themeName, onToggleTheme }) {
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      });
      const data = await res.json();
      if (res.ok && data.success) {
        localStorage.setItem('carshop_token', data.token);
        onSuccess();
      } else {
        setError(data.error || 'Incorrect password');
      }
    } catch (err) {
      setError('Could not reach server. Try again in a moment.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', fontFamily: "'JetBrains Mono', monospace", background: theme.bg, padding: 20, transition: 'background 0.2s ease' }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Space+Grotesk:wght@600;700;800&display=swap');
        @keyframes spin { to { transform: rotate(360deg); } }
      `}</style>
      <div style={{ position: 'fixed', top: 20, right: 20 }}>
        <ThemeToggle theme={theme} themeName={themeName} onToggle={onToggleTheme} />
      </div>
      <form onSubmit={handleSubmit} style={{ background: theme.card, border: `1px solid ${theme.border}`, borderRadius: 14, padding: '40px 36px', maxWidth: 360, width: '100%', textAlign: 'center' }}>
        <div style={{ fontSize: 11, letterSpacing: 4, color: theme.accent, marginBottom: 6, textTransform: 'uppercase' }}>Membership System</div>
        <h1 style={{ fontFamily: "'Space Grotesk', sans-serif", fontSize: 28, color: theme.text, fontWeight: 800, marginBottom: 24, letterSpacing: -0.5 }}>
          Car Shop<br /><span style={{ color: theme.accent }}>Dashboard</span>
        </h1>
        <input type="password" placeholder="Enter password…" value={password} onChange={e => setPassword(e.target.value)} autoFocus
          style={inputStyle(theme, { width: '100%', textAlign: 'center', fontSize: 16, marginBottom: 14 })} />
        {error && <div style={{ color: '#ef4444', fontSize: 13, marginBottom: 14 }}>{error}</div>}
        <button type="submit" disabled={loading} style={{ ...btnStyle(theme.accent, theme.bg), width: '100%', opacity: loading ? 0.6 : 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8 }}>
          {loading && <span style={{ width: 14, height: 14, border: `2px solid ${theme.bg}`, borderTopColor: 'transparent', borderRadius: '50%', display: 'inline-block', animation: 'spin 0.7s linear infinite' }} />}
          {loading ? 'Checking…' : 'Unlock'}
        </button>
      </form>
    </div>
  );
}

// ════════════════════════════════════════════════
export default function App() {
  const [authed, setAuthed] = useState(!!localStorage.getItem('carshop_token'));
  const [themeName, setThemeName] = useState(getInitialTheme);
  const theme = THEMES[themeName];

  const [members, setMembers] = useState([]);
  const [newName, setNewName] = useState('');
  const [newPlate, setNewPlate] = useState('');
  const [newModel, setNewModel] = useState('');
  const [adjustments, setAdjustments] = useState({});
  const [descriptions, setDescriptions] = useState({});
  const [searchQuery, setSearchQuery] = useState('');
  const [loading, setLoading] = useState(true);
  const [registering, setRegistering] = useState(false);
  const [connected, setConnected] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(null);
  const [showChangePassword, setShowChangePassword] = useState(false);
  const [serverWaking, setServerWaking] = useState(false);
  const [openHistory, setOpenHistory] = useState({});
  const [historyData, setHistoryData] = useState({});
  const [historyLoading, setHistoryLoading] = useState({});
  const [openPointsPanel, setOpenPointsPanel] = useState(null);

  const toggleTheme = () => {
    const next = themeName === 'dark' ? 'light' : 'dark';
    setThemeName(next);
    localStorage.setItem('carshop_theme', next);
  };

  const fetchMembers = useCallback(() => {
    setLoading(true);
    const wakeTimer = setTimeout(() => setServerWaking(true), 4000);
    apiFetch('/api/members')
      .then(data => { if (Array.isArray(data)) setMembers(data); })
      .catch(() => toast('Could not reach server. Render may be waking up — try again in 15s.', 'error'))
      .finally(() => { setLoading(false); clearTimeout(wakeTimer); setServerWaking(false); });
  }, []);

  useEffect(() => {
    _onUnauthorized = () => setAuthed(false);
    if (!authed) { setLoading(false); return; }
    fetchMembers();
    socket.on('connect', () => setConnected(true));
    socket.on('disconnect', () => setConnected(false));
    socket.on('pointsUpdated', ({ memberId, newTotal }) => {
      setMembers(prev => prev.map(m => m.member_id == memberId ? { ...m, total_points: newTotal } : m));
    });
    socket.on('memberAdded', (newMember) => setMembers(prev => [...prev, newMember]));
    socket.on('memberDeleted', ({ memberId }) => setMembers(prev => prev.filter(m => m.member_id != memberId)));
    socket.on('carAdded', ({ memberId, car }) => {
      setMembers(prev => prev.map(m => m.member_id === memberId ? { ...m, cars: [...(m.cars || []), car] } : m));
    });
    socket.on('carDeleted', ({ memberId, carId }) => {
      setMembers(prev => prev.map(m => m.member_id === memberId ? { ...m, cars: (m.cars || []).filter(c => c.car_id !== carId) } : m));
    });
    socket.on('transactionAdded', ({ memberId, transaction }) => {
      setHistoryData(prev => {
        if (!prev[memberId]) return prev;
        return { ...prev, [memberId]: [transaction, ...prev[memberId]] };
      });
    });
    return () => {
      socket.off('connect'); socket.off('disconnect'); socket.off('pointsUpdated');
      socket.off('memberAdded'); socket.off('memberDeleted');
      socket.off('carAdded'); socket.off('carDeleted'); socket.off('transactionAdded');
    };
  }, [fetchMembers, authed]);

  const handleAddMember = async (e) => {
    e.preventDefault();
    if (!newName.trim()) return;
    setRegistering(true);
    try {
      await apiFetch('/api/new-member', {
        method: 'POST',
        body: JSON.stringify({ fullName: newName.trim(), carPlate: newPlate.trim().toUpperCase(), carModel: newModel.trim() }),
      });
      toast(`✅ ${newName.trim()} registered!`);
      setNewName(''); setNewPlate(''); setNewModel('');
    } catch (err) {
      toast(`Registration failed: ${err.message}`, 'error');
    } finally {
      setRegistering(false);
    }
  };

  const handleUpdatePoints = async (id) => {
    const pts = parseInt(adjustments[id], 10);
    if (isNaN(pts)) { toast('Enter a number first', 'warn'); return; }
    if (pts < 0) {
      const member = members.find(m => m.member_id == id);
      const currentPoints = member ? (member.total_points ?? 0) : 0;
      if (currentPoints + pts < 0) {
        toast(`Not enough points! ${currentPoints} pts available, need ${Math.abs(pts)} pts.`, 'error');
        return;
      }
    }
    const description = (descriptions[id] || '').trim() || 'Manual Adjustment';
    try {
      await apiFetch('/api/add-points', {
        method: 'POST',
        body: JSON.stringify({ memberId: id, points: pts, description }),
      });
      toast(`${pts >= 0 ? '+' : ''}${pts} pts · ${description}`);
      setAdjustments(prev => ({ ...prev, [id]: '' }));
      setDescriptions(prev => ({ ...prev, [id]: '' }));
      setOpenPointsPanel(null);
    } catch (err) {
      toast(`Points update failed: ${err.message}`, 'error');
    }
  };

  const handleDeleteMember = (id, name) => setConfirmDelete({ id, name });
  const confirmDeleteMember = async () => {
    const { id, name } = confirmDelete;
    setConfirmDelete(null);
    try {
      await apiFetch(`/api/delete-member/${id}`, { method: 'DELETE' });
      toast(`${name} removed.`, 'warn');
    } catch (err) {
      toast(`Delete failed: ${err.message}`, 'error');
    }
  };

  const toggleHistory = async (memberId) => {
    const isOpen = openHistory[memberId];
    setOpenHistory(prev => ({ ...prev, [memberId]: !isOpen }));
    if (!isOpen && !historyData[memberId]) {
      setHistoryLoading(prev => ({ ...prev, [memberId]: true }));
      try {
        const data = await apiFetch(`/api/transactions/${memberId}`);
        setHistoryData(prev => ({ ...prev, [memberId]: Array.isArray(data) ? data : [] }));
      } catch (err) {
        toast(`Could not load history: ${err.message}`, 'error');
        setHistoryData(prev => ({ ...prev, [memberId]: [] }));
      } finally {
        setHistoryLoading(prev => ({ ...prev, [memberId]: false }));
      }
    }
  };

  const handleCarAdded = (memberId, car) => {
    setMembers(prev => prev.map(m => m.member_id === memberId ? { ...m, cars: [...(m.cars || []), car] } : m));
  };

  const handleCarDeleted = (memberId, carId) => {
    setMembers(prev => prev.map(m => m.member_id === memberId ? { ...m, cars: (m.cars || []).filter(c => c.car_id !== carId) } : m));
  };

  const filteredMembers = members
    .filter(m => {
      if (!m.full_name) return false;
      const q = searchQuery.toLowerCase();
      const nameMatch = m.full_name.toLowerCase().includes(q);
      const carMatch = (m.cars || []).some(c =>
        (c.car_plate && c.car_plate.toLowerCase().includes(q)) ||
        (c.car_model && c.car_model.toLowerCase().includes(q))
      );
      return nameMatch || carMatch;
    })
    .sort((a, b) => a.full_name.localeCompare(b.full_name));

  if (!authed) {
    return <LoginScreen onSuccess={() => setAuthed(true)} theme={theme} themeName={themeName} onToggleTheme={toggleTheme} />;
  }

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Space+Grotesk:wght@600;700;800&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: ${theme.bg}; min-height: 100vh; transition: background 0.2s ease; }
        @keyframes slideUp { from { transform: translateY(16px); opacity:0; } to { transform: translateY(0); opacity:1; } }
        @keyframes fadeIn { from { opacity:0; transform:translateY(8px); } to { opacity:1; transform:translateY(0); } }
        @keyframes spin { to { transform: rotate(360deg); } }
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-thumb { background: ${theme.scrollbar}; border-radius: 3px; }
        ::placeholder { color: ${theme.textFaint}; }
      `}</style>

      <Toast />
      {confirmDelete && (
        <ConfirmDialog
          title="Delete Member?"
          message={`This will permanently remove ${confirmDelete.name}, all their cars, and all their points.`}
          theme={theme} onConfirm={confirmDeleteMember} onCancel={() => setConfirmDelete(null)}
        />
      )}
      {showChangePassword && <ChangePasswordModal onClose={() => setShowChangePassword(false)} theme={theme} />}

      <div style={{ maxWidth: 900, margin: '0 auto', padding: '40px 20px', fontFamily: "'JetBrains Mono', monospace" }}>

        {/* HEADER */}
        <div style={{ marginBottom: 40, display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div>
            <div style={{ fontSize: 11, letterSpacing: 4, color: theme.accent, marginBottom: 6, textTransform: 'uppercase' }}>Membership System</div>
            <h1 style={{ fontFamily: "'Space Grotesk', sans-serif", fontSize: 'clamp(28px,5vw,42px)', color: theme.text, fontWeight: 800, lineHeight: 1.1, letterSpacing: -0.5 }}>
              Car Shop<br /><span style={{ color: theme.accent }}>Dashboard</span>
            </h1>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 10 }}>
            <ThemeToggle theme={theme} themeName={themeName} onToggle={toggleTheme} />
            <StatusBadge connected={connected} />
            <span style={{ fontSize: 11, color: theme.textFaint }}>{filteredMembers.length} member{filteredMembers.length !== 1 ? 's' : ''}</span>
            <div style={{ display: 'flex', gap: 6 }}>
              <button onClick={() => setShowChangePassword(true)} style={{ background: 'none', border: `1px solid ${theme.border}`, color: theme.textFaint, fontFamily: "'JetBrains Mono', monospace", fontSize: 11, letterSpacing: 1, padding: '4px 10px', borderRadius: 6, cursor: 'pointer' }}>Settings</button>
              <button onClick={() => { localStorage.removeItem('carshop_token'); setAuthed(false); }} style={{ background: 'none', border: `1px solid ${theme.border}`, color: theme.textFaint, fontFamily: "'JetBrains Mono', monospace", fontSize: 11, letterSpacing: 1, padding: '4px 10px', borderRadius: 6, cursor: 'pointer' }}>Lock</button>
            </div>
          </div>
        </div>

        {serverWaking && (
          <div style={{ background: '#f59e0b18', border: '1px solid #f59e0b44', borderRadius: 10, padding: '12px 18px', marginBottom: 24, color: '#f59e0b', fontSize: 13 }}>
            ⏳ Render server is waking up — this can take up to 15 seconds on the free plan…
          </div>
        )}

        {/* REGISTER FORM */}
        <div style={{ background: theme.card, border: `1px solid ${theme.border}`, borderRadius: 14, padding: 28, marginBottom: 28 }}>
          <div style={{ fontSize: 11, color: theme.accent, letterSpacing: 3, marginBottom: 14, textTransform: 'uppercase' }}>Register New Customer</div>
          <form onSubmit={handleAddMember} style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
            <input type="text" placeholder="Customer name…" value={newName} onChange={e => setNewName(e.target.value)} required style={inputStyle(theme, { flex: '2 1 160px' })} />
            <input type="text" placeholder="Plate (e.g. SBA1234A)" value={newPlate} onChange={e => setNewPlate(e.target.value.toUpperCase())} style={inputStyle(theme, { flex: '1 1 130px', textTransform: 'uppercase' })} />
            <input type="text" placeholder="Car model (e.g. Tesla Model 3)" value={newModel} onChange={e => setNewModel(e.target.value)} style={inputStyle(theme, { flex: '2 1 180px' })} />
            <button type="submit" disabled={registering} style={{ ...btnStyle(theme.accent, theme.bg), flex: '0 0 auto', opacity: registering ? 0.6 : 1, display: 'flex', alignItems: 'center', gap: 8 }}>
              {registering ? <span style={{ width: 14, height: 14, border: `2px solid ${theme.bg}`, borderTopColor: 'transparent', borderRadius: '50%', display: 'inline-block', animation: 'spin 0.7s linear infinite' }} /> : '＋'}
              {registering ? 'Saving…' : 'Register'}
            </button>
          </form>
        </div>

        {/* SEARCH */}
        <div style={{ marginBottom: 28, position: 'relative' }}>
          <span style={{ position: 'absolute', left: 16, top: '50%', transform: 'translateY(-50%)', color: theme.textFaint, fontSize: 18, pointerEvents: 'none' }}>🔍</span>
          <input type="text" placeholder="Search by name, plate or car model…" value={searchQuery} onChange={e => setSearchQuery(e.target.value)} style={inputStyle(theme, { width: '100%', paddingLeft: 48, fontSize: 16 })} />
          {searchQuery && (
            <button onClick={() => setSearchQuery('')} style={{ position: 'absolute', right: 14, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', color: theme.textFaint, cursor: 'pointer', fontSize: 18 }}>✕</button>
          )}
        </div>

        {/* MEMBER LIST */}
        {loading ? (
          <div style={{ textAlign: 'center', padding: '60px 0', color: theme.textFaint }}>
            <div style={{ width: 36, height: 36, border: `3px solid ${theme.border}`, borderTopColor: theme.accent, borderRadius: '50%', animation: 'spin 0.8s linear infinite', margin: '0 auto 16px' }} />
            <p style={{ fontSize: 14 }}>Loading members…</p>
          </div>
        ) : filteredMembers.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '60px 0', color: theme.textFaint, fontSize: 15 }}>
            {searchQuery ? `No results for "${searchQuery}"` : 'No members yet. Register the first one above.'}
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {filteredMembers.map((member, index) => {
              const pts = member.total_points ?? 0;
              const cars = member.cars || [];
              const tier = pts >= 1000 ? { label: 'GOLD', color: '#f59e0b' }
                : pts >= 500 ? { label: 'SILVER', color: '#94a3b8' }
                : { label: 'BRONZE', color: '#cd7c3a' };
              const isHistoryOpen = !!openHistory[member.member_id];

              return (
                <div key={member.member_id || index} style={{ background: theme.card, border: `1px solid ${theme.border}`, borderRadius: 12, padding: '18px 20px', animation: 'fadeIn 0.25s ease both', animationDelay: `${index * 0.04}s` }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 16, flexWrap: 'wrap' }}>

                    {/* INFO */}
                    <div style={{ flex: '1 1 200px', minWidth: 0 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', marginBottom: 6 }}>
                        <span style={{ fontFamily: "'Space Grotesk', sans-serif", fontWeight: 700, fontSize: 18, color: theme.text, letterSpacing: -0.3 }}>{member.full_name}</span>

                        {/* show first car plate inline */}
                        {cars[0]?.car_plate && (
                          <span style={{ background: '#f59e0b22', color: '#f59e0b', border: '1px solid #f59e0b55', padding: '2px 10px', borderRadius: 6, fontSize: 11, fontWeight: 600, letterSpacing: 2 }}>
                            {cars[0].car_plate.toUpperCase()}
                          </span>
                        )}
                        {cars.length > 1 && (
                          <span style={{ background: `${theme.accent}18`, color: theme.accent, border: `1px solid ${theme.accent}44`, padding: '2px 8px', borderRadius: 6, fontSize: 10, fontWeight: 700 }}>
                            +{cars.length - 1} more
                          </span>
                        )}
                        <span style={{ background: `${tier.color}18`, color: tier.color, border: `1px solid ${tier.color}44`, padding: '2px 8px', borderRadius: 6, fontSize: 10, fontWeight: 700, letterSpacing: 1.5 }}>
                          {tier.label}
                        </span>
                      </div>

                      <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', marginBottom: 8 }}>
                        {cars[0]?.car_model && <span style={{ fontSize: 12, color: theme.textDim }}>🚗 {cars[0].car_model}</span>}
                        <span style={{ fontSize: 12, color: theme.textFaint }}>📅 Joined {formatDate(member.date_joined)}</span>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'baseline', gap: 5 }}>
                        <span style={{ fontSize: 28, fontWeight: 700, color: theme.accent }}>{pts.toLocaleString()}</span>
                        <span style={{ fontSize: 12, color: theme.textFaint }}>pts</span>
                      </div>
                    </div>

                    {/* CONTROLS */}
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                      <button
                        onClick={() => setOpenPointsPanel(prev => prev === member.member_id ? null : member.member_id)}
                        style={btnStyle('#3b82f6', '#fff')}
                      >
                        {openPointsPanel === member.member_id ? 'Close' : '＋ Add Points'}
                      </button>
                      <button onClick={() => handleDeleteMember(member.member_id, member.full_name)} style={btnStyle('#ef444422', '#ef4444', { border: '1px solid #ef444455' })}>Delete</button>
                    </div>
                  </div>

                  {/* Points panel */}
                  {openPointsPanel === member.member_id && (
                    <PointsPanel
                      memberId={member.member_id}
                      theme={theme}
                      pointsValue={adjustments[member.member_id] || ''}
                      descriptionValue={descriptions[member.member_id] || ''}
                      onPointsChange={v => setAdjustments(prev => ({ ...prev, [member.member_id]: v }))}
                      onDescriptionChange={v => setDescriptions(prev => ({ ...prev, [member.member_id]: v }))}
                      onApply={() => handleUpdatePoints(member.member_id)}
                    />
                  )}

                  {/* Cars panel */}
                  <CarsPanel
                    member={member}
                    theme={theme}
                    onCarAdded={handleCarAdded}
                    onCarDeleted={handleCarDeleted}
                  />

                  {/* History toggle */}
                  <div style={{ marginTop: 8 }}>
                    <button onClick={() => toggleHistory(member.member_id)} style={{ background: 'none', border: 'none', color: theme.accent, fontFamily: "'JetBrains Mono', monospace", fontSize: 12, cursor: 'pointer', padding: 0, display: 'flex', alignItems: 'center', gap: 6, letterSpacing: 1 }}>
                      <span style={{ display: 'inline-block', transition: 'transform 0.2s', transform: isHistoryOpen ? 'rotate(90deg)' : 'rotate(0deg)' }}>▶</span>
                      {isHistoryOpen ? 'Hide History' : 'View History'}
                    </button>
                  </div>

                  <HistoryDrawer
                    memberId={member.member_id}
                    isOpen={isHistoryOpen}
                    transactions={historyData[member.member_id] || []}
                    loading={!!historyLoading[member.member_id]}
                    theme={theme}
                  />
                </div>
              );
            })}
          </div>
        )}

        <div style={{ marginTop: 48, textAlign: 'center', fontSize: 11, color: theme.textFaint, letterSpacing: 2 }}>
          CAR SHOP SYSTEM · {new Date().getFullYear()}
        </div>
      </div>
    </>
  );
}