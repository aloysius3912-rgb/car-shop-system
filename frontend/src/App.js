import React, { useEffect, useState, useCallback } from 'react';
import io from 'socket.io-client';

const API_BASE = 'https://car-shop-system.onrender.com';
const socket = io(API_BASE, { transports: ['websocket', 'polling'] });

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
      fontFamily: "'DM Mono', monospace", fontWeight: 600, fontSize: 14,
      boxShadow: '0 4px 20px rgba(0,0,0,0.25)',
      animation: 'slideUp 0.25s ease',
    }}>{item.msg}</div>
  );
}

const norm = (raw) => raw?.['0'] || raw;

const apiFetch = (path, opts = {}) =>
  fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  }).then(async (res) => {
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `HTTP ${res.status}`);
    }
    return res.json();
  });

function ConfirmDialog({ name, onConfirm, onCancel }) {
  return (
    <div style={{
      position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.55)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 8888,
    }}>
      <div style={{
        background: '#1a1a2e', border: '1px solid #ef4444', borderRadius: 14,
        padding: '32px 36px', maxWidth: 360, width: '90%', textAlign: 'center',
        fontFamily: "'DM Mono', monospace",
      }}>
        <div style={{ fontSize: 36, marginBottom: 12 }}>⚠️</div>
        <h3 style={{ color: '#fff', margin: '0 0 8px', fontSize: 18 }}>Delete Member?</h3>
        <p style={{ color: '#aaa', margin: '0 0 24px', fontSize: 14, lineHeight: 1.5 }}>
          This will permanently remove <strong style={{ color: '#ef4444' }}>{name}</strong> and all their points.
        </p>
        <div style={{ display: 'flex', gap: 12, justifyContent: 'center' }}>
          <button onClick={onCancel} style={btnStyle('#374151', '#fff')}>Cancel</button>
          <button onClick={onConfirm} style={btnStyle('#ef4444', '#fff')}>Delete</button>
        </div>
      </div>
    </div>
  );
}

const btnStyle = (bg, color, extra = {}) => ({
  padding: '10px 22px', borderRadius: 8, border: 'none', cursor: 'pointer',
  background: bg, color, fontWeight: 700, fontSize: 14,
  fontFamily: "'DM Mono', monospace",
  ...extra,
});

function StatusBadge({ connected }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 7, fontSize: 12, fontFamily: "'DM Mono', monospace", color: connected ? '#10b981' : '#f59e0b' }}>
      <span style={{
        width: 8, height: 8, borderRadius: '50%',
        background: connected ? '#10b981' : '#f59e0b',
        boxShadow: connected ? '0 0 6px #10b981' : '0 0 6px #f59e0b',
        display: 'inline-block',
      }} />
      {connected ? 'Live' : 'Connecting…'}
    </div>
  );
}

function inputStyle(extra = {}) {
  return {
    background: '#0d0d1a', border: '1px solid #1e1e3f',
    color: '#fff', padding: '11px 16px', borderRadius: 8,
    fontSize: 14, fontFamily: "'DM Mono', monospace",
    ...extra,
  };
}

// Format date nicely e.g. "9 Jun 2026"
function formatDate(dateStr) {
  if (!dateStr) return 'Unknown';
  const d = new Date(dateStr);
  return d.toLocaleDateString('en-SG', { day: 'numeric', month: 'short', year: 'numeric' });
}

export default function App() {
  const [members, setMembers] = useState([]);
  const [newName, setNewName] = useState('');
  const [newPlate, setNewPlate] = useState('');
  const [newModel, setNewModel] = useState('');
  const [adjustments, setAdjustments] = useState({});
  const [searchQuery, setSearchQuery] = useState('');
  const [loading, setLoading] = useState(true);
  const [registering, setRegistering] = useState(false);
  const [connected, setConnected] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(null);
  const [serverWaking, setServerWaking] = useState(false);

  const fetchMembers = useCallback(() => {
    setLoading(true);
    const wakeTimer = setTimeout(() => setServerWaking(true), 4000);
    apiFetch('/api/members')
      .then((data) => {
        if (Array.isArray(data)) setMembers(data);
      })
      .catch(() => toast('Could not reach server. Render may be waking up — try again in 15s.', 'error'))
      .finally(() => { setLoading(false); clearTimeout(wakeTimer); setServerWaking(false); });
  }, []);

  useEffect(() => {
    fetchMembers();
    socket.on('connect', () => setConnected(true));
    socket.on('disconnect', () => setConnected(false));
    socket.on('pointsUpdated', ({ memberId, newTotal }) => {
      setMembers(prev => prev.map(raw => {
        const m = norm(raw);
        return m.member_id == memberId ? { ...m, total_points: newTotal } : raw;
      }));
    });
    socket.on('memberAdded', (newMember) => setMembers(prev => [...prev, newMember]));
    socket.on('memberDeleted', ({ memberId }) => {
      setMembers(prev => prev.filter(raw => norm(raw).member_id != memberId));
    });
    return () => {
      socket.off('connect'); socket.off('disconnect');
      socket.off('pointsUpdated'); socket.off('memberAdded'); socket.off('memberDeleted');
    };
  }, [fetchMembers]);

  const handleAddMember = async (e) => {
    e.preventDefault();
    if (!newName.trim()) return;
    setRegistering(true);
    try {
      await apiFetch('/api/new-member', {
        method: 'POST',
        body: JSON.stringify({
          fullName: newName.trim(),
          carPlate: newPlate.trim().toUpperCase(),
          carModel: newModel.trim(),
        }),
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
    try {
      await apiFetch('/api/add-points', {
        method: 'POST',
        body: JSON.stringify({ memberId: id, points: pts, description: 'Manual Adjustment' }),
      });
      toast(`${pts >= 0 ? '+' : ''}${pts} pts applied`);
      setAdjustments(prev => ({ ...prev, [id]: '' }));
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

  const filteredMembers = members
    .filter(raw => {
      const m = norm(raw);
      if (!m.full_name) return false;
      const q = searchQuery.toLowerCase();
      return (
        m.full_name.toLowerCase().includes(q) ||
        (m.car_plate && m.car_plate.toLowerCase().includes(q)) ||
        (m.car_model && m.car_model.toLowerCase().includes(q))
      );
    })
    .sort((a, b) => norm(a).full_name.localeCompare(norm(b).full_name));

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Syne:wght@700;800&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: #0d0d1a; min-height: 100vh; }
        @keyframes slideUp { from { transform: translateY(16px); opacity:0; } to { transform: translateY(0); opacity:1; } }
        @keyframes fadeIn { from { opacity:0; transform:translateY(8px); } to { opacity:1; transform:translateY(0); } }
        @keyframes spin { to { transform: rotate(360deg); } }
      `}</style>

      <Toast />
      {confirmDelete && <ConfirmDialog name={confirmDelete.name} onConfirm={confirmDeleteMember} onCancel={() => setConfirmDelete(null)} />}

      <div style={{ maxWidth: 900, margin: '0 auto', padding: '40px 20px', fontFamily: "'DM Mono', monospace" }}>

        {/* HEADER */}
        <div style={{ marginBottom: 40, display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div>
            <div style={{ fontSize: 11, letterSpacing: 4, color: '#10b981', marginBottom: 6, textTransform: 'uppercase' }}>Membership System</div>
            <h1 style={{ fontFamily: "'Syne', sans-serif", fontSize: 'clamp(28px,5vw,42px)', color: '#fff', fontWeight: 800, lineHeight: 1.1 }}>
              Car Shop<br /><span style={{ color: '#10b981' }}>Dashboard</span>
            </h1>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 8 }}>
            <StatusBadge connected={connected} />
            <span style={{ fontSize: 11, color: '#555' }}>{filteredMembers.length} member{filteredMembers.length !== 1 ? 's' : ''}</span>
          </div>
        </div>

        {serverWaking && (
          <div style={{ background: '#f59e0b18', border: '1px solid #f59e0b44', borderRadius: 10, padding: '12px 18px', marginBottom: 24, color: '#f59e0b', fontSize: 13 }}>
            ⏳ Render server is waking up — this can take up to 15 seconds on the free plan…
          </div>
        )}

        {/* REGISTER FORM */}
        <div style={{ background: '#13132a', border: '1px solid #1e1e3f', borderRadius: 14, padding: 28, marginBottom: 28 }}>
          <div style={{ fontSize: 11, color: '#10b981', letterSpacing: 3, marginBottom: 14, textTransform: 'uppercase' }}>Register New Customer</div>
          <form onSubmit={handleAddMember} style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
            <input
              type="text" placeholder="Customer name…" value={newName} onChange={e => setNewName(e.target.value)} required
              style={inputStyle({ flex: '2 1 160px' })}
            />
            <input
              type="text" placeholder="Plate (e.g. SBA1234A)" value={newPlate} onChange={e => setNewPlate(e.target.value.toUpperCase())}
              style={inputStyle({ flex: '1 1 130px', textTransform: 'uppercase' })}
            />
            <input
              type="text" placeholder="Car model (e.g. Tesla Model 3)" value={newModel} onChange={e => setNewModel(e.target.value)}
              style={inputStyle({ flex: '2 1 180px' })}
            />
            <button type="submit" disabled={registering} style={{ ...btnStyle('#10b981', '#0d0d1a'), flex: '0 0 auto', opacity: registering ? 0.6 : 1, display: 'flex', alignItems: 'center', gap: 8 }}>
              {registering ? <span style={{ width: 14, height: 14, border: '2px solid #0d0d1a', borderTopColor: 'transparent', borderRadius: '50%', display: 'inline-block', animation: 'spin 0.7s linear infinite' }} /> : '＋'}
              {registering ? 'Saving…' : 'Register'}
            </button>
          </form>
        </div>

        {/* SEARCH */}
        <div style={{ marginBottom: 28, position: 'relative' }}>
          <span style={{ position: 'absolute', left: 16, top: '50%', transform: 'translateY(-50%)', color: '#555', fontSize: 18, pointerEvents: 'none' }}>🔍</span>
          <input
            type="text" placeholder="Search by name, plate or car model…" value={searchQuery} onChange={e => setSearchQuery(e.target.value)}
            style={inputStyle({ width: '100%', paddingLeft: 48, fontSize: 16 })}
          />
          {searchQuery && (
            <button onClick={() => setSearchQuery('')} style={{ position: 'absolute', right: 14, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', color: '#555', cursor: 'pointer', fontSize: 18 }}>✕</button>
          )}
        </div>

        {/* MEMBER LIST */}
        {loading ? (
          <div style={{ textAlign: 'center', padding: '60px 0', color: '#555' }}>
            <div style={{ width: 36, height: 36, border: '3px solid #1e1e3f', borderTopColor: '#10b981', borderRadius: '50%', animation: 'spin 0.8s linear infinite', margin: '0 auto 16px' }} />
            <p style={{ fontSize: 14 }}>Loading members…</p>
          </div>
        ) : filteredMembers.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '60px 0', color: '#555', fontSize: 15 }}>
            {searchQuery ? `No results for "${searchQuery}"` : 'No members yet. Register the first one above.'}
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {filteredMembers.map((raw, index) => {
              const member = norm(raw);
              const pts = member.total_points ?? 0;
              const tier = pts >= 1000 ? { label: 'GOLD', color: '#f59e0b' }
                : pts >= 500 ? { label: 'SILVER', color: '#94a3b8' }
                : { label: 'BRONZE', color: '#cd7c3a' };

              return (
                <div key={member.member_id || index} style={{
                  background: '#13132a', border: '1px solid #1e1e3f', borderRadius: 12,
                  padding: '18px 20px', display: 'flex', justifyContent: 'space-between',
                  alignItems: 'center', gap: 16, flexWrap: 'wrap',
                  animation: 'fadeIn 0.25s ease both', animationDelay: `${index * 0.04}s`,
                }}>
                  {/* INFO */}
                  <div style={{ flex: '1 1 200px', minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', marginBottom: 6 }}>
                      <span style={{ fontFamily: "'Syne', sans-serif", fontWeight: 800, fontSize: 18, color: '#fff' }}>{member.full_name}</span>

                      {member.car_plate && (
                        <span style={{ background: '#f59e0b22', color: '#f59e0b', border: '1px solid #f59e0b55', padding: '2px 10px', borderRadius: 6, fontSize: 11, fontWeight: 600, letterSpacing: 2 }}>
                          {member.car_plate.toUpperCase()}
                        </span>
                      )}

                      <span style={{ background: `${tier.color}18`, color: tier.color, border: `1px solid ${tier.color}44`, padding: '2px 8px', borderRadius: 6, fontSize: 10, fontWeight: 700, letterSpacing: 1.5 }}>
                        {tier.label}
                      </span>
                    </div>

                    {/* Car model + date joined */}
                    <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', marginBottom: 8 }}>
                      {member.car_model && (
                        <span style={{ fontSize: 12, color: '#888' }}>🚗 {member.car_model}</span>
                      )}
                      <span style={{ fontSize: 12, color: '#555' }}>
                        📅 Joined {formatDate(member.date_joined)}
                      </span>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'baseline', gap: 5 }}>
                      <span style={{ fontSize: 28, fontWeight: 700, color: '#10b981' }}>{pts.toLocaleString()}</span>
                      <span style={{ fontSize: 12, color: '#555' }}>pts</span>
                    </div>
                  </div>

                  {/* CONTROLS */}
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                    <input
                      type="number" placeholder="+/-"
                      value={adjustments[member.member_id] || ''}
                      onChange={e => setAdjustments(prev => ({ ...prev, [member.member_id]: e.target.value }))}
                      onKeyDown={e => e.key === 'Enter' && handleUpdatePoints(member.member_id)}
                      style={inputStyle({ width: 80, textAlign: 'center', padding: '9px 8px' })}
                    />
                    <button onClick={() => handleUpdatePoints(member.member_id)} style={btnStyle('#3b82f6', '#fff')}>Apply</button>
                    <button onClick={() => handleDeleteMember(member.member_id, member.full_name)} style={btnStyle('#ef444422', '#ef4444', { border: '1px solid #ef444455' })}>Delete</button>
                  </div>
                </div>
              );
            })}
          </div>
        )}

        <div style={{ marginTop: 48, textAlign: 'center', fontSize: 11, color: '#2a2a45', letterSpacing: 2 }}>
          CAR SHOP SYSTEM · {new Date().getFullYear()}
        </div>
      </div>
    </>
  );
}