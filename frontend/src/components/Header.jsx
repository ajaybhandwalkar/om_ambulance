export default function Header({ onLogout, showLogout }) {
  return (
    <header style={{ background: '#eee', padding: '1rem 2rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
      <h1 style={{ margin: 0 }}>Patient Management System</h1>
      {showLogout && (
        <button onClick={onLogout} style={{ padding: '0.5rem 1rem', cursor: 'pointer' }}>
          Logout
        </button>
      )}
    </header>
  );
}
