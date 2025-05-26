
import { useNavigate } from 'react-router-dom';

export default function Header({ onLogout, showButtons }) {
  const navigate = useNavigate();

  const handleAddPatientClick = () => {
    navigate('/add-patient');  // Navigate to Add Patient page
  };

  const handleRegisterUserClick = () => {
    navigate('/register-user');  // Navigate to Register User page
  };

  const handleDashboardClick = () => {
    navigate('/');  // Navigate to Register User page
  };

  const handleLogoutClick = () => {
    onLogout();  // Logout function (clear token)
  };

  return (
    <header style={{ background: '#eee', padding: '1rem 2rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
      <h1 style={{ margin: 0 }} onClick={handleDashboardClick}>Om Ambulance</h1>
      {showButtons && (
        <div style={{ display: 'flex', gap: '1rem' }}>
          <button onClick={handleDashboardClick} style={{ padding: '0.5rem 1rem', cursor: 'pointer' }}>
            Dashboard
          </button>
          <button onClick={handleAddPatientClick} style={{ padding: '0.5rem 1rem', cursor: 'pointer' }}>
            Add Patient
          </button>
          <button onClick={handleRegisterUserClick} style={{ padding: '0.5rem 1rem', cursor: 'pointer' }}>
            Register User
          </button>
          <button onClick={handleLogoutClick} style={{ padding: '0.5rem 1rem', cursor: 'pointer' }}>
            Logout
          </button>
        </div>
      )}
    </header>
  );
}

