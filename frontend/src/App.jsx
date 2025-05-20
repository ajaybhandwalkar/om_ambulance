import { useState } from 'react';
import Login from './components/Login';
import PatientDashboard from './components/PatientDashboard';
import Header from './components/Header';
import Footer from './components/Footer';


export default function App() {
  const [token, setToken] = useState('');

  const handleLogout = () => {
    setToken('');
  };

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      minHeight: '100vh'
    }}>
      <Header onLogout={handleLogout} showLogout={!!token} />
      <main style={{ flex: 1, padding: '20px' }}>
        {!token
          ? <Login setToken={setToken} />
          : <PatientDashboard token={token} />}
      </main>
      <Footer />
    </div>
  );
}
