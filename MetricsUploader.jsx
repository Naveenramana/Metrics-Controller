import { useState, useEffect, createContext, useContext } from 'react';
import axios from 'axios';
import { BrowserRouter, Routes, Route, Navigate, useNavigate } from 'react-router-dom';
import AdminDashboard from './AdminDashboard';
import AlarmList from './AlarmList';
import Login from './Login';
import MetricsCharts from './MetricsCharts';
import OperatorDashboard from './OperatorDashboard';
import RetentionSettings from './RetentionSettings';
import './styles.css';

axios.defaults.withCredentials = true;
axios.defaults.baseURL = 'http://localhost:8081';

// Create contexts
const AuthContext = createContext({
  user: null,
  handleLogin: () => {},
  handleLogout: () => {}
});

const AlarmsContext = createContext({
  alarms: [],
  updateAlarms: () => {}
});

function App() {
  const [user, setUser] = useState(() => {
    const savedUser = localStorage.getItem('metricsDashboardUser');
    return savedUser ? JSON.parse(savedUser) : null;
  });
  const [alarms, setAlarms] = useState([]);

  const updateAlarms = (newAlarms) => setAlarms(newAlarms);

  const handleLogin = (userData) => {
    setUser(userData);
    localStorage.setItem('metricsDashboardUser', JSON.stringify(userData));
  };

  const handleLogout = () => {
    setUser(null);
    localStorage.removeItem('metricsDashboardUser');
  };

  return (
    <AuthContext.Provider value={{ user, handleLogin, handleLogout }}>
      <AlarmsContext.Provider value={{ alarms, updateAlarms }}>
        <BrowserRouter>
          <Routes>
            <Route path="/" element={user ? <Navigate to={user.role === 'admin' ? '/admin' : '/operator'} /> : <Navigate to="/login" />} />
            <Route path="/login" element={<Login />} />
            <Route path="/admin" element={user?.role === 'admin' ? <AdminDashboard /> : <Navigate to="/login" />} />
            <Route path="/operator" element={user ? <OperatorDashboard /> : <Navigate to="/login" />} />
          </Routes>
        </BrowserRouter>
      </AlarmsContext.Provider>
    </AuthContext.Provider>
  );
}

// Export both the default App and named contexts
export { AuthContext, AlarmsContext };
export default App;
