import { useState, useEffect, createContext, useContext, useRef } from 'react';
import axios from 'axios';
import { BrowserRouter, Routes, Route, Navigate, useNavigate } from 'react-router-dom';
import DatePicker from 'react-datepicker';
import { Chart, registerables } from 'chart.js';
import 'react-datepicker/dist/react-datepicker.css';
import './styles.css';

// Register Chart.js components
Chart.register(...registerables);

// Create a shared context for alarms
const AlarmsContext = createContext({
  alarms: [],
  updateAlarms: () => {}
});

// Auth Context
const AuthContext = createContext({
  user: null,
  handleLogin: () => {},
  handleLogout: () => {}
});

// MetricsCharts Component
function MetricsCharts({ metrics }) {
  const lineChartRef = useRef(null);
  const pieChartRef = useRef(null);
  
  useEffect(() => {
    if (!metrics || metrics.length === 0) return;

    // Destroy existing charts if they exist
    if (lineChartRef.current?.chart) {
      lineChartRef.current.chart.destroy();
    }
    if (pieChartRef.current?.chart) {
      pieChartRef.current.chart.destroy();
    }

    // Prepare data
    const timestamps = metrics.map(m => new Date(m.timestamp).toLocaleTimeString());
    const latestMetric = metrics[0];

    // Line Chart
    const lineCtx = lineChartRef.current.getContext('2d');
    lineChartRef.current.chart = new Chart(lineCtx, {
      type: 'line',
      data: {
        labels: timestamps,
        datasets: [
          {
            label: 'CPU Usage %',
            data: metrics.map(m => m.cpuUsage),
            borderColor: 'rgb(255, 99, 132)',
            backgroundColor: 'rgba(255, 99, 132, 0.1)',
            tension: 0.1,
            fill: true
          },
          {
            label: 'Memory Usage %',
            data: metrics.map(m => m.memoryUsage),
            borderColor: 'rgb(54, 162, 235)',
            backgroundColor: 'rgba(54, 162, 235, 0.1)',
            tension: 0.1,
            fill: true
          },
          {
            label: 'Disk Usage %',
            data: metrics.map(m => m.diskUsage),
            borderColor: 'rgb(75, 192, 192)',
            backgroundColor: 'rgba(75, 192, 192, 0.1)',
            tension: 0.1,
            fill: true
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          title: {
            display: true,
            text: 'System Metrics Over Time',
            color: '#dfe6e9',
            font: {
              size: 16
            }
          },
          legend: {
            labels: {
              color: '#dfe6e9'
            }
          },
          tooltip: {
            mode: 'index',
            intersect: false
          }
        },
        scales: {
          x: {
            grid: {
              color: 'rgba(255, 255, 255, 0.1)'
            },
            ticks: {
              color: '#dfe6e9'
            }
          },
          y: {
            beginAtZero: true,
            max: 100,
            grid: {
              color: 'rgba(255, 255, 255, 0.1)'
            },
            ticks: {
              color: '#dfe6e9'
            }
          }
        },
        interaction: {
          mode: 'nearest',
          axis: 'x',
          intersect: false
        }
      }
    });

    // Pie Chart
    const pieCtx = pieChartRef.current.getContext('2d');
    pieChartRef.current.chart = new Chart(pieCtx, {
      type: 'pie',
      data: {
        labels: ['CPU', 'Memory', 'Disk'],
        datasets: [{
          data: [latestMetric.cpuUsage, latestMetric.memoryUsage, latestMetric.diskUsage],
          backgroundColor: [
            'rgba(255, 99, 132, 0.7)',
            'rgba(54, 162, 235, 0.7)',
            'rgba(75, 192, 192, 0.7)'
          ],
          borderColor: [
            'rgba(255, 99, 132, 1)',
            'rgba(54, 162, 235, 1)',
            'rgba(75, 192, 192, 1)'
          ],
          borderWidth: 1
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          title: {
            display: true,
            text: 'Current Resource Usage',
            color: '#dfe6e9',
            font: {
              size: 16
            }
          },
          legend: {
            labels: {
              color: '#dfe6e9'
            }
          }
        }
      }
    });

    return () => {
      if (lineChartRef.current?.chart) {
        lineChartRef.current.chart.destroy();
      }
      if (pieChartRef.current?.chart) {
        pieChartRef.current.chart.destroy();
      }
    };
  }, [metrics]);

  return (
    <div className="metrics-charts">
      <div className="chart-container">
        <canvas ref={lineChartRef}></canvas>
      </div>
      <div className="chart-container">
        <canvas ref={pieChartRef}></canvas>
      </div>
    </div>
  );
}

// Main App Component
function App() {
  const [user, setUser] = useState(() => {
    const savedUser = localStorage.getItem('metricsDashboardUser');
    return savedUser ? JSON.parse(savedUser) : null;
  });
  const [alarms, setAlarms] = useState([]);

  // Update alarms function to be shared across components
  const updateAlarms = (newAlarms) => {
    setAlarms(newAlarms);
  };

  useEffect(() => {
    const requestInterceptor = axios.interceptors.request.use(config => {
      if (user) {
        config.headers.Authorization = `Bearer ${user.token}`;
      }
      return config;
    });

    const responseInterceptor = axios.interceptors.response.use(
      response => response,
      error => {
        if (error.response?.status === 401) {
          handleLogout();
        }
        return Promise.reject(error);
      }
    );

    return () => {
      axios.interceptors.request.eject(requestInterceptor);
      axios.interceptors.response.eject(responseInterceptor);
    };
  }, [user]);

  const handleLogin = (userData) => {
    localStorage.setItem('metricsDashboardUser', JSON.stringify(userData));
    setUser(userData);
  };

  const handleLogout = () => {
    localStorage.removeItem('metricsDashboardUser');
    setUser(null);
    setAlarms([]);
  };

  return (
    <AuthContext.Provider value={{ user, handleLogin, handleLogout }}>
      <AlarmsContext.Provider value={{ alarms, updateAlarms }}>
        <BrowserRouter>
          <Routes>
            <Route path="/login" element={
              user ? <Navigate to={user.role === 'admin' ? '/admin' : '/operator'} /> : 
              <Login />
            } />
            
            <Route path="/admin" element={
              user?.role === 'admin' ? 
                <AdminDashboard /> : 
                <Navigate to="/login" replace />
            } />
            
            <Route path="/operator" element={
              user?.role === 'operator' ? 
                <OperatorDashboard /> : 
                <Navigate to="/login" replace />
            } />
            
            <Route path="*" element={<Navigate to={user ? (user.role === 'admin' ? '/admin' : '/operator') : '/login'} replace />} />
          </Routes>
        </BrowserRouter>
      </AlarmsContext.Provider>
    </AuthContext.Provider>
  );
}

// Login Component
function Login() {
  const [credentials, setCredentials] = useState({ username: '', password: '' });
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const { handleLogin } = useContext(AuthContext);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);
    
    try {
      const response = await axios.post('http://localhost:8081/api/login', credentials);
      handleLogin({
        ...response.data,
        token: 'mock-token'
      });
      navigate(response.data.role === 'admin' ? '/admin' : '/operator');
    } catch (err) {
      setError(err.response?.data?.error || 'Invalid credentials');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="login-container">
      <div className="login-card">
        <h1>Metrics Dashboard</h1>
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="username">Username</label>
            <input
              id="username"
              type="text"
              value={credentials.username}
              onChange={(e) => setCredentials({...credentials, username: e.target.value})}
              required
            />
          </div>
          
          <div className="form-group">
            <label htmlFor="password">Password</label>
            <input
              id="password"
              type="password"
              value={credentials.password}
              onChange={(e) => setCredentials({...credentials, password: e.target.value})}
              required
            />
          </div>
          
          {error && <div className="alert error">{error}</div>}
          
          <button type="submit" disabled={isLoading} className="login-button">
            {isLoading ? (
              <>
                <span className="spinner"></span> Logging in...
              </>
            ) : 'Login'}
          </button>
        </form>
      </div>
    </div>
  );
}

// Admin Dashboard Component
function AdminDashboard() {
  const [retentionDays, setRetentionDays] = useState(30);
  const [thresholds, setThresholds] = useState({ cpu: 50, memory: 50, disk: 50 });
  const [metrics, setMetrics] = useState([]);
  const [dateRange, setDateRange] = useState({
    start: new Date(Date.now() - 24 * 60 * 60 * 1000),
    end: new Date()
  });
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [refreshKey, setRefreshKey] = useState(0);
  const { user, handleLogout } = useContext(AuthContext);
  const { alarms, updateAlarms } = useContext(AlarmsContext);
  const navigate = useNavigate();

  const fetchData = async () => {
    setIsLoading(true);
    try {
      const [settingsRes, alarmsRes, metricsRes] = await Promise.all([
        axios.get('http://localhost:8081/api/alarms/settings'),
        axios.get('http://localhost:8081/api/alarms', {
          params: {
            start: dateRange.start.toISOString(),
            end: dateRange.end.toISOString(),
            includeAcknowledged: true,
            _: Date.now() // Cache buster
          }
        }),
        axios.get('http://localhost:8081/api/metrics/latest')
      ]);
      
      setRetentionDays(settingsRes.data.retention_days);
      setThresholds({
        cpu: settingsRes.data.cpu || 50,
        memory: settingsRes.data.memory || 50,
        disk: settingsRes.data.disk || 50
      });
      updateAlarms(alarmsRes.data);
      setMetrics(metricsRes.data);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to load data');
      updateAlarms([]);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    
    // Set up auto-refresh for both metrics and alarms
    const interval = setInterval(() => {
      Promise.all([
        axios.get('http://localhost:8081/api/metrics/latest'),
        axios.get('http://localhost:8081/api/alarms', {
          params: {
            start: dateRange.start.toISOString(),
            end: dateRange.end.toISOString(),
            includeAcknowledged: true,
            _: Date.now() // Cache buster
          }
        })
      ])
      .then(([metricsRes, alarmsRes]) => {
        setMetrics(metricsRes.data);
        updateAlarms(alarmsRes.data);
      })
      .catch(err => console.error('Failed to refresh data:', err));
    }, 5000);

    return () => clearInterval(interval);
  }, [dateRange, refreshKey]);

  const handleUpdateSettings = async (settings) => {
    try {
      await axios.post('http://localhost:8081/api/alarms/settings', settings);
      if (settings.retention_days) setRetentionDays(settings.retention_days);
      if (settings.cpu_threshold || settings.memory_threshold || settings.disk_threshold) {
        setThresholds({
          cpu: settings.cpu_threshold || thresholds.cpu,
          memory: settings.memory_threshold || thresholds.memory,
          disk: settings.disk_threshold || thresholds.disk
        });
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to update settings');
    }
  };

  const handleDownloadCSV = async () => {
    try {
      const response = await axios.get('http://localhost:8081/api/metrics/download', {
        responseType: 'blob'
      });
      
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', 'metrics.csv');
      document.body.appendChild(link);
      link.click();
      link.parentNode.removeChild(link);
    } catch (err) {
      setError('Failed to download CSV file');
    }
  };

  const handleLogoutClick = () => {
    handleLogout();
    navigate('/login');
  };

  const handleForceRefresh = () => {
    setRefreshKey(prev => prev + 1);
    console.log("Manual refresh triggered");
  };

  return (
    <div className="dashboard admin-dashboard">
      <header className="dashboard-header">
        <h1>Admin Dashboard</h1>
        <div className="header-buttons">
          <button onClick={handleDownloadCSV} className="download-csv-button">
            Download CSV
          </button>
          <button onClick={handleLogoutClick} className="logout-button">
            Logout
          </button>
        </div>
      </header>

      {error && <div className="alert error">{error}</div>}

      <div className="dashboard-content">
        <section className="dashboard-section">
          <h2>System Metrics</h2>
          <MetricsCharts metrics={metrics} />
        </section>

        <section className="dashboard-section">
          <h2>Alarm Time Range</h2>
          <div className="time-range-picker">
            <div className="date-picker-group">
              <label>From:</label>
              <DatePicker
                selected={dateRange.start}
                onChange={(date) => setDateRange({...dateRange, start: date})}
                showTimeSelect
                timeFormat="HH:mm"
                timeIntervals={15}
                dateFormat="MMMM d, yyyy HH:mm"
                maxDate={new Date()}
                className="date-picker-input"
              />
            </div>
            <div className="date-picker-group">
              <label>To:</label>
              <DatePicker
                selected={dateRange.end}
                onChange={(date) => setDateRange({...dateRange, end: date})}
                showTimeSelect
                timeFormat="HH:mm"
                timeIntervals={15}
                dateFormat="MMMM d, yyyy HH:mm"
                maxDate={new Date()}
                minDate={dateRange.start}
                className="date-picker-input"
              />
            </div>
            <button 
              onClick={fetchData}
              className="refresh-button"
              disabled={isLoading}
            >
              {isLoading ? 'Refreshing...' : 'Refresh Data'}
            </button>
            <button onClick={handleForceRefresh} className="refresh-button">
              Force Refresh
            </button>
          </div>
        </section>

        <section className="dashboard-section">
          <h2>System Settings</h2>
          <RetentionSettings 
            retentionDays={retentionDays}
            thresholds={thresholds}
            onUpdate={handleUpdateSettings}
            isLoading={isLoading}
          />
        </section>

        <section className="dashboard-section">
          <h2>Alarm History</h2>
          {isLoading ? (
            <div className="loading-spinner">Loading...</div>
          ) : (
            <AlarmList 
              alarms={alarms} 
              showAcknowledged={true}
              showAcknowledgedBy={true}
            />
          )}
        </section>
      </div>
    </div>
  );
}

// Operator Dashboard Component
function OperatorDashboard() {
  const [metrics, setMetrics] = useState([]);
  const [dateRange, setDateRange] = useState({
    start: new Date(Date.now() - 24 * 60 * 60 * 1000),
    end: new Date()
  });
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const { user, handleLogout } = useContext(AuthContext);
  const { alarms, updateAlarms } = useContext(AlarmsContext);
  const navigate = useNavigate();

  const fetchMetricsForRange = async () => {
    setIsLoading(true);
    try {
      const params = {
        start: dateRange.start.toISOString(),
        end: dateRange.end.toISOString(),
        userId: user.id
      };
      const [alarmsRes, metricsRes] = await Promise.all([
        axios.get('http://localhost:8081/api/alarms', { params }),
        axios.get('http://localhost:8081/api/metrics/range', { params })
      ]);
      updateAlarms(alarmsRes.data);
      setMetrics(metricsRes.data);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to load data');
      updateAlarms([]);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchMetricsForRange();
    
    // Set up auto-refresh for metrics
    const interval = setInterval(() => {
      const params = {
        start: dateRange.start.toISOString(),
        end: dateRange.end.toISOString(),
        userId: user.id
      };
      Promise.all([
        axios.get('http://localhost:8081/api/alarms', { params }),
        axios.get('http://localhost:8081/api/metrics/range', { params })
      ])
      .then(([alarmsRes, metricsRes]) => {
        updateAlarms(alarmsRes.data);
        setMetrics(metricsRes.data);
      })
      .catch(err => console.error('Failed to refresh metrics:', err));
    }, 5000);

    return () => clearInterval(interval);
  }, [dateRange, user?.id]);

  const handleAcknowledge = async (alarmId) => {
    try {
      const response = await axios.post('http://localhost:8081/api/alarms/acknowledge', { 
        alarmId, 
        userId: user.id 
      });
      
      // Update the alarms list immediately in both dashboards
      const updatedAlarms = alarms.map(alarm => 
        alarm.id === alarmId 
          ? { 
              ...alarm, 
              acknowledged_by: user.id, 
              acknowledged_by_name: user.name,
              status: 'Acknowledged'
            } 
          : alarm
      );
      updateAlarms(updatedAlarms);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to acknowledge alarm');
    }
  };

  const handleDownloadCSV = async () => {
    try {
      const response = await axios.get('http://localhost:8081/api/metrics/download', {
        responseType: 'blob',
        params: {
          start: dateRange.start.toISOString(),
          end: dateRange.end.toISOString()
        }
      });
      
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', 'metrics.csv');
      document.body.appendChild(link);
      link.click();
      link.parentNode.removeChild(link);
    } catch (err) {
      setError('Failed to download CSV file');
    }
  };

  const handleLogoutClick = () => {
    handleLogout();
    navigate('/login');
  };

  return (
    <div className="dashboard operator-dashboard">
      <header className="dashboard-header">
        <h1>Operator Dashboard</h1>
        <div className="header-buttons">
          <button onClick={handleDownloadCSV} className="download-csv-button">
            Download CSV
          </button>
          <button onClick={handleLogoutClick} className="logout-button">
            Logout
          </button>
        </div>
      </header>

      {error && <div className="alert error">{error}</div>}

      <div className="dashboard-content">
        <section className="dashboard-section">
          <h2>Metrics Overview</h2>
          <MetricsCharts metrics={metrics} />
        </section>

        <section className="dashboard-section">
          <h2>Time Range Filter</h2>
          <div className="time-range-picker">
            <div className="date-picker-group">
              <label>From:</label>
              <DatePicker
                selected={dateRange.start}
                onChange={(date) => setDateRange({...dateRange, start: date})}
                showTimeSelect
                timeFormat="HH:mm"
                timeIntervals={15}
                dateFormat="MMMM d, yyyy HH:mm"
                maxDate={new Date()}
                className="date-picker-input"
              />
            </div>
            <div className="date-picker-group">
              <label>To:</label>
              <DatePicker
                selected={dateRange.end}
                onChange={(date) => setDateRange({...dateRange, end: date})}
                showTimeSelect
                timeFormat="HH:mm"
                timeIntervals={15}
                dateFormat="MMMM d, yyyy HH:mm"
                maxDate={new Date()}
                minDate={dateRange.start}
                className="date-picker-input"
              />
            </div>
            <button 
              onClick={fetchMetricsForRange} 
              className="fetch-metrics-button"
              disabled={isLoading}
            >
              {isLoading ? 'Loading...' : 'Fetch Metrics'}
            </button>
          </div>
        </section>

        <section className="dashboard-section">
          <h2>Active Alarms</h2>
          {isLoading ? (
            <div className="loading-spinner">Loading...</div>
          ) : (
            <AlarmList 
              alarms={alarms.filter(a => !a.acknowledged_by)} 
              showAcknowledged={false}
              onAcknowledge={handleAcknowledge}
            />
          )}
        </section>
      </div>
    </div>
  );
}

// AlarmList Component
function AlarmList({ alarms, showAcknowledged, showAcknowledgedBy, onAcknowledge }) {
  const [sortConfig, setSortConfig] = useState({
    key: 'timestamp',
    direction: 'descending'
  });

  const requestSort = (key) => {
    let direction = 'ascending';
    if (sortConfig.key === key && sortConfig.direction === 'ascending') {
      direction = 'descending';
    }
    setSortConfig({ key, direction });
  };

  const sortedAlarms = [...alarms].sort((a, b) => {
    if (a[sortConfig.key] < b[sortConfig.key]) {
      return sortConfig.direction === 'ascending' ? -1 : 1;
    }
    if (a[sortConfig.key] > b[sortConfig.key]) {
      return sortConfig.direction === 'ascending' ? 1 : -1;
    }
    return 0;
  });

  return (
    <div className="alarm-list-container">
      {sortedAlarms.length === 0 ? (
        <div className="no-alarms">No alarms found</div>
      ) : (
        <table className="alarm-table">
          <thead>
            <tr>
              <th onClick={() => requestSort('timestamp')}>
                Timestamp {sortConfig.key === 'timestamp' && (
                  sortConfig.direction === 'ascending' ? '↑' : '↓'
                )}
              </th>
              <th onClick={() => requestSort('cpuUsage')}>
                CPU {sortConfig.key === 'cpuUsage' && (
                  sortConfig.direction === 'ascending' ? '↑' : '↓'
                )}
              </th>
              <th onClick={() => requestSort('memoryUsage')}>
                Memory {sortConfig.key === 'memoryUsage' && (
                  sortConfig.direction === 'ascending' ? '↑' : '↓'
                )}
              </th>
              <th onClick={() => requestSort('diskUsage')}>
                Disk {sortConfig.key === 'diskUsage' && (
                  sortConfig.direction === 'ascending' ? '↑' : '↓'
                )}
              </th>
              {showAcknowledged && (
                <th onClick={() => requestSort('acknowledged_by')}>
                  Status {sortConfig.key === 'acknowledged_by' && (
                    sortConfig.direction === 'ascending' ? '↑' : '↓'
                  )}
                </th>
              )}
              {showAcknowledgedBy && (
                <th onClick={() => requestSort('acknowledged_by_name')}>
                  Acknowledged By {sortConfig.key === 'acknowledged_by_name' && (
                    sortConfig.direction === 'ascending' ? '↑' : '↓'
                  )}
                </th>
              )}
              {!showAcknowledged && <th>Action</th>}
            </tr>
          </thead>
          <tbody>
            {sortedAlarms.map(alarm => (
              <tr 
                key={alarm.id} 
                className={`alarm-row ${alarm.acknowledged_by ? 'acknowledged' : 'pending'}`}
              >
                <td>{new Date(alarm.timestamp).toLocaleString()}</td>
                <td className={alarm.cpuUsage > 50 ? 'critical' : ''}>
                  {alarm.cpuUsage.toFixed(2)}%
                </td>
                <td className={alarm.memoryUsage > 50 ? 'critical' : ''}>
                  {alarm.memoryUsage.toFixed(2)}%
                </td>
                <td className={alarm.diskUsage > 50 ? 'critical' : ''}>
                  {alarm.diskUsage.toFixed(2)}%
                </td>
                {showAcknowledged && (
                  <td>
                    {alarm.acknowledged_by ? 
                      <span className="acknowledged-status">Acknowledged</span> : 
                      alarm.is_alarm ? 
                        <span className="active">Active</span> : 
                        <span className="pending">Pending</span>}
                  </td>
                )}
                {showAcknowledgedBy && alarm.acknowledged_by && (
                  <td>{alarm.acknowledged_by_name || 'Operator'}</td>
                )}
                {!showAcknowledged && !alarm.acknowledged_by && (
                  <td>
                    <button 
                      onClick={() => onAcknowledge(alarm.id)}
                      className="acknowledge-button"
                    >
                      Acknowledge
                    </button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

// RetentionSettings Component
function RetentionSettings({ retentionDays, thresholds, onUpdate, isLoading }) {
  const [days, setDays] = useState(retentionDays);
  const [cpuThreshold, setCpuThreshold] = useState(thresholds.cpu);
  const [memoryThreshold, setMemoryThreshold] = useState(thresholds.memory);
  const [diskThreshold, setDiskThreshold] = useState(thresholds.disk);
  const [isSaved, setIsSaved] = useState(false);

  useEffect(() => {
    setDays(retentionDays);
    setCpuThreshold(thresholds.cpu);
    setMemoryThreshold(thresholds.memory);
    setDiskThreshold(thresholds.disk);
  }, [retentionDays, thresholds]);

  const handleSave = () => {
    onUpdate({
      retention_days: days,
      cpu_threshold: cpuThreshold,
      memory_threshold: memoryThreshold,
      disk_threshold: diskThreshold
    });
    setIsSaved(true);
    setTimeout(() => setIsSaved(false), 3000);
  };

  return (
    <div className="retention-settings">
      <div className="settings-controls">
        <div className="setting-group">
          <label htmlFor="retentionDays">Retention Period (days):</label>
          <input
            id="retentionDays"
            type="number"
            min="1"
            max="365"
            value={days}
            onChange={(e) => setDays(parseInt(e.target.value) || 1)}
            disabled={isLoading}
            className="settings-input"
          />
        </div>

        <div className="setting-group">
          <label htmlFor="cpuThreshold">CPU Threshold (%):</label>
          <input
            id="cpuThreshold"
            type="number"
            min="1"
            max="100"
            value={cpuThreshold}
            onChange={(e) => setCpuThreshold(parseInt(e.target.value) || 1)}
            disabled={isLoading}
            className="settings-input"
          />
        </div>

        <div className="setting-group">
          <label htmlFor="memoryThreshold">Memory Threshold (%):</label>
          <input
            id="memoryThreshold"
            type="number"
            min="1"
            max="100"
            value={memoryThreshold}
            onChange={(e) => setMemoryThreshold(parseInt(e.target.value) || 1)}
            disabled={isLoading}
            className="settings-input"
          />
        </div>

        <div className="setting-group">
          <label htmlFor="diskThreshold">Disk Threshold (%):</label>
          <input
            id="diskThreshold"
            type="number"
            min="1"
            max="100"
            value={diskThreshold}
            onChange={(e) => setDiskThreshold(parseInt(e.target.value) || 1)}
            disabled={isLoading}
            className="settings-input"
          />
        </div>

        <button 
          onClick={handleSave}
          disabled={isLoading}
          className="save-settings-button"
        >
          {isLoading ? 'Saving...' : 'Save Settings'}
        </button>
      </div>
      {isSaved && <div className="save-confirmation">Settings saved successfully!</div>}
    </div>
  );
}

export default App;
