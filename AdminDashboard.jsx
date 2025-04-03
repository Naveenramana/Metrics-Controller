import { useState, useEffect, useContext } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import DatePicker from 'react-datepicker';
import 'react-datepicker/dist/react-datepicker.css';
import MetricsCharts from './MetricsCharts';
import AlarmList from './AlarmList';
import RetentionSettings from './RetentionSettings';
import { AuthContext, AlarmsContext } from './MetricsUploader';

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
  const { user, handleLogout } = useContext(AuthContext);
  const { alarms, updateAlarms } = useContext(AlarmsContext);
  const navigate = useNavigate();

  const fetchData = async () => {
    setIsLoading(true);
    try {
      const [settingsRes, alarmsRes, metricsRes] = await Promise.all([
        axios.get('/api/alarms/settings'),
        axios.get('/api/alarms', {
          params: {
            start: dateRange.start.toISOString(),
            end: dateRange.end.toISOString(),
            includeAcknowledged: true
          }
        }),
        axios.get('/api/metrics/latest')
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
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (!user || user.role !== 'admin') {
      navigate('/login');
      return;
    }
    fetchData();
  }, [user, dateRange]);

  const handleUpdateSettings = async (settings) => {
    try {
      await axios.post('/api/alarms/settings', settings);
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
      const response = await axios.get('/api/metrics/download', {
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
              />
            </div>
            <button 
              onClick={fetchData}
              className="refresh-button"
              disabled={isLoading}
            >
              {isLoading ? 'Refreshing...' : 'Refresh Data'}
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

export default AdminDashboard;
