import { useState, useEffect, useContext } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import DatePicker from 'react-datepicker';
import 'react-datepicker/dist/react-datepicker.css';
import MetricsCharts from './MetricsCharts';
import AlarmList from './AlarmList';
import { AuthContext, AlarmsContext } from './MetricsUploader';

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
        end: dateRange.end.toISOString()
      };
      const [alarmsRes, metricsRes] = await Promise.all([
        axios.get('/api/alarms', { params }),
        axios.get('/api/metrics/range', { params })
      ]);
      updateAlarms(alarmsRes.data);
      setMetrics(metricsRes.data);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to load data');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (!user) {
      navigate('/login');
      return;
    }
    fetchMetricsForRange();
  }, [user, dateRange]);

  const handleAcknowledge = async (alarmId) => {
    try {
      await axios.post('/api/alarms/acknowledge', { 
        alarmId, 
        userId: user.id 
      });
      
      const updatedAlarms = alarms.map(alarm => 
        alarm.id === alarmId 
          ? { ...alarm, acknowledged: true, acknowledgedBy: user.username } 
          : alarm
      );
      updateAlarms(updatedAlarms);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to acknowledge alarm');
    }
  };

  const handleDownloadCSV = async () => {
    try {
      const response = await axios.get('/api/metrics/download', {
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
              alarms={alarms.filter(a => !a.acknowledged)} 
              showAcknowledged={false}
              onAcknowledge={handleAcknowledge}
            />
          )}
        </section>
      </div>
    </div>
  );
}

export default OperatorDashboard;
