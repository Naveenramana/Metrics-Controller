import { useState } from 'react';

function AlarmList({ alarms, showAcknowledged, showAcknowledgedBy, onAcknowledge }) {
  const [sortConfig, setSortConfig] = useState({
    key: 'timestamp',
    direction: 'descending'
  });

  const sortedAlarms = [...alarms].sort((a, b) => {
    if (a[sortConfig.key] < b[sortConfig.key]) {
      return sortConfig.direction === 'ascending' ? -1 : 1;
    }
    if (a[sortConfig.key] > b[sortConfig.key]) {
      return sortConfig.direction === 'ascending' ? 1 : -1;
    }
    return 0;
  });

  const requestSort = (key) => {
    let direction = 'ascending';
    if (sortConfig.key === key && sortConfig.direction === 'ascending') {
      direction = 'descending';
    }
    setSortConfig({ key, direction });
  };

  return (
    <div className="alarm-list-container">
      {sortedAlarms.length === 0 ? (
        <div className="no-alarms">No alarms found</div>
      ) : (
        <table className="alarm-table">
          <thead>
            <tr>
              <th onClick={() => requestSort('timestamp')}>Timestamp</th>
              <th onClick={() => requestSort('cpuUsage')}>CPU</th>
              <th onClick={() => requestSort('memoryUsage')}>Memory</th>
              <th onClick={() => requestSort('diskUsage')}>Disk</th>
              {showAcknowledged && (
                <th onClick={() => requestSort('acknowledged')}>Status</th>
              )}
              {showAcknowledgedBy && (
                <th onClick={() => requestSort('acknowledgedBy')}>Acknowledged By</th>
              )}
              {onAcknowledge && <th>Action</th>}
            </tr>
          </thead>
          <tbody>
            {sortedAlarms.map(alarm => (
              <tr key={alarm.id} className={alarm.acknowledged ? 'acknowledged' : 'pending'}>
                <td>{new Date(alarm.timestamp).toLocaleString()}</td>
                <td>{alarm.cpuUsage?.toFixed(2)}%</td>
                <td>{alarm.memoryUsage?.toFixed(2)}%</td>
                <td>{alarm.diskUsage?.toFixed(2)}%</td>
                {showAcknowledged && (
                  <td>{alarm.acknowledged ? 'Acknowledged' : 'Pending'}</td>
                )}
                {showAcknowledgedBy && alarm.acknowledged && (
                  <td>{alarm.acknowledgedBy || '-'}</td>
                )}
                {onAcknowledge && !alarm.acknowledged && (
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

export default AlarmList;
