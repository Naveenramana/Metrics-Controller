import { useState, useEffect } from 'react';

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

export default RetentionSettings;
