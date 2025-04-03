import { useEffect, useRef } from 'react';
import { Chart, registerables } from 'chart.js';

Chart.register(...registerables);

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

export default MetricsCharts;
