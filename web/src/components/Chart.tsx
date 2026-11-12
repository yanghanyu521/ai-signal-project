import { useEffect, useRef } from 'react';
import * as echarts from 'echarts';

export default function BarChart({ data, xKey, yKey, xLabel, yLabel, height = 300 }: {
  data: Record<string, unknown>[];
  xKey: string;
  yKey: string;
  xLabel?: string;
  yLabel?: string;
  height?: number;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const chartRef = useRef<echarts.ECharts>();

  useEffect(() => {
    if (!ref.current) return;
    const chart = echarts.init(ref.current);
    chartRef.current = chart;
    chart.setOption({
      grid: { left: 48, right: 24, top: 32, bottom: 56 },
      tooltip: { trigger: 'axis' },
      xAxis: {
        type: 'category',
        data: data.map((item) => String(item[xKey])),
        name: xLabel,
        axisLabel: { rotate: data.length > 10 ? 35 : 0, fontSize: 11 },
      },
      yAxis: { type: 'value', name: yLabel, minInterval: 1 },
      series: [{
        type: 'bar',
        data: data.map((item) => Number(item[yKey]) || 0),
        itemStyle: { color: '#4F46E5', borderRadius: [6, 6, 0, 0] },
        barMaxWidth: 42,
      }],
    });
    const resize = () => chart.resize();
    window.addEventListener('resize', resize);
    return () => {
      window.removeEventListener('resize', resize);
      chart.dispose();
    };
  }, [JSON.stringify(data), xKey, yKey, xLabel, yLabel]);

  return <div ref={ref} style={{ width: '100%', height }} />;
}
