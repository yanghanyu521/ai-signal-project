import { useEffect, useRef } from 'react';
import { Empty } from 'antd';
import * as echarts from 'echarts';

const PALETTE = ['#4F46E5', '#16A34A', '#D97706', '#7C3AED', '#DC2626', '#0891B2', '#64748B', '#DB2777'];

function baseOption(): echarts.EChartsOption {
  return {
    color: PALETTE,
    textStyle: { fontFamily: "-apple-system, 'Segoe UI', 'PingFang SC', 'Microsoft YaHei', sans-serif" },
    tooltip: {
      backgroundColor: '#FFFFFF',
      borderColor: '#E5E7EB',
      textStyle: { color: '#111827', fontSize: 13 },
      extraCssText: 'box-shadow: 0 4px 12px rgba(17,24,39,0.08); border-radius: 8px;',
    },
  };
}

function useChart(option: echarts.EChartsOption, deps: unknown[]) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!ref.current) return;
    const chart = echarts.init(ref.current);
    chart.setOption(option);
    const resize = () => chart.resize();
    window.addEventListener('resize', resize);
    return () => {
      window.removeEventListener('resize', resize);
      chart.dispose();
    };
  }, deps);
  return ref;
}

const axisStyle = {
  axisLine: { lineStyle: { color: '#E5E7EB' } },
  axisTick: { show: false },
  axisLabel: { color: '#6B7280', fontSize: 12 },
  splitLine: { lineStyle: { color: '#F0F1F5', type: 'dashed' as const } },
};

type Series = { data: Record<string, unknown>[]; xKey: string; yKey: string };

function sortByX(series: Series): Record<string, unknown>[] {
  return [...series.data].sort((a, b) => String(a[series.xKey]).localeCompare(String(b[series.xKey])));
}

export function BarChart({ data, xKey, yKey, xLabel, yLabel, height = 280 }: Series & { xLabel?: string; yLabel?: string; height?: number }) {
  const sorted = sortByX({ data, xKey, yKey });
  const ref = useChart({
    ...baseOption(),
    grid: { left: 52, right: 20, top: 36, bottom: 64 },
    tooltip: { ...baseOption().tooltip, trigger: 'axis' },
    xAxis: {
      type: 'category',
      data: sorted.map((item) => String(item[xKey])),
      name: xLabel,
      nameTextStyle: { color: '#6B7280', fontSize: 12 },
      ...axisStyle,
      axisLabel: { ...axisStyle.axisLabel, rotate: sorted.length > 8 ? 32 : 0, interval: 0 },
    },
    yAxis: { type: 'value', name: yLabel, nameTextStyle: { color: '#6B7280', fontSize: 12 }, minInterval: 1, ...axisStyle },
    series: [{
      type: 'bar',
      data: sorted.map((item) => Number(item[yKey]) || 0),
      itemStyle: { color: '#4F46E5', borderRadius: [5, 5, 0, 0] },
      barMaxWidth: 36,
    }],
  }, [JSON.stringify(data), xKey, yKey, xLabel, yLabel]);

  if (!data.length) return <Empty description="暂无数据" style={{ padding: '40px 0' }} />;
  return <div ref={ref} style={{ width: '100%', height }} />;
}

export function LineChart({ data, xKey, yKey, xLabel, yLabel, height = 280 }: Series & { xLabel?: string; yLabel?: string; height?: number }) {
  const sorted = sortByX({ data, xKey, yKey });
  const ref = useChart({
    ...baseOption(),
    grid: { left: 52, right: 20, top: 36, bottom: 64 },
    tooltip: { ...baseOption().tooltip, trigger: 'axis' },
    xAxis: {
      type: 'category',
      data: sorted.map((item) => String(item[xKey])),
      name: xLabel,
      nameTextStyle: { color: '#6B7280', fontSize: 12 },
      boundaryGap: false,
      ...axisStyle,
      axisLabel: { ...axisStyle.axisLabel, rotate: sorted.length > 8 ? 32 : 0 },
    },
    yAxis: { type: 'value', name: yLabel, nameTextStyle: { color: '#6B7280', fontSize: 12 }, minInterval: 1, ...axisStyle },
    series: [{
      type: 'line',
      data: sorted.map((item) => Number(item[yKey]) || 0),
      smooth: 0.3,
      symbolSize: 7,
      lineStyle: { width: 2.5, color: '#4F46E5' },
      itemStyle: { color: '#4F46E5' },
      areaStyle: {
        color: {
          type: 'linear', x: 0, y: 0, x2: 0, y2: 1,
          colorStops: [
            { offset: 0, color: 'rgba(79,70,229,0.14)' },
            { offset: 1, color: 'rgba(79,70,229,0)' },
          ],
        },
      },
    }],
  }, [JSON.stringify(data), xKey, yKey, xLabel, yLabel]);

  if (!data.length) return <Empty description="暂无数据" style={{ padding: '40px 0' }} />;
  return <div ref={ref} style={{ width: '100%', height }} />;
}

const STATUS_LABELS: Record<string, string> = {
  llm_supported: '有 LLM 证据',
  llm_assisted_dev: 'LLM 辅助开发',
  no_ai_signals: '无 AI 信号',
  unknown: '未确定',
  confirmed: '已确认',
  suspected: '疑似',
};

export function DonutChart({ data, height = 280 }: { data: Record<string, unknown>[]; height?: number }) {
  const ref = useChart({
    ...baseOption(),
    tooltip: { ...baseOption().tooltip, trigger: 'item', formatter: '{b}：{c}（{d}%）' },
    legend: { bottom: 0, icon: 'circle', itemWidth: 8, itemHeight: 8, textStyle: { fontSize: 12, color: '#6B7280' } },
    series: [{
      type: 'pie',
      radius: ['52%', '74%'],
      center: ['50%', '44%'],
      avoidLabelOverlap: true,
      itemStyle: { borderColor: '#FFFFFF', borderWidth: 2, borderRadius: 4 },
      label: { show: false },
      data: data.map((item) => ({
        name: STATUS_LABELS[String(item.label)] || String(item.label),
        value: Number(item.count) || 0,
      })),
    }],
  }, [JSON.stringify(data)]);

  if (!data.length) return <Empty description="暂无数据" style={{ padding: '40px 0' }} />;
  return <div ref={ref} style={{ width: '100%', height }} />;
}

export default BarChart;
