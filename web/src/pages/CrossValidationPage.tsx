import { useEffect, useState } from 'react';
import { Alert, App as AntApp, Button, Card, Collapse, Select } from 'antd';
import { SwapOutlined } from '@ant-design/icons';
import { getJson, postJson } from '../api/client';
import { PageHeader, StatCards } from '../components/common';
import JointSummary from '../components/JointSummary';

export default function CrossValidationPage() {
  const [cases, setCases] = useState<any[]>([]);
  const [caseId, setCaseId] = useState<string>();
  const [detail, setDetail] = useState<any>(null);
  const [sampleSha, setSampleSha] = useState<string>();
  const [reportId, setReportId] = useState<string>();
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState('');
  const [running, setRunning] = useState(false);
  const { message } = AntApp.useApp();

  useEffect(() => {
    getJson<any[]>('/api/v1/analysis-cases', { limit: 500 })
      .then((items) => {
        const ready = items.filter((item) => item.sample_count && item.report_count);
        setCases(ready);
        if (ready.length) setCaseId(ready[0].id);
      })
      .catch((exc) => setError(exc.message));
  }, []);

  useEffect(() => {
    if (!caseId) return;
    setResult(null);
    getJson<any>(`/api/v1/analysis-cases/${caseId}`).then((data) => {
      setDetail(data);
      setSampleSha(data.samples?.[0]?.sha256);
      setReportId(data.reports?.[0]?.report_id);
    }).catch((exc) => setError(exc.message));
  }, [caseId]);

  const run = async () => {
    setRunning(true);
    setError('');
    try {
      const response = await postJson(`/api/v1/analysis-cases/${caseId}/cross-validate`, {
        sample_sha256: sampleSha, report_id: reportId, event_id: null,
      });
      setResult(response);
      message.success('交叉验证完成');
    } catch (exc: any) {
      setError(exc.message);
    } finally {
      setRunning(false);
    }
  };

  if (!cases.length && !error) return <Alert type="info" showIcon message="暂无同时包含样本和报告的案例。请先在「联合分析」页面补齐案例。" />;

  return (
    <>
      <PageHeader title="按分析案例执行交叉验证"
        description="先选择联合分析案例，系统只允许比较该案例中已经对应的样本和报告，避免任意对象误配。" />
      {error && <Alert type="error" message={error} showIcon style={{ marginBottom: 16 }} />}
      <Card size="small" style={{ marginBottom: 20 }}>
        <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <div style={{ minWidth: 260, flex: 1 }}>
            <div style={{ marginBottom: 6, color: '#64748B' }}>分析案例</div>
            <Select style={{ width: '100%' }} value={caseId} onChange={setCaseId}
              options={cases.map((item) => ({ value: item.id, label: `${item.title} · ${item.status} · ${item.id.slice(0, 8)}` }))} />
          </div>
          <div style={{ minWidth: 220, flex: 1 }}>
            <div style={{ marginBottom: 6, color: '#64748B' }}>案例内样本</div>
            <Select style={{ width: '100%' }} value={sampleSha} onChange={setSampleSha}
              options={(detail?.samples || []).map((item: any) => ({
                value: item.sha256, label: `${item.source_case || '未标注'} · ${item.sha256.slice(0, 12)}…`,
              }))} />
          </div>
          <div style={{ minWidth: 220, flex: 1 }}>
            <div style={{ marginBottom: 6, color: '#64748B' }}>案例内报告</div>
            <Select style={{ width: '100%' }} value={reportId} onChange={setReportId}
              options={(detail?.reports || []).map((item: any) => ({
                value: item.report_id, label: `${item.title || item.report_id} · ${item.report_id.slice(0, 12)}…`,
              }))} />
          </div>
          <Button type="primary" icon={<SwapOutlined />} loading={running} onClick={run} disabled={!sampleSha || !reportId}>
            执行交叉验证
          </Button>
        </div>
        {detail && <p style={{ color: '#64748B', marginTop: 12, marginBottom: 0 }}>
          案例状态：{detail.status} · 样本 {detail.samples?.length || 0} 个 · 报告 {detail.reports?.length || 0} 份
        </p>}
      </Card>
      {result?.joint_summary && <JointSummary summary={result.joint_summary} />}
      {result && (
        <Collapse style={{ marginTop: 16 }} items={[{
          key: 'raw', label: '原始验证结果（审计用）',
          children: <pre style={{ maxHeight: 480, overflow: 'auto', fontSize: 12 }}>{JSON.stringify(result, null, 2)}</pre>,
        }]} />
      )}
    </>
  );
}
