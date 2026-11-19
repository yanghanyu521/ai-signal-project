import { useState } from 'react';
import { Alert, Button, Card, DatePicker, Input } from 'antd';
import { DownloadOutlined, FileTextOutlined } from '@ant-design/icons';
import { postJson } from '../api/client';
import { PageHeader } from '../components/common';

export default function ReportGenerationPage() {
  const [title, setTitle] = useState('AI 安全事件与样本分析统计报告');
  const [range, setRange] = useState<[any, any]>([null, null]);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const generate = async () => {
    setLoading(true);
    setError('');
    try {
      const response = await postJson('/api/v1/generated-reports', {
        title,
        date_from: range[0]?.format('YYYY-MM-DD'),
        date_to: range[1]?.format('YYYY-MM-DD'),
      });
      setResult(response);
    } catch (exc: any) {
      setError(exc.message);
    } finally {
      setLoading(false);
    }
  };

  const download = () => {
    const blob = new Blob([result.content], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${result.id}.md`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <>
      <PageHeader title="自动生成统计报告"
        description="报告保存生成时的统计快照；选择时间范围后，事件按发生日期过滤，样本、报告、案例和交叉验证按知识库创建日期过滤。" />
      {error && <Alert type="error" message={error} showIcon style={{ marginBottom: 16 }} />}
      <Card size="small" style={{ marginBottom: 20 }}>
        <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <div style={{ minWidth: 280, flex: 1 }}>
            <div style={{ marginBottom: 6, color: '#64748B' }}>报告标题</div>
            <Input value={title} onChange={(event) => setTitle(event.target.value)} />
          </div>
          <div>
            <div style={{ marginBottom: 6, color: '#64748B' }}>统计时间范围（可选）</div>
            <DatePicker.RangePicker value={range} onChange={(values) => setRange(values || [null, null])} />
          </div>
          <Button type="primary" icon={<FileTextOutlined />} loading={loading} onClick={generate}>
            生成 Markdown 报告
          </Button>
        </div>
      </Card>
      {result && (
        <Card size="small" title="报告内容" extra={
          <Button icon={<DownloadOutlined />} onClick={download}>下载 Markdown</Button>
        }>
          <Alert type="success" message="报告已生成并保存。" showIcon style={{ marginBottom: 16 }} />
          <pre style={{ whiteSpace: 'pre-wrap', fontFamily: 'inherit', lineHeight: 1.8 }}>{result.content}</pre>
        </Card>
      )}
    </>
  );
}
