import { useEffect, useState } from 'react';
import { Alert, App as AntApp, Button, Card, Col, Collapse, Form, Input, Row, Select, Upload } from 'antd';
import { ApiOutlined, InboxOutlined } from '@ant-design/icons';
import { getJson, postFiles } from '../api/client';
import { DataTable, PageHeader, Section, StatCards } from '../components/common';
import JointSummary from '../components/JointSummary';

const SCRIPT_ACCEPT = '.py,.pyw,.ps1,.psm1,.psd1,.js,.mjs,.cjs,.vbs,.vbe,.sh,.bash,.bat,.cmd,.php,.pl,.rb,.lua,.txt';

export default function IntakePage() {
  const [lists, setLists] = useState<{ samples: any[]; reports: any[]; cases: any[] }>({ samples: [], reports: [], cases: [] });
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [caseDetail, setCaseDetail] = useState<any>(null);
  const [sampleFile, setSampleFile] = useState<File | null>(null);
  const [reportFile, setReportFile] = useState<File | null>(null);
  const [form] = Form.useForm();
  const { message } = AntApp.useApp();
  const selectedCase = Form.useWatch('case_id', form);

  useEffect(() => {
    Promise.all([
      getJson<any[]>('/api/v1/samples', { limit: 500 }),
      getJson<any[]>('/api/v1/reports', { limit: 500 }),
      getJson<any[]>('/api/v1/analysis-cases', { limit: 500 }),
    ]).then(([samples, reports, cases]) => setLists({ samples, reports, cases }))
      .catch((exc) => setError(exc.message));
  }, []);

  useEffect(() => {
    if (!selectedCase) { setCaseDetail(null); return; }
    getJson(`/api/v1/analysis-cases/${selectedCase}`).then(setCaseDetail).catch((exc) => setError(exc.message));
  }, [selectedCase]);

  const submit = async (values: any) => {
    if (sampleFile && values.existing_sample_sha256) { message.error('样本侧只能选择"上传新样本"或"已有样本"之一。'); return; }
    if (reportFile && values.existing_report_id) { message.error('报告侧只能选择"上传新报告"或"已有报告"之一。'); return; }
    if (reportFile && !(values.target_name || values.source_case || caseDetail)) {
      message.error('上传报告前请填写"报告抽取目标样本/家族"。'); return;
    }
    if (!sampleFile && !reportFile && !values.existing_sample_sha256 && !values.existing_report_id && !values.case_id) {
      message.error('请至少上传或选择一个样本/报告。'); return;
    }
    setSubmitting(true);
    setError('');
    try {
      const files: Record<string, File> = {};
      if (sampleFile) files.sample_file = sampleFile;
      if (reportFile) files.report_file = reportFile;
      const response = await postFiles<any>('/api/v1/analysis-cases', files, {
        case_id: values.case_id,
        title: values.title,
        notes: values.notes,
        existing_sample_sha256: values.existing_sample_sha256,
        existing_report_id: values.existing_report_id,
        source_case: values.source_case,
        canonical_url: values.canonical_url,
        target_name: values.target_name,
        target_aliases: values.target_aliases,
      });
      setResult(response);
      message.success('联合分析完成');
    } catch (exc: any) {
      setError(exc.message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <>
      <PageHeader title="样本与报告联合分析"
        description="一个案例代表一组明确对应的样本与技术报告。可以同时上传，也可以先建案例、后续补齐另一侧。" />
      <Alert type="warning" showIcon style={{ marginBottom: 16 }}
        message="恶意样本仅做纯静态分析，禁止执行、导入、调试、仿真或上传外部服务；仅分析脚本文件，二进制会被拒绝。" />
      {error && <Alert type="error" message={error} showIcon style={{ marginBottom: 16 }} />}
      <Collapse ghost style={{ marginBottom: 8 }} items={[{
        key: 'guide', label: '操作指引',
        children: <ol style={{ color: '#64748B', lineHeight: 2 }}>
          <li>首次分析选择"新建分析案例"，上传样本和/或报告。</li>
          <li>先只上传样本后，回到本页选择原案例，只上传对应报告即可。</li>
          <li>样本按 SHA-256 去重，报告按规范化标题逻辑去重。</li>
          <li>上传报告时必须指定要抽取的样本或家族，系统不会把其他事件算到该样本名下。</li>
        </ol>,
      }]} />
      <Card size="small" style={{ marginBottom: 20 }}>
        <Form form={form} layout="vertical" onFinish={submit} initialValues={{ case_id: undefined }}>
          <Section title="1 案例信息">
            <Row gutter={20}>
              <Col xs={24} md={12}>
                <Form.Item name="case_id" label="新建还是继续已有案例？">
                  <Select allowClear placeholder="新建分析案例"
                    options={lists.cases.map((item) => ({
                      value: item.id,
                      label: `${item.title} · ${item.status} · ${item.id.slice(0, 8)}`,
                    }))} />
                </Form.Item>
                <Form.Item name="title" label="案例标题">
                  <Input placeholder="例如 PromptLock 样本与报告复核" disabled={!!selectedCase} />
                </Form.Item>
              </Col>
              <Col xs={24} md={12}>
                <Form.Item name="notes" label="备注（可选）"><Input.TextArea rows={4} /></Form.Item>
              </Col>
            </Row>
            {caseDetail && <Alert type="info" showIcon message={`当前案例：${caseDetail.title} · 已有样本 ${caseDetail.samples?.length || 0} 个 · 报告 ${caseDetail.reports?.length || 0} 份`} />}
          </Section>
          <Section title="2 样本与报告">
            <Row gutter={[20, 0]}>
              <Col xs={24} lg={12}>
                <Card type="inner" title="样本侧" size="small">
                  <Form.Item label="上传新样本（仅脚本文件）" extra="PE/ELF/APK 等二进制不再分析，会被 API 拒绝；无扩展名脚本可改名后上传。">
                    <Upload.Dragger accept={SCRIPT_ACCEPT} maxCount={1}
                      beforeUpload={(file) => { setSampleFile(file); return false; }}
                      onRemove={() => setSampleFile(null)}>
                      <p className="ant-upload-drag-icon"><InboxOutlined /></p>
                      <p className="ant-upload-text">点击或拖拽脚本文件到此</p>
                      <p className="ant-upload-hint">Python / PowerShell / JavaScript / VBScript / Shell 等</p>
                    </Upload.Dragger>
                  </Form.Item>
                  <Form.Item name="existing_sample_sha256" label="或者选择已有样本">
                    <Select allowClear placeholder="不选择已有样本" showSearch optionFilterProp="label"
                      options={lists.samples.map((item) => ({
                        value: item.sha256,
                        label: `${item.source_case || '未标注'} · ${item.sha256.slice(0, 12)}…`,
                      }))} />
                  </Form.Item>
                  <Form.Item name="source_case" label="样本来源/家族"><Input placeholder="例如 PROMPTFLUX" /></Form.Item>
                </Card>
              </Col>
              <Col xs={24} lg={12}>
                <Card type="inner" title="报告侧" size="small">
                  <Form.Item label="上传新报告">
                    <Upload.Dragger accept=".pdf,.html,.htm,.docx,.md,.txt" maxCount={1}
                      beforeUpload={(file) => { setReportFile(file); return false; }}
                      onRemove={() => setReportFile(null)}>
                      <p className="ant-upload-drag-icon"><InboxOutlined /></p>
                      <p className="ant-upload-text">点击或拖拽报告到此</p>
                      <p className="ant-upload-hint">PDF / HTML / DOCX / Markdown / TXT</p>
                    </Upload.Dragger>
                  </Form.Item>
                  <Form.Item name="existing_report_id" label="或者选择已有报告">
                    <Select allowClear placeholder="不选择已有报告" showSearch optionFilterProp="label"
                      options={lists.reports.map((item) => ({
                        value: item.report_id,
                        label: `${item.title || item.report_id} · ${item.report_id.slice(0, 12)}…`,
                      }))} />
                  </Form.Item>
                  <Form.Item name="target_name" label="报告抽取目标样本/家族" extra="只抽取报告中与这个名称对应的事件信息。">
                    <Input placeholder="例如 PROMPTFLUX" />
                  </Form.Item>
                  <Form.Item name="target_aliases" label="目标别名（可选，逗号分隔）"><Input placeholder="例如 APT28, UAC-0001" /></Form.Item>
                  <Form.Item name="canonical_url" label="报告原始 URL（可选）"><Input /></Form.Item>
                  <Alert type="info" showIcon style={{ fontSize: 12 }}
                    message="报告默认由大模型直接提取；提交新报告会将全文发送到已配置的 DeepSeek 兼容接口。恶意样本文件不会发送。" />
                </Card>
              </Col>
            </Row>
          </Section>
          <Button type="primary" htmlType="submit" icon={<ApiOutlined />} loading={submitting} size="large">
            提交联合分析
          </Button>
        </Form>
      </Card>
      {result && (
        <>
          <StatCards items={[
            { label: '案例状态', value: result.case?.status },
            { label: '关联样本', value: result.case?.samples?.length || 0 },
            { label: '关联报告', value: result.case?.reports?.length || 0 },
            { label: '自动验证', value: result.validation_status || '未触发' },
          ]} />
          {result.joint_summary && <JointSummary summary={result.joint_summary} />}
          {result.sample_associations && (
            <Section title="新样本知识库关联">
              <DataTable rows={result.sample_associations.related_samples || []} />
              <p style={{ color: '#64748B' }}>{result.sample_associations.interpretation}</p>
            </Section>
          )}
          <Collapse style={{ marginTop: 16 }} items={[{
            key: 'raw', label: '原始联合分析结果（审计用）',
            children: <pre style={{ maxHeight: 480, overflow: 'auto', fontSize: 12 }}>{JSON.stringify(result, null, 2)}</pre>,
          }]} />
        </>
      )}
    </>
  );
}
