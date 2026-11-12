import { useState } from 'react';
import { App as AntApp, Button, Col, Form, Input, Row } from 'antd';
import { patchJson } from '../api/client';
import { DataTable, Section, StatCards } from './common';

const text = (value: unknown) => (value === null || value === undefined || value === '' ? '—' : String(value));

export default function JointSummary({ summary }: { summary: any }) {
  const subject = summary.case_subject || {};
  const toolchain = summary.sample_ai_toolchain || {};
  const attribution = toolchain.model_attribution || {};
  const evidenceRows = (toolchain.evidence || []).map((item: any) => ({
    线索类型: text(item.type),
    具体内容: text(item.raw || item.value),
    模型厂商: text(item.normalized?.vendor),
    具体模型: text(item.normalized?.model),
    来源位置: text(item.source || item.location),
  }));
  const reportTools = (summary.report_ai_toolchain || []).map((item: any) => ({
    模型厂商: text(item.provider),
    模型家族: text(item.family),
    具体模型: text(item.model),
    '服务/API': text(item.service || item.endpoint || item.sdk_or_library),
    用途: text(item.purpose),
    证据引用: (item.evidence_ids || []).join('、') || '—',
  }));

  return (
    <>
      <StatCards items={[
        { label: '目标样本/家族', value: subject.sample_family || subject.event_name || '未标注' },
        { label: '报告目标事件', value: subject.event_name || '未匹配' },
        { label: '确认项', value: (summary.confirmed || []).length },
        { label: '补充项', value: (summary.report_complements || []).length },
        { label: '冲突项', value: (summary.conflicts || []).length },
      ]} />
      <Row gutter={[20, 20]}>
        <Col xs={24} lg={12}>
          <Section title="样本侧 AI 工具链">
            <p style={{ lineHeight: 2 }}>
              <b>语言：</b>{text(toolchain.source_language)}　<b>文件类型：</b>{text(toolchain.file_type)}<br />
              <b>模型厂商：</b>{text(attribution.vendor)}　<b>模型家族：</b>{text(attribution.family)}　<b>具体模型：</b>{text(attribution.model)}
            </p>
            {evidenceRows.length ? <DataTable rows={evidenceRows} /> : <span style={{ color: '#64748B' }}>样本中没有更多可直接展示的工具链证据。</span>}
          </Section>
        </Col>
        <Col xs={24} lg={12}>
          <Section title="报告侧 AI 工具链">
            {reportTools.length ? <DataTable rows={reportTools} /> : <span style={{ color: '#64748B' }}>报告中没有抽取到目标对象的 AI 工具链描述。</span>}
          </Section>
        </Col>
      </Row>
      <EventContextEditor summary={summary} />
    </>
  );
}

function EventContextEditor({ summary }: { summary: any }) {
  const context = summary.event_context || {};
  const { message } = AntApp.useApp();
  const [form] = Form.useForm();
  const [saving, setSaving] = useState(false);
  if (!context.editable || !context.event_id) return null;
  const effective = context.effective || {};

  const save = async (values: { organizations: string; locations: string }) => {
    const split = (value: string) => value.split(/[\n,，;；]+/).map((item) => item.trim()).filter(Boolean);
    setSaving(true);
    try {
      await patchJson(`/api/v1/events/${context.event_id}/context`, {
        organizations: split(values.organizations || ''),
        countries_or_regions: split(values.locations || ''),
      });
      message.success('已永久保存到本地知识库。');
    } catch (exc: any) {
      message.error(exc.message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Section title="人工修订组织与国家/地区">
      <p style={{ color: '#64748B', fontSize: 13 }}>一行一项；保存后写入本地知识库并永久覆盖展示值，报告模型抽取原值仍保留用于审计。</p>
      <Form form={form} layout="vertical" onFinish={save} initialValues={{
        organizations: (effective.organizations || []).join('\n'),
        locations: (effective.countries_or_regions || []).join('\n'),
      }}>
        <Row gutter={20}>
          <Col span={12}><Form.Item name="organizations" label="相关组织"><Input.TextArea rows={3} placeholder="例如 APT28" /></Form.Item></Col>
          <Col span={12}><Form.Item name="locations" label="国家/地区"><Input.TextArea rows={3} placeholder="例如 Russia" /></Form.Item></Col>
        </Row>
        <Button type="primary" htmlType="submit" loading={saving}>保存到知识库</Button>
      </Form>
    </Section>
  );
}
