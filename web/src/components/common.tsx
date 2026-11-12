import { Card, Col, Row, Statistic, Table, Typography } from 'antd';
import type { ReactNode } from 'react';

export function PageHeader({ title, description, extra }: { title: string; description?: string; extra?: ReactNode }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20, gap: 16, flexWrap: 'wrap' }}>
      <div>
        <Typography.Title level={3} style={{ margin: 0 }}>{title}</Typography.Title>
        {description && <Typography.Paragraph type="secondary" style={{ marginTop: 6, marginBottom: 0, maxWidth: 900 }}>{description}</Typography.Paragraph>}
      </div>
      {extra && <div style={{ display: 'flex', gap: 8 }}>{extra}</div>}
    </div>
  );
}

export function StatCards({ items }: { items: { label: string; value: string | number | null | undefined }[] }) {
  return (
    <Row gutter={[16, 16]} style={{ marginBottom: 20 }}>
      {items.map((item) => (
        <Col key={item.label} flex="1 1 160px">
          <Card size="small" styles={{ body: { padding: '14px 18px' } }}>
            <Statistic title={item.label} value={item.value ?? '—'} valueStyle={{ fontSize: 26 }} />
          </Card>
        </Col>
      ))}
    </Row>
  );
}

export function DataTable({ rows, rowKey, maxHeight }: { rows: Record<string, unknown>[]; rowKey?: string; maxHeight?: number }) {
  if (!rows.length) return <Typography.Text type="secondary">暂无数据</Typography.Text>;
  const columns = Object.keys(rows[0]).map((key) => ({
    title: key,
    dataIndex: key,
    key,
    ellipsis: true,
    render: (value: unknown) => {
      if (value === null || value === undefined || value === '') return '—';
      if (typeof value === 'boolean') return value ? '是' : '否';
      if (typeof value === 'object') return JSON.stringify(value);
      return String(value);
    },
  }));
  return (
    <Table
      size="small"
      columns={columns}
      dataSource={rows.map((row, index) => ({ ...row, __key: rowKey ? String(row[rowKey]) : index }))}
      rowKey="__key"
      pagination={rows.length > 12 ? { pageSize: 12, hideOnSinglePage: true } : false}
      scroll={{ x: 'max-content', y: maxHeight }}
    />
  );
}

export function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Card title={title} size="small" style={{ marginBottom: 20 }} styles={{ header: { fontWeight: 600 } }}>
      {children}
    </Card>
  );
}
