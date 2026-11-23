import { useEffect, useState } from 'react'
import { Card, Form, Input, Select, Switch, Button, Space, Typography, message, Divider } from 'antd'
import { SaveOutlined } from '@ant-design/icons'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { retentionStorageApi } from '../services/api'

const { Title, Paragraph, Text } = Typography

function RetentionStorage() {
  const [form] = Form.useForm()
  const queryClient = useQueryClient()
  const [testing, setTesting] = useState(false)
  const [loaded, setLoaded] = useState(false)
  const backend = (Form.useWatch('backend', form) as string) || 'local'

  const configQ = useQuery({
    queryKey: ['retention-storage-config'],
    queryFn: () => retentionStorageApi.get().then((r) => r.data),
  })

  useEffect(() => {
    if (configQ.data && !loaded) {
      const d = configQ.data
      form.setFieldsValue({
        backend: d.backend || 'local',
        local_path: d.local_path || '',
        s3_endpoint: d.s3_endpoint || '',
        s3_bucket: d.s3_bucket || '',
        s3_access_key: d.s3_access_key || '',
        s3_secret_key: '',
        s3_region: d.s3_region || '',
        s3_prefix: d.s3_prefix || '',
        s3_use_ssl: d.s3_use_ssl ?? true,
      })
      setLoaded(true)
    }
  }, [configQ.data, loaded, form])

  const saveM = useMutation({
    mutationFn: (v: Record<string, unknown>) => retentionStorageApi.update(v),
    onSuccess: () => {
      message.success('已保存,约 1 分钟内热生效(不用重启)')
      queryClient.invalidateQueries({ queryKey: ['retention-storage-config'] })
    },
    onError: (e: any) => message.error('保存失败: ' + (e?.response?.data?.error?.message || e?.message || '')),
  })

  const handleTest = async () => {
    setTesting(true)
    try {
      const res = await retentionStorageApi.test(form.getFieldsValue())
      if (res.data.ok) message.success(res.data.message || '连接成功')
      else message.error('测试失败: ' + (res.data.message || ''))
    } catch (e: any) {
      message.error('测试失败: ' + (e?.message || ''))
    } finally {
      setTesting(false)
    }
  }

  const hasSecret = configQ.data?.has_secret

  return (
    <div>
      <div className="page-header">
        <Title level={3}>内容留存存储</Title>
        <Paragraph type="secondary">
          配置留证图片/文件的存储后端。默认本机磁盘;可改为挂载目录(NFS/SMB 先在主机/compose 挂好)或 S3 兼容对象存储。改动约 1 分钟热生效,不用重启;切到 S3 后历史的本机图片仍可显示(自动回退本机读)。
        </Paragraph>
      </div>
      <Card>
        <Form form={form} layout="vertical" initialValues={{ backend: 'local', s3_use_ssl: true }} onFinish={(v) => saveM.mutate(v)}>
          <Form.Item name="backend" label="存储后端">
            <Select
              style={{ maxWidth: 520 }}
              options={[
                { value: 'local', label: '本地 / 挂载目录(本机磁盘,或 NFS/SMB 挂载点)' },
                { value: 's3', label: 'S3 兼容对象存储(MinIO / NAS-S3 / 云 OSS)' },
              ]}
            />
          </Form.Item>

          {backend === 'local' && (
            <>
              <Form.Item name="local_path" label="挂载/本地目录(留空 = 用环境变量 RETENTION_STORE_PATH)">
                <Input placeholder="/var/lib/jjdguard/retention 或 /mnt/retention-nfs" style={{ maxWidth: 520 }} />
              </Form.Item>
            </>
          )}

          {backend === 's3' && (
            <>
              <Form.Item name="s3_endpoint" label="Endpoint" rules={[{ required: true, message: '请填 endpoint' }]}>
                <Input placeholder="s3.example.com 或 https://oss-cn-hangzhou.aliyuncs.com" style={{ maxWidth: 520 }} />
              </Form.Item>
              <Form.Item name="s3_bucket" label="Bucket" rules={[{ required: true, message: '请填 bucket' }]}>
                <Input style={{ maxWidth: 520 }} />
              </Form.Item>
              <Form.Item name="s3_access_key" label="Access Key">
                <Input style={{ maxWidth: 520 }} />
              </Form.Item>
              <Form.Item name="s3_secret_key" label={hasSecret ? 'Secret Key(已设置,留空 = 不修改)' : 'Secret Key'}>
                <Input.Password placeholder={hasSecret ? '••••••(留空保留原密钥)' : ''} style={{ maxWidth: 520 }} />
              </Form.Item>
              <Space size="large" wrap>
                <Form.Item name="s3_region" label="Region">
                  <Input style={{ width: 200 }} placeholder="us-east-1" />
                </Form.Item>
                <Form.Item name="s3_prefix" label="路径前缀(可选)">
                  <Input style={{ width: 200 }} placeholder="retention/" />
                </Form.Item>
                <Form.Item name="s3_use_ssl" label="使用 HTTPS" valuePropName="checked">
                  <Switch />
                </Form.Item>
              </Space>
              <Form.Item>
                <Button onClick={handleTest} loading={testing}>测试连接</Button>
              </Form.Item>
            </>
          )}

          <Divider />
          <Space>
            <Button type="primary" htmlType="submit" icon={<SaveOutlined />} loading={saveM.isPending}>
              保存
            </Button>
            {configQ.data?.updated_by ? <Text type="secondary">最后修改: {configQ.data.updated_by}</Text> : null}
          </Space>
        </Form>
      </Card>
    </div>
  )
}

export default RetentionStorage
