package handler

import (
	"context"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/corpusscan"
)

// 语料扫描任务的租约：执行器每 20 秒续一次，过期即视为执行进程已退出（规格 5.4）。
const (
	corpusScanLease            = 60 * time.Second
	corpusScanHeartbeat        = 20 * time.Second
	corpusScanRetention        = 7 * 24 * time.Hour
	corpusScanUploadingTimeout = 24 * time.Hour
	// 排队任务等不到执行器（例如所有控制面实例都已退出）时的上限，过期标记为 interrupted。
	corpusScanQueueTimeout = 24 * time.Hour
)

var (
	ErrCorpusScanNotFound   = errors.New("corpus scan job not found")
	ErrCorpusScanState      = errors.New("corpus scan job is not in the required state")
	ErrCorpusScanChunkOrder = errors.New("corpus scan chunk is out of order")
	ErrCorpusScanTooLarge   = errors.New("corpus scan upload exceeds the declared size")
	ErrCorpusScanIncomplete = errors.New("corpus scan upload is incomplete")
	ErrCorpusScanDigest     = errors.New("corpus scan upload digest does not match")
	ErrCorpusScanLeaseLost  = errors.New("corpus scan job lease lost")
	ErrCorpusScanCanceled   = errors.New("corpus scan job cancel requested")
)

// CorpusScanJob 是任务的对外视图。存储 key、哈希中间状态与租约令牌不下发前端。
type CorpusScanJob struct {
	ID                string                     `json:"job_id"`
	TenantID          string                     `json:"-"`
	CreatedBy         string                     `json:"created_by"`
	FileName          string                     `json:"file_name"`
	Format            string                     `json:"format"`
	SizeBytes         int64                      `json:"size_bytes"`
	SHA256            string                     `json:"sha256"`
	Status            string                     `json:"status"`
	ErrorCode         string                     `json:"error_code"`
	CancelRequested   bool                       `json:"cancel_requested"`
	UploadedBytes     int64                      `json:"uploaded_bytes"`
	NextChunk         int                        `json:"next_chunk"`
	ProcessedBytes    int64                      `json:"processed_bytes"`
	TotalRecords      int64                      `json:"total_records"`
	ScannedRecords    int64                      `json:"scanned_records"`
	HitRecords        int64                      `json:"hit_records"`
	UnscannedRecords  int64                      `json:"unscanned_records"`
	IncompleteRecords int64                      `json:"incomplete_records"`
	Stats             []corpusscan.TypeStat      `json:"stats"`
	Samples           []corpusscan.Sample        `json:"samples"`
	Unscanned         []corpusscan.UnscannedLine `json:"unscanned"`
	Notes             []string                   `json:"notes"`
	MaskedFormat      string                     `json:"masked_format"`
	RulePackVersion   string                     `json:"rule_pack_version"`
	HasReport         bool                       `json:"has_report"`
	HasMasked         bool                       `json:"has_masked"`
	ExpiresAt         time.Time                  `json:"expires_at"`
	CreatedAt         time.Time                  `json:"created_at"`
	UpdatedAt         time.Time                  `json:"updated_at"`
	StartedAt         *time.Time                 `json:"started_at"`
	CompletedAt       *time.Time                 `json:"completed_at"`

	SourceKeys []string `json:"-"`
	ReportKey  string   `json:"-"`
	MaskedKey  string   `json:"-"`
	ownerToken string
}

// CorpusScanCreate 是新建任务的输入。
type CorpusScanCreate struct {
	TenantID  string
	CreatedBy string
	FileName  string
	Format    string
	SizeBytes int64
	SHA256    string
}

// CorpusScanChunk 是一个已写入留存卷的分片。
type CorpusScanChunk struct {
	Index int
	Size  int64
	Key   string
	Data  []byte // 只用于累计哈希；不落库
}

// CorpusScanOutcome 是任务终态。
type CorpusScanOutcome struct {
	Status       string
	ErrorCode    string
	Report       corpusscan.Report
	Notes        []string
	ReportKey    string
	MaskedKey    string
	MaskedFormat string
}

// CorpusScanStore 是语料扫描任务的持久化接口。
type CorpusScanStore interface {
	Create(ctx context.Context, in CorpusScanCreate) (CorpusScanJob, error)
	Get(ctx context.Context, tenant, id string) (CorpusScanJob, error)
	List(ctx context.Context, tenant string, limit int) ([]CorpusScanJob, error)
	AppendChunk(ctx context.Context, tenant, id string, chunk CorpusScanChunk) (CorpusScanJob, error)
	Queue(ctx context.Context, tenant, id string) (CorpusScanJob, error)
	ClaimNext(ctx context.Context, owner string) (CorpusScanJob, bool, error)
	Heartbeat(ctx context.Context, job CorpusScanJob, progress corpusscan.Progress) error
	Finish(ctx context.Context, job CorpusScanJob, outcome CorpusScanOutcome) error
	Cancel(ctx context.Context, tenant, id string) (CorpusScanJob, error)
	Delete(ctx context.Context, tenant, id string) (CorpusScanJob, error)
	Reap(ctx context.Context) error
	Expired(ctx context.Context, limit int) ([]CorpusScanJob, error)
	Purge(ctx context.Context, job CorpusScanJob) error
	PendingSourceCleanup(ctx context.Context, limit int) ([]CorpusScanJob, error)
	ClearSourceKeys(ctx context.Context, job CorpusScanJob) error
}

// PostgresCorpusScanStore 基于迁移 990 的 corpus_scan_jobs。
type PostgresCorpusScanStore struct{ pool *pgxpool.Pool }

func NewPostgresCorpusScanStore(pool *pgxpool.Pool) *PostgresCorpusScanStore {
	return &PostgresCorpusScanStore{pool: pool}
}

const corpusScanColumns = `id,tenant_id,created_by,file_name,format,size_bytes,sha256,status,error_code,cancel_requested,owner_token,
uploaded_bytes,next_chunk,processed_bytes,total_records,scanned_records,hit_records,unscanned_records,incomplete_records,
stats_json,samples_json,unscanned_json,notes_json,source_keys,report_key,masked_key,masked_format,rule_pack_version,
expires_at,created_at,updated_at,started_at,completed_at`

func scanCorpusJob(row pgx.Row) (CorpusScanJob, error) {
	var j CorpusScanJob
	var stats, samples, unscanned, notes, keys []byte
	err := row.Scan(&j.ID, &j.TenantID, &j.CreatedBy, &j.FileName, &j.Format, &j.SizeBytes, &j.SHA256, &j.Status, &j.ErrorCode,
		&j.CancelRequested, &j.ownerToken, &j.UploadedBytes, &j.NextChunk, &j.ProcessedBytes, &j.TotalRecords, &j.ScannedRecords,
		&j.HitRecords, &j.UnscannedRecords, &j.IncompleteRecords, &stats, &samples, &unscanned, &notes, &keys, &j.ReportKey,
		&j.MaskedKey, &j.MaskedFormat, &j.RulePackVersion, &j.ExpiresAt, &j.CreatedAt, &j.UpdatedAt, &j.StartedAt, &j.CompletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return j, ErrCorpusScanNotFound
	}
	if err != nil {
		return j, err
	}
	j.Stats, j.Samples, j.Unscanned, j.Notes, j.SourceKeys = []corpusscan.TypeStat{}, []corpusscan.Sample{}, []corpusscan.UnscannedLine{}, []string{}, []string{}
	if string(stats) != "{}" {
		if err := json.Unmarshal(stats, &j.Stats); err != nil {
			return j, err
		}
	}
	for _, field := range []struct {
		raw    []byte
		target any
	}{{samples, &j.Samples}, {unscanned, &j.Unscanned}, {notes, &j.Notes}, {keys, &j.SourceKeys}} {
		if err := json.Unmarshal(field.raw, field.target); err != nil {
			return j, err
		}
	}
	j.HasReport = j.ReportKey != ""
	j.HasMasked = j.MaskedKey != ""
	return j, nil
}

func (s *PostgresCorpusScanStore) queryJobs(ctx context.Context, sql string, args ...any) ([]CorpusScanJob, error) {
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	jobs := []CorpusScanJob{}
	for rows.Next() {
		job, err := scanCorpusJob(rows)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	return jobs, rows.Err()
}

func (s *PostgresCorpusScanStore) Create(ctx context.Context, in CorpusScanCreate) (CorpusScanJob, error) {
	return scanCorpusJob(s.pool.QueryRow(ctx, `INSERT INTO corpus_scan_jobs(id,tenant_id,created_by,file_name,format,size_bytes,sha256,status,expires_at)
VALUES($1,$2,$3,$4,$5,$6,$7,'uploading',clock_timestamp()+$8::interval) RETURNING `+corpusScanColumns,
		"corpus_"+uuid.NewString(), in.TenantID, in.CreatedBy, in.FileName, in.Format, in.SizeBytes, in.SHA256,
		corpusScanUploadingTimeout.String()))
}

// Get 读取任务；顺带把过期的租约标为 interrupted，避免页面一直显示「运行中」。
func (s *PostgresCorpusScanStore) Get(ctx context.Context, tenant, id string) (CorpusScanJob, error) {
	if err := s.Reap(ctx); err != nil {
		return CorpusScanJob{}, err
	}
	return scanCorpusJob(s.pool.QueryRow(ctx, `SELECT `+corpusScanColumns+` FROM corpus_scan_jobs WHERE tenant_id=$1 AND id=$2`, tenant, id))
}

func (s *PostgresCorpusScanStore) List(ctx context.Context, tenant string, limit int) ([]CorpusScanJob, error) {
	if err := s.Reap(ctx); err != nil {
		return nil, err
	}
	return s.queryJobs(ctx, `SELECT `+corpusScanColumns+` FROM corpus_scan_jobs WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`, tenant, limit)
}

// AppendChunk 登记一个已经写入留存卷的分片：只接受下一个序号，累计大小不得超过声明大小，
// 同时在同一事务里推进 SHA-256 中间状态。失败时调用方负责删除刚写入的对象。
func (s *PostgresCorpusScanStore) AppendChunk(ctx context.Context, tenant, id string, chunk CorpusScanChunk) (CorpusScanJob, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return CorpusScanJob{}, err
	}
	defer tx.Rollback(ctx)
	var status string
	var next int
	var uploaded, size int64
	var cancel bool
	var state []byte
	err = tx.QueryRow(ctx, `SELECT status,next_chunk,uploaded_bytes,size_bytes,cancel_requested,upload_hash_state FROM corpus_scan_jobs WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, id).
		Scan(&status, &next, &uploaded, &size, &cancel, &state)
	if errors.Is(err, pgx.ErrNoRows) {
		return CorpusScanJob{}, ErrCorpusScanNotFound
	}
	if err != nil {
		return CorpusScanJob{}, err
	}
	if status != "uploading" || cancel {
		return CorpusScanJob{}, ErrCorpusScanState
	}
	if chunk.Index != next {
		return CorpusScanJob{}, ErrCorpusScanChunkOrder
	}
	if uploaded+chunk.Size > size || int64(len(chunk.Data)) != chunk.Size {
		return CorpusScanJob{}, ErrCorpusScanTooLarge
	}
	hash := sha256.New()
	if len(state) > 0 {
		if err := hash.(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err != nil {
			return CorpusScanJob{}, err
		}
	}
	hash.Write(chunk.Data)
	state, err = hash.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		return CorpusScanJob{}, err
	}
	digest := ""
	if uploaded+chunk.Size == size {
		digest = hex.EncodeToString(hash.Sum(nil))
	}
	keys, err := json.Marshal([]string{chunk.Key})
	if err != nil {
		return CorpusScanJob{}, err
	}
	job, err := scanCorpusJob(tx.QueryRow(ctx, `UPDATE corpus_scan_jobs SET uploaded_bytes=uploaded_bytes+$3,next_chunk=next_chunk+1,
upload_hash_state=$4,upload_sha256=$5,source_keys=source_keys||$6::jsonb,updated_at=clock_timestamp()
WHERE tenant_id=$1 AND id=$2 RETURNING `+corpusScanColumns, tenant, id, chunk.Size, state, digest, string(keys)))
	if err != nil {
		return job, err
	}
	return job, tx.Commit(ctx)
}

// Queue 校验上传完整且 sha256 一致后排队。排队不占用执行位，执行器按创建顺序逐个认领。
func (s *PostgresCorpusScanStore) Queue(ctx context.Context, tenant, id string) (CorpusScanJob, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return CorpusScanJob{}, err
	}
	defer tx.Rollback(ctx)
	var status, declared, actual string
	var uploaded, size int64
	var cancel bool
	err = tx.QueryRow(ctx, `SELECT status,sha256,upload_sha256,uploaded_bytes,size_bytes,cancel_requested FROM corpus_scan_jobs WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, id).
		Scan(&status, &declared, &actual, &uploaded, &size, &cancel)
	if errors.Is(err, pgx.ErrNoRows) {
		return CorpusScanJob{}, ErrCorpusScanNotFound
	}
	if err != nil {
		return CorpusScanJob{}, err
	}
	if status != "uploading" || cancel {
		return CorpusScanJob{}, ErrCorpusScanState
	}
	if uploaded != size {
		return CorpusScanJob{}, ErrCorpusScanIncomplete
	}
	if actual == "" || actual != declared {
		return CorpusScanJob{}, ErrCorpusScanDigest
	}
	job, err := scanCorpusJob(tx.QueryRow(ctx, `UPDATE corpus_scan_jobs SET status='queued',upload_hash_state=NULL,
lease_until=clock_timestamp()+$3::interval,updated_at=clock_timestamp()
WHERE tenant_id=$1 AND id=$2 RETURNING `+corpusScanColumns, tenant, id, corpusScanQueueTimeout.String()))
	if err != nil {
		return job, err
	}
	return job, tx.Commit(ctx)
}

// ClaimNext 认领最早排队的任务并标为 running。已有运行中的任务时，部分唯一索引会拒绝，返回 ok=false。
func (s *PostgresCorpusScanStore) ClaimNext(ctx context.Context, owner string) (CorpusScanJob, bool, error) {
	if err := s.Reap(ctx); err != nil {
		return CorpusScanJob{}, false, err
	}
	job, err := scanCorpusJob(s.pool.QueryRow(ctx, `UPDATE corpus_scan_jobs SET status='running',owner_token=$1,started_at=clock_timestamp(),
lease_until=clock_timestamp()+$2::interval,updated_at=clock_timestamp()
WHERE id=(SELECT id FROM corpus_scan_jobs WHERE status='queued' AND NOT cancel_requested ORDER BY created_at, id LIMIT 1 FOR UPDATE SKIP LOCKED)
AND status='queued' RETURNING `+corpusScanColumns, owner, corpusScanLease.String()))
	var pgErr *pgconn.PgError
	switch {
	case errors.As(err, &pgErr) && pgErr.Code == "23505":
		return CorpusScanJob{}, false, nil
	case errors.Is(err, ErrCorpusScanNotFound):
		return CorpusScanJob{}, false, nil
	case err != nil:
		return CorpusScanJob{}, false, err
	}
	return job, true, nil
}

// Heartbeat 续租并写入进度。取消请求或租约丢失时返回错误，执行器据此停止。
func (s *PostgresCorpusScanStore) Heartbeat(ctx context.Context, job CorpusScanJob, p corpusscan.Progress) error {
	result, err := s.pool.Exec(ctx, `UPDATE corpus_scan_jobs SET lease_until=clock_timestamp()+$4::interval,updated_at=clock_timestamp(),
processed_bytes=$5,total_records=$6,scanned_records=$7,hit_records=$8,unscanned_records=$9,incomplete_records=$10
WHERE id=$1 AND tenant_id=$2 AND owner_token=$3 AND status='running' AND NOT cancel_requested AND lease_until>clock_timestamp()`,
		job.ID, job.TenantID, job.ownerToken, corpusScanLease.String(),
		p.ProcessedBytes, p.TotalRecords, p.ScannedRecords, p.HitRecords, p.UnscannedRecords, p.IncompleteRecords)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 1 {
		return nil
	}
	var canceled bool
	err = s.pool.QueryRow(ctx, `SELECT cancel_requested FROM corpus_scan_jobs WHERE id=$1 AND tenant_id=$2 AND owner_token=$3 AND status='running'`,
		job.ID, job.TenantID, job.ownerToken).Scan(&canceled)
	if err == nil && canceled {
		return ErrCorpusScanCanceled
	}
	return ErrCorpusScanLeaseLost
}

// Finish 写终态。已请求取消的任务一律记为 canceled，不保留报告和副本 key（调用方随后删除文件）。
// 原始语料 key 不在这里清空：调用方删除文件后调用 ClearSourceKeys，删除失败时由清理器重试。
func (s *PostgresCorpusScanStore) Finish(ctx context.Context, job CorpusScanJob, o CorpusScanOutcome) error {
	stats, err := json.Marshal(nonNil(o.Report.Stats))
	if err != nil {
		return err
	}
	samples, err := json.Marshal(nonNil(o.Report.Samples))
	if err != nil {
		return err
	}
	unscanned, err := json.Marshal(nonNil(o.Report.Unscanned))
	if err != nil {
		return err
	}
	notes, err := json.Marshal(nonNil(o.Notes))
	if err != nil {
		return err
	}
	p := o.Report.Progress
	result, err := s.pool.Exec(ctx, `UPDATE corpus_scan_jobs SET
status=CASE WHEN cancel_requested THEN 'canceled' ELSE $4 END,
error_code=CASE WHEN cancel_requested THEN 'canceled' ELSE $5 END,
report_key=CASE WHEN cancel_requested THEN '' ELSE $6 END,
masked_key=CASE WHEN cancel_requested THEN '' ELSE $7 END,
masked_format=CASE WHEN cancel_requested THEN '' ELSE $8 END,
processed_bytes=$9,total_records=$10,scanned_records=$11,hit_records=$12,unscanned_records=$13,incomplete_records=$14,
stats_json=$15::jsonb,samples_json=$16::jsonb,unscanned_json=$17::jsonb,notes_json=$18::jsonb,rule_pack_version=$19,
completed_at=clock_timestamp(),updated_at=clock_timestamp(),expires_at=clock_timestamp()+$20::interval
WHERE id=$1 AND tenant_id=$2 AND owner_token=$3 AND status='running'`,
		job.ID, job.TenantID, job.ownerToken, o.Status, o.ErrorCode, o.ReportKey, o.MaskedKey, o.MaskedFormat,
		p.ProcessedBytes, p.TotalRecords, p.ScannedRecords, p.HitRecords, p.UnscannedRecords, p.IncompleteRecords,
		string(stats), string(samples), string(unscanned), string(notes), o.Report.RulePackVersion, corpusScanRetention.String())
	if err == nil && result.RowsAffected() != 1 {
		return ErrCorpusScanLeaseLost
	}
	return err
}

// Cancel 请求取消。上传中和排队中的任务直接进入 canceled；运行中的由执行器在下一个批次停止。
func (s *PostgresCorpusScanStore) Cancel(ctx context.Context, tenant, id string) (CorpusScanJob, error) {
	return scanCorpusJob(s.pool.QueryRow(ctx, `UPDATE corpus_scan_jobs SET
cancel_requested=CASE WHEN status IN ('uploading','queued','running') THEN TRUE ELSE cancel_requested END,
status=CASE WHEN status IN ('uploading','queued') THEN 'canceled' ELSE status END,
error_code=CASE WHEN status IN ('uploading','queued') THEN 'canceled' ELSE error_code END,
completed_at=CASE WHEN status IN ('uploading','queued') THEN clock_timestamp() ELSE completed_at END,
expires_at=CASE WHEN status IN ('uploading','queued') THEN clock_timestamp()+$3::interval ELSE expires_at END,
upload_hash_state=CASE WHEN status IN ('uploading','queued') THEN NULL ELSE upload_hash_state END,
updated_at=clock_timestamp()
WHERE tenant_id=$1 AND id=$2 RETURNING `+corpusScanColumns, tenant, id, corpusScanRetention.String()))
}

// Delete 删除非运行中的任务记录，返回删除前的记录供调用方清理文件。运行中的任务要先取消。
func (s *PostgresCorpusScanStore) Delete(ctx context.Context, tenant, id string) (CorpusScanJob, error) {
	job, err := scanCorpusJob(s.pool.QueryRow(ctx, `DELETE FROM corpus_scan_jobs WHERE tenant_id=$1 AND id=$2 AND status<>'running' RETURNING `+corpusScanColumns, tenant, id))
	if errors.Is(err, ErrCorpusScanNotFound) {
		if _, getErr := s.Get(ctx, tenant, id); getErr != nil {
			return CorpusScanJob{}, getErr
		}
		return CorpusScanJob{}, ErrCorpusScanState
	}
	return job, err
}

// Reap 把租约过期的运行中任务、等太久的排队任务标为 interrupted。
func (s *PostgresCorpusScanStore) Reap(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `UPDATE corpus_scan_jobs SET status='interrupted',error_code='worker_interrupted',completed_at=clock_timestamp(),
updated_at=clock_timestamp(),expires_at=clock_timestamp()+$1::interval
WHERE status IN ('queued','running') AND lease_until<clock_timestamp()`, corpusScanRetention.String())
	return err
}

// Expired 返回 expires_at 已过的非运行中任务（含超时未传完的上传）。
func (s *PostgresCorpusScanStore) Expired(ctx context.Context, limit int) ([]CorpusScanJob, error) {
	return s.queryJobs(ctx, `SELECT `+corpusScanColumns+` FROM corpus_scan_jobs WHERE expires_at<clock_timestamp() AND status NOT IN ('queued','running') ORDER BY expires_at LIMIT $1`, limit)
}

// Purge 删除过期任务记录（文件已由调用方删除）。
func (s *PostgresCorpusScanStore) Purge(ctx context.Context, job CorpusScanJob) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM corpus_scan_jobs WHERE id=$1 AND tenant_id=$2 AND expires_at<clock_timestamp() AND status NOT IN ('queued','running')`, job.ID, job.TenantID)
	return err
}

// PendingSourceCleanup 返回已进入终态但原始语料还没删的任务（执行器删除失败或进程中断）。
func (s *PostgresCorpusScanStore) PendingSourceCleanup(ctx context.Context, limit int) ([]CorpusScanJob, error) {
	return s.queryJobs(ctx, `SELECT `+corpusScanColumns+` FROM corpus_scan_jobs WHERE source_keys<>'[]'::jsonb AND status IN ('succeeded','failed','canceled','interrupted') LIMIT $1`, limit)
}

// ClearSourceKeys 在原始语料删除后清空 key。
func (s *PostgresCorpusScanStore) ClearSourceKeys(ctx context.Context, job CorpusScanJob) error {
	_, err := s.pool.Exec(ctx, `UPDATE corpus_scan_jobs SET source_keys='[]'::jsonb,updated_at=clock_timestamp() WHERE id=$1 AND tenant_id=$2 AND status IN ('succeeded','failed','canceled','interrupted')`, job.ID, job.TenantID)
	return err
}

func nonNil[T any](v []T) []T {
	if v == nil {
		return []T{}
	}
	return v
}
