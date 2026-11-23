// Command migrate-externalize 一次性把 access_content_logs 里残留的历史 inline data_base64
// 外移到 LocalStore(DB 只留指针),回收 JSONB 膨胀。默认 dry-run(只统计不改),加 -run 才真改。
// 只依赖两个环境变量:DATABASE_URL、RETENTION_STORE_PATH(-run 时必需),便于在最小容器里跑。
package main

import (
	"context"
	"flag"
	"log"
	"os"

	"github.com/yangjiyj/aiguard/apps/proxy-server/internal/handler"

	sharedDB "github.com/yangjiyj/aiguard/packages/shared-go/dbhelpers"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionstore"
)

func main() {
	run := flag.Bool("run", false, "真正执行迁移(默认 false=dry-run 只统计不改)")
	batch := flag.Int("batch", 200, "每批处理行数")
	images := flag.Bool("images", false, "回填引用式图片(json_image_url/json_file_url 抓 URL 字节);默认 false=外移历史 inline 附件")
	flag.Parse()
	dryRun := !*run

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL is required")
	}
	storePath := os.Getenv("RETENTION_STORE_PATH")

	ctx := context.Background()
	db, err := sharedDB.NewPoolFromURL(ctx, dbURL)
	if err != nil {
		log.Fatalf("connect db: %v", err)
	}
	defer db.Close()

	var store retentionstore.Store
	if storePath != "" {
		ls, err := retentionstore.NewLocalStore(storePath)
		if err != nil {
			log.Fatalf("open retention store: %v", err)
		}
		store = ls
	} else if !dryRun {
		log.Fatal("RETENTION_STORE_PATH required for -run")
	}

	mode := "inline-externalize"
	if *images {
		mode = "reference-images"
	}
	log.Printf("[migrate-externalize] start mode=%s dry_run=%v batch=%d store=%q", mode, dryRun, *batch, storePath)
	var res handler.BackfillResult
	if *images {
		res, err = handler.BackfillReferenceImages(ctx, db, store, *batch, dryRun)
	} else {
		res, err = handler.BackfillExternalizeInlineAttachments(ctx, db, store, *batch, dryRun)
	}
	if err != nil {
		log.Fatalf("[migrate-externalize] failed (partial=%+v): %v", res, err)
	}
	log.Printf("[migrate-externalize] done mode=%s dry_run=%v result=%+v", mode, dryRun, res)
}
