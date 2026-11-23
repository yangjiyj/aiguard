package main

import (
	"os"
	"strings"
	"testing"
)

// 关停顺序：排空原文留证队列必须在 db.Close() 之前，否则排队中的留证丢失、后台协程对已关闭的连接池报错。
func TestShutdownDrainsRawEvidenceBeforeClosingDB(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	drain := strings.Index(s, "baseAuditWriter.DrainRawEvidence(")
	closeDB := strings.LastIndex(s, "\tdb.Close()\n")
	if drain < 0 || closeDB < 0 || drain > closeDB {
		t.Fatalf("raw evidence queue must be drained before db.Close() (drain=%d close=%d)", drain, closeDB)
	}
}
