package handler

import (
	"encoding/binary"
	"testing"
)

// kimiConnectFrame 构造一帧 Connect-RPC（application/connect+json）消息帧：
// 1 字节 flag + 4 字节大端 uint32 长度 + 该长度的 JSON 体。flag 0x00 = 普通消息帧。
func kimiConnectFrame(jsonStr string) []byte {
	body := []byte(jsonStr)
	frame := make([]byte, 5+len(body))
	frame[0] = 0x00
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(body)))
	copy(frame[5:], body)
	return frame
}

// kimiConnectEndStreamFrame 构造 end-stream 帧：flag 含 0x02 位，体是 trailers（如 "{}"）。
// 重组器必须容错跳过，不得把它当答案。
func kimiConnectEndStreamFrame(jsonStr string) []byte {
	body := []byte(jsonStr)
	frame := make([]byte, 5+len(body))
	frame[0] = 0x02
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(body)))
	copy(frame[5:], body)
	return frame
}

// kimi 网页版响应是 Connect-RPC（connect+json）连续帧，不是 ChatGPT 的 SSE。
// 模型答案的【首段】在种子帧 op:"set",mask:"block.text" 的 block.text.content（真包 163 实证），
// 其后的增量才走 op:"append",mask:"block.text.content"。按帧序拼接（种子 + 增量）= 完整答案。
// 回归保护：曾只收 append → 丢答案开头（种子帧首段被漏掉）。
func TestDecodeKimiWebResponse_ConnectJSONReassemblesAnswer(t *testing.T) {
	var body []byte
	// heartbeat 帧（无 op/mask）——忽略。
	body = append(body, kimiConnectFrame(`{"heartbeat":{}}`)...)
	// op:"set"（带 chat.id）：会话元数据，chat.id 作分组键。
	body = append(body, kimiConnectFrame(`{"op":"set","eventOffset":0,"chat":{"id":"chat-abc-123","name":"未命名会话"}}`)...)
	// set/message：用户消息，role:user，blocks 含 text"测试问题"——非模型答案，忽略。
	body = append(body, kimiConnectFrame(`{"op":"set","mask":"message","message":{"role":"user","blocks":[{"text":{"content":"测试问题"}}]}}`)...)
	// 种子帧 set/block.text：模型答案【首段】"你好"，文本在 block.text.content。
	body = append(body, kimiConnectFrame(`{"op":"set","mask":"block.text","block":{"id":"1","text":{"content":"你好"}}}`)...)
	// append/block.text.content：模型答案正文增量，按帧序拼接。
	body = append(body, kimiConnectFrame(`{"op":"append","mask":"block.text.content","block":{"id":"1","text":{"content":"世界"}}}`)...)
	body = append(body, kimiConnectFrame(`{"op":"append","mask":"block.text.content","block":{"id":"1","text":{"content":"！"}}}`)...)
	// set/message.status：消息状态元数据——不是答案。
	body = append(body, kimiConnectFrame(`{"op":"set","mask":"message.status","message":{"status":"finished"}}`)...)
	// end-stream 帧（flag 0x02，体 "{}"）——容错跳过。
	body = append(body, kimiConnectEndStreamFrame(`{}`)...)

	got, ok := decodeKimiWebResponse(body, "application/connect+json")
	if !ok {
		t.Fatalf("expected decode to succeed")
	}
	// 关键断言：种子帧首段"你好"必须在答案开头，不得被漏。
	if got.Text != "你好世界！" {
		t.Fatalf("answer mismatch (seed frame first segment must be included):\n got=%q\nwant=%q", got.Text, "你好世界！")
	}
	if got.ConversationID != "chat-abc-123" {
		t.Fatalf("conversation_id mismatch: got %q want %q", got.ConversationID, "chat-abc-123")
	}
}

// chat.files 是【用户上传文件被服务端回显】（真包 186 实证：用户上传的图片，meta.sizeBytes 是 JSON 字符串
// "2012314" 不是数字），不是模型产出 → 响应侧绝不登记为附件，否则后台误显示"模型返回了文件/图片"，
// 把用户的隐私文件（如身份证图）错误归属为模型输出。用户上传文件已在请求侧 + /file/upload 被捕获。
// 同时验证：字符串型 sizeBytes 不得导致崩溃（旧代码用 .(float64) 断言会失败，删除收集逻辑后该问题消失）。
func TestDecodeKimiWebResponse_ChatFilesEchoNotResponseAttachment(t *testing.T) {
	var body []byte
	body = append(body, kimiConnectFrame(`{"heartbeat":{}}`)...)
	// append/chat.files：用户上传文件回显，sizeBytes 为字符串"2012314"（真包形态），带 chat.id。
	body = append(body, kimiConnectFrame(`{"op":"append","mask":"chat.files","chat":{"id":"chat-file-456","files":[{"id":"file-xyz-789","meta":{"name":"用户文件.pdf","contentType":"application/pdf","sizeBytes":"2012314","checksum":"deadbeef","type":"FILE_TYPE_DOCUMENT"},"blob":{"signUrl":"https://www.kimi.com/apiv2-files/sign-obj/blob/xyz?sig=secret"}}]}}`)...)
	// 种子帧 + 增量：模型只回了文字。
	body = append(body, kimiConnectFrame(`{"op":"set","mask":"block.text","block":{"id":"1","text":{"content":"这是一份"}}}`)...)
	body = append(body, kimiConnectFrame(`{"op":"append","mask":"block.text.content","block":{"id":"1","text":{"content":"文档摘要。"}}}`)...)
	body = append(body, kimiConnectEndStreamFrame(`{}`)...)

	got, ok := decodeKimiWebResponse(body, "application/connect+json")
	if !ok {
		t.Fatalf("expected decode to succeed despite string sizeBytes")
	}
	if got.Text != "这是一份文档摘要。" {
		t.Fatalf("answer mismatch: got=%q want=%q", got.Text, "这是一份文档摘要。")
	}
	if got.ConversationID != "chat-file-456" {
		t.Fatalf("conversation_id mismatch: got %q want %q", got.ConversationID, "chat-file-456")
	}
	// 核心回归：chat.files 回显绝不登记为响应附件（防隐私误归属）。
	if len(got.Attachments) != 0 {
		t.Fatalf("chat.files echo must not be a response attachment, got %d: %+v", len(got.Attachments), got.Attachments)
	}
}

// 坏帧（JSON 解析失败 / 长度越界）必须容错跳过，不崩，仍抽出其余有效帧的答案（含种子帧首段）。
func TestDecodeKimiWebResponse_ToleratesCorruptFrames(t *testing.T) {
	var body []byte
	// 一帧体是非法 JSON。
	body = append(body, kimiConnectFrame(`{this is not json`)...)
	body = append(body, kimiConnectFrame(`{"op":"set","mask":"block.text","block":{"text":{"content":"种子"}}}`)...)
	body = append(body, kimiConnectFrame(`{"op":"append","mask":"block.text.content","block":{"text":{"content":"有效正文"}}}`)...)
	got, ok := decodeKimiWebResponse(body, "application/connect+json")
	if !ok {
		t.Fatalf("expected decode to succeed despite corrupt frame")
	}
	if got.Text != "种子有效正文" {
		t.Fatalf("answer mismatch: got=%q want=%q", got.Text, "种子有效正文")
	}
}
