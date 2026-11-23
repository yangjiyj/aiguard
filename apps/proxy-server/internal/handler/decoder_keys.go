package handler

var commonProtocolJSONKeys = map[string]struct{}{
	"id": {}, "uid": {}, "uuid": {}, "sid": {}, "log_id": {}, "trace_id": {}, "conversation_id": {},
	"created_at": {}, "updated_at": {}, "create_time": {}, "update_time": {}, "timestamp": {}, "time": {},
	"role": {}, "status": {}, "reply_mode": {}, "mode": {}, "type": {}, "block_type": {},
	"reasoning": {}, "reasoning_content": {}, "thinking": {}, "thinking_content": {}, "think": {}, "thought": {},
	"scenario": {}, "tool_type": {}, "event": {}, "op": {}, "path": {}, "name": {}, "ip": {}, "inner_user_ip": {},
	"chain_of_thought": {}, "cot": {},
	"url": {}, "uri": {}, "icon_url": {}, "icon_url_dark": {}, "image_thumb_url": {}, "image_ori_url": {},
}

var vendorProtocolJSONKeys = map[string]map[string]struct{}{
	"chatgpt_web": {
		"message_status": {},
	},
	"deepseek_web": {},
	"claude_web":   {},
	"gemini_web": {
		"rcid": {}, "f.sid": {}, "bl": {}, "at": {}, "rpcids": {},
	},
	"kimi_web": {
		"local_conversation_id": {},
	},
	"qwen_web": {},
	"doubao_web": {
		"agent_id": {}, "agent_name": {}, "bot_id": {}, "bot_name": {}, "intent_agent_name": {},
		"ack_cost_time": {}, "first_packet_cost_time": {}, "llm_intention": {}, "llm_intention_detail": {},
		"plugin_intention": {}, "plugin_generalize_intention": {}, "vlm_intention": {}, "browsing_intention": {},
		"rich_media_intention": {}, "branch_intention": {}, "creation_detail_intention": {}, "deep_think_intention": {},
		"freshness": {}, "appended_system_prompt": {}, "valid": {}, "plugin_name": {}, "plugin_name_generalized": {},
		"origin_plugin_name": {}, "rich_media_intervene": {}, "z_agent_name": {}, "z_hit_intervene": {},
		"z_intervene_type": {}, "z_is_xianliu": {}, "z_is_jiangji_vlm": {}, "file_link_current_round": {},
		"intention_ori_score": {},
	},
}

var commonSemanticJSONKeys = map[string]struct{}{
	"content": {}, "text": {}, "prompt": {}, "query": {}, "question": {}, "answer": {}, "response": {}, "output": {}, "delta": {}, "payload": {}, "message": {},
}

var vendorSemanticJSONKeys = map[string]map[string]struct{}{
	"chatgpt_web":  {},
	"deepseek_web": {},
	"claude_web":   {},
	"gemini_web":   {},
	"kimi_web":     {},
	"qwen_web":     {},
	"doubao_web":   {},
}

func hasProtocolJSONKey(vendor, key string) bool {
	if _, ok := commonProtocolJSONKeys[key]; ok {
		return true
	}
	if vendor == "" {
		for _, keys := range vendorProtocolJSONKeys {
			if _, ok := keys[key]; ok {
				return true
			}
		}
		return false
	}
	if keys, ok := vendorProtocolJSONKeys[vendor]; ok {
		_, ok = keys[key]
		return ok
	}
	return false
}

func hasSemanticJSONKey(vendor, key string) bool {
	if _, ok := commonSemanticJSONKeys[key]; ok {
		return true
	}
	if vendor == "" {
		for _, keys := range vendorSemanticJSONKeys {
			if _, ok := keys[key]; ok {
				return true
			}
		}
		return false
	}
	if keys, ok := vendorSemanticJSONKeys[vendor]; ok {
		_, ok = keys[key]
		return ok
	}
	return false
}
