package handler

import "sync"

var (
	captchaIssuedMu sync.Mutex
	captchaIssued   = map[string]string{}
)

func resetCaptchaFallbackForTest() {
	captchaFallback = &captchaLocalStore{entries: map[string]captchaLocalEntry{}}
	captchaIssuedMu.Lock()
	captchaIssued = map[string]string{}
	captchaIssuedMu.Unlock()
	captchaFallbackIssuedHook = func(id, code string) {
		captchaIssuedMu.Lock()
		captchaIssued[id] = code
		captchaIssuedMu.Unlock()
	}
}

func captchaFallbackCodeForTest(id string) (string, bool) {
	captchaIssuedMu.Lock()
	defer captchaIssuedMu.Unlock()
	code, ok := captchaIssued[id]
	return code, ok
}
