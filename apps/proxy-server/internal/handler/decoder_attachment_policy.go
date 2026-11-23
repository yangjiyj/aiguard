package handler

type AttachmentRetentionPolicy interface {
	ShouldRetainBytes(contentType, fileName string, body []byte) bool
}

type defaultAttachmentPolicy struct{}

func defaultAttachmentRetentionPolicy() AttachmentRetentionPolicy {
	return defaultAttachmentPolicy{}
}

func (defaultAttachmentPolicy) ShouldRetainBytes(contentType, fileName string, body []byte) bool {
	return shouldRetainAttachmentBytes(contentType, fileName, body)
}
