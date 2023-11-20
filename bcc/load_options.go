package bcc

type LoadOptions struct {
	Device     string
	AttachType int
}

type LoadOption func(*LoadOptions)

func DefaultLoadOptions() *LoadOptions {
	return &LoadOptions{AttachType: -1}
}

func LoadWithDevice(device string) LoadOption {
	return func(lo *LoadOptions) { lo.Device = device }
}

func LoadWithAttachType(attachType int) LoadOption {
	return func(lo *LoadOptions) {
		if attachType > -1 {
			lo.AttachType = attachType
		}
	}
}
