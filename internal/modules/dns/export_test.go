package dns

var ScoreEmailSecurity = scoreEmailSecurity

// exported for tests so we can inject a fake resolver
var CheckSPF = checkSPF
var CheckDMARC = checkDMARC
var CheckDKIM = checkDKIM

type TXTResolver = txtResolver
