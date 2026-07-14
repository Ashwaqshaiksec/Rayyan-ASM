package scheduler

// Export unexported methods for white-box testing from the _test package.

func (s *Scheduler) CheckSLABreaches() {
	s.checkSLABreaches()
}

func (s *Scheduler) PurgeExpiredVerificationTokens() {
	s.purgeExpiredVerificationTokens()
}
