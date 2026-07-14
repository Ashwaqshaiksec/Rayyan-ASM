package scheduler

import "github.com/robfig/cron/v3"

// AddCron registers a 5-field cron expression (e.g. "0 3 * * *" = 03:00 daily).
// The underlying cron instance runs with WithSeconds() so AddFunc expects 6
// fields — use ParseStandard + Schedule instead to keep the 5-field syntax.
func (s *Scheduler) AddCron(expr string, fn func()) {
	sched, err := cron.ParseStandard(expr)
	if err != nil {
		s.log.Warnw("AddCron: invalid cron expression", "expr", expr, "error", err)
		return
	}
	s.cron.Schedule(sched, cron.FuncJob(fn))
}
