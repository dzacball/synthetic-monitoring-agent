package prober

import (
	"context"
	"fmt"

	"github.com/dzacball/synthetic-monitoring-agent/internal/k6runner"
	"github.com/dzacball/synthetic-monitoring-agent/internal/model"
	"github.com/dzacball/synthetic-monitoring-agent/misizonsniper/prober/dns"
	"github.com/dzacball/synthetic-monitoring-agent/misizonsniper/prober/http"
	"github.com/dzacball/synthetic-monitoring-agent/misizonsniper/prober/icmp"
	"github.com/dzacball/synthetic-monitoring-agent/misizonsniper/prober/k6"
	"github.com/dzacball/synthetic-monitoring-agent/misizonsniper/prober/logger"
	"github.com/dzacball/synthetic-monitoring-agent/misizonsniper/prober/multihttp"
	"github.com/dzacball/synthetic-monitoring-agent/misizonsniper/prober/tcp"
	"github.com/dzacball/synthetic-monitoring-agent/misizonsniper/prober/traceroute"
	sm "github.com/dzacball/synthetic-monitoring-agent/pkg/pb/synthetic_monitoring"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
)

type Prober interface {
	Name() string
	Probe(ctx context.Context, target string, registry *prometheus.Registry, logger logger.Logger) bool
}

func Run(ctx context.Context, p Prober, target string, registry *prometheus.Registry, logger logger.Logger) bool {
	return p.Probe(ctx, target, registry, logger)
}

type ProberFactory interface {
	New(ctx context.Context, logger zerolog.Logger, check model.Check) (Prober, string, error)
}

type proberFactory struct {
	runner k6runner.Runner
}

func NewProberFactory(runner k6runner.Runner) ProberFactory {
	return proberFactory{
		runner: runner,
	}
}

func (f proberFactory) New(ctx context.Context, logger zerolog.Logger, check model.Check) (Prober, string, error) {
	var (
		p      Prober
		target string
		err    error
	)

	switch checkType := check.Type(); checkType {
	case sm.CheckTypePing:
		p, err = icmp.NewProber(check.Check)
		target = check.Target

	case sm.CheckTypeHttp:
		p, err = http.NewProber(ctx, check.Check, logger)
		target = check.Target

	case sm.CheckTypeDns:
		p, err = dns.NewProber(check.Check)
		target = check.Settings.Dns.Server

	case sm.CheckTypeTcp:
		p, err = tcp.NewProber(ctx, check.Check, logger)
		target = check.Target

	case sm.CheckTypeTraceroute:
		p, err = traceroute.NewProber(check.Check, logger)
		target = check.Target

	case sm.CheckTypeK6:
		if f.runner != nil {
			p, err = k6.NewProber(ctx, check.Check, logger, f.runner)
			target = check.Target
		} else {
			err = fmt.Errorf("k6 checks are not enabled")
		}

	case sm.CheckTypeMultiHttp:
		if f.runner != nil {
			p, err = multihttp.NewProber(ctx, check.Check, logger, f.runner)
			target = check.Target
		} else {
			err = fmt.Errorf("k6 checks are not enabled")
		}

	default:
		return nil, "", fmt.Errorf("unsupported check type")
	}

	return p, target, err
}
