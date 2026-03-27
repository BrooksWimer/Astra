package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/netwise/agent/internal/api"
	"github.com/netwise/agent/internal/config"
	"github.com/netwise/agent/internal/eval"
	"github.com/netwise/agent/internal/labeling"
	"github.com/netwise/agent/internal/mdns"
	"github.com/netwise/agent/internal/network"
	"github.com/netwise/agent/internal/optimize"
	"github.com/netwise/agent/internal/scanner"
	"github.com/netwise/agent/internal/strategy"
)

const (
	version = "0.1.0"
	port    = 7777
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "experiment":
			runExperimentMode()
			return
		case "evaluate":
			runEvaluateMode()
			return
		case "dataset":
			runDatasetMode()
			return
		case "optimize":
			runOptimizeMode()
			return
		case "catalog":
			runCatalogMode()
			return
		}
	}

	cfg, err := config.Load("config.json")
	if err != nil {
		log.Printf("config load: %v, using defaults", err)
		cfg = config.Default()
	}

	iface, netInfo, err := network.PrimaryInterface()
	if err != nil {
		log.Fatalf("primary interface: %v", err)
	}
	log.Printf("Using interface %s: %s / %s gw %s", iface.Name, netInfo.LocalIP, netInfo.Subnet, netInfo.GatewayIP)

	hostname, _ := os.Hostname()
	svc, err := mdns.Advertise(port, version, hostname)
	if err != nil {
		log.Printf("mDNS advertise: %v (continuing without)", err)
	} else {
		defer svc.Shutdown()
	}

	srv := api.NewServer(port, version, hostname, netInfo, cfg)
	go func() {
		if err := srv.Run(); err != nil {
			log.Fatalf("server: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down...")
}

func runExperimentMode() {
	fs := flag.NewFlagSet("experiment", flag.ContinueOnError)
	outPath := fs.String("out", "scan-report.json", "optional output path for JSON report")
	pretty := fs.Bool("pretty", true, "pretty-print JSON output")
	timeout := fs.Int("timeout", 0, "override scan timeout in seconds")
	maxProbe := fs.Int("max-probe-ips", 0, "override max IP probes (0 means config default)")
	enablePortScan := fs.Bool("enable-port-scan", false, "enable optional port scan during discovery")
	profile := fs.String("profile", "", "named strategy profile to run (fast|medium|full|label_core)")
	strategyNames := fs.String("strategies", "", "comma-separated strategies to run (empty runs all discovered strategies)")
	corpusInputs := fs.String("corpus", "", "comma-separated corpus files/directories for offline experiment mode")
	fs.Usage = func() {
		log.Printf("Usage: agent experiment [--out <file>] [--profile <fast|medium|full|label_core>] [--timeout <seconds>] [--max-probe-ips <n>] [--enable-port-scan] [--corpus <file-or-dir,...>]")
	}
	if err := fs.Parse(os.Args[2:]); err != nil {
		log.Fatalf("experiment flags: %v", err)
	}

	cfg, err := config.Load("config.json")
	if err != nil {
		log.Printf("config load: %v, using defaults", err)
		cfg = config.Default()
	}
	if *timeout > 0 {
		cfg.ScanTimeoutSeconds = *timeout
	}
	if *maxProbe > 0 {
		cfg.MaxProbeIPs = *maxProbe
	}
	if *enablePortScan {
		cfg.EnablePortScan = true
	}
	if strings.TrimSpace(*profile) != "" {
		cfg.StrategyProfile = strings.ToLower(strings.TrimSpace(*profile))
	}

	filter := parseStrategyNames(*strategyNames)
	var out []byte
	var report *scanner.StrategyExperimentReport
	if strings.TrimSpace(*corpusInputs) != "" {
		report, err = scanner.RunCorpusExperiment(parseCSVList(*corpusInputs), cfg, filter)
		if err != nil {
			log.Fatalf("experiment: %v", err)
		}
		if *pretty {
			out, err = json.MarshalIndent(report, "", "  ")
		} else {
			out, err = json.Marshal(report)
		}
	} else {
		_, netInfo, err := network.PrimaryInterface()
		if err != nil {
			log.Fatalf("primary interface: %v", err)
		}
		if netInfo == nil {
			log.Fatalf("no primary interface found")
		}

		log.Printf("Running experiment on %s / %s (%s)", netInfo.InterfaceName, netInfo.LocalIP, netInfo.Subnet)
		report, err = scanner.RunStrategyExperiment(netInfo, cfg, filter)
		if err != nil {
			log.Fatalf("experiment: %v", err)
		}
		if *pretty {
			out, err = json.MarshalIndent(report, "", "  ")
		} else {
			out, err = json.Marshal(report)
		}
	}
	if err != nil {
		log.Fatalf("marshal report: %v", err)
	}

	if *outPath != "" {
		dir := filepath.Dir(*outPath)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			log.Fatalf("mkdir output directory: %v", err)
		}
		if err := os.WriteFile(*outPath, out, 0o644); err != nil {
			log.Fatalf("write report: %v", err)
		}
		log.Printf("experiment report written to %s", *outPath)
	} else {
		log.Printf("experiment report:\n%s", string(out))
	}

	log.Printf("experiment complete")
}

func runOptimizeMode() {
	fs := flag.NewFlagSet("optimize", flag.ContinueOnError)
	outPath := fs.String("out", "optimization-report.json", "optional output path for JSON report")
	pretty := fs.Bool("pretty", true, "pretty-print JSON output")
	inputs := fs.String("inputs", "", "comma-separated corpus files/directories")
	reportPath := fs.String("report", "", "optional experiment report path for strategy timing and status data")
	profiles := fs.String("profiles", "fast,medium", "comma-separated profiles to compare against full")
	fs.Usage = func() {
		log.Printf("Usage: agent optimize --inputs <file-or-dir,...> [--report <experiment-report.json>] [--profiles <fast,medium>] [--out <file>]")
	}
	if err := fs.Parse(os.Args[2:]); err != nil {
		log.Fatalf("optimize flags: %v", err)
	}
	if strings.TrimSpace(*inputs) == "" {
		log.Fatalf("optimize requires --inputs")
	}

	cfg, err := config.Load("config.json")
	if err != nil {
		log.Printf("config load: %v, using defaults", err)
		cfg = config.Default()
	}

	report, err := optimize.BuildReport(parseCSVList(*inputs), strings.TrimSpace(*reportPath), cfg, parseCSVList(*profiles))
	if err != nil {
		log.Fatalf("optimize: %v", err)
	}

	var out []byte
	if *pretty {
		out, err = json.MarshalIndent(report, "", "  ")
	} else {
		out, err = json.Marshal(report)
	}
	if err != nil {
		log.Fatalf("marshal optimization report: %v", err)
	}

	if *outPath != "" {
		dir := filepath.Dir(*outPath)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			log.Fatalf("mkdir output directory: %v", err)
		}
		if err := os.WriteFile(*outPath, out, 0o644); err != nil {
			log.Fatalf("write optimization report: %v", err)
		}
		log.Printf("optimization report written to %s", *outPath)
		return
	}

	log.Printf("optimization report:\n%s", string(out))
}

func runEvaluateMode() {
	fs := flag.NewFlagSet("evaluate", flag.ContinueOnError)
	outPath := fs.String("out", "evaluation-report.json", "optional output path for JSON report")
	pretty := fs.Bool("pretty", true, "pretty-print JSON output")
	name := fs.String("name", "corpus-eval", "evaluation report name")
	inputs := fs.String("inputs", "", "comma-separated corpus files/directories")
	fs.Usage = func() {
		log.Printf("Usage: agent evaluate --inputs <file-or-dir,...> [--name <report-name>] [--out <file>]")
	}
	if err := fs.Parse(os.Args[2:]); err != nil {
		log.Fatalf("evaluate flags: %v", err)
	}
	if strings.TrimSpace(*inputs) == "" {
		log.Fatalf("evaluate requires --inputs")
	}

	cfg, err := config.Load("config.json")
	if err != nil {
		log.Printf("config load: %v, using defaults", err)
		cfg = config.Default()
	}

	report, err := eval.BuildEvaluationReportFromCorpusInputsWithConfig(*name, parseCSVList(*inputs), cfg)
	if err != nil {
		log.Fatalf("evaluate: %v", err)
	}

	var out []byte
	if *pretty {
		out, err = json.MarshalIndent(report, "", "  ")
	} else {
		out, err = json.Marshal(report)
	}
	if err != nil {
		log.Fatalf("marshal evaluation report: %v", err)
	}

	if *outPath != "" {
		dir := filepath.Dir(*outPath)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			log.Fatalf("mkdir output directory: %v", err)
		}
		if err := os.WriteFile(*outPath, out, 0o644); err != nil {
			log.Fatalf("write evaluation report: %v", err)
		}
		log.Printf("evaluation report written to %s", *outPath)
		return
	}

	log.Printf("evaluation report:\n%s", string(out))
}

func runDatasetMode() {
	fs := flag.NewFlagSet("dataset", flag.ContinueOnError)
	outPath := fs.String("out", "labeling-dataset.json", "optional output path for JSON dataset")
	pretty := fs.Bool("pretty", true, "pretty-print JSON output")
	inputs := fs.String("inputs", "", "comma-separated corpus files/directories")
	fs.Usage = func() {
		log.Printf("Usage: agent dataset --inputs <file-or-dir,...> [--out <file>]")
	}
	if err := fs.Parse(os.Args[2:]); err != nil {
		log.Fatalf("dataset flags: %v", err)
	}
	if strings.TrimSpace(*inputs) == "" {
		log.Fatalf("dataset requires --inputs")
	}

	cfg, err := config.Load("config.json")
	if err != nil {
		log.Printf("config load: %v, using defaults", err)
		cfg = config.Default()
	}

	dataset, err := labeling.BuildDatasetFromCorpusInputs(parseCSVList(*inputs), cfg)
	if err != nil {
		log.Fatalf("dataset: %v", err)
	}

	var out []byte
	if *pretty {
		out, err = json.MarshalIndent(dataset, "", "  ")
	} else {
		out, err = json.Marshal(dataset)
	}
	if err != nil {
		log.Fatalf("marshal dataset: %v", err)
	}

	if *outPath != "" {
		dir := filepath.Dir(*outPath)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			log.Fatalf("mkdir output directory: %v", err)
		}
		if err := os.WriteFile(*outPath, out, 0o644); err != nil {
			log.Fatalf("write dataset: %v", err)
		}
		log.Printf("dataset written to %s", *outPath)
		return
	}

	log.Printf("dataset:\n%s", string(out))
}

func runCatalogMode() {
	fs := flag.NewFlagSet("catalog", flag.ContinueOnError)
	outPath := fs.String("out", "", "optional output path for JSON catalog")
	pretty := fs.Bool("pretty", true, "pretty-print JSON output")
	format := fs.String("format", "json", "output format (json)")
	fs.Usage = func() {
		log.Printf("Usage: agent catalog [--format json] [--out <file>]")
	}
	if err := fs.Parse(os.Args[2:]); err != nil {
		log.Fatalf("catalog flags: %v", err)
	}

	switch strings.ToLower(strings.TrimSpace(*format)) {
	case "", "json":
	default:
		log.Fatalf("catalog format %q is not supported", *format)
	}

	catalog := strategy.BuildOperatorCatalog()
	var out []byte
	var err error
	if *pretty {
		out, err = json.MarshalIndent(catalog, "", "  ")
	} else {
		out, err = json.Marshal(catalog)
	}
	if err != nil {
		log.Fatalf("marshal catalog: %v", err)
	}

	if *outPath != "" {
		dir := filepath.Dir(*outPath)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			log.Fatalf("mkdir output directory: %v", err)
		}
		if err := os.WriteFile(*outPath, out, 0o644); err != nil {
			log.Fatalf("write catalog: %v", err)
		}
		log.Printf("catalog written to %s", *outPath)
		return
	}

	if _, err := os.Stdout.Write(append(out, '\n')); err != nil {
		log.Fatalf("write catalog: %v", err)
	}
}

func parseStrategyNames(csv string) []string {
	return parseCSVList(csv)
}

func parseCSVList(csv string) []string {
	if strings.TrimSpace(csv) == "" {
		return nil
	}
	lines := strings.Split(csv, ",")
	out := make([]string, 0, len(lines))
	for _, raw := range lines {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		out = append(out, name)
	}
	return out
}
