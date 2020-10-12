package utils

import (
	"fmt"
	"github.com/montanaflynn/stats"
	"sort"
	"sync"
	"time"
)

type Phase uint64

type StartTime struct {
	stime map[string]map[Phase]time.Time // time[holderId][phase] returns stored start time
	mutex sync.RWMutex
}

const (
	ConnectPhase Phase = 1 << iota
	IssuePhase
	VerifyPhase
	AllPhase = ConnectPhase | IssuePhase | VerifyPhase
)

var (
	PhaseMap = map[Phase]string{
		ConnectPhase: "Connect",
		IssuePhase:   "Issue",
		VerifyPhase:  "Verify",
		AllPhase:     "Total"}
)

func NewStartTime() *StartTime {
	startTime := &StartTime{}
	startTime.stime = make(map[string]map[Phase]time.Time)

	return startTime
}

func (st *StartTime) SetStartTime(holderId string, phase Phase) {
	st.mutex.Lock()
	st.stime[holderId] = map[Phase]time.Time{phase: time.Now()}
	st.mutex.Unlock()
}

func (st *StartTime) GetStartTime(holderId string, phase Phase) time.Time {
	st.mutex.RLock()
	startTime := st.stime[holderId][phase]
	st.mutex.RUnlock()

	return startTime
}

type Record struct {
	holderId  string
	phase     Phase
	startTime time.Time
	endTime   time.Time
	duration  time.Duration
}

type Report struct {
	records []Record
	mutex   sync.RWMutex
}

func NewReport() *Report {
	return &Report{}
}

func (rpt *Report) AddRecord(holderId string, phase Phase, startTime time.Time, endTime time.Time) {
	rcd := Record{
		holderId:  holderId,
		phase:     phase,
		startTime: startTime,
		endTime:   endTime,
		duration:  endTime.Sub(startTime),
	}
	rpt.mutex.Lock()
	rpt.records = append(rpt.records, rcd)
	rpt.mutex.Unlock()
}

func (rpt *Report) GetRecords() []Record {
	rpt.mutex.RLock()
	records := make([]Record, len(rpt.records))
	copy(records, rpt.records)
	rpt.mutex.RUnlock()

	return records
}

func (rpt *Report) FilterRecords(phaseList ...Phase) []Record {
	var (
		result []Record
		mask   = Phase(0)
	)

	if len(phaseList) == 0 {
		return result
	}

	for _, phase := range phaseList {
		mask |= phase
	}

	rpt.mutex.RLock()
	for _, rcd := range rpt.records {
		if rcd.phase&mask != 0 {
			result = append(result, rcd)
		}
	}
	rpt.mutex.RUnlock()

	return result
}

func (rpt *Report) Print() {
	var (
		phaseAnals []PhaseAnalysis
	)

	connectRecords := rpt.FilterRecords(ConnectPhase)
	issueRecords := rpt.FilterRecords(IssuePhase)
	verifyRecords := rpt.FilterRecords(VerifyPhase)
	allRecords := rpt.FilterRecords(AllPhase)

	phaseAnals = append(phaseAnals, *NewPhaseAnalysis(connectRecords, ConnectPhase))
	phaseAnals = append(phaseAnals, *NewPhaseAnalysis(issueRecords, IssuePhase))
	phaseAnals = append(phaseAnals, *NewPhaseAnalysis(verifyRecords, VerifyPhase))
	phaseAnals = append(phaseAnals, *NewPhaseAnalysis(allRecords, AllPhase))

	for _, analysis := range phaseAnals {
		fmt.Printf("\n------ %s Performance ------\n", PhaseMap[analysis.phase])
		fmt.Printf("*** Throughput ***\n")
		fmt.Printf("Duration %.1f secs to %d transactions.\n", analysis.duration.Seconds(), analysis.numTrans)
		fmt.Printf("PerSec %.1f  PerMinute %.1f\n", analysis.transPerSec, analysis.transPerMinute)
		fmt.Printf("\n*** Transaction time (sec) ***\n")
		fmt.Printf("Min %.1f Max %.1f\n", analysis.transMin, analysis.transMax)
		fmt.Printf("Median %.1f  Variance %.2f\n", analysis.transMedian, analysis.transVariance)
		fmt.Printf("------------------------------------\n")
	}

}

type PhaseAnalysis struct {
	phase             Phase
	duration          time.Duration
	numTrans          uint64
	transPerSec       float64
	transPerMinute    float64
	transMin          float64	// sec
	transMax          float64	// sec
	transMedian       float64	// sec
	transVariance     float64	// sec
}

func NewPhaseAnalysis(records []Record, phase Phase) *PhaseAnalysis {
	sort.Slice(records, func(i, j int) bool {
		return records[i].startTime.Before(records[j].startTime)
	})

	startMin := records[0].startTime

	sort.Slice(records, func(i, j int) bool {
		return records[i].endTime.After(records[j].endTime)
	})

	endMax := records[0].endTime

	duration := endMax.Sub(startMin)
	numTrans := uint64(len(records))

	sort.Slice(records, func(i, j int) bool {
		return records[i].duration < records[j].duration
	})

	transMinAsSec := records[0].duration.Seconds()
	transMaxAsSec := records[len(records)-1].duration.Seconds()

	var (
		durationsAsSec []float64
	)

	// Get duration as seconds
	for _, rcd := range records {
		durationsAsSec = append(durationsAsSec, rcd.duration.Seconds())
	}

	medianAsSec, _ := stats.Median(durationsAsSec)
	varianceAsSec, _ := stats.Variance(durationsAsSec)

	return &PhaseAnalysis{
		phase:             phase,
		duration:          duration,
		numTrans:          numTrans,
		transPerSec:       float64(numTrans) / duration.Seconds(),
		transPerMinute:    float64(numTrans) / duration.Seconds() * 60.0,
		transMin:          transMinAsSec,
		transMax:          transMaxAsSec,
		transMedian:       medianAsSec,
		transVariance:     varianceAsSec,
	}
}
