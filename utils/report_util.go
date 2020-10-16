/**************************************************
 * Author  : Jihyuck Yun (dr.jhyun@gmail.com)     *
 *           Baegjae Sung (baegjae@gmail.com)     *
 * since October 12, 2020                         *
 **************************************************/

package utils

import (
	"fmt"
	"github.com/montanaflynn/stats"
	"sort"
	"sync"
	"time"
)

type Phase uint64

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

/**************************************************
 * StartTime type implementation                  *
 **************************************************/
type StartTime struct {
	stime sync.Map // stime[holderId][phase] -> start time
}

func NewStartTime() *StartTime {
	return &StartTime{}
}

func (st *StartTime) SetStartTime(holderId string, phase Phase) {
	phaseTime := make(map[Phase]time.Time)
	phaseTime[phase] = time.Now()
	st.stime.Store(holderId, phaseTime)

	return
}

func (st *StartTime) GetStartTime(holderId string, phase Phase) time.Time {
	phaseTime, ok := st.stime.Load(holderId)
	if ok == false {
		log.Fatal("[" + holderId + "] get phaseTime before setting")
	}

	return phaseTime.(map[Phase]time.Time)[phase]
}

/**************************************************
 * Record type implementation                     *
 **************************************************/
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

	if rcd.duration.Seconds() > float64(HttpTimeout) {
		log.Fatal("AddRecord() error:",
			"\n\tholderId:", rcd.holderId,
			"\n\tphase:", PhaseMap[rcd.phase],
			"\n\tstartTime:", rcd.startTime,
			"\n\tendTime:", rcd.endTime,
			"\n\tduration:", rcd.duration,
			"\n[" + holderId + "] invalid duration value (sec):", rcd.duration.Seconds())
	}
	return
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
		fmt.Printf("Percentile[95%%, 99%%]=[%.1f, %.1f]\n", analysis.transPercentile95, analysis.transPercentile99)
		fmt.Printf("------------------------------------\n")
	}

	return
}

/**************************************************
 * PhaseAnalysis type implementation              *
 **************************************************/
type PhaseAnalysis struct {
	phase             Phase
	duration          time.Duration
	numTrans          uint64
	transPerSec       float64
	transPerMinute    float64
	transMin          float64 // sec
	transMax          float64 // sec
	transMedian       float64 // sec
	transVariance     float64 // sec
	transPercentile95 float64 // sec
	transPercentile99 float64 // sec
}

func NewPhaseAnalysis(records []Record, phase Phase) *PhaseAnalysis {
	if len(records) == 0 {
		return &PhaseAnalysis{}
	}

	sort.Slice(records, func(i, j int) bool {
		return records[i].startTime.Before(records[j].startTime)
	})

	startTimeMin := records[0].startTime

	sort.Slice(records, func(i, j int) bool {
		return records[i].endTime.After(records[j].endTime)
	})

	endTimeMax := records[0].endTime

	duration := endTimeMax.Sub(startTimeMin)
	numTrans := uint64(len(records))

	// Get statistics data
	var (
		durationsAsSec stats.Float64Data // []float64
	)

	// Get duration slice as seconds
	for _, rcd := range records {
		durationsAsSec = append(durationsAsSec, rcd.duration.Seconds())
	}

	transMinAsSec, _ := stats.Min(durationsAsSec)
	transMaxAsSec, _ := stats.Max(durationsAsSec)
	transMedianAsSec, _ := stats.Median(durationsAsSec)
	transVarianceAsSec, _ := stats.Variance(durationsAsSec)
	transPercentile95, _ := stats.Percentile(durationsAsSec, 95.0)
	transPercentile99, _ := stats.Percentile(durationsAsSec, 99.0)

	return &PhaseAnalysis{
		phase:             phase,
		duration:          duration,
		numTrans:          numTrans,
		transPerSec:       float64(numTrans) / duration.Seconds(),
		transPerMinute:    float64(numTrans) / duration.Seconds() * 60.0,
		transMin:          transMinAsSec,
		transMax:          transMaxAsSec,
		transMedian:       transMedianAsSec,
		transVariance:     transVarianceAsSec,
		transPercentile95: transPercentile95,
		transPercentile99: transPercentile99,
	}
}
