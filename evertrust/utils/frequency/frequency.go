package frequency

import (
	"fmt"
	"github.com/pkg/errors"
	"CRD-chain/log"
	"sync"
	"time"
)

const (
	flushFrequencyInterval = 15 * time.Minute //刷新频率表的间隔时长
	ReqIntervalLimit       = 1 * time.Second  //second 发送交易的间隔时长
)

var (
	FrequencyControlMap  sync.Map
	PeriodFreqControlMap sync.Map
)

type FreqNums struct {
	StartTime int64
	Nums      int64
	EndTime   int64
}

func InitFlush() {
	go flushFrequencyControl()
}

func flushFrequencyControl() {
	ticker := time.NewTicker(flushFrequencyInterval)
	for {
		select {
		case <-ticker.C:
			log.Trace("flush frequency start")
			//now := time.Now().Unix()
			now := time.Now().UnixNano()
			FrequencyControlMap.Range(func(key, value interface{}) bool {
				timestamp, ok := value.(int64)
				if !ok {
					log.Warn("assertion fail in range")
				}
				if now-timestamp > ReqIntervalLimit.Nanoseconds() {
					//fmt.Println("del", key)
					FrequencyControlMap.Delete(key)
				}
				return true
			})

			PeriodFreqControlMap.Range(func(key, value interface{}) bool {
				fn, ok := value.(FreqNums)
				if !ok {
					log.Warn("FreqNums assertion fail")
				}

				if now > fn.EndTime {
					//fmt.Println("del key", key)
					PeriodFreqControlMap.Delete(key)
				}

				return true
			})

		}
	}
}

func FrequencyControl(controlKey string, intervalLimit time.Duration) error {
	//now := time.Now().Unix()
	now := time.Now().UnixNano()

	value, loaded := PeriodFreqControlMap.LoadOrStore(controlKey, now)
	if loaded {
		timestamp, ok := value.(int64)
		if !ok {
			log.Warn("assertion fail")
		}

		interval := now - timestamp
		if interval < intervalLimit.Nanoseconds() {
			log.Warn("frequency too quick", "now", now, "timestamp", timestamp)
			return fmt.Errorf("req too quick, guarantee one req per %d nanoSecond", intervalLimit.Nanoseconds())
		}
		//update timestamp
		FrequencyControlMap.Store(controlKey, now)
	}
	return nil
}

func PeriodFreqControl(key interface{}, period time.Duration, numLimit int64) error {
	now := time.Now().UnixNano()
	freqNums := FreqNums{
		now,
		1,
		now + period.Nanoseconds(),
	}

	value, loaded := PeriodFreqControlMap.LoadOrStore(key, freqNums)
	if loaded {
		fn, ok := value.(FreqNums)
		if !ok {
			log.Warn("assertion fail")
			return errors.New("assertion fail")
		}
		if now <= fn.EndTime {
			//fmt.Println("nums", fn.Nums)
			fn.Nums++
			if fn.Nums >= numLimit {
				return fmt.Errorf("freq too quick, nums:%d, limit:%d, now:%d, start:%d, period:%d", fn.Nums, numLimit, now, fn.StartTime, period)
			}
			PeriodFreqControlMap.Store(key, fn)
		} else {
			//fmt.Println("now", time.Unix(0, now).Format("2006-01-02T15:04:05.999999999Z07:00"))
			//fmt.Println("end", time.Unix(0, fn.EndTime).Format("2006-01-02T15:04:05.999999999Z07:00"))
			//fmt.Println("start", time.Unix(0, fn.StartTime).Format("2006-01-02T15:04:05.999999999Z07:00"))
			PeriodFreqControlMap.Store(key, freqNums)
		}
	}

	return nil
}
